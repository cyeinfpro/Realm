from __future__ import annotations

import asyncio
import json
import os
import time
from typing import Any, Dict, List, Optional, Tuple

from fastapi import FastAPI

from ..clients.agent import agent_post
from ..db import (
    insert_netmon_samples,
    list_netmon_monitors,
    list_nodes,
    prune_netmon_samples,
    update_netmon_monitor,
)
from .apply import node_verify_tls


_NETMON_BG_ENABLED = (os.getenv("REALM_NETMON_BG_ENABLED") or "1").strip() not in ("0", "false", "False")
try:
    _NETMON_RETENTION_DAYS = int((os.getenv("REALM_NETMON_RETENTION_DAYS") or "7").strip() or 7)
except Exception:
    _NETMON_RETENTION_DAYS = 7
if _NETMON_RETENTION_DAYS < 1:
    _NETMON_RETENTION_DAYS = 1
if _NETMON_RETENTION_DAYS > 90:
    _NETMON_RETENTION_DAYS = 90

try:
    _NETMON_HTTP_TIMEOUT = float((os.getenv("REALM_NETMON_HTTP_TIMEOUT") or "8.0").strip() or 3.5)
except Exception:
    _NETMON_HTTP_TIMEOUT = 3.5
if _NETMON_HTTP_TIMEOUT < 1.5:
    _NETMON_HTTP_TIMEOUT = 1.5
if _NETMON_HTTP_TIMEOUT > 20:
    _NETMON_HTTP_TIMEOUT = 20.0

try:
    _NETMON_PROBE_TIMEOUT = float((os.getenv("REALM_NETMON_PROBE_TIMEOUT") or "2.5").strip() or 2.5)
except Exception:
    _NETMON_PROBE_TIMEOUT = 2.5
if _NETMON_PROBE_TIMEOUT < 0.5:
    _NETMON_PROBE_TIMEOUT = 0.5
if _NETMON_PROBE_TIMEOUT > 10:
    _NETMON_PROBE_TIMEOUT = 10.0

try:
    _NETMON_MAX_CONCURRENCY = int((os.getenv("REALM_NETMON_CONCURRENCY") or "40").strip() or 40)
except Exception:
    _NETMON_MAX_CONCURRENCY = 40
if _NETMON_MAX_CONCURRENCY < 4:
    _NETMON_MAX_CONCURRENCY = 4
if _NETMON_MAX_CONCURRENCY > 200:
    _NETMON_MAX_CONCURRENCY = 200

_NETMON_SEM = asyncio.Semaphore(_NETMON_MAX_CONCURRENCY)
_NETMON_BG_LAST_RUN: Dict[int, float] = {}


def enabled() -> bool:
    return bool(_NETMON_BG_ENABLED)


def _netmon_chunk(items: List[Optional[str]], size: int) -> List[List[str]]:
    out: List[List[str]] = []
    buf: List[str] = []
    for x in items:
        if x is None:
            continue
        s = str(x)
        if not s:
            continue
        buf.append(s)
        if len(buf) >= size:
            out.append(buf)
            buf = []
    if buf:
        out.append(buf)
    return out


async def _netmon_call_agent(node: Dict[str, Any], body: Dict[str, Any], timeout: float) -> Dict[str, Any]:
    """Call agent /api/v1/netprobe with a global concurrency limit."""
    async with _NETMON_SEM:
        return await agent_post(
            node.get("base_url", ""),
            node.get("api_key", ""),
            "/api/v1/netprobe",
            body,
            node_verify_tls(node),
            timeout=timeout,
        )


async def _netmon_collect_due(monitors_due: List[Dict[str, Any]], nodes_map: Dict[int, Dict[str, Any]]) -> None:
    """Collect a batch of due monitors.

    This is an optimized collector that batches probes per-node/per-mode/per-port so we don't
    generate M*N HTTP calls (which can cause intermittent timeouts/failures when monitors scale).
    """

    if not monitors_due:
        return

    ts_ms = int(time.time() * 1000)

    # group key: (node_id, mode, tcp_port)
    groups: Dict[Tuple[int, str, int], Dict[str, Any]] = {}
    # per monitor status for last_run_msg
    mon_stat: Dict[int, Dict[str, Any]] = {}

    def _mon_node_ids(mon: Dict[str, Any]) -> List[int]:
        node_ids = mon.get("node_ids") if isinstance(mon.get("node_ids"), list) else None
        if node_ids is None:
            try:
                raw = json.loads(str(mon.get("node_ids_json") or "[]"))
            except Exception:
                raw = []
            node_ids = raw if isinstance(raw, list) else []
        cleaned: List[int] = []
        for x in node_ids:
            try:
                nid = int(x)
            except Exception:
                continue
            if nid > 0 and nid not in cleaned:
                cleaned.append(nid)
        return cleaned[:60]

    # build groups
    for mon in monitors_due:
        try:
            mid = int(mon.get("id") or 0)
        except Exception:
            continue
        if mid <= 0:
            continue

        target = str(mon.get("target") or "").strip()
        if not target:
            continue

        mode = str(mon.get("mode") or "ping").strip().lower()
        if mode not in ("ping", "tcping"):
            mode = "ping"

        try:
            tcp_port = int(mon.get("tcp_port") or 443)
        except Exception:
            tcp_port = 443
        if tcp_port < 1 or tcp_port > 65535:
            tcp_port = 443

        node_ids = _mon_node_ids(mon)
        if not node_ids:
            # no nodes selected
            try:
                update_netmon_monitor(mid, last_run_ts_ms=ts_ms, last_run_msg="no_nodes")
            except Exception:
                pass
            continue

        mon_stat[mid] = {"ok_any": False, "err": "", "ts": ts_ms, "seen": 0}

        for nid in node_ids:
            node = nodes_map.get(int(nid))
            if not node:
                # record a synthetic failure so the monitor shows something meaningful
                mon_stat[mid]["seen"] += 1
                if not mon_stat[mid]["err"]:
                    mon_stat[mid]["err"] = "node_missing"
                continue
            key = (int(nid), mode, int(tcp_port))
            g = groups.get(key)
            if not g:
                g = {"targets": [], "mids_by_target": {}}
                groups[key] = g
            m = g["mids_by_target"].get(target)
            if not m:
                g["mids_by_target"][target] = [mid]
                g["targets"].append(target)
            else:
                m.append(mid)

    if not groups:
        return

    rows: List[tuple] = []

    def _should_retry_err(s: str) -> bool:
        s = (s or "").lower()
        for kw in (
            "timeout",
            "timed out",
            "temporar",
            "connection aborted",
            "connection reset",
            "broken pipe",
        ):
            if kw in s:
                return True
        return False

    async def _run_group(nid: int, mode: str, tcp_port: int, targets: List[str], mids_by_target: Dict[str, List[int]]):
        node = nodes_map.get(int(nid))
        if not node:
            # should not happen (filtered above)
            for t in targets:
                for mid in (mids_by_target.get(t) or []):
                    stt = mon_stat.get(int(mid))
                    if stt:
                        stt["seen"] += 1
                        if not stt["err"]:
                            stt["err"] = "node_missing"
                    rows.append((int(mid), int(nid), int(ts_ms), 0, None, "node_missing"))
            return

        # HTTP timeout should always be larger than probe timeout + overhead
        http_timeout = float(max(_NETMON_HTTP_TIMEOUT, float(_NETMON_PROBE_TIMEOUT) + 3.0))

        for chunk in _netmon_chunk(targets, 50):
            body = {
                "mode": mode,
                "targets": chunk,
                "tcp_port": int(tcp_port),
                "timeout": float(_NETMON_PROBE_TIMEOUT),
            }

            last: Optional[Dict[str, Any]] = None
            # at most 2 tries on transient failures
            for attempt in range(2):
                try:
                    data = await _netmon_call_agent(node, body, timeout=http_timeout)
                    last = data if isinstance(data, dict) else {"ok": False, "error": "bad_response"}
                except Exception as exc:
                    last = {"ok": False, "error": str(exc)}

                if not isinstance(last, dict) or last.get("ok") is not True:
                    err = str(last.get("error") if isinstance(last, dict) else last)
                    if attempt == 0 and _should_retry_err(err):
                        await asyncio.sleep(0.12)
                        continue
                    break

                # agent call ok
                break

            # parse results
            ok_call = isinstance(last, dict) and last.get("ok") is True
            res_map = last.get("results") if ok_call and isinstance(last.get("results"), dict) else {}

            for t in chunk:
                mids = mids_by_target.get(t) or []
                item = res_map.get(t) if isinstance(res_map, dict) else None

                if ok_call and isinstance(item, dict):
                    if item.get("ok"):
                        try:
                            v = float(item.get("latency_ms")) if item.get("latency_ms") is not None else None
                        except Exception:
                            v = None
                        for mid in mids:
                            mid_i = int(mid)
                            stt = mon_stat.get(mid_i)
                            if stt:
                                stt["seen"] += 1
                                stt["ok_any"] = True
                            rows.append((mid_i, int(nid), int(ts_ms), 1, v, None))
                        continue

                    # probe failed for this target
                    err = str(item.get("error") or "probe_failed")
                    if len(err) > 200:
                        err = err[:200] + "…"

                    # retry per-target once if it looks transient and we haven't retried the call already
                    if _should_retry_err(err):
                        # do a best-effort single-target retry (cheaper than re-running the whole chunk)
                        try:
                            one_body = {
                                "mode": mode,
                                "targets": [t],
                                "tcp_port": int(tcp_port),
                                "timeout": float(_NETMON_PROBE_TIMEOUT),
                            }
                            data2 = await _netmon_call_agent(node, one_body, timeout=http_timeout)
                            if isinstance(data2, dict) and data2.get("ok") is True:
                                rm2 = data2.get("results") if isinstance(data2.get("results"), dict) else {}
                                it2 = rm2.get(t) if isinstance(rm2, dict) else None
                                if isinstance(it2, dict) and it2.get("ok"):
                                    try:
                                        v = float(it2.get("latency_ms")) if it2.get("latency_ms") is not None else None
                                    except Exception:
                                        v = None
                                    for mid in mids:
                                        mid_i = int(mid)
                                        stt = mon_stat.get(mid_i)
                                        if stt:
                                            stt["seen"] += 1
                                            stt["ok_any"] = True
                                        rows.append((mid_i, int(nid), int(ts_ms), 1, v, None))
                                    continue
                                if isinstance(it2, dict) and it2.get("error"):
                                    err = str(it2.get("error"))
                        except Exception:
                            pass

                    for mid in mids:
                        mid_i = int(mid)
                        stt = mon_stat.get(mid_i)
                        if stt:
                            stt["seen"] += 1
                            if not stt["err"]:
                                stt["err"] = err
                        rows.append((mid_i, int(nid), int(ts_ms), 0, None, err))
                    continue

                # agent call failed or missing item
                err = "agent_failed"
                if isinstance(last, dict) and last.get("error"):
                    err = str(last.get("error"))
                if len(err) > 200:
                    err = err[:200] + "…"
                for mid in mids:
                    mid_i = int(mid)
                    stt = mon_stat.get(mid_i)
                    if stt:
                        stt["seen"] += 1
                        if not stt["err"]:
                            stt["err"] = err
                    rows.append((mid_i, int(nid), int(ts_ms), 0, None, err))

    tasks: List[asyncio.Task] = []
    for (nid, mode, tcp_port), g in groups.items():
        targets = g.get("targets") or []
        mids_by_target = g.get("mids_by_target") or {}
        if not targets:
            continue
        tasks.append(
            asyncio.create_task(_run_group(int(nid), str(mode), int(tcp_port), list(targets), dict(mids_by_target)))
        )

    if tasks:
        await asyncio.gather(*tasks, return_exceptions=True)

    # Persist samples (best-effort)
    try:
        if rows:
            insert_netmon_samples(rows)
    except Exception:
        pass

    # Update monitor last_run
    for mid, stt in mon_stat.items():
        try:
            msg = "ok" if bool(stt.get("ok_any")) else (str(stt.get("err") or "failed"))
            update_netmon_monitor(int(mid), last_run_ts_ms=int(ts_ms), last_run_msg=msg)
        except Exception:
            pass


async def _netmon_bg_loop() -> None:
    """Background loop that continuously collects NetMon monitors."""
    last_refresh = 0.0
    last_cleanup = 0.0
    monitors_cache: List[Dict[str, Any]] = []
    nodes_map: Dict[int, Dict[str, Any]] = {}

    while True:
        try:
            now = time.time()

            # Refresh config cache periodically
            if (now - last_refresh) >= 3.0:
                try:
                    monitors_cache = list_netmon_monitors()
                except Exception:
                    monitors_cache = []
                try:
                    nodes_map = {int(n.get("id") or 0): n for n in list_nodes() if int(n.get("id") or 0) > 0}
                except Exception:
                    nodes_map = {}
                last_refresh = now

            # Schedule due monitors (batch)
            due: List[Dict[str, Any]] = []
            for mon in monitors_cache:
                try:
                    mid = int(mon.get("id") or 0)
                except Exception:
                    continue
                if mid <= 0:
                    continue
                if not bool(mon.get("enabled") or 0):
                    continue
                try:
                    interval = int(mon.get("interval_sec") or 5)
                except Exception:
                    interval = 5
                if interval < 1:
                    interval = 1
                if interval > 3600:
                    interval = 3600

                last = float(_NETMON_BG_LAST_RUN.get(mid, 0.0) or 0.0)
                if (now - last) >= float(interval):
                    _NETMON_BG_LAST_RUN[mid] = now
                    due.append(mon)

            if due:
                # Optimized collector: batch probes per node/mode/port to avoid overload.
                await _netmon_collect_due(due, nodes_map)

            # Cleanup old samples
            if (now - last_cleanup) >= 60.0:
                try:
                    cutoff_ms = int((now - (_NETMON_RETENTION_DAYS * 86400)) * 1000)
                    prune_netmon_samples(cutoff_ms)
                except Exception:
                    pass
                last_cleanup = now

        except Exception:
            # Never crash the loop
            pass

        await asyncio.sleep(1.0)


def start_background(app: FastAPI) -> None:
    """Start NetMon background collector (idempotent)."""
    if not _NETMON_BG_ENABLED:
        return
    if getattr(app.state, "netmon_bg_started", False):
        return
    app.state.netmon_bg_started = True
    try:
        asyncio.create_task(_netmon_bg_loop())
    except Exception:
        pass
