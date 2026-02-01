from __future__ import annotations

import asyncio
import json
import os
import time
import base64
import hmac
import hashlib
import secrets
import uuid
import io
import zipfile
from datetime import datetime
from urllib.parse import urlparse, urlencode
from pathlib import Path
from typing import Any, Dict, Optional, List

from fastapi import Depends, FastAPI, File, Form, HTTPException, Request, UploadFile
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse, Response, PlainTextResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.middleware.sessions import SessionMiddleware

from .auth import ensure_secret_key, load_credentials, save_credentials, verify_login
from .db import (
    add_node,
    delete_node,
    ensure_db,
    get_group_orders,
    get_node,
    get_node_by_api_key,
    get_node_by_base_url,
    get_desired_pool,
    get_last_report,
    list_nodes,
    upsert_group_order,
    set_desired_pool,
    set_desired_pool_exact,
    set_desired_pool_version_exact,
    update_node_basic,
    update_node_report,
    set_agent_rollout_all,
    update_agent_status,

    # NetMon
    list_netmon_monitors,
    get_netmon_monitor,
    add_netmon_monitor,
    update_netmon_monitor,
    delete_netmon_monitor,
    list_netmon_samples,
    list_netmon_samples_range,
    list_netmon_samples_rollup,
    insert_netmon_samples,
    prune_netmon_samples,
)
from .agents import agent_get, agent_post, agent_ping

BASE_DIR = Path(__file__).resolve().parent.parent
TEMPLATES_DIR = BASE_DIR / "templates"
STATIC_DIR = BASE_DIR / "static"

DEFAULT_AGENT_PORT = 18700


def _read_latest_agent_version() -> str:
    """Return latest agent version shipped with this panel.

    We read it from panel/static/realm-agent.zip -> agent/app/main.py -> FastAPI(..., version='XX').
    """
    zpath = STATIC_DIR / "realm-agent.zip"
    try:
        with zipfile.ZipFile(str(zpath), "r") as z:
            raw = z.read("agent/app/main.py").decode("utf-8", errors="ignore")
        # FastAPI(title='Realm Agent', version='31')
        import re

        m = re.search(r"FastAPI\([^\)]*version\s*=\s*['\"]([^'\"]+)['\"]", raw)
        if m:
            return str(m.group(1)).strip()
    except Exception:
        pass
    return ""


# NOTE:
#   不要把 latest agent version 缓存在 import-time 常量里。
#   面板在“自更新/替换静态文件”后，如果不重启进程，常量会变旧，
#   导致一键更新仍然下发旧版本号，进而触发不了 Agent 的自更新。
#   因此，下面相关 API 都会在调用时动态读取 realm-agent.zip 里的版本号。
LATEST_AGENT_VERSION = _read_latest_agent_version()


def _parse_agent_version_from_ua(ua: str) -> str:
    try:
        import re

        m = re.search(r"realm-agent\/([0-9A-Za-z._-]+)", ua or "", re.I)
        return (m.group(1) if m else "")
    except Exception:
        return ""


def _ver_int(v: str) -> int:
    try:
        return int(str(v or '').strip())
    except Exception:
        return 0


def _file_sha256(p: Path) -> str:
    try:
        h = hashlib.sha256()
        with open(p, 'rb') as f:
            for chunk in iter(lambda: f.read(1024 * 1024), b''):
                if not chunk:
                    break
                h.update(chunk)
        return h.hexdigest()
    except Exception:
        return ""


def _panel_asset_source() -> str:
    """Return where nodes should fetch installer assets.

    Values:
      - "panel"  : fetch from panel /static (default)
      - "github" : fetch from GitHub (for private panel without public reachability)
    """

    return (os.getenv("REALM_PANEL_ASSET_SOURCE") or "panel").strip().lower() or "panel"


def _agent_asset_urls(base_url: str) -> tuple[str, str, bool]:
    """Return (agent_sh_url, agent_zip_url, github_only)."""
    src = _panel_asset_source()
    if src == "github":
        sh_url = (os.getenv("REALM_PANEL_AGENT_SH_URL") or "").strip() or (
            "https://raw.githubusercontent.com/cyeinfpro/Realm/main/realm_agent.sh"
        )
        zip_url = (os.getenv("REALM_PANEL_AGENT_ZIP_URL") or "").strip() or (
            "https://github.com/cyeinfpro/Realm/archive/refs/heads/main.zip"
        )
        return sh_url, zip_url, True

    return f"{base_url}/static/realm_agent.sh", f"{base_url}/static/realm-agent.zip", False

def _panel_public_base_url(request: Request) -> str:
    """Return panel public base URL for generating scripts/links.

    If REALM_PANEL_PUBLIC_URL is set, it takes precedence.
    """
    cfg = (os.getenv("REALM_PANEL_PUBLIC_URL") or os.getenv("REALM_PANEL_URL") or "").strip()
    if cfg:
        cfg = cfg.rstrip('/')
        if '://' not in cfg:
            # When user only provides domain/host, default to https (typical reverse-proxy setup).
            cfg = 'https://' + cfg
        return cfg
    return str(request.base_url).rstrip('/')


app = FastAPI(title="Realm Pro Panel", version="34")

# Session
secret = ensure_secret_key()
app.add_middleware(SessionMiddleware, secret_key=secret, session_cookie="realm_panel_sess")

# Static + templates
app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")
templates = Jinja2Templates(directory=str(TEMPLATES_DIR))

# DB init
ensure_db()


# ------------------------ NetMon background collector ------------------------

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


async def _netmon_call_agent(node: Dict[str, Any], body: Dict[str, Any], timeout: float) -> Dict[str, Any]:
    """Call agent /api/v1/netprobe with a global concurrency limit."""
    async with _NETMON_SEM:
        return await agent_post(
            node.get("base_url", ""),
            node.get("api_key", ""),
            "/api/v1/netprobe",
            body,
            _node_verify_tls(node),
            timeout=timeout,
        )


async def _netmon_collect_one(mon: Dict[str, Any], nodes_map: Dict[int, Dict[str, Any]]) -> None:
    """Collect one monitor tick and persist samples."""
    try:
        mid = int(mon.get("id") or 0)
    except Exception:
        mid = 0
    if mid <= 0:
        return

    target = str(mon.get("target") or "").strip()
    if not target:
        return

    mode = str(mon.get("mode") or "ping").strip().lower()
    if mode not in ("ping", "tcping"):
        mode = "ping"

    try:
        tcp_port = int(mon.get("tcp_port") or 443)
    except Exception:
        tcp_port = 443
    if tcp_port < 1 or tcp_port > 65535:
        tcp_port = 443

    # select nodes for this monitor
    node_ids = mon.get("node_ids") if isinstance(mon.get("node_ids"), list) else None
    if node_ids is None:
        # fallback parse json field for compatibility
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

    nodes: List[Dict[str, Any]] = []
    for nid in cleaned[:60]:
        n = nodes_map.get(int(nid))
        if n:
            nodes.append(n)

    if not nodes:
        # no nodes selected / missing
        try:
            update_netmon_monitor(mid, last_run_ts_ms=int(time.time() * 1000), last_run_msg="no_nodes")
        except Exception:
            pass
        return

    ts_ms = int(time.time() * 1000)

    # One target per monitor, but agent API supports batch.
    body = {"mode": mode, "targets": [target], "tcp_port": tcp_port, "timeout": float(_NETMON_PROBE_TIMEOUT)}

    async def _one(n: Dict[str, Any]):
        nid = int(n.get("id") or 0)

        # HTTP timeout should always be larger than probe timeout + overhead
        http_timeout = float(max(_NETMON_HTTP_TIMEOUT, float(_NETMON_PROBE_TIMEOUT) + 3.0))

        def _should_retry_err(s: str) -> bool:
            s = (s or "").lower()
            # Only retry typical transient failures/timeouts
            for kw in ("timeout", "timed out", "temporar", "connection aborted", "connection reset", "broken pipe"):
                if kw in s:
                    return True
            return False

        # Try at most 2 times on transient failures.
        last = None
        for attempt in range(2):
            try:
                data = await _netmon_call_agent(n, body, timeout=http_timeout)
                last = data
            except Exception as exc:
                last = {"ok": False, "error": str(exc)}

            # If agent call failed, retry on transient errors
            if not isinstance(last, dict) or last.get("ok") is not True:
                err = str(last.get("error") if isinstance(last, dict) else last)
                if attempt == 0 and _should_retry_err(err):
                    await asyncio.sleep(0.12)
                    continue
                return nid, (last if isinstance(last, dict) else {"ok": False, "error": "agent_failed"})

            # Agent call ok: check item result
            try:
                res_map = last.get("results") if isinstance(last.get("results"), dict) else {}
                item = res_map.get(target) if isinstance(res_map, dict) else None
                if isinstance(item, dict) and item.get("ok"):
                    return nid, last
                err = str(item.get("error") or "probe_failed") if isinstance(item, dict) else "probe_failed"
                if attempt == 0 and _should_retry_err(err):
                    await asyncio.sleep(0.08)
                    continue
            except Exception:
                # If parsing failed, don't retry aggressively
                pass

            return nid, last

        return nid, (last if isinstance(last, dict) else {"ok": False, "error": "probe_failed"})

    results = await asyncio.gather(*[_one(n) for n in nodes])

    # Persist samples
    rows: List[tuple] = []
    ok_any = False
    last_msg = ""

    for nid, data in results:
        ok = False
        latency = None
        err = None
        if isinstance(data, dict) and data.get("ok") is True:
            res_map = data.get("results") if isinstance(data.get("results"), dict) else {}
            item = res_map.get(target) if isinstance(res_map, dict) else None
            if isinstance(item, dict) and item.get("ok"):
                ok = True
                try:
                    v = float(item.get("latency_ms")) if item.get("latency_ms") is not None else None
                except Exception:
                    v = None
                latency = v
                ok_any = True
            else:
                ok = False
                err = str(item.get("error") or "probe_failed") if isinstance(item, dict) else "probe_failed"
        else:
            err = str((data or {}).get("error") or "agent_failed") if isinstance(data, dict) else "agent_failed"

        if err and not last_msg:
            last_msg = err

        rows.append((mid, int(nid), int(ts_ms), 1 if ok else 0, latency, (err or None)))

    try:
        insert_netmon_samples(rows)
    except Exception:
        # ignore DB errors to keep background running
        pass

    try:
        update_netmon_monitor(
            mid,
            last_run_ts_ms=int(ts_ms),
            last_run_msg=("ok" if ok_any else (last_msg or "failed")),
        )
    except Exception:
        pass


def _netmon_chunk(items: List[str], size: int) -> List[List[str]]:
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


async def _netmon_collect_due(monitors_due: List[Dict[str, Any]], nodes_map: Dict[int, Dict[str, Any]]) -> None:
    """Collect a batch of due monitors.

    This is an optimized collector that batches probes per-node/per-mode/per-port so we don't
    generate M*N HTTP calls (which can cause intermittent timeouts/failures when monitors scale).
    """

    if not monitors_due:
        return

    ts_ms = int(time.time() * 1000)

    # group key: (node_id, mode, tcp_port)
    groups: Dict[tuple[int, str, int], Dict[str, Any]] = {}
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
        for kw in ("timeout", "timed out", "temporar", "connection aborted", "connection reset", "broken pipe"):
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
            body = {"mode": mode, "targets": chunk, "tcp_port": int(tcp_port), "timeout": float(_NETMON_PROBE_TIMEOUT)}

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
                            one_body = {"mode": mode, "targets": [t], "tcp_port": int(tcp_port), "timeout": float(_NETMON_PROBE_TIMEOUT)}
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
        tasks.append(asyncio.create_task(_run_group(int(nid), str(mode), int(tcp_port), list(targets), dict(mids_by_target))))

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


@app.on_event("startup")
async def _start_netmon_bg() -> None:
    if not _NETMON_BG_ENABLED:
        return
    if getattr(app.state, "netmon_bg_started", False):
        return
    app.state.netmon_bg_started = True
    try:
        asyncio.create_task(_netmon_bg_loop())
    except Exception:
        pass


# ------------------------ Backup helpers ------------------------


async def _get_pool_for_backup(node: Dict[str, Any]) -> Dict[str, Any]:
    """Get pool data for backup.

    Prefer panel-desired (push mode), then cached report, then pull from agent.
    """
    node_id = int(node.get("id") or 0)
    desired_ver, desired_pool = get_desired_pool(node_id)
    if isinstance(desired_pool, dict):
        return {
            "ok": True,
            "pool": desired_pool,
            "desired_version": desired_ver,
            "source": "panel_desired",
        }

    rep = get_last_report(node_id)
    if isinstance(rep, dict) and isinstance(rep.get("pool"), dict):
        return {"ok": True, "pool": rep.get("pool"), "source": "report_cache"}

    try:
        data = await agent_get(node.get("base_url", ""), node.get("api_key", ""), "/api/v1/pool", _node_verify_tls(node))
        # keep consistent shape
        if isinstance(data, dict) and isinstance(data.get("pool"), dict):
            return {"ok": True, "pool": data.get("pool"), "source": "agent_pull"}
        return data if isinstance(data, dict) else {"ok": False, "error": "agent_return_invalid"}
    except Exception as exc:
        return {"ok": False, "error": str(exc), "source": "agent_pull"}


# ------------------------ Command signing (HMAC-SHA256) ------------------------


def _canonical_json(obj: Any) -> str:
    return json.dumps(obj, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _cmd_signature(secret: str, cmd: Dict[str, Any]) -> str:
    """Return hex HMAC-SHA256 signature for cmd (excluding sig field)."""
    data = {k: v for k, v in cmd.items() if k != "sig"}
    msg = _canonical_json(data).encode("utf-8")
    return hmac.new(secret.encode("utf-8"), msg, hashlib.sha256).hexdigest()


def _sign_cmd(secret: str, cmd: Dict[str, Any]) -> Dict[str, Any]:
    out = dict(cmd)
    # always include ts so signature cannot be replayed across long time windows
    out.setdefault("ts", int(time.time()))
    out["sig"] = _cmd_signature(secret, out)
    return out


# ------------------------ Pool diff: single-rule incremental patch ------------------------


def _single_rule_ops(base_pool: Dict[str, Any], desired_pool: Dict[str, Any]) -> Optional[list[Dict[str, Any]]]:
    """Return ops when there is exactly ONE rule change between base_pool and desired_pool.

    ops format:
      - {op: 'upsert', endpoint: {...}}
      - {op: 'remove', listen: '0.0.0.0:443'}

    If there are 0 changes -> returns []
    If changes > 1 -> returns None
    """

    def key_of(ep: Any) -> str:
        if not isinstance(ep, dict):
            return ""
        return str(ep.get("listen") or "").strip()

    base_eps = base_pool.get("endpoints") if isinstance(base_pool, dict) else None
    desired_eps = desired_pool.get("endpoints") if isinstance(desired_pool, dict) else None
    if not isinstance(base_eps, list) or not isinstance(desired_eps, list):
        return None

    base_map = {key_of(e): e for e in base_eps if key_of(e)}
    desired_map = {key_of(e): e for e in desired_eps if key_of(e)}

    changes: list[tuple[str, Any]] = []

    # add or update
    for listen, ep in desired_map.items():
        if listen not in base_map:
            changes.append(("upsert", ep))
        else:
            if _canonical_json(ep) != _canonical_json(base_map[listen]):
                changes.append(("upsert", ep))

    # remove
    for listen in base_map.keys():
        if listen not in desired_map:
            changes.append(("remove", listen))

    if len(changes) == 0:
        return []
    if len(changes) != 1:
        return None

    op, payload = changes[0]
    if op == "upsert":
        return [{"op": "upsert", "endpoint": payload}]
    return [{"op": "remove", "listen": payload}]


def _is_report_fresh(node: Dict[str, Any], max_age_sec: int = 90) -> bool:
    ts = node.get("last_seen_at")
    if not ts:
        return False
    try:
        dt = datetime.strptime(str(ts), "%Y-%m-%d %H:%M:%S")
        return (datetime.now() - dt).total_seconds() <= max_age_sec
    except Exception:
        return False


def _flash(request: Request) -> Optional[str]:
    msg = request.session.pop("flash", None)
    return msg


def _set_flash(request: Request, msg: str) -> None:
    request.session["flash"] = msg


def _has_credentials() -> bool:
    return load_credentials() is not None


def _generate_api_key() -> str:
    return secrets.token_hex(16)


def _split_host_and_port(value: str, fallback_port: int) -> tuple[str, int, bool, str]:
    raw = value.strip()
    if not raw:
        return "", fallback_port, False, "http"
    if "://" in raw:
        parsed = urlparse(raw)
        host = parsed.hostname or ""
        port = parsed.port or fallback_port
        scheme = parsed.scheme or "http"
        return host, port, parsed.port is not None, scheme
    if raw.startswith("[") and "]" in raw:
        host_part, rest = raw.split("]", 1)
        host = host_part[1:].strip()
        rest = rest.strip()
        if rest.startswith(":") and rest[1:].isdigit():
            return host, int(rest[1:]), True, "http"
        return host, fallback_port, False, "http"
    if raw.count(":") == 1 and raw.rsplit(":", 1)[1].isdigit():
        host, port_s = raw.rsplit(":", 1)
        return host.strip(), int(port_s), True, "http"
    return raw, fallback_port, False, "http"


def _format_host_for_url(host: str) -> str:
    if ":" in host and not host.startswith("["):
        return f"[{host}]"
    return host


def _safe_filename_part(name: str, default: str = "node", max_len: int = 60) -> str:
    """Make a filesystem-friendly filename part (keeps Chinese/letters/numbers/_-)."""
    raw = (name or "").strip()
    if not raw:
        return default
    out = []
    for ch in raw:
        if ch.isalnum() or ch in ("-", "_") or ("\u4e00" <= ch <= "\u9fff"):
            out.append(ch)
        elif ch in (" ", "."):
            out.append("-")
        # else: drop
    s = "".join(out).strip("-")
    s = s or default
    return s[:max_len]


def _extract_port_from_url(base_url: str, fallback_port: int) -> int:
    target = base_url.strip()
    if "://" not in target:
        target = f"http://{target}"
    parsed = urlparse(target)
    return parsed.port or fallback_port


def _extract_ip_for_display(base_url: str) -> str:
    """UI 只展示纯 IP/Host（不展示端口、不展示协议）。"""
    raw = (base_url or "").strip()
    if not raw:
        return ""
    if "://" not in raw:
        raw = f"http://{raw}"
    try:
        parsed = urlparse(raw)
        return parsed.hostname or (base_url or "").strip()
    except Exception:
        return (base_url or "").strip()


def _node_verify_tls(node: Dict[str, Any]) -> bool:
    return bool(node.get("verify_tls", 0))



async def _bg_apply_pool(node: Dict[str, Any], pool: Dict[str, Any]) -> None:
    """Best-effort: push pool to agent and apply in background (do not block HTTP responses)."""
    try:
        data = await agent_post(
            node["base_url"],
            node["api_key"],
            "/api/v1/pool",
            {"pool": pool},
            _node_verify_tls(node),
        )
        if isinstance(data, dict) and data.get("ok", True):
            await agent_post(node["base_url"], node["api_key"], "/api/v1/apply", {}, _node_verify_tls(node))
    except Exception:
        return


def _schedule_apply_pool(node: Dict[str, Any], pool: Dict[str, Any]) -> None:
    """Schedule best-effort agent apply without blocking the request."""
    try:
        asyncio.create_task(_bg_apply_pool(node, pool))
    except Exception:
        pass

def require_login(request: Request) -> str:
    user = request.session.get("user")
    if not user:
        raise HTTPException(status_code=401, detail="Not logged in")
    return user


def require_login_page(request: Request) -> str:
    user = request.session.get("user")
    if not user:
        raise HTTPException(status_code=302, headers={"Location": "/login"})
    return user


# ------------------------ NetMon share token (read-only, no-login) ------------------------

_NETMON_SHARE_PUBLIC = (os.getenv("REALM_NETMON_SHARE_PUBLIC") or "1").strip() not in ("0", "false", "False")
try:
    _NETMON_SHARE_TTL_SEC = int((os.getenv("REALM_NETMON_SHARE_TTL_SEC") or "604800").strip() or 604800)  # default 7d
except Exception:
    _NETMON_SHARE_TTL_SEC = 604800
if _NETMON_SHARE_TTL_SEC < 300:
    _NETMON_SHARE_TTL_SEC = 300
if _NETMON_SHARE_TTL_SEC > 30 * 86400:
    _NETMON_SHARE_TTL_SEC = 30 * 86400


def _b64url_encode(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode("utf-8").rstrip("=")


def _b64url_decode(s: str) -> bytes:
    s = str(s or "").strip()
    if not s:
        return b""
    pad = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + pad)


def _share_canon(obj: Any) -> str:
    return json.dumps(obj, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _make_share_token(payload: Dict[str, Any]) -> str:
    try:
        exp = int(time.time()) + int(_NETMON_SHARE_TTL_SEC)
    except Exception:
        exp = int(time.time()) + 86400
    p = dict(payload or {})
    p["exp"] = exp
    raw = _share_canon(p).encode("utf-8")
    sig = hmac.new(secret.encode("utf-8"), raw, hashlib.sha256).hexdigest()
    return f"{_b64url_encode(raw)}.{sig}"


def _verify_share_token(token: str) -> Optional[Dict[str, Any]]:
    try:
        tok = str(token or "").strip()
        if not tok or "." not in tok:
            return None
        b64, sig = tok.split(".", 1)
        raw = _b64url_decode(b64)
        if not raw:
            return None
        exp_sig = hmac.new(secret.encode("utf-8"), raw, hashlib.sha256).hexdigest()
        if not hmac.compare_digest(exp_sig, str(sig or "").strip()):
            return None
        obj = json.loads(raw.decode("utf-8", errors="ignore"))
        if not isinstance(obj, dict):
            return None
        exp = int(obj.get("exp") or 0)
        if exp and int(time.time()) > exp:
            return None
        return obj
    except Exception:
        return None


def require_login_or_share_page(request: Request, allow_page: str) -> str:
    """Allow either a logged-in session OR a valid share token for a given page."""
    user = request.session.get("user")
    if user:
        return user
    # Share links should be viewable without login as long as the signed token is valid.
    # (Important for load-balancer scenarios where visitors do not have a session cookie.)
    payload = _verify_share_token(request.query_params.get("t") or "")
    if payload and str(payload.get("page") or "") == str(allow_page):
        request.state.share = payload
        return ""
    raise HTTPException(status_code=302, headers={"Location": "/login"})


def require_login_or_share_view_page(request: Request) -> str:
    return require_login_or_share_page(request, "view")


def require_login_or_share_wall_page(request: Request) -> str:
    return require_login_or_share_page(request, "wall")


def require_login_or_share_api(request: Request) -> str:
    """Allow either a logged-in session OR a valid share token for API calls."""
    user = request.session.get("user")
    if user:
        return user
    # Allow anonymous read-only access via signed share token.
    token = request.query_params.get("t") or request.headers.get("X-Share-Token") or ""
    payload = _verify_share_token(token)
    if payload:
        request.state.share = payload
        return "__share__"
    raise HTTPException(status_code=401, detail="Not logged in")



@app.get("/login", response_class=HTMLResponse)
async def login_page(request: Request):
    if not _has_credentials():
        return RedirectResponse(url="/setup", status_code=303)
    return templates.TemplateResponse(
        "login.html",
        {"request": request, "user": None, "flash": _flash(request), "title": "登录"},
    )


@app.post("/login")
async def login_action(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
):
    if not _has_credentials():
        _set_flash(request, "请先初始化面板账号")
        return RedirectResponse(url="/setup", status_code=303)
    if verify_login(username, password):
        request.session["user"] = username
        _set_flash(request, "登录成功")
        return RedirectResponse(url="/", status_code=303)
    _set_flash(request, "账号或密码错误")
    return RedirectResponse(url="/login", status_code=303)


@app.get("/logout")
async def logout(request: Request):
    request.session.clear()
    return RedirectResponse(url="/login", status_code=303)


@app.get("/setup", response_class=HTMLResponse)
async def setup_page(request: Request):
    if _has_credentials():
        return RedirectResponse(url="/login", status_code=303)
    return templates.TemplateResponse(
        "setup.html",
        {"request": request, "user": None, "flash": _flash(request), "title": "初始化账号"},
    )


@app.post("/setup")
async def setup_action(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    confirm: str = Form(...),
):
    if _has_credentials():
        return RedirectResponse(url="/login", status_code=303)
    if password != confirm:
        _set_flash(request, "两次输入的密码不一致")
        return RedirectResponse(url="/setup", status_code=303)
    try:
        save_credentials(username, password)
    except ValueError as exc:
        _set_flash(request, str(exc))
        return RedirectResponse(url="/setup", status_code=303)
    _set_flash(request, "账号已初始化，请登录")
    return RedirectResponse(url="/login", status_code=303)


@app.get("/", response_class=HTMLResponse)
async def index(request: Request, user: str = Depends(require_login_page)):
    nodes = list_nodes()

    group_orders = get_group_orders()

    def _gk(name: str) -> tuple[int, str]:
        """Group sort key: user-defined sort_order (smaller first), then name."""
        n = (name or '').strip() or '默认分组'
        try:
            order = int(group_orders.get(n, 1000))
        except Exception:
            order = 1000
        return (order, n)

    def _gn(x: dict) -> str:
        g = str(x.get("group_name") or "").strip()
        return g or "默认分组"

    for n in nodes:
        n["display_ip"] = _extract_ip_for_display(n.get("base_url", ""))
        n["online"] = _is_report_fresh(n)
        # 分组名为空时统一归入“默认分组”
        n["group_name"] = _gn(n)
        # For UI display
        if "agent_version" not in n:
            n["agent_version"] = str(n.get("agent_reported_version") or "").strip()

    # 控制台卡片：按分组聚合展示
    # - 组内排序：在线优先，其次按 id 倒序
    nodes_sorted = sorted(
        nodes,
        key=lambda x: (
            _gk(_gn(x)),
            0 if bool(x.get("online")) else 1,
            -int(x.get("id") or 0),
        ),
    )

    dashboard_groups = []
    cur = None
    buf = []
    for n in nodes_sorted:
        g = _gn(n)
        if cur is None:
            cur = g
        if g != cur:
            dashboard_groups.append(
                {
                    "name": cur,
                    "sort_order": _gk(cur)[0],
                    "nodes": buf,
                    "online": sum(1 for i in buf if i.get("online")),
                    "total": len(buf),
                }
            )
            cur = g
            buf = []
        buf.append(n)

    if cur is not None:
        dashboard_groups.append(
            {
                "name": cur,
                "sort_order": _gk(cur)[0],
                "nodes": buf,
                "online": sum(1 for i in buf if i.get("online")),
                "total": len(buf),
            }
        )

    return templates.TemplateResponse(
        "index.html",
        {
            "request": request,
            "user": (user or None),
            "nodes": nodes,
            "dashboard_groups": dashboard_groups,
            "flash": _flash(request),
            "title": "控制台",
        },
    )



@app.get("/netmon", response_class=HTMLResponse)
async def netmon_page(request: Request, user: str = Depends(require_login_page)):
    """Network fluctuation monitoring page."""
    nodes = list_nodes()

    group_orders = get_group_orders()

    def _gk(name: str) -> tuple[int, str]:
        n = (name or '').strip() or '默认分组'
        try:
            order = int(group_orders.get(n, 1000))
        except Exception:
            order = 1000
        return (order, n)

    def _gn(x: Dict[str, Any]) -> str:
        g = str(x.get("group_name") or "").strip()
        return g or "默认分组"

    for n in nodes:
        n["display_ip"] = _extract_ip_for_display(n.get("base_url", ""))
        # 用更宽松的阈值显示在线状态（避免轻微抖动导致频繁显示离线）
        n["online"] = _is_report_fresh(n, max_age_sec=90)
        n["group_name"] = _gn(n)

    nodes_sorted = sorted(
        nodes,
        key=lambda x: (
            _gk(_gn(x)),
            0 if bool(x.get("online")) else 1,
            -int(x.get("id") or 0),
        ),
    )

    node_groups: List[Dict[str, Any]] = []
    cur = None
    buf: List[Dict[str, Any]] = []
    for n in nodes_sorted:
        g = _gn(n)
        if cur is None:
            cur = g
        if g != cur:
            node_groups.append(
                {
                    "name": cur,
                    "sort_order": _gk(cur)[0],
                    "nodes": buf,
                    "online": sum(1 for i in buf if i.get("online")),
                    "total": len(buf),
                }
            )
            cur = g
            buf = []
        buf.append(n)

    if cur is not None:
        node_groups.append(
            {
                "name": cur,
                "sort_order": _gk(cur)[0],
                "nodes": buf,
                "online": sum(1 for i in buf if i.get("online")),
                "total": len(buf),
            }
        )

    return templates.TemplateResponse(
        "netmon.html",
        {
            "request": request,
            "user": (user or None),
            "node_groups": node_groups,
            "flash": _flash(request),
            "title": "网络波动监控",
        },
    )


@app.get("/netmon/view", response_class=HTMLResponse)
async def netmon_view_page(request: Request, user: str = Depends(require_login_or_share_view_page)):
    """Read-only NetMon display page (for sharing / wallboard).

    Notes:
      - Still requires login session (same as other pages).
      - The UI hides create/edit/delete/toggle controls.
      - Frontend will request /api/netmon/snapshot?mid=... when URL contains mid.
    """
    return templates.TemplateResponse(
        "netmon_view.html",
        {
            "request": request,
            "user": (user or None),
            "flash": _flash(request),
            "title": "网络波动 · 只读展示",
        },
    )


@app.get("/netmon/wall", response_class=HTMLResponse)
async def netmon_wall_page(request: Request, user: str = Depends(require_login_or_share_wall_page)):
    """NetMon wallboard (read-only).

    Designed for NOC / TV screens:
      - hides management controls
      - grid layout
      - optional auto rotation highlight
    """
    return templates.TemplateResponse(
        "netmon_wall.html",
        {
            "request": request,
            "user": (user or None),
            "flash": _flash(request),
            "title": "网络波动 · 大屏展示",
        },
    )



@app.get("/nodes/new", response_class=HTMLResponse)
async def node_new_page(request: Request, user: str = Depends(require_login_page)):
    api_key = _generate_api_key()
    return templates.TemplateResponse(
        "nodes_new.html",
        {
            "request": request,
            "user": user,
            "flash": _flash(request),
            "title": "添加机器",
            "api_key": api_key,
            "default_port": DEFAULT_AGENT_PORT,
        },
    )


@app.post("/nodes/new")
async def node_new_action(
    request: Request,
    name: str = Form(""),
    group_name: str = Form("默认分组"),
    is_private: Optional[str] = Form(None),
    ip_address: str = Form(...),
    scheme: str = Form("http"),
    api_key: str = Form(""),
    verify_tls: Optional[str] = Form(None),
):
    user = request.session.get("user")
    if not user:
        return RedirectResponse(url="/login", status_code=303)

    ip_address = ip_address.strip()
    api_key = api_key.strip() or _generate_api_key()
    scheme = scheme.strip().lower() or "http"
    if scheme not in ("http", "https"):
        _set_flash(request, "协议仅支持 http 或 https")
        return RedirectResponse(url="/nodes/new", status_code=303)
    if not ip_address:
        _set_flash(request, "IP 地址不能为空")
        return RedirectResponse(url="/nodes/new", status_code=303)
    if "://" not in ip_address:
        ip_address = f"{scheme}://{ip_address}"

    # 端口在 UI 中隐藏：
    # - 默认使用 Agent 标准端口 18700
    # - 如用户在 IP 中自带 :port，则仍可解析并写入 base_url（兼容特殊环境）
    port_value = DEFAULT_AGENT_PORT
    host, parsed_port, has_port, scheme = _split_host_and_port(ip_address, port_value)
    if not host:
        _set_flash(request, "IP 地址不能为空")
        return RedirectResponse(url="/nodes/new", status_code=303)
    if has_port:
        port_value = parsed_port

    base_url = f"{scheme}://{_format_host_for_url(host)}:{port_value}"  # 不在 UI 展示端口

    # name 为空则默认使用“纯 IP/Host”
    display_name = (name or "").strip() or _extract_ip_for_display(base_url)

    node_id = add_node(
        display_name,
        base_url,
        api_key,
        verify_tls=bool(verify_tls),
        is_private=bool(is_private),
        group_name=group_name,
    )
    request.session["show_install_cmd"] = True
    _set_flash(request, "已添加机器")
    return RedirectResponse(url=f"/nodes/{node_id}", status_code=303)


@app.post("/nodes/add")
async def node_add_action(
    request: Request,
    name: str = Form(""),
    group_name: str = Form("默认分组"),
    is_private: Optional[str] = Form(None),
    base_url: str = Form(...),
    api_key: str = Form(...),
    verify_tls: Optional[str] = Form(None),
):
    if not request.session.get("user"):
        return RedirectResponse(url="/login", status_code=303)

    base_url = base_url.strip()
    api_key = api_key.strip()
    if not base_url or not api_key:
        _set_flash(request, "API 地址与 Token 不能为空")
        return RedirectResponse(url="/", status_code=303)

    node_id = add_node(
        name or base_url,
        base_url,
        api_key,
        verify_tls=bool(verify_tls),
        is_private=bool(is_private),
        group_name=group_name,
    )
    _set_flash(request, "已添加节点")
    return RedirectResponse(url=f"/nodes/{node_id}", status_code=303)


@app.post("/nodes/{node_id}/delete")
async def node_delete(request: Request, node_id: int):
    if not request.session.get("user"):
        return RedirectResponse(url="/login", status_code=303)
    delete_node(node_id)
    _set_flash(request, "已删除机器")
    return RedirectResponse(url="/", status_code=303)


@app.get("/nodes/{node_id}", response_class=HTMLResponse)
async def node_detail(request: Request, node_id: int, user: str = Depends(require_login_page)):
    node = get_node(node_id)
    if not node:
        _set_flash(request, "机器不存在")
        return RedirectResponse(url="/", status_code=303)

    # 用于节点页左侧快速切换列表
    nodes = list_nodes()

    group_orders = get_group_orders()

    def _gk(name: str) -> tuple[int, str]:
        n = (name or '').strip() or '默认分组'
        try:
            order = int(group_orders.get(n, 1000))
        except Exception:
            order = 1000
        return (order, n)
    for n in nodes:
        n["display_ip"] = _extract_ip_for_display(n.get("base_url", ""))
        # 用更宽松的阈值显示在线状态（避免轻微抖动导致频繁显示离线）
        n["online"] = _is_report_fresh(n, max_age_sec=90)

    # 节点页左侧列表：按分组聚合展示
    # - 分组名为空时统一归入“默认分组”
    # - 组内排序：在线优先，其次按 id 倒序
    def _gn(x: Dict[str, Any]) -> str:
        g = str(x.get("group_name") or "").strip()
        return g or "默认分组"

    for n in nodes:
        n["group_name"] = _gn(n)

    nodes_sorted = sorted(
        nodes,
        key=lambda x: (
            _gk(_gn(x)),
            0 if bool(x.get("online")) else 1,
            -int(x.get("id") or 0),
        ),
    )
    node_groups: List[Dict[str, Any]] = []
    cur = None
    buf: List[Dict[str, Any]] = []
    for n in nodes_sorted:
        g = _gn(n)
        if cur is None:
            cur = g
        if g != cur:
            node_groups.append(
                {
                    "name": cur,
                    "sort_order": _gk(cur)[0],
                    "nodes": buf,
                    "online": sum(1 for i in buf if i.get("online")),
                    "total": len(buf),
                }
            )
            cur = g
            buf = []
        buf.append(n)
    if cur is not None:
        node_groups.append(
            {
                "name": cur,
                "sort_order": _gk(cur)[0],
                "nodes": buf,
                "online": sum(1 for i in buf if i.get("online")),
                "total": len(buf),
            }
        )
    show_install_cmd = bool(request.session.pop("show_install_cmd", False))
    show_edit_node = str(request.query_params.get("edit") or "").strip() in ("1", "true", "yes")
    base_url = _panel_public_base_url(request)
    node["display_ip"] = _extract_ip_for_display(node.get("base_url", ""))

    # 在线判定：默认心跳 30s，取 3 倍窗口避免误判
    node["online"] = _is_report_fresh(node, max_age_sec=90)

    # ✅ 一键接入 / 卸载命令（短命令，避免超长）
    # 说明：使用 node.api_key 作为 join token，脚本由面板返回并带参数执行。
    install_cmd = f"curl -fsSL {base_url}/join/{node['api_key']} | bash"
    uninstall_cmd = f"curl -fsSL {base_url}/uninstall/{node['api_key']} | bash"

    # 兼容旧字段（模板里可能还引用 node_port）
    agent_port = DEFAULT_AGENT_PORT
    return templates.TemplateResponse(
        "node.html",
        {
            "request": request,
            "user": user,
            "nodes": nodes,
            "node_groups": node_groups,
            "node": node,
            "flash": _flash(request),
            "title": node["name"],
            "node_port": agent_port,
            "install_cmd": install_cmd,
            "uninstall_cmd": uninstall_cmd,
            "show_install_cmd": show_install_cmd,
            "show_edit_node": show_edit_node,
        },
    )


# ------------------------ Short join / uninstall scripts (no login) ------------------------


@app.get("/join/{token}", response_class=PlainTextResponse)
async def join_script(request: Request, token: str):
    """短命令接入脚本：curl .../join/<token> | bash

    token = node.api_key（用于定位节点），脚本内部会写入 /etc/realm-agent/api.key。

    资产拉取策略：
    - 默认：从面板 /static 拉取 realm_agent.sh + realm-agent.zip
    - 若 REALM_PANEL_ASSET_SOURCE=github：从 GitHub 拉取（适用于面板非公网可达）
    """

    node = get_node_by_api_key(token)
    if not node:
        return PlainTextResponse("""echo '[错误] 接入链接无效：token 不存在或已失效' >&2
exit 1
""", status_code=404)

    base_url = _panel_public_base_url(request)
    node_id = int(node.get("id"))
    api_key = str(node.get("api_key"))
    agent_sh_url, repo_zip_url, github_only = _agent_asset_urls(base_url)
    gh_only_env = "  REALM_AGENT_GITHUB_ONLY=1 \\\n" if github_only else ""

    script = f"""#!/usr/bin/env bash
set -euo pipefail

PANEL_URL=\"{base_url}\"
NODE_ID=\"{node_id}\"
API_KEY=\"{api_key}\"

if [[ \"$(id -u)\" -ne 0 ]]; then
  if command -v sudo >/dev/null 2>&1; then
    echo \"[提示] 需要 root，自动尝试 sudo...\" >&2
    exec sudo -E bash -c \"curl -fsSL $PANEL_URL/join/{api_key} | bash\"
  fi
  echo \"[错误] 需要 root 权限运行，但系统未安装 sudo。请切换到 root 后重试（sudo -i / su -）。\" >&2
  exit 1
fi

mkdir -p /etc/realm-agent
echo \"$API_KEY\" > /etc/realm-agent/api.key

echo \"[提示] 正在安装/更新 Realm Agent…\" >&2
curl -fsSL \"{agent_sh_url}\" | \
{gh_only_env}  REALM_AGENT_REPO_ZIP_URL=\"{repo_zip_url}\" \
  REALM_AGENT_FORCE_UPDATE=1 \
  REALM_AGENT_MODE=1 \
  REALM_AGENT_PORT={DEFAULT_AGENT_PORT} \
  REALM_AGENT_ASSUME_YES=1 \
  REALM_PANEL_URL=\"$PANEL_URL\" \
  REALM_AGENT_ID=\"$NODE_ID\" \
  REALM_AGENT_HEARTBEAT_INTERVAL=3 \
  bash
"""
    return PlainTextResponse(script, media_type="text/plain; charset=utf-8")


@app.get("/uninstall/{token}", response_class=PlainTextResponse)
async def uninstall_script(request: Request, token: str):
    """短命令卸载脚本：curl .../uninstall/<token> | bash"""

    node = get_node_by_api_key(token)
    if not node:
        return PlainTextResponse("""echo '[错误] 接入链接无效：token 不存在或已失效' >&2
exit 1
""", status_code=404)

    base_url = _panel_public_base_url(request)
    api_key = str(node.get("api_key"))
    script = f"""#!/usr/bin/env bash
set -euo pipefail

PANEL_URL=\"{base_url}\"

if [[ \"$(id -u)\" -ne 0 ]]; then
  if command -v sudo >/dev/null 2>&1; then
    echo \"[提示] 需要 root，自动尝试 sudo...\" >&2
    exec sudo -E bash -c \"curl -fsSL $PANEL_URL/uninstall/{api_key} | bash\"
  fi
  echo \"[错误] 需要 root 权限运行，但系统未安装 sudo。请切换到 root 后重试（sudo -i / su -）。\" >&2
  exit 1
fi

echo \"[提示] 正在卸载 Realm Agent / Realm…\" >&2
systemctl disable --now realm-agent.service realm-agent-https.service realm.service realm \
  >/dev/null 2>&1 || true
rm -f /etc/systemd/system/realm-agent.service /etc/systemd/system/realm-agent-https.service \
  /etc/systemd/system/realm.service || true
systemctl daemon-reload || true

rm -rf /opt/realm-agent /etc/realm-agent /etc/realm /opt/realm || true
rm -f /usr/local/bin/realm /usr/bin/realm || true

echo \"[OK] 卸载完成\" >&2
"""
    return PlainTextResponse(script, media_type="text/plain; charset=utf-8")


# ------------------------ Agent push-report API (no login) ------------------------


@app.post("/api/agent/report")
async def api_agent_report(request: Request, payload: Dict[str, Any]):
    """Agent主动上报接口。

    认证：HTTP Header `X-API-Key: <node.api_key>`。
    载荷：至少包含 node_id 字段。

    返回：commands（例如同步规则池）。
    """

    api_key = (request.headers.get("x-api-key") or request.headers.get("X-API-Key") or "").strip()
    node_id_raw = payload.get("node_id")
    try:
        node_id = int(node_id_raw)
    except Exception:
        return JSONResponse({"ok": False, "error": "节点 ID 无效"}, status_code=400)

    node = get_node(node_id)
    if not node:
        return JSONResponse({"ok": False, "error": "节点不存在"}, status_code=404)
    if not api_key or api_key != node.get("api_key"):
        return JSONResponse({"ok": False, "error": "无权限（API Key 不正确）"}, status_code=403)

    # Agent software/update meta (optional)
    agent_version = str(payload.get("agent_version") or "").strip()
    if not agent_version:
        agent_version = _parse_agent_version_from_ua(
            (request.headers.get("User-Agent") or request.headers.get("user-agent") or "").strip()
        )

    agent_update = payload.get("agent_update")
    if not isinstance(agent_update, dict):
        agent_update = {}

    # report_json：尽量只保存 report 字段（更干净），但也兼容直接上报全量
    report = payload.get("report") if isinstance(payload, dict) else None
    if report is None:
        report = payload
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    ack_version = payload.get("ack_version")

    # Parse agent ack version early (used for version realignment)
    try:
        agent_ack = int(ack_version) if ack_version is not None else 0
    except Exception:
        agent_ack = 0
    try:
        update_node_report(
            node_id=node_id,
            report_json=json.dumps(report, ensure_ascii=False),
            last_seen_at=now,
            agent_ack_version=int(ack_version) if ack_version is not None else None,
        )
    except Exception:
        # 不要让写库失败影响 agent
        pass

    # Persist agent version + update status (best-effort)
    # ⚠️ 关键：面板触发新一轮更新（desired_agent_update_id 改变）时，
    # Agent 可能还在上报「上一轮」的状态（甚至旧版本 Agent 的状态里没有 update_id）。
    # 如果直接用 agent_update.state 覆盖 DB，就会把面板刚设置的 queued/sent 覆盖成 done，
    # 从而出现“下发完就显示完成”。
    # 解决：
    #   - 若面板当前存在 desired_update_id：只接受 update_id == desired_update_id 的状态回报。
    #   - 若面板未在滚动更新：允许无 update_id 的旧状态回报（仅用于展示历史状态）。
    try:
        desired_update_id_now = str(node.get('desired_agent_update_id') or '').strip()
        rep_update_id = str(agent_update.get('update_id') or '').strip() if isinstance(agent_update, dict) else ''
        st = str(agent_update.get('state') or '').strip() if isinstance(agent_update, dict) else ''
        msg = str(agent_update.get('error') or agent_update.get('msg') or '').strip() if isinstance(agent_update, dict) else ''

        if desired_update_id_now:
            # 正在更新：必须强制对齐 update_id，否则视为“旧状态/噪声”不覆盖
            if rep_update_id and rep_update_id == desired_update_id_now:
                update_agent_status(
                    node_id=node_id,
                    agent_reported_version=agent_version or None,
                    state=st or None,
                    msg=msg or None,
                )
            else:
                # 仅更新版本号，不覆盖面板当前批次的状态
                update_agent_status(node_id=node_id, agent_reported_version=agent_version or None)
        else:
            # 未处于滚动更新中：允许旧版 agent（无 update_id）也能回报“上次更新状态”
            update_agent_status(
                node_id=node_id,
                agent_reported_version=agent_version or None,
                state=st or None,
                msg=msg or None,
            )
    except Exception:
        pass

    # 若面板尚无 desired_pool，则尝试把 agent 当前 pool 作为初始 desired_pool。
    # ⚠️ 关键：当面板重装/恢复后，Agent 可能还保留旧的 ack_version（例如 33），
    # 如果面板把 desired_pool_version 从 1 开始，后续新增规则会一直小于 ack_version，
    # 导致面板永远不下发 commands，看起来像“不同步”。
    # 这里将面板 desired_pool_version 对齐到 agent_ack（至少 1），避免版本回退。
    desired_ver, desired_pool = get_desired_pool(node_id)
    if desired_pool is None:
        rep_pool = None
        if isinstance(report, dict):
            rep_pool = report.get("pool")
        if isinstance(rep_pool, dict):
            init_ver = max(1, agent_ack)
            desired_ver, desired_pool = set_desired_pool_exact(node_id, rep_pool, init_ver)
    else:
        # Desired exists but version is behind agent ack (panel DB reset or migrated)
        if agent_ack > desired_ver:
            rep_pool = None
            if isinstance(report, dict):
                rep_pool = report.get('pool')
            if isinstance(rep_pool, dict):
                # Trust agent as source of truth when panel version went backwards (e.g. DB restore).
                desired_ver, desired_pool = set_desired_pool_exact(node_id, rep_pool, agent_ack)
            else:
                desired_ver = set_desired_pool_version_exact(node_id, agent_ack)

    # 下发命令：规则池同步
    cmds: list[dict[str, Any]] = []
    if isinstance(desired_pool, dict) and desired_ver > agent_ack:
        # ✅ 单条规则增量下发：仅当 agent 落后 1 个版本，且报告中存在当前 pool 时才尝试 patch
        base_pool = None
        if isinstance(report, dict):
            base_pool = report.get("pool") if isinstance(report.get("pool"), dict) else None

        cmd: Dict[str, Any]
        ops = None
        if desired_ver == agent_ack + 1 and isinstance(base_pool, dict):
            ops = _single_rule_ops(base_pool, desired_pool)

        if isinstance(ops, list) and len(ops) == 1:
            cmd = {
                "type": "pool_patch",
                "version": desired_ver,
                "base_version": agent_ack,
                "ops": ops,
                "apply": True,
            }
        else:
            cmd = {
                "type": "sync_pool",
                "version": desired_ver,
                "pool": desired_pool,
                "apply": True,
            }

        cmds.append(_sign_cmd(str(node.get("api_key") or ""), cmd))

    # 下发命令：Agent 自更新（可选）
    try:
        desired_agent_ver = str(node.get('desired_agent_version') or '').strip()
        desired_update_id = str(node.get('desired_agent_update_id') or '').strip()
        cur_agent_ver = (agent_version or str(node.get('agent_reported_version') or '')).strip()

        rep_update_id = str(agent_update.get('update_id') or '').strip() if isinstance(agent_update, dict) else ''
        rep_state = str(agent_update.get('state') or '').strip().lower() if isinstance(agent_update, dict) else ''

        if desired_agent_ver and desired_update_id:
            # ✅ “一键更新”=强制按面板/GitHub 文件重装：不再用版本号短路。
            # 只有当 agent 明确回报「本批次 update_id 已 done」时才停止下发。
            already_done = (rep_update_id == desired_update_id and rep_state == 'done')

            if already_done:
                if str(node.get('agent_update_state') or '').strip() != 'done':
                    try:
                        update_agent_status(node_id=node_id, state='done', msg='')
                    except Exception:
                        pass
            else:
                # ✅ 不对旧版本做“硬阻断”。
                # 有些环境里节点上跑的 Agent 版本可能很旧/无法准确上报版本号。
                # 这里仍然尝试下发 update_agent，让节点“尽最大可能”自更新。

                panel_base = _panel_public_base_url(request)
                sh_url, zip_url, github_only = _agent_asset_urls(panel_base)
                zip_sha256 = '' if github_only else _file_sha256(STATIC_DIR / 'realm-agent.zip')

                # ✅ 强制更新关键：
                # 旧版 Agent 的 update_agent 实现里存在“版本号短路”逻辑：
                #   - 当 current_version >= desired_version 时，直接标记 done 并返回
                # 这会导致“面板点更新但实际不更新”（例如 target=38，节点也是 38）。
                # 为了做到“无论当前版本如何，点更新就必须重装”，我们给 desired_version
                # 加一个批次后缀，让旧版 Agent 的 int() 解析失败，从而不会短路。
                # 新版 Agent 会解析前缀数字（见 agent/_reconcile_update_state），不影响展示。
                desired_ver_for_cmd = desired_agent_ver
                try:
                    suf = (desired_update_id or '')[:8] or str(int(time.time()))
                    if desired_ver_for_cmd:
                        desired_ver_for_cmd = f"{desired_ver_for_cmd}-force-{suf}"
                except Exception:
                    pass
                ucmd: Dict[str, Any] = {
                    'type': 'update_agent',
                    'update_id': desired_update_id,
                    'desired_version': desired_ver_for_cmd,
                    'panel_url': panel_base,
                    'sh_url': sh_url,
                    'zip_url': zip_url,
                    'zip_sha256': zip_sha256,
                    'github_only': bool(github_only),
                    'force': True,
                }
                cmds.append(_sign_cmd(str(node.get('api_key') or ''), ucmd))

                # mark queued->sent (best-effort)
                if str(node.get('agent_update_state') or '').strip() in ('', 'queued'):
                    try:
                        update_agent_status(node_id=node_id, state='sent')
                    except Exception:
                        pass
    except Exception:
        pass

    return {"ok": True, "server_time": now, "desired_version": desired_ver, "commands": cmds}


# ------------------------ API (needs login) ------------------------


@app.get('/api/agents/latest')
async def api_agents_latest(_: Request, user: str = Depends(require_login)):
    """Return the latest agent version bundled with this panel."""
    latest = _read_latest_agent_version()
    zip_sha256 = _file_sha256(STATIC_DIR / 'realm-agent.zip')
    return {
        'ok': True,
        'latest_version': latest,
        'zip_sha256': zip_sha256,
    }


@app.post('/api/agents/update_all')
async def api_agents_update_all(request: Request, user: str = Depends(require_login)):
    """Trigger an agent rollout to all nodes."""
    target = (_read_latest_agent_version() or '').strip()
    if not target:
        return JSONResponse({'ok': False, 'error': '无法确定当前面板内置的 Agent 版本（realm-agent.zip 缺失或不可解析）'}, status_code=500)

    update_id = uuid.uuid4().hex
    affected = 0
    try:
        affected = set_agent_rollout_all(desired_version=target, update_id=update_id, state='queued', msg='')
    except Exception:
        affected = 0

    return {
        'ok': True,
        'update_id': update_id,
        'target_version': target,
        'affected': affected,
        'server_time': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
    }


@app.get('/api/agents/update_progress')
async def api_agents_update_progress(update_id: str = '', user: str = Depends(require_login)):
    """Return rollout progress."""
    uid = (update_id or '').strip()
    nodes = list_nodes()
    orders = get_group_orders()

    items: List[Dict[str, Any]] = []
    summary = {'total': 0, 'done': 0, 'failed': 0, 'installing': 0, 'sent': 0, 'queued': 0, 'offline': 0, 'other': 0}

    for n in nodes:
        nuid = str(n.get('desired_agent_update_id') or '').strip()
        if uid and nuid != uid:
            continue

        summary['total'] += 1
        online = _is_report_fresh(n)
        desired = str(n.get('desired_agent_version') or '').strip()
        cur = str(n.get('agent_reported_version') or '').strip()
        st = str(n.get('agent_update_state') or '').strip() or 'queued'

        # ✅ 一键更新进度：以 agent_update_state 为准。
        # 不再用“当前版本 >= 目标版本”来直接判定 done，避免强制重装场景下被提前标记完成。
        if not online:
            st2 = 'offline'
        else:
            st2 = st

        if st2 in summary:
            summary[st2] += 1
        else:
            summary['other'] += 1

        group_name = str(n.get('group_name') or '').strip() or '默认分组'
        group_order = int(orders.get(group_name, 9999) or 9999)

        items.append({
            'id': n.get('id'),
            'name': n.get('name'),
            'group_name': group_name,
            'group_order': group_order,
            'online': bool(online),
            'agent_version': cur,
            'desired_version': desired,
            'state': st2,
            'msg': str(n.get('agent_update_msg') or '').strip(),
            'last_seen_at': n.get('last_seen_at'),
        })

    # Deterministic ordering (group order -> group -> name -> id)
    try:
        items.sort(key=lambda x: (
            int(x.get('group_order') or 9999),
            str(x.get('group_name') or ''),
            str(x.get('name') or ''),
            int(x.get('id') or 0),
        ))
    except Exception:
        pass

    return {'ok': True, 'update_id': uid, 'summary': summary, 'nodes': items}

@app.get("/api/nodes/{node_id}/ping")
async def api_ping(request: Request, node_id: int, user: str = Depends(require_login)):
    node = get_node(node_id)
    if not node:
        return JSONResponse({"ok": False, "error": "节点不存在"}, status_code=404)

    # Push-report mode: agent has reported recently -> online (no need panel->agent reachability)
    if _is_report_fresh(node):
        rep = get_last_report(node_id)
        info = rep.get("info") if isinstance(rep, dict) else None
        # keep兼容旧前端：ping 只关心 ok + latency_ms
        return {
            "ok": True,
            "source": "report",
            "last_seen_at": node.get("last_seen_at"),
            "info": info,
        }

    info = await agent_ping(node["base_url"], node["api_key"], _node_verify_tls(node))
    if not info.get("ok"):
        return {"ok": False, "error": info.get("error", "offline")}
    return info


@app.get("/api/nodes/{node_id}/pool")
async def api_pool_get(request: Request, node_id: int, user: str = Depends(require_login)):
    node = get_node(node_id)
    if not node:
        return JSONResponse({"ok": False, "error": "节点不存在"}, status_code=404)

    # Push-report mode: prefer desired pool stored on panel
    desired_ver, desired_pool = get_desired_pool(node_id)
    if isinstance(desired_pool, dict):
        return {"ok": True, "pool": desired_pool, "desired_version": desired_ver, "source": "panel_desired"}

    # If no desired pool, try last report snapshot
    rep = get_last_report(node_id)
    if isinstance(rep, dict) and isinstance(rep.get("pool"), dict):
        return {"ok": True, "pool": rep.get("pool"), "source": "report_cache"}
    try:
        data = await agent_get(node["base_url"], node["api_key"], "/api/v1/pool", _node_verify_tls(node))
        return data
    except Exception as exc:
        return JSONResponse({"ok": False, "error": str(exc)}, status_code=502)


@app.get("/api/nodes/{node_id}/backup")
async def api_backup(request: Request, node_id: int, user: str = Depends(require_login)):
    node = get_node(node_id)
    if not node:
        return JSONResponse({"ok": False, "error": "节点不存在"}, status_code=404)
    data = await _get_pool_for_backup(node)
    # 规则文件名包含节点名，便于区分
    safe = _safe_filename_part(node.get("name") or f"node-{node_id}")
    filename = f"realm-rules-{safe}-id{node_id}.json"
    payload = json.dumps(data, ensure_ascii=False, indent=2)
    headers = {"Content-Disposition": f'attachment; filename="{filename}"'}
    return Response(content=payload, media_type="application/json", headers=headers)


@app.get("/api/backup/full")
async def api_backup_full(request: Request, user: str = Depends(require_login)):
    """Download a full backup zip: nodes list + per-node rules."""
    nodes = list_nodes()
    group_orders = get_group_orders()
    ts = datetime.now().strftime("%Y%m%d-%H%M%S")

    # Build backup payloads (fetch missing pools concurrently)
    async def build_one(n: Dict[str, Any]) -> tuple[str, Dict[str, Any]]:
        node_id = int(n.get("id") or 0)
        data = await _get_pool_for_backup(n)
        data.setdefault("node", {"id": node_id, "name": n.get("name"), "base_url": n.get("base_url")})
        safe = _safe_filename_part(n.get("name") or f"node-{node_id}")
        path = f"rules/realm-rules-{safe}-id{node_id}.json"
        return path, data

    rules_entries: list[tuple[str, Dict[str, Any]]] = []
    if nodes:
        # Avoid unbounded parallelism
        import asyncio

        sem = asyncio.Semaphore(12)

        async def guarded(n: Dict[str, Any]):
            async with sem:
                return await build_one(n)

        rules_entries = list(await asyncio.gather(*[guarded(n) for n in nodes]))

    nodes_payload = {
        "kind": "realm_full_backup",
        "created_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "panel_public_url": _panel_public_base_url(request),
        "group_orders": [
            {"group_name": k, "sort_order": int(v)} for k, v in sorted(group_orders.items(), key=lambda kv: (kv[1], kv[0]))
        ],
        "nodes": [
            {
                "source_id": int(n.get("id") or 0),
                "name": n.get("name"),
                "base_url": n.get("base_url"),
                "api_key": n.get("api_key"),
                "verify_tls": bool(n.get("verify_tls", 0)),
                "group_name": n.get("group_name") or "默认分组",
            }
            for n in nodes
        ],
    }

    meta_payload = {
        "kind": "realm_backup_meta",
        "created_at": nodes_payload["created_at"],
        "nodes": len(nodes),
        "files": 2 + len(rules_entries),
    }

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as z:
        z.writestr("backup_meta.json", json.dumps(meta_payload, ensure_ascii=False, indent=2))
        z.writestr("nodes.json", json.dumps(nodes_payload, ensure_ascii=False, indent=2))
        for path, data in rules_entries:
            z.writestr(path, json.dumps(data, ensure_ascii=False, indent=2))
        z.writestr(
            "README.txt",
            "Realm 全量备份说明\n\n"
            "1) 恢复节点列表：登录面板 → 控制台 → 点击『恢复节点列表』，上传本压缩包（或解压后的 nodes.json）。\n"
            "2) 恢复单节点规则：进入节点页面 → 更多 → 恢复规则，把 rules/ 目录下对应节点的规则文件上传/粘贴即可。\n",
        )

    filename = f"realm-backup-{ts}.zip"
    headers = {"Content-Disposition": f'attachment; filename="{filename}"'}
    return Response(content=buf.getvalue(), media_type="application/zip", headers=headers)


@app.post("/api/restore/nodes")
async def api_restore_nodes(
    request: Request,
    file: UploadFile = File(...),
    user: str = Depends(require_login),
):
    """Restore nodes list from nodes.json or full backup zip."""
    try:
        raw = await file.read()
    except Exception as exc:
        return JSONResponse({"ok": False, "error": f"读取文件失败：{exc}"}, status_code=400)

    payload = None
    # Zip?
    if raw[:2] == b"PK":
        try:
            z = zipfile.ZipFile(io.BytesIO(raw))
            # find nodes.json
            name = None
            for n in z.namelist():
                if n.lower().endswith("nodes.json"):
                    name = n
                    break
            if not name:
                return JSONResponse({"ok": False, "error": "压缩包中未找到 nodes.json"}, status_code=400)
            payload = json.loads(z.read(name).decode("utf-8"))
        except Exception as exc:
            return JSONResponse({"ok": False, "error": f"压缩包解析失败：{exc}"}, status_code=400)
    else:
        try:
            payload = json.loads(raw.decode("utf-8"))
        except Exception as exc:
            return JSONResponse({"ok": False, "error": f"JSON 解析失败：{exc}"}, status_code=400)

    # Accept: {nodes:[...]} or plain list
    nodes_list = None
    if isinstance(payload, dict) and isinstance(payload.get("nodes"), list):
        nodes_list = payload.get("nodes")
    elif isinstance(payload, list):
        nodes_list = payload

    if not isinstance(nodes_list, list):
        return JSONResponse({"ok": False, "error": "备份内容缺少 nodes 列表"}, status_code=400)

    # Optional: restore group orders (UI sorting)
    try:
        go = payload.get('group_orders') if isinstance(payload, dict) else None
        items: list[dict[str, Any]] = []
        if isinstance(go, dict):
            items = [{"group_name": k, "sort_order": v} for k, v in go.items()]
        elif isinstance(go, list):
            items = [x for x in go if isinstance(x, dict)]
        for it in items:
            gname = str(it.get('group_name') or it.get('name') or '').strip() or '默认分组'
            try:
                s = int(it.get('sort_order', it.get('order', 1000)))
            except Exception:
                continue
            upsert_group_order(gname, s)
    except Exception:
        pass

    added = 0
    updated = 0
    skipped = 0
    mapping: Dict[str, int] = {}

    for item in nodes_list:
        if not isinstance(item, dict):
            skipped += 1
            continue
        name = (item.get("name") or "").strip()
        base_url = (item.get("base_url") or "").strip().rstrip('/')
        api_key = (item.get("api_key") or "").strip()
        verify_tls = bool(item.get("verify_tls", False))
        is_private = bool(item.get("is_private", False))
        group_name = (item.get("group_name") or "默认分组").strip() if isinstance(item.get("group_name"), str) else ("默认分组" if not item.get("group_name") else str(item.get("group_name")))
        group_name = (group_name or "默认分组").strip() or "默认分组"
        source_id = item.get("source_id")
        try:
            source_id_i = int(source_id) if source_id is not None else None
        except Exception:
            source_id_i = None

        if not base_url or not api_key:
            skipped += 1
            continue

        existing = get_node_by_api_key(api_key) or get_node_by_base_url(base_url)
        if existing:
            update_node_basic(
                existing["id"],
                name or existing.get("name") or _extract_ip_for_display(base_url),
                base_url,
                api_key,
                verify_tls=verify_tls,
                is_private=is_private,
                group_name=group_name,
            )
            updated += 1
            if source_id_i is not None:
                mapping[str(source_id_i)] = int(existing["id"])
        else:
            new_id = add_node(
                name or _extract_ip_for_display(base_url),
                base_url,
                api_key,
                verify_tls=verify_tls,
                is_private=is_private,
                group_name=group_name,
            )
            added += 1
            if source_id_i is not None:
                mapping[str(source_id_i)] = int(new_id)

    return {
        "ok": True,
        "added": added,
        "updated": updated,
        "skipped": skipped,
        "mapping": mapping,
    }




@app.post("/api/restore/full")
async def api_restore_full(
    request: Request,
    file: UploadFile = File(...),
    user: str = Depends(require_login),
):
    """Restore nodes list + per-node rules from full backup zip."""
    try:
        raw = await file.read()
    except Exception as exc:
        return JSONResponse({"ok": False, "error": f"读取文件失败：{exc}"}, status_code=400)

    if not raw or raw[:2] != b"PK":
        return JSONResponse({"ok": False, "error": "请上传 realm-backup-*.zip（全量备份包）"}, status_code=400)

    try:
        z = zipfile.ZipFile(io.BytesIO(raw))
    except Exception as exc:
        return JSONResponse({"ok": False, "error": f"压缩包解析失败：{exc}"}, status_code=400)

    # ---- read nodes.json ----
    nodes_payload = None
    nodes_name = None
    for n in z.namelist():
        if n.lower().endswith('nodes.json'):
            nodes_name = n
            break
    if not nodes_name:
        return JSONResponse({"ok": False, "error": "压缩包中未找到 nodes.json"}, status_code=400)

    try:
        nodes_payload = json.loads(z.read(nodes_name).decode('utf-8'))
    except Exception as exc:
        return JSONResponse({"ok": False, "error": f"nodes.json 解析失败：{exc}"}, status_code=400)

    # Accept: {nodes:[...]} or plain list
    nodes_list = None
    if isinstance(nodes_payload, dict) and isinstance(nodes_payload.get('nodes'), list):
        nodes_list = nodes_payload.get('nodes')
    elif isinstance(nodes_payload, list):
        nodes_list = nodes_payload

    if not isinstance(nodes_list, list):
        return JSONResponse({"ok": False, "error": "备份内容缺少 nodes 列表"}, status_code=400)

    # Optional: restore group orders (UI sorting)
    try:
        go = nodes_payload.get('group_orders') if isinstance(nodes_payload, dict) else None
        items: list[dict[str, Any]] = []
        if isinstance(go, dict):
            items = [{"group_name": k, "sort_order": v} for k, v in go.items()]
        elif isinstance(go, list):
            items = [x for x in go if isinstance(x, dict)]
        for it in items:
            gname = str(it.get('group_name') or it.get('name') or '').strip() or '默认分组'
            try:
                s = int(it.get('sort_order', it.get('order', 1000)))
            except Exception:
                continue
            upsert_group_order(gname, s)
    except Exception:
        pass

    # ---- restore nodes ----
    added = 0
    updated = 0
    skipped = 0
    mapping: Dict[str, int] = {}
    srcid_to_baseurl: Dict[str, str] = {}
    baseurl_to_nodeid: Dict[str, int] = {}

    for item in nodes_list:
        if not isinstance(item, dict):
            skipped += 1
            continue
        name = (item.get('name') or '').strip()
        base_url = (item.get('base_url') or '').strip().rstrip('/')
        api_key = (item.get('api_key') or '').strip()
        verify_tls = bool(item.get('verify_tls', False))
        is_private = bool(item.get('is_private', False))
        group_name = (item.get('group_name') or '默认分组')
        group_name = (str(group_name).strip() or '默认分组')
        source_id = item.get('source_id')
        try:
            source_id_i = int(source_id) if source_id is not None else None
        except Exception:
            source_id_i = None

        if base_url and source_id_i is not None:
            srcid_to_baseurl[str(source_id_i)] = base_url

        if not base_url or not api_key:
            skipped += 1
            continue

        existing = get_node_by_api_key(api_key) or get_node_by_base_url(base_url)
        if existing:
            update_node_basic(
                existing['id'],
                name or existing.get('name') or _extract_ip_for_display(base_url),
                base_url,
                api_key,
                verify_tls=verify_tls,
                is_private=is_private,
                group_name=group_name,
            )
            updated += 1
            node_id = int(existing['id'])
        else:
            node_id = int(add_node(name or _extract_ip_for_display(base_url), base_url, api_key, verify_tls=verify_tls, is_private=is_private, group_name=group_name))
            added += 1

        baseurl_to_nodeid[base_url] = node_id
        if source_id_i is not None:
            mapping[str(source_id_i)] = node_id

    # ---- restore rules (batch) ----
    rule_paths = [
        n for n in z.namelist()
        if n.lower().startswith('rules/') and n.lower().endswith('.json')
    ]

    import re as _re
    import asyncio

    async def apply_pool_to_node(target_id: int, pool: Dict[str, Any]) -> Dict[str, Any]:
        node = get_node(int(target_id))
        if not node:
            raise RuntimeError('节点不存在')
        # store desired on panel
        desired_ver, _ = set_desired_pool(int(target_id), pool)

        # best-effort immediate apply
        applied = False
        try:
            data = await agent_post(
                node['base_url'],
                node['api_key'],
                '/api/v1/pool',
                {'pool': pool},
                _node_verify_tls(node),
            )
            if isinstance(data, dict) and data.get('ok', True):
                await agent_post(node['base_url'], node['api_key'], '/api/v1/apply', {}, _node_verify_tls(node))
                applied = True
        except Exception:
            applied = False

        return {"node_id": int(target_id), "desired_version": desired_ver, "applied": applied}

    sem = asyncio.Semaphore(6)

    async def guarded_apply(target_id: int, pool: Dict[str, Any]) -> Dict[str, Any]:
        async with sem:
            return await apply_pool_to_node(target_id, pool)

    total_rules = len(rule_paths)
    restored_rules = 0
    failed_rules = 0
    unmatched_rules = 0
    rule_failed: list[Dict[str, Any]] = []
    rule_unmatched: list[Dict[str, Any]] = []

    tasks = []
    task_meta = []

    for p in rule_paths:
        try:
            payload = json.loads(z.read(p).decode('utf-8'))
        except Exception as exc:
            failed_rules += 1
            rule_failed.append({"path": p, "error": f"JSON 解析失败：{exc}"})
            continue

        pool = payload.get('pool') if isinstance(payload, dict) else None
        if pool is None:
            pool = payload
        if not isinstance(pool, dict):
            failed_rules += 1
            rule_failed.append({"path": p, "error": "备份内容缺少 pool 数据"})
            continue
        if not isinstance(pool.get('endpoints'), list):
            pool.setdefault('endpoints', [])

        # resolve source_id / base_url
        node_meta = payload.get('node') if isinstance(payload, dict) else None
        source_id = None
        base_url = None
        if isinstance(node_meta, dict):
            try:
                if node_meta.get('id') is not None:
                    source_id = int(node_meta.get('id'))
            except Exception:
                source_id = None
            base_url = (node_meta.get('base_url') or '').strip().rstrip('/') or None

        if source_id is None:
            m = _re.search(r'id(\d+)\.json$', p)
            if m:
                try:
                    source_id = int(m.group(1))
                except Exception:
                    source_id = None

        if base_url is None and source_id is not None:
            base_url = srcid_to_baseurl.get(str(source_id))

        target_id = None
        if source_id is not None:
            target_id = mapping.get(str(source_id))
        if target_id is None and base_url:
            target_id = baseurl_to_nodeid.get(base_url)
        if target_id is None and base_url:
            ex = get_node_by_base_url(base_url)
            if ex:
                target_id = int(ex.get('id'))

        if target_id is None:
            unmatched_rules += 1
            rule_unmatched.append({"path": p, "source_id": source_id, "base_url": base_url, "error": "未找到对应节点"})
            continue

        tasks.append(guarded_apply(int(target_id), pool))
        task_meta.append({"path": p, "target_id": int(target_id), "source_id": source_id, "base_url": base_url})

    if tasks:
        results = await asyncio.gather(*tasks, return_exceptions=True)
        for meta, res in zip(task_meta, results):
            if isinstance(res, Exception):
                failed_rules += 1
                rule_failed.append({"path": meta.get('path'), "target_id": meta.get('target_id'), "error": str(res)})
            else:
                restored_rules += 1

    return {
        "ok": True,
        "nodes": {"added": added, "updated": updated, "skipped": skipped, "mapping": mapping},
        "rules": {
            "total": total_rules,
            "restored": restored_rules,
            "unmatched": unmatched_rules,
            "failed": failed_rules,
        },
        "rule_unmatched": rule_unmatched[:50],
        "rule_failed": rule_failed[:50],
    }

@app.post("/api/nodes/{node_id}/restore")
async def api_restore(
    request: Request,
    node_id: int,
    file: UploadFile = File(...),
    user: str = Depends(require_login),
):
    node = get_node(node_id)
    if not node:
        return JSONResponse({"ok": False, "error": "节点不存在"}, status_code=404)
    try:
        raw = await file.read()
        payload = json.loads(raw.decode("utf-8"))
    except Exception as exc:
        return JSONResponse({"ok": False, "error": f"备份文件解析失败：{exc}"}, status_code=400)
    pool = payload.get("pool") if isinstance(payload, dict) else None
    if pool is None:
        pool = payload
    if not isinstance(pool, dict):
        return JSONResponse({"ok": False, "error": "备份内容缺少 pool 数据"}, status_code=400)

    # sanitize (trim spaces)
    try:
        eps = pool.get("endpoints")
        if isinstance(eps, list):
            for e in eps:
                if not isinstance(e, dict):
                    continue
                if e.get("listen") is not None:
                    e["listen"] = str(e.get("listen") or "").strip()
                if e.get("remote") is not None:
                    e["remote"] = str(e.get("remote") or "").strip()
                if isinstance(e.get("remotes"), list):
                    e["remotes"] = [str(x).strip() for x in e.get("remotes") if str(x).strip()]
                if isinstance(e.get("extra_remotes"), list):
                    e["extra_remotes"] = [str(x).strip() for x in e.get("extra_remotes") if str(x).strip()]
    except Exception:
        pass
    # Store on panel; apply will be done asynchronously (avoid blocking / proxy timeouts).
    desired_ver, _ = set_desired_pool(node_id, pool)
    _schedule_apply_pool(node, pool)
    return {"ok": True, "desired_version": desired_ver, "queued": True}


@app.post("/api/nodes/{node_id}/pool")
async def api_pool_set(request: Request, node_id: int, payload: Dict[str, Any], user: str = Depends(require_login)):
    node = get_node(node_id)
    if not node:
        return JSONResponse({"ok": False, "error": "节点不存在"}, status_code=404)
    pool = payload.get("pool") if isinstance(payload, dict) else None
    if pool is None and isinstance(payload, dict):
        # some callers may post the pool dict directly
        pool = payload
    if not isinstance(pool, dict):
        return JSONResponse({"ok": False, "error": "请求缺少 pool 字段"}, status_code=400)

    # --- Sanitize pool fields (trim spaces) ---
    # 说明：Agent 侧会对 listen 做 strip()，如果面板保存了带空格/不可见字符的 listen，
    # 前端按 listen 精确匹配 stats 时会出现“暂无检测数据”。
    try:
        eps = pool.get("endpoints")
        if isinstance(eps, list):
            for e in eps:
                if not isinstance(e, dict):
                    continue
                if e.get("listen") is not None:
                    e["listen"] = str(e.get("listen") or "").strip()
                if e.get("remote") is not None:
                    e["remote"] = str(e.get("remote") or "").strip()
                if isinstance(e.get("remotes"), list):
                    e["remotes"] = [str(x).strip() for x in e.get("remotes") if str(x).strip()]
                if isinstance(e.get("extra_remotes"), list):
                    e["extra_remotes"] = [str(x).strip() for x in e.get("extra_remotes") if str(x).strip()]
                # common optional string fields
                for k in ("through", "interface", "listen_interface", "listen_transport", "remote_transport", "protocol", "balance"):
                    if e.get(k) is not None and isinstance(e.get(k), str):
                        e[k] = e[k].strip()
    except Exception:
        pass


    # Prevent editing/deleting synced receiver rules from UI
    try:
        _, existing_desired = get_desired_pool(node_id)
        existing_pool = existing_desired
        if not isinstance(existing_pool, dict):
            rep = get_last_report(node_id)
            if isinstance(rep, dict) and isinstance(rep.get("pool"), dict):
                existing_pool = rep.get("pool")
        locked: Dict[str, Any] = {}
        if isinstance(existing_pool, dict):
            for ep in existing_pool.get("endpoints") or []:
                if not isinstance(ep, dict):
                    continue
                ex0 = ep.get("extra_config") or {}
                if not isinstance(ex0, dict):
                    ex0 = {}
                sid = ex0.get("sync_id")
                if sid and (ex0.get("sync_lock") is True or ex0.get("sync_role") == "receiver" or ex0.get("intranet_lock") is True or ex0.get("intranet_role") == "client"):
                    locked[str(sid)] = ep

        if locked:
            posted: Dict[str, Any] = {}
            for ep in pool.get("endpoints") or []:
                if not isinstance(ep, dict):
                    continue
                ex0 = ep.get("extra_config") or {}
                if not isinstance(ex0, dict):
                    ex0 = {}
                sid = ex0.get("sync_id")
                if sid:
                    posted[str(sid)] = ep

            def _canon(e: Dict[str, Any]) -> Dict[str, Any]:
                ex = dict(e.get("extra_config") or {})
                ex.pop("last_sync_at", None)
                ex.pop("sync_updated_at", None)
                ex.pop("intranet_updated_at", None)
                return {
                    "listen": e.get("listen"),
                    "remotes": e.get("remotes") or [],
                    "disabled": bool(e.get("disabled", False)),
                    "balance": e.get("balance"),
                    "protocol": e.get("protocol"),
                    "extra_config": ex,
                }

            for sid, old_ep in locked.items():
                new_ep = posted.get(sid)
                if not new_ep:
                    return JSONResponse(
                        {"ok": False, "error": "该节点存在由发送机同步的锁定规则，无法手动删除/修改（请在发送机上操作）"},
                        status_code=403,
                    )
                if _canon(old_ep) != _canon(new_ep):
                    return JSONResponse(
                        {"ok": False, "error": "该节点存在由发送机同步的锁定规则，无法手动删除/修改（请在发送机上操作）"},
                        status_code=403,
                    )
    except Exception:
        pass

    # Store desired pool on panel. Agent will pull it on next report.
    desired_ver, _ = set_desired_pool(node_id, pool)

    # Apply in background: do not block HTTP response (prevents frontend seeing “Load failed” under proxy timeouts).
    _schedule_apply_pool(node, pool)

    return {"ok": True, "pool": pool, "desired_version": desired_ver, "queued": True, "note": "waiting agent report"}


@app.post("/api/nodes/{node_id}/purge")
async def api_node_purge(
    request: Request,
    node_id: int,
    payload: Dict[str, Any],
    user: str = Depends(require_login),
):
    """Dangerous: clear all endpoints on a node (including locked/synced rules).

    Workflow is enforced both on UI and server side:
      - UI asks for 2-step confirmation and requires typing "确认删除".
      - Server also verifies confirm_text == "确认删除".

    Best-effort: also cleans up paired synced rules on peer nodes (WSS sync / Intranet tunnel).
    """

    confirm_text = str((payload or {}).get("confirm_text") or "").strip()
    if confirm_text != "确认删除":
        return JSONResponse({"ok": False, "error": "确认文本不匹配（需要完整输入：确认删除）"}, status_code=400)

    node = get_node(node_id)
    if not node:
        return JSONResponse({"ok": False, "error": "节点不存在"}, status_code=404)

    # Load current pool snapshot (desired > report > agent)
    cur_pool = await _load_pool_for_node(node)

    # Collect sync pairs so we can remove peer rules too (avoid leaving orphaned locked rules)
    peer_tasks: list[tuple[int, str]] = []  # (peer_node_id, sync_id)
    seen_pairs: set[tuple[int, str]] = set()

    for ep in (cur_pool.get("endpoints") or []):
        if not isinstance(ep, dict):
            continue
        ex = ep.get("extra_config") or {}
        if not isinstance(ex, dict):
            continue
        sid = str(ex.get("sync_id") or "").strip()
        if not sid:
            continue

        peer_id = 0

        # WSS node-to-node sync
        role = str(ex.get("sync_role") or "").strip()
        if role == "sender":
            try:
                peer_id = int(ex.get("sync_peer_node_id") or 0)
            except Exception:
                peer_id = 0
        elif role == "receiver":
            try:
                peer_id = int(ex.get("sync_from_node_id") or 0)
            except Exception:
                peer_id = 0

        # Intranet tunnel sync (server/client)
        if peer_id <= 0:
            irole = str(ex.get("intranet_role") or "").strip()
            if irole in ("server", "client"):
                try:
                    peer_id = int(ex.get("intranet_peer_node_id") or 0)
                except Exception:
                    peer_id = 0

        if peer_id > 0 and peer_id != int(node_id):
            key = (peer_id, sid)
            if key not in seen_pairs:
                seen_pairs.add(key)
                peer_tasks.append((peer_id, sid))

    # Remove peers first (best effort). We do not block purge if peers fail.
    peers_cleared: list[int] = []
    for peer_id, sid in peer_tasks:
        peer = get_node(int(peer_id))
        if not peer:
            continue
        try:
            peer_pool = await _load_pool_for_node(peer)
            _remove_endpoints_by_sync_id(peer_pool, sid)
            set_desired_pool(int(peer_id), peer_pool)
            _schedule_apply_pool(peer, peer_pool)
            peers_cleared.append(int(peer_id))
        except Exception:
            continue

    # Clear local endpoints (keep other pool keys as-is)
    new_pool = dict(cur_pool)
    new_pool["endpoints"] = []

    desired_ver, _ = set_desired_pool(node_id, new_pool)
    _schedule_apply_pool(node, new_pool)

    return {
        "ok": True,
        "node_id": int(node_id),
        "cleared": True,
        "peer_nodes_touched": sorted(set(peers_cleared)),
        "desired_version": desired_ver,
        "queued": True,
    }



# -------------------- WSS tunnel node-to-node sync --------------------

def _split_host_port(addr: str) -> tuple[str, Optional[int]]:
    addr = (addr or "").strip()
    if not addr:
        return "", None
    if addr.startswith("["):
        # [IPv6]:port
        if "]" in addr:
            host = addr[1: addr.index("]")]
            rest = addr[addr.index("]") + 1 :]
            if rest.startswith(":"):
                try:
                    return host, int(rest[1:])
                except Exception:
                    return host, None
            return host, None
        return addr, None
    if ":" in addr:
        host, p = addr.rsplit(":", 1)
        try:
            return host, int(p)
        except Exception:
            return addr, None
    return addr, None


def _format_addr(host: str, port: int) -> str:
    host = (host or "").strip()
    if ":" in host and not host.startswith("["):
        host = f"[{host}]"
    return f"{host}:{int(port)}"


def _node_host_for_realm(node: Dict[str, Any]) -> str:
    base = (node.get("base_url") or "").strip()
    if not base:
        return ""
    if "://" not in base:
        base = "http://" + base
    u = urlparse(base)
    return u.hostname or ""


async def _load_pool_for_node(node: Dict[str, Any]) -> Dict[str, Any]:
    nid = int(node.get("id") or 0)
    _, desired = get_desired_pool(nid)
    if isinstance(desired, dict):
        pool = desired
    else:
        rep = get_last_report(nid)
        if isinstance(rep, dict) and isinstance(rep.get("pool"), dict):
            pool = rep.get("pool")
        else:
            try:
                data = await agent_get(node["base_url"], node["api_key"], "/api/v1/pool", _node_verify_tls(node))
                pool = data.get("pool") if isinstance(data, dict) else None
            except Exception:
                pool = None
    if not isinstance(pool, dict):
        pool = {}
    if not isinstance(pool.get("endpoints"), list):
        pool["endpoints"] = []
    return pool


def _remove_endpoints_by_sync_id(pool: Dict[str, Any], sync_id: str) -> None:
    if not isinstance(pool, dict):
        return
    eps = pool.get("endpoints")
    if not isinstance(eps, list):
        pool["endpoints"] = []
        return
    new_eps = []
    for ep in eps:
        if not isinstance(ep, dict):
            continue
        ex = ep.get("extra_config") or {}
        sid = ex.get("sync_id") if isinstance(ex, dict) else None
        if sid and str(sid) == str(sync_id):
            continue
        new_eps.append(ep)
    pool["endpoints"] = new_eps


def _upsert_endpoint_by_sync_id(pool: Dict[str, Any], sync_id: str, endpoint: Dict[str, Any]) -> None:
    """Upsert an endpoint by extra_config.sync_id while preserving original ordering.

    Background:
      For WSS/内网穿透这类“同步规则”，面板后端过去采取
      `remove(sync_id) + append(new)` 的策略。
      这会导致：每次启停/编辑同步规则时，该规则会被移动到列表末尾。
      前端又会用规则数组下标去关联 stats（连接数/流量/健康探测），在 Agent
      尚未完成应用/上报前，会出现“暂停一个规则，其他规则统计也跟着错位”的视觉错乱。

    This helper keeps the endpoint at its original index (if it already exists),
    and also deduplicates any stale duplicates with the same sync_id.
    """
    if not isinstance(pool, dict):
        return
    eps = pool.get("endpoints")
    if not isinstance(eps, list):
        pool["endpoints"] = [endpoint]
        return

    keep_index: Optional[int] = None
    new_eps: list[Any] = []
    for ep in eps:
        if not isinstance(ep, dict):
            new_eps.append(ep)
            continue
        ex = ep.get("extra_config") or {}
        sid = ex.get("sync_id") if isinstance(ex, dict) else None
        if sid and str(sid) == str(sync_id):
            if keep_index is None:
                keep_index = len(new_eps)
            # drop duplicates
            continue
        new_eps.append(ep)

    if keep_index is None or keep_index < 0 or keep_index > len(new_eps):
        new_eps.append(endpoint)
    else:
        new_eps.insert(keep_index, endpoint)

    pool["endpoints"] = new_eps


def _find_sync_listen_port(pool: Dict[str, Any], sync_id: str, role: Optional[str] = None) -> Optional[int]:
    """Find listen port for an endpoint identified by extra_config.sync_id.

    Used by WSS tunnel autosync to keep receiver port stable across enable/disable.

    Args:
        pool: realm pool dict
        sync_id: sync id
        role: optional extra_config role filter (e.g. "receiver" / "sender")
    """
    if not isinstance(pool, dict):
        return None
    for ep in pool.get("endpoints") or []:
        if not isinstance(ep, dict):
            continue
        ex = ep.get("extra_config") or {}
        if not isinstance(ex, dict):
            continue
        sid = ex.get("sync_id")
        if not sid or str(sid) != str(sync_id):
            continue
        if role and str(ex.get("sync_role") or "") != str(role):
            continue
        _, p = _split_host_port(str(ep.get("listen") or ""))
        if p:
            try:
                return int(p)
            except Exception:
                return None
    return None


def _port_used_by_other_sync(receiver_pool: Dict[str, Any], port: int, sync_id: str) -> bool:
    """Return True if `port` is already used by another endpoint (different sync_id)."""
    if not isinstance(receiver_pool, dict):
        return False
    for ep in receiver_pool.get("endpoints") or []:
        if not isinstance(ep, dict):
            continue
        _, p = _split_host_port(str(ep.get("listen") or ""))
        if not p:
            continue
        try:
            if int(p) != int(port):
                continue
        except Exception:
            continue
        ex = ep.get("extra_config") or {}
        sid = ex.get("sync_id") if isinstance(ex, dict) else None
        if sid and str(sid) == str(sync_id):
            continue
        return True
    return False


def _choose_receiver_port(receiver_pool: Dict[str, Any], preferred: Optional[int], ignore_sync_id: Optional[str] = None) -> int:
    used = set()
    for ep in receiver_pool.get("endpoints") or []:
        if not isinstance(ep, dict):
            continue
        ex = ep.get("extra_config") or {}
        sid = ex.get("sync_id") if isinstance(ex, dict) else None
        if ignore_sync_id and sid and str(sid) == str(ignore_sync_id):
            # allow reusing the same port for the same sync tunnel
            continue
        h, p = _split_host_port(str(ep.get("listen") or ""))
        if p:
            used.add(int(p))
    if preferred and 1 <= int(preferred) <= 65535 and int(preferred) not in used:
        return int(preferred)
    # pick a random-ish high port
    seed = int(uuid.uuid4().int % 20000)
    port = 20000 + seed
    for _ in range(20000):
        if port not in used and 1 <= port <= 65535:
            return port
        port += 1
        if port > 65535:
            port = 20000
    # fallback
    return 33394



@app.post("/api/nodes/create")
async def api_nodes_create(request: Request, user: str = Depends(require_login)):
    """Dashboard 快速接入节点（弹窗模式）。返回 JSON，前端可直接跳转节点详情页。"""
    try:
        data = await request.json()
    except Exception:
        data = {}
    name = str(data.get("name") or "").strip()
    ip_address = str(data.get("ip_address") or "").strip()
    scheme = str(data.get("scheme") or "http").strip().lower()
    verify_tls = bool(data.get("verify_tls") or False)
    is_private = bool(data.get("is_private") or False)
    group_name = str(data.get("group_name") or "").strip() or "默认分组"

    if scheme not in ("http", "https"):
        return JSONResponse({"ok": False, "error": "协议仅支持 http 或 https"}, status_code=400)
    if not ip_address:
        return JSONResponse({"ok": False, "error": "节点地址不能为空"}, status_code=400)

    # 端口在 UI 中隐藏：默认 18700；如用户自带 :port 则兼容解析（仍不展示）
    if "://" not in ip_address:
        ip_address = f"{scheme}://{ip_address}"

    port_value = DEFAULT_AGENT_PORT
    host, parsed_port, has_port, scheme = _split_host_and_port(ip_address, port_value)
    if not host:
        return JSONResponse({"ok": False, "error": "节点地址不能为空"}, status_code=400)
    if has_port:
        port_value = parsed_port

    base_url = f"{scheme}://{_format_host_for_url(host)}:{port_value}"
    api_key = _generate_api_key()

    display_name = name or _extract_ip_for_display(base_url)
    node_id = add_node(display_name, base_url, api_key, verify_tls=verify_tls, is_private=is_private, group_name=group_name)
    # 创建完成后，进入节点详情页时自动弹出“接入命令”窗口
    # 说明：会通过 SessionMiddleware 写入签名 Cookie；前端跳转到 /nodes/{id} 后读取并触发弹窗。
    try:
        request.session["show_install_cmd"] = True
    except Exception:
        pass
    return JSONResponse({"ok": True, "node_id": node_id, "redirect_url": f"/nodes/{node_id}"})

@app.post("/api/nodes/{node_id}/update")
async def api_nodes_update(node_id: int, request: Request, user: str = Depends(require_login)):
    """编辑节点：修改名称 / 地址 / 分组（不改 api_key）。"""
    try:
        data = await request.json()
    except Exception:
        data = {}

    node = get_node(int(node_id))
    if not node:
        return JSONResponse({"ok": False, "error": "节点不存在"}, status_code=404)

    name_in = data.get("name", None)
    ip_in = data.get("ip_address", None)
    scheme_in = data.get("scheme", None)
    group_in = data.get("group_name", None)

    # is_private: only update when provided
    if "is_private" in data:
        is_private = bool(data.get("is_private") or False)
    else:
        is_private = bool(node.get("is_private", 0))

    # verify_tls: only update when provided
    if "verify_tls" in data:
        verify_tls = bool(data.get("verify_tls") or False)
    else:
        verify_tls = bool(node.get("verify_tls", 0))

    # group name
    if group_in is None:
        group_name = str(node.get("group_name") or "默认分组").strip() or "默认分组"
    else:
        group_name = str(group_in or "").strip() or "默认分组"

    # parse existing base_url
    raw_old = str(node.get("base_url") or "").strip()
    if not raw_old:
        return JSONResponse({"ok": False, "error": "节点地址异常"}, status_code=400)
    if "://" not in raw_old:
        raw_old = "http://" + raw_old
    parsed_old = urlparse(raw_old)
    old_scheme = (parsed_old.scheme or "http").lower()
    old_host = parsed_old.hostname or ""
    old_port = parsed_old.port
    old_has_port = parsed_old.port is not None

    scheme = str(scheme_in or old_scheme).strip().lower() or "http"
    if scheme not in ("http", "https"):
        return JSONResponse({"ok": False, "error": "协议仅支持 http 或 https"}, status_code=400)

    host = old_host
    port_value = old_port
    has_port = old_has_port

    if ip_in is not None:
        ip_address = str(ip_in or "").strip()
        if not ip_address:
            return JSONResponse({"ok": False, "error": "节点地址不能为空"}, status_code=400)

        # allow user paste full url
        ip_full = ip_address
        if "://" not in ip_full:
            ip_full = f"{scheme}://{ip_full}"

        fallback_port = int(old_port) if old_has_port and old_port else DEFAULT_AGENT_PORT
        h, p, has_p, parsed_scheme = _split_host_and_port(ip_full, fallback_port)
        if not h:
            return JSONResponse({"ok": False, "error": "节点地址不能为空"}, status_code=400)

        # only override scheme when user explicitly provided scheme
        if "://" in ip_address:
            scheme = (parsed_scheme or scheme).lower()
        host = h

        if has_p:
            port_value = int(p)
            has_port = True
        else:
            # preserve old explicit port; otherwise keep no-port
            if old_has_port and old_port:
                port_value = int(old_port)
                has_port = True
            else:
                port_value = None
                has_port = False

    base_url = f"{scheme}://{_format_host_for_url(host)}"
    if has_port and port_value:
        base_url += f":{int(port_value)}"

    # prevent duplicates
    other = get_node_by_base_url(base_url)
    if other and int(other.get("id") or 0) != int(node_id):
        return JSONResponse({"ok": False, "error": "该节点地址已被其他节点使用"}, status_code=400)

    # name
    if name_in is None:
        name = str(node.get("name") or "").strip() or _extract_ip_for_display(base_url)
    else:
        name = str(name_in or "").strip() or _extract_ip_for_display(base_url)

    update_node_basic(
        int(node_id),
        name,
        base_url,
        str(node.get("api_key") or ""),
        verify_tls=verify_tls,
        is_private=is_private,
        group_name=group_name,
    )

    # Return updated fields for client-side UI refresh (avoid full page reload)
    updated = get_node(int(node_id)) or {}
    display_ip = _extract_ip_for_display(str(updated.get("base_url") or base_url))
    return JSONResponse(
        {
            "ok": True,
            "node": {
                "id": int(node_id),
                "name": str(updated.get("name") or name),
                "base_url": str(updated.get("base_url") or base_url),
                "group_name": str(updated.get("group_name") or group_name),
                "display_ip": display_ip,
                "verify_tls": bool(updated.get("verify_tls") or verify_tls),
                "is_private": bool(updated.get("is_private") or is_private),
            },
        }
    )



@app.get("/api/nodes")
async def api_nodes_list(user: str = Depends(require_login)):
    out = []
    for n in list_nodes():
        out.append({
            "id": int(n["id"]),
            "name": n["name"],
            "base_url": n["base_url"],
            "group_name": n.get("group_name"),
            "is_private": bool(n.get("is_private") or 0),
        })
    return {"ok": True, "nodes": out}




@app.get("/api/netmon/snapshot")
async def api_netmon_snapshot(request: Request, user: str = Depends(require_login_or_share_api)):
    """Return NetMon monitors + samples (history window).

    Query:
      - window_min: minutes, default 10
      - window_sec: seconds, alternative to window_min
    """
    qp = request.query_params
    raw_min = qp.get("window_min")
    raw_sec = qp.get("window_sec")
    raw_mid = qp.get("mid") or qp.get("monitor_id")
    raw_rollup = qp.get("rollup_ms") or qp.get("resolution_ms")

    # Share-token access: enforce monitor scope & default window
    share_ctx = getattr(request.state, "share", None)
    if isinstance(share_ctx, dict):
        try:
            smid = int(share_ctx.get("mid") or 0)
        except Exception:
            smid = 0
        if smid > 0:
            raw_mid = str(smid)

        # Share link may carry a fixed range or a window size; use it as an upper bound.
        try:
            s_win = int(share_ctx.get("win") or 0)
        except Exception:
            s_win = 0

        try:
            s_from = int(share_ctx.get("from") or 0)
        except Exception:
            s_from = 0
        try:
            s_to = int(share_ctx.get("to") or 0)
        except Exception:
            s_to = 0

        if s_from > 0 and s_to > s_from:
            # Bound the returned dataset to the shared fixed window (+ small pad).
            span_ms = max(1000, s_to - s_from)
            pad_ms = min(int(span_ms * 0.15), 5 * 60 * 1000)
            need_sec = int((span_ms + pad_ms * 2) / 1000) + 1
            raw_sec = str(max(10, min(24 * 3600, need_sec)))
        elif s_win > 0:
            raw_min = str(max(1, min(24 * 60, s_win)))

    window_sec = None
    if raw_sec is not None and str(raw_sec).strip() != "":
        try:
            window_sec = int(raw_sec)
        except Exception:
            window_sec = None
    if window_sec is None:
        try:
            window_min = int(raw_min) if raw_min is not None else 10
        except Exception:
            window_min = 10
        if window_min < 1:
            window_min = 1
        if window_min > 24 * 60:
            window_min = 24 * 60
        window_sec = window_min * 60

    if window_sec < 10:
        window_sec = 10
    if window_sec > 24 * 3600:
        window_sec = 24 * 3600

    # Optional: limit response to one monitor (share/read-only view).
    only_mid: Optional[int] = None
    if raw_mid is not None and str(raw_mid).strip() != "":
        try:
            only_mid = int(str(raw_mid).strip())
        except Exception:
            only_mid = None
        if only_mid is not None and only_mid <= 0:
            only_mid = None

    # Backend resolution tiering (rollup) for large windows.
    # The chart also has client-side LTTB downsampling, but server rollup reduces DB/io payload.
    #
    # Behavior:
    #  - If rollup_ms is omitted: backend chooses a tier automatically.
    #  - If rollup_ms is present:
    #      * 0  => raw (no rollup)
    #      * >0 => force that bucket size
    rollup_param_present = False
    rollup_ms = 0
    if raw_rollup is not None and str(raw_rollup).strip() != "":
        rollup_param_present = True
        try:
            rollup_ms = int(str(raw_rollup).strip())
        except Exception:
            rollup_ms = 0
        if rollup_ms < 0:
            rollup_ms = 0

    if not rollup_param_present:
        # Default tiers (feel free to tune):
        #  - <= 1h  : raw
        #  - <= 6h  : 10s
        #  - <= 24h : 30s
        #  - <= 7d  : 5m
        #  - <= 30d : 15m
        #  - > 30d  : 1h
        if window_sec <= 3600:
            rollup_ms = 0
        elif window_sec <= 6 * 3600:
            rollup_ms = 10_000
        elif window_sec <= 24 * 3600:
            rollup_ms = 30_000
        elif window_sec <= 7 * 86400:
            rollup_ms = 300_000
        elif window_sec <= 30 * 86400:
            rollup_ms = 900_000
        else:
            rollup_ms = 3_600_000

    now_ms = int(time.time() * 1000)
    cutoff_ms = now_ms - int(window_sec * 1000)

    monitors = list_netmon_monitors()
    if only_mid is not None:
        monitors = [m for m in monitors if int(m.get("id") or 0) == int(only_mid)]
    monitor_ids = [int(m.get("id") or 0) for m in monitors if int(m.get("id") or 0) > 0]

    # Node metadata (for legend)
    nodes = list_nodes()
    nodes_meta: Dict[str, Any] = {}
    for n in nodes:
        nid = int(n.get("id") or 0)
        if nid <= 0:
            continue
        nodes_meta[str(nid)] = {
            "id": nid,
            "name": n.get("name") or _extract_ip_for_display(n.get("base_url", "")),
            "group_name": str(n.get("group_name") or "").strip() or "默认分组",
            "display_ip": _extract_ip_for_display(n.get("base_url", "")),
            "online": _is_report_fresh(n, max_age_sec=90),
        }

    # Samples
    if monitor_ids:
        if rollup_ms and rollup_ms > 0:
            samples = list_netmon_samples_rollup(monitor_ids, cutoff_ms, rollup_ms)
        else:
            samples = list_netmon_samples(monitor_ids, cutoff_ms)
    else:
        samples = []

    series: Dict[str, Dict[str, List[Dict[str, Any]]]] = {}
    for m in monitors:
        mid = int(m.get("id") or 0)
        if mid <= 0:
            continue
        mid_s = str(mid)
        series[mid_s] = {}
        # pre-create node arrays for configured nodes
        for nid in (m.get("node_ids") or []):
            try:
                nid_i = int(nid)
            except Exception:
                continue
            series[mid_s][str(nid_i)] = []

    for r in samples:
        try:
            mid = int(r.get("monitor_id") or 0)
            nid = int(r.get("node_id") or 0)
            # raw rows use ts_ms; rollup rows use bucket_ts_ms
            ts = int(r.get("bucket_ts_ms") or r.get("ts_ms") or 0)
        except Exception:
            continue
        if mid <= 0 or nid <= 0 or ts <= 0:
            continue
        mid_s = str(mid)
        nid_s = str(nid)
        if mid_s not in series:
            series[mid_s] = {}
        if nid_s not in series[mid_s]:
            series[mid_s][nid_s] = []
        # raw schema
        if "ts_ms" in r and "ok" in r:
            ok = bool(r.get("ok") or 0)
            v = None
            if ok and r.get("latency_ms") is not None:
                try:
                    v = float(r.get("latency_ms"))
                except Exception:
                    v = None

            pt: Dict[str, Any] = {"t": ts, "v": v, "ok": ok}
            if not ok:
                err = r.get("error")
                if err is not None:
                    em = str(err)
                    if len(em) > 120:
                        em = em[:120] + "…"
                    pt["e"] = em

        else:
            # rollup schema
            try:
                ok_cnt = int(r.get("ok_cnt") or 0)
            except Exception:
                ok_cnt = 0
            try:
                cnt = int(r.get("cnt") or 0)
            except Exception:
                cnt = 0
            try:
                fail_cnt = int(r.get("fail_cnt") or 0)
            except Exception:
                fail_cnt = 0

            ok = ok_cnt > 0
            v = None
            if ok and r.get("max_latency_ms") is not None:
                try:
                    v = float(r.get("max_latency_ms"))
                except Exception:
                    v = None

            pt = {"t": ts, "v": v, "ok": ok}
            if cnt:
                pt["n"] = cnt
            if fail_cnt:
                pt["f"] = fail_cnt
            if not ok:
                err = r.get("error")
                if err is not None:
                    em = str(err)
                    if len(em) > 120:
                        em = em[:120] + "…"
                    pt["e"] = em

        # Attach point
        series[mid_s][nid_s].append(pt)

    monitors_out: List[Dict[str, Any]] = []
    for m in monitors:
        try:
            mid = int(m.get("id") or 0)
        except Exception:
            continue
        if mid <= 0:
            continue
        monitors_out.append(
            {
                "id": mid,
                "target": str(m.get("target") or ""),
                "mode": str(m.get("mode") or "ping"),
                "tcp_port": int(m.get("tcp_port") or 443),
                "interval_sec": int(m.get("interval_sec") or 5),
                "warn_ms": int(m.get("warn_ms") or 0),
                "crit_ms": int(m.get("crit_ms") or 0),
                "enabled": bool(m.get("enabled") or 0),
                "node_ids": [int(x) for x in (m.get("node_ids") or []) if isinstance(x, int) or str(x).isdigit()],
                "last_run_ts_ms": int(m.get("last_run_ts_ms") or 0),
                "last_run_msg": str(m.get("last_run_msg") or ""),
            }
        )

    return {
        "ok": True,
        "ts": now_ms,
        "cutoff_ms": cutoff_ms,
        "window_sec": int(window_sec),
        "rollup_ms": int(rollup_ms or 0),
        "monitors": monitors_out,
        "nodes": nodes_meta,
        "series": series,
    }


@app.get("/api/netmon/range")
async def api_netmon_range(request: Request, user: str = Depends(require_login_or_share_api)):
    """Return raw samples for one monitor within a time range.

    This is used for the "abnormal event detail" diagnosis modal.

    Query:
      - mid (or monitor_id): monitor id
      - from / to (ms timestamp)

    Notes:
      - Always returns raw points (no rollup) to preserve details.
      - Range and row count are capped for safety.
    """
    qp = request.query_params
    raw_mid = qp.get("mid") or qp.get("monitor_id")
    raw_from = qp.get("from") or qp.get("from_ts_ms")
    raw_to = qp.get("to") or qp.get("to_ts_ms")

    try:
        mid = int(str(raw_mid).strip()) if raw_mid is not None else 0
    except Exception:
        mid = 0

    # Share-token access: force monitor scope
    share_ctx = getattr(request.state, "share", None)
    if isinstance(share_ctx, dict):
        try:
            smid = int(share_ctx.get("mid") or 0)
        except Exception:
            smid = 0
        if smid > 0:
            mid = smid
    if mid <= 0:
        return JSONResponse({"ok": False, "error": "mid 无效"}, status_code=400)

    try:
        from_ms = int(str(raw_from).strip()) if raw_from is not None else 0
    except Exception:
        from_ms = 0
    try:
        to_ms = int(str(raw_to).strip()) if raw_to is not None else 0
    except Exception:
        to_ms = 0
    if from_ms <= 0 or to_ms <= 0 or to_ms <= from_ms:
        return JSONResponse({"ok": False, "error": "from/to 无效"}, status_code=400)


    # Share-token access: keep range within allowed window (best-effort clamp)
    share_ctx = getattr(request.state, "share", None)
    if isinstance(share_ctx, dict):
        now_ms = int(time.time() * 1000)
        # Allowed window derived from token:
        # - fixed range: within [from - 10m, to + 10m]
        # - follow window: within last win minutes
        try:
            s_from = int(share_ctx.get("from") or 0)
        except Exception:
            s_from = 0
        try:
            s_to = int(share_ctx.get("to") or 0)
        except Exception:
            s_to = 0
        try:
            s_win = int(share_ctx.get("win") or 0)
        except Exception:
            s_win = 0

        if s_from > 0 and s_to > s_from:
            allow_from = max(0, s_from - 10 * 60 * 1000)
            allow_to = s_to + 10 * 60 * 1000
        else:
            if s_win <= 0:
                s_win = 10
            s_win = max(1, min(24 * 60, s_win))
            allow_to = now_ms + 60 * 1000
            allow_from = max(0, allow_to - s_win * 60 * 1000)

        # Clamp
        if from_ms < allow_from:
            from_ms = allow_from
        if to_ms > allow_to:
            to_ms = allow_to
        if to_ms <= from_ms:
            return JSONResponse({"ok": False, "error": "range 超出分享窗口"}, status_code=403)

    # Safety: cap maximum range (default 6h)
    max_span_ms = 6 * 3600 * 1000
    if (to_ms - from_ms) > max_span_ms:
        # Keep it safe: shrink to the last max_span_ms ending at to_ms
        from_ms = to_ms - max_span_ms

    mon = get_netmon_monitor(mid)
    if not mon:
        return JSONResponse({"ok": False, "error": "monitor 不存在"}, status_code=404)

    # Node metadata (for legend/table)
    nodes = list_nodes()
    nodes_meta: Dict[str, Any] = {}
    for n in nodes:
        nid = int(n.get("id") or 0)
        if nid <= 0:
            continue
        nodes_meta[str(nid)] = {
            "id": nid,
            "name": n.get("name") or _extract_ip_for_display(n.get("base_url", "")),
            "group_name": str(n.get("group_name") or "").strip() or "默认分组",
            "display_ip": _extract_ip_for_display(n.get("base_url", "")),
            "online": _is_report_fresh(n, max_age_sec=90),
        }

    # Raw samples
    rows = list_netmon_samples_range(mid, from_ms, to_ms, limit=80000)
    series: Dict[str, List[Dict[str, Any]]] = {}

    # Pre-create node arrays for configured nodes
    for nid in (mon.get("node_ids") or []):
        try:
            nid_i = int(nid)
        except Exception:
            continue
        series[str(nid_i)] = []

    for r in rows:
        try:
            nid = int(r.get("node_id") or 0)
            ts = int(r.get("ts_ms") or 0)
        except Exception:
            continue
        if nid <= 0 or ts <= 0:
            continue
        nid_s = str(nid)
        if nid_s not in series:
            series[nid_s] = []

        ok = bool(r.get("ok") or 0)
        v = None
        if ok and r.get("latency_ms") is not None:
            try:
                v = float(r.get("latency_ms"))
            except Exception:
                v = None
        pt: Dict[str, Any] = {"t": ts, "v": v, "ok": ok}
        if not ok:
            err = r.get("error")
            if err is not None:
                em = str(err)
                if len(em) > 160:
                    em = em[:160] + "…"
                pt["e"] = em
        series[nid_s].append(pt)

    now_ms = int(time.time() * 1000)
    return {
        "ok": True,
        "ts": now_ms,
        "monitor": {
            "id": int(mon.get("id") or 0),
            "target": str(mon.get("target") or ""),
            "mode": str(mon.get("mode") or "ping"),
            "tcp_port": int(mon.get("tcp_port") or 443),
            "interval_sec": int(mon.get("interval_sec") or 5),
            "warn_ms": int(mon.get("warn_ms") or 0),
            "crit_ms": int(mon.get("crit_ms") or 0),
            "enabled": bool(mon.get("enabled") or 0),
            "node_ids": [int(x) for x in (mon.get("node_ids") or []) if isinstance(x, int) or str(x).isdigit()],
        },
        "from": int(from_ms),
        "to": int(to_ms),
        "nodes": nodes_meta,
        "series": series,
    }
@app.post("/api/netmon/share")
async def api_netmon_share(request: Request, user: str = Depends(require_login)):
    """Create a signed share link for read-only NetMon page.

    Body (json):
      - page: 'view' | 'wall' (default 'view')
      - mid: monitor id (required)
      - mode: 'follow' | 'fixed'
      - from/to/span/win/hidden: optional view state
      - rollup_ms: optional resolution hint (0/raw or bucket ms)
    """
    try:
        payload = await request.json()
    except Exception:
        payload = {}

    page = str(payload.get("page") or "view").strip().lower()
    if page not in ("view", "wall"):
        page = "view"

    try:
        mid = int(payload.get("mid") or payload.get("monitor_id") or 0)
    except Exception:
        mid = 0
    mon = None
    if mid <= 0:
        if page != "wall":
            return JSONResponse({"ok": False, "error": "mid 无效"}, status_code=400)
    else:
        # Verify monitor exists
        mon = get_netmon_monitor(mid)
        if not mon:
            return JSONResponse({"ok": False, "error": "monitor 不存在"}, status_code=404)

    mode = str(payload.get("mode") or "follow").strip().lower()
    if mode not in ("follow", "fixed"):
        mode = "follow"

    def _num(v):
        try:
            x = int(float(v))
            return x
        except Exception:
            return None

    s_from = _num(payload.get("from"))
    s_to = _num(payload.get("to"))
    span = _num(payload.get("span"))
    win = _num(payload.get("win"))

    # Keep hidden nodes within monitor scope
    hidden_in = payload.get("hidden") or []
    hidden: list[str] = []
    if isinstance(hidden_in, str):
        hidden_in = [x for x in hidden_in.split(",") if x.strip()]
    if isinstance(hidden_in, list):
        allow = set(str(int(x)) for x in ((mon.get("node_ids") or []) if mon else []) if str(x).isdigit())
        for x in hidden_in:
            s = str(x or "").strip()
            if not s:
                continue
            if s in allow and s not in hidden:
                hidden.append(s)
    hidden = hidden[:60]

    rollup_ms = _num(payload.get("rollup_ms"))
    if rollup_ms is not None and rollup_ms < 0:
        rollup_ms = 0

    token_payload: Dict[str, Any] = {
        "page": page,
        "mode": mode,
    }
    if mid > 0:
        token_payload["mid"] = int(mid)
    if win is not None:
        token_payload["win"] = int(max(1, min(24 * 60, win)))
    if mode == "fixed" and s_from is not None and s_to is not None and s_to > s_from:
        token_payload["from"] = int(s_from)
        token_payload["to"] = int(s_to)
    elif span is not None and span > 0:
        token_payload["span"] = int(span)

    if hidden:
        token_payload["hidden"] = hidden
    if rollup_ms is not None:
        token_payload["rollup_ms"] = int(rollup_ms)

    # Create token
    token = _make_share_token(token_payload)

    # Build URL (include view state in query for front-end convenience)
    base = _panel_public_base_url(request)
    path = "/netmon/view" if page == "view" else "/netmon/wall"
    q: Dict[str, Any] = {"ro": "1", "v": "1", "t": token}

    # Prefer minimal UI for shared links by default (can be disabled by kiosk=0)
    try:
        kiosk = payload.get("kiosk")
    except Exception:
        kiosk = None
    if kiosk is None:
        kiosk = 1
    try:
        kiosk_on = str(kiosk).strip().lower() in ("1", "true", "yes", "y", "on")
    except Exception:
        kiosk_on = True
    if kiosk_on:
        q["kiosk"] = "1"
    if mid > 0:
        q["mid"] = str(mid)
    if "win" in token_payload:
        q["win"] = str(token_payload["win"])
    if mode == "fixed" and "from" in token_payload and "to" in token_payload:
        q["mode"] = "fixed"
        q["from"] = str(token_payload["from"])
        q["to"] = str(token_payload["to"])
    elif "span" in token_payload:
        q["mode"] = "follow"
        q["span"] = str(token_payload["span"])
    if hidden:
        q["hidden"] = ",".join(hidden)
    if rollup_ms is not None:
        q["rollup_ms"] = str(int(rollup_ms))
    url = f"{base}{path}?{urlencode(q)}"

    return {"ok": True, "url": url, "token": token}



@app.get("/api/netmon/monitors")
async def api_netmon_monitors_list(user: str = Depends(require_login)):
    monitors = list_netmon_monitors()
    out: List[Dict[str, Any]] = []
    for m in monitors:
        try:
            mid = int(m.get("id") or 0)
        except Exception:
            continue
        if mid <= 0:
            continue
        out.append(
            {
                "id": mid,
                "target": str(m.get("target") or ""),
                "mode": str(m.get("mode") or "ping"),
                "tcp_port": int(m.get("tcp_port") or 443),
                "interval_sec": int(m.get("interval_sec") or 5),
                "warn_ms": int(m.get("warn_ms") or 0),
                "crit_ms": int(m.get("crit_ms") or 0),
                "enabled": bool(m.get("enabled") or 0),
                "node_ids": [int(x) for x in (m.get("node_ids") or []) if isinstance(x, int) or str(x).isdigit()],
                "last_run_ts_ms": int(m.get("last_run_ts_ms") or 0),
                "last_run_msg": str(m.get("last_run_msg") or ""),
            }
        )
    return {"ok": True, "monitors": out}


@app.post("/api/netmon/monitors")
async def api_netmon_monitors_create(request: Request, user: str = Depends(require_login)):
    try:
        payload = await request.json()
    except Exception:
        payload = {}

    target = str(payload.get("target") or "").strip()
    mode = str(payload.get("mode") or "ping").strip().lower()
    tcp_port = payload.get("tcp_port", 443)
    interval_sec = payload.get("interval_sec", payload.get("interval", 5))
    warn_ms = payload.get("warn_ms", payload.get("warn", 0))
    crit_ms = payload.get("crit_ms", payload.get("crit", 0))
    node_ids = payload.get("node_ids") or payload.get("nodes") or []
    enabled = bool(payload.get("enabled", True))

    if not target:
        return JSONResponse({"ok": False, "error": "target 不能为空"}, status_code=400)
    if len(target) > 128:
        return JSONResponse({"ok": False, "error": "target 太长"}, status_code=400)
    if mode not in ("ping", "tcping"):
        mode = "ping"

    try:
        tcp_port_i = int(tcp_port)
    except Exception:
        tcp_port_i = 443
    if tcp_port_i < 1 or tcp_port_i > 65535:
        tcp_port_i = 443

    try:
        interval_i = int(interval_sec)
    except Exception:
        interval_i = 5
    if interval_i < 1:
        interval_i = 1
    if interval_i > 3600:
        interval_i = 3600


    try:
        warn_i = int(warn_ms)
    except Exception:
        warn_i = 0
    if warn_i < 0:
        warn_i = 0
    if warn_i > 600000:
        warn_i = 600000

    try:
        crit_i = int(crit_ms)
    except Exception:
        crit_i = 0
    if crit_i < 0:
        crit_i = 0
    if crit_i > 600000:
        crit_i = 600000

    if warn_i > 0 and crit_i > 0 and warn_i > crit_i:
        warn_i, crit_i = crit_i, warn_i

    if not isinstance(node_ids, list):
        node_ids = []

    cleaned: List[int] = []
    for x in node_ids:
        try:
            nid = int(x)
        except Exception:
            continue
        if nid > 0 and nid not in cleaned:
            cleaned.append(nid)
    cleaned = cleaned[:60]
    if not cleaned:
        return JSONResponse({"ok": False, "error": "请选择至少一个节点"}, status_code=400)

    mid = add_netmon_monitor(target, mode, tcp_port_i, interval_i, cleaned, warn_ms=warn_i, crit_ms=crit_i, enabled=enabled)
    mon = get_netmon_monitor(mid) or {}
    return {
        "ok": True,
        "monitor": {
            "id": mid,
            "target": str(mon.get("target") or target),
            "mode": str(mon.get("mode") or mode),
            "tcp_port": int(mon.get("tcp_port") or tcp_port_i),
            "interval_sec": int(mon.get("interval_sec") or interval_i),
            "warn_ms": int(mon.get("warn_ms") or warn_i),
            "crit_ms": int(mon.get("crit_ms") or crit_i),
            "enabled": bool(mon.get("enabled") or enabled),
            "node_ids": [int(x) for x in (mon.get("node_ids") or cleaned) if int(x) > 0],
        },
    }


@app.post("/api/netmon/monitors/{monitor_id}")
async def api_netmon_monitors_update(monitor_id: int, request: Request, user: str = Depends(require_login)):
    mon = get_netmon_monitor(int(monitor_id))
    if not mon:
        return JSONResponse({"ok": False, "error": "monitor 不存在"}, status_code=404)

    try:
        payload = await request.json()
    except Exception:
        payload = {}

    fields: Dict[str, Any] = {}
    if "target" in payload:
        target = str(payload.get("target") or "").strip()
        if not target:
            return JSONResponse({"ok": False, "error": "target 不能为空"}, status_code=400)
        if len(target) > 128:
            return JSONResponse({"ok": False, "error": "target 太长"}, status_code=400)
        fields["target"] = target

    if "mode" in payload:
        mode = str(payload.get("mode") or "ping").strip().lower()
        if mode not in ("ping", "tcping"):
            mode = "ping"
        fields["mode"] = mode

    if "tcp_port" in payload:
        try:
            tp = int(payload.get("tcp_port"))
        except Exception:
            tp = 443
        if tp < 1 or tp > 65535:
            tp = 443
        fields["tcp_port"] = tp

    if "interval_sec" in payload or "interval" in payload:
        raw = payload.get("interval_sec", payload.get("interval"))
        try:
            itv = int(raw)
        except Exception:
            itv = 5
        if itv < 1:
            itv = 1
        if itv > 3600:
            itv = 3600
        fields["interval_sec"] = itv

    if "warn_ms" in payload or "warn" in payload:
        raw = payload.get("warn_ms", payload.get("warn"))
        try:
            wm = int(raw)
        except Exception:
            wm = 0
        if wm < 0:
            wm = 0
        if wm > 600000:
            wm = 600000
        fields["warn_ms"] = wm

    if "crit_ms" in payload or "crit" in payload:
        raw = payload.get("crit_ms", payload.get("crit"))
        try:
            cm = int(raw)
        except Exception:
            cm = 0
        if cm < 0:
            cm = 0
        if cm > 600000:
            cm = 600000
        fields["crit_ms"] = cm

    # Ensure warn <= crit when both present and enabled
    if fields.get("warn_ms", 0) and fields.get("crit_ms", 0):
        try:
            wv = int(fields.get("warn_ms") or 0)
            cv = int(fields.get("crit_ms") or 0)
        except Exception:
            wv, cv = 0, 0
        if wv > 0 and cv > 0 and wv > cv:
            fields["warn_ms"], fields["crit_ms"] = cv, wv


    if "node_ids" in payload or "nodes" in payload:
        node_ids = payload.get("node_ids") or payload.get("nodes") or []
        if not isinstance(node_ids, list):
            node_ids = []
        cleaned: List[int] = []
        for x in node_ids:
            try:
                nid = int(x)
            except Exception:
                continue
            if nid > 0 and nid not in cleaned:
                cleaned.append(nid)
        cleaned = cleaned[:60]
        if not cleaned:
            return JSONResponse({"ok": False, "error": "请选择至少一个节点"}, status_code=400)
        fields["node_ids"] = cleaned

    if "enabled" in payload:
        fields["enabled"] = bool(payload.get("enabled"))

    update_netmon_monitor(int(monitor_id), **fields)

    mon2 = get_netmon_monitor(int(monitor_id)) or {}
    return {
        "ok": True,
        "monitor": {
            "id": int(monitor_id),
            "target": str(mon2.get("target") or ""),
            "mode": str(mon2.get("mode") or "ping"),
            "tcp_port": int(mon2.get("tcp_port") or 443),
            "interval_sec": int(mon2.get("interval_sec") or 5),
            "warn_ms": int(mon2.get("warn_ms") or 0),
            "crit_ms": int(mon2.get("crit_ms") or 0),
            "enabled": bool(mon2.get("enabled") or 0),
            "node_ids": [int(x) for x in (mon2.get("node_ids") or []) if int(x) > 0],
            "last_run_ts_ms": int(mon2.get("last_run_ts_ms") or 0),
            "last_run_msg": str(mon2.get("last_run_msg") or ""),
        },
    }


@app.post("/api/netmon/monitors/{monitor_id}/delete")
async def api_netmon_monitors_delete(monitor_id: int, user: str = Depends(require_login)):
    mon = get_netmon_monitor(int(monitor_id))
    if not mon:
        return JSONResponse({"ok": False, "error": "monitor 不存在"}, status_code=404)
    delete_netmon_monitor(int(monitor_id))
    return {"ok": True}

@app.post("/api/netmon/probe")
async def api_netmon_probe(request: Request, user: str = Depends(require_login)):
    """Probe one or more targets from one or more nodes.

    Frontend will poll this endpoint periodically to build time-series charts.
    """
    try:
        payload = await request.json()
    except Exception:
        payload = {}

    node_ids = payload.get('node_ids') or payload.get('nodes') or []
    targets = payload.get('targets') or []
    mode = str(payload.get('mode') or 'ping').strip().lower()
    tcp_port = payload.get('tcp_port')
    timeout = payload.get('timeout')

    # sanitize
    if not isinstance(node_ids, list):
        node_ids = []
    if not isinstance(targets, list):
        targets = []

    cleaned_node_ids = []
    for x in node_ids:
        try:
            nid = int(x)
        except Exception:
            continue
        if nid > 0 and nid not in cleaned_node_ids:
            cleaned_node_ids.append(nid)
    node_ids = cleaned_node_ids[:30]

    cleaned_targets = []
    for t in targets:
        s = str(t or '').strip()
        if not s:
            continue
        if len(s) > 128:
            continue
        if s not in cleaned_targets:
            cleaned_targets.append(s)
    targets = cleaned_targets[:20]

    if mode not in ('ping', 'tcping'):
        mode = 'ping'

    try:
        tcp_port_i = int(tcp_port) if tcp_port is not None else 443
    except Exception:
        tcp_port_i = 443
    if tcp_port_i < 1 or tcp_port_i > 65535:
        tcp_port_i = 443

    try:
        timeout_f = float(timeout) if timeout is not None else 1.5
    except Exception:
        timeout_f = 1.5
    if timeout_f < 0.2:
        timeout_f = 0.2
    if timeout_f > 10:
        timeout_f = 10.0

    if not node_ids:
        return JSONResponse({"ok": False, "error": "请选择至少一个节点"}, status_code=400)
    if not targets:
        return JSONResponse({"ok": False, "error": "请填写至少一个目标"}, status_code=400)

    # load node records
    nodes = []
    for nid in node_ids:
        n = get_node(nid)
        if n:
            nodes.append(n)
    if not nodes:
        return JSONResponse({"ok": False, "error": "节点不存在"}, status_code=404)

    # call agents concurrently
    body = {
        "mode": mode,
        "targets": targets,
        "tcp_port": tcp_port_i,
        "timeout": timeout_f,
    }

    async def _call_one(n: Dict[str, Any]):
        nid = int(n.get('id') or 0)
        try:
            # keep the HTTP timeout small for UI polling
            http_timeout = max(2.5, timeout_f + 1.0)
            data = await agent_post(
                n.get('base_url', ''),
                n.get('api_key', ''),
                '/api/v1/netprobe',
                body,
                _node_verify_tls(n),
                timeout=http_timeout,
            )
            return nid, data
        except Exception as exc:
            return nid, {"ok": False, "error": str(exc)}

    tasks = [_call_one(n) for n in nodes]
    results = await asyncio.gather(*tasks)

    matrix: Dict[str, Dict[str, Any]] = {t: {} for t in targets}
    node_errors: Dict[str, str] = {}

    for nid, data in results:
        nid_s = str(nid)
        if not isinstance(data, dict) or data.get('ok') is not True:
            err = str((data or {}).get('error') or 'agent_failed')
            node_errors[nid_s] = err
            for t in targets:
                matrix[t][nid_s] = {"ok": False, "latency_ms": None, "error": err}
            continue

        res_map = data.get('results') if isinstance(data.get('results'), dict) else {}
        for t in targets:
            item = res_map.get(t)
            if not isinstance(item, dict):
                matrix[t][nid_s] = {"ok": False, "latency_ms": None, "error": "no_data"}
                continue
            out_item: Dict[str, Any] = {"ok": bool(item.get('ok'))}
            if item.get('latency_ms') is not None:
                out_item['latency_ms'] = item.get('latency_ms')
            else:
                out_item['latency_ms'] = None
            if item.get('error'):
                out_item['error'] = str(item.get('error'))
            matrix[t][nid_s] = out_item

    nodes_meta = []
    for n in nodes:
        nodes_meta.append({
            "id": int(n.get('id') or 0),
            "name": n.get('name') or _extract_ip_for_display(n.get('base_url', '')),
            "group_name": str(n.get('group_name') or '').strip() or '默认分组',
        })

    return {
        "ok": True,
        "ts": int(time.time() * 1000),
        "mode": mode,
        "tcp_port": tcp_port_i,
        "timeout": timeout_f,
        "targets": targets,
        "nodes": nodes_meta,
        "matrix": matrix,
        "errors": node_errors,
    }


@app.post("/api/groups/order")
async def api_groups_order(request: Request, user: str = Depends(require_login)):
    """Update group sort order (UI only)."""
    try:
        data = await request.json()
    except Exception:
        data = {}

    name = str(data.get("group_name") or "").strip() or "默认分组"
    raw = data.get("sort_order", data.get("order", 1000))
    try:
        order = int(raw)
    except Exception:
        return JSONResponse({"ok": False, "error": "排序序号必须是数字"}, status_code=400)

    # keep within a reasonable range to prevent weird UI
    if order < -999999:
        order = -999999
    if order > 999999:
        order = 999999

    upsert_group_order(name, order)
    return {"ok": True, "group_name": name, "sort_order": order}


def _random_wss_params() -> tuple[str, str, str]:
    """Generate a reasonable random WSS {host, path, sni}.

    Used when UI leaves Host/Path/SNI empty (auto-fill). Keep it conservative:
    - Host picked from common CDN/static domains
    - Path includes a short random token
    - SNI defaults to Host
    """

    hosts = [
        "cdn.jsdelivr.net",
        "assets.cloudflare.com",
        "edge.microsoft.com",
        "static.cloudflareinsights.com",
        "ajax.googleapis.com",
        "fonts.gstatic.com",
        "images.unsplash.com",
        "cdn.discordapp.com",
    ]
    path_templates = [
        "/ws",
        "/ws/{token}",
        "/socket",
        "/socket/{token}",
        "/connect",
        "/gateway",
        "/api/ws",
        "/v1/ws/{token}",
        "/edge/{token}",
    ]

    host = secrets.choice(hosts)
    token = secrets.token_hex(5)
    tpl = secrets.choice(path_templates)
    path = str(tpl or "/ws").replace("{token}", token)
    if path and not path.startswith("/"):
        path = "/" + path
    sni = host
    return host, path, sni


@app.post("/api/wss_tunnel/save")
async def api_wss_tunnel_save(payload: Dict[str, Any], user: str = Depends(require_login)):
    try:
        sender_id = int(payload.get("sender_node_id") or 0)
        receiver_id = int(payload.get("receiver_node_id") or 0)
    except Exception:
        sender_id = 0
        receiver_id = 0

    if sender_id <= 0 or receiver_id <= 0 or sender_id == receiver_id:
        return JSONResponse({"ok": False, "error": "sender_node_id / receiver_node_id 无效"}, status_code=400)

    sender = get_node(sender_id)
    receiver = get_node(receiver_id)
    if not sender or not receiver:
        return JSONResponse({"ok": False, "error": "节点不存在"}, status_code=404)

    listen = str(payload.get("listen") or "").strip()
    remotes = payload.get("remotes") or []
    if isinstance(remotes, str):
        remotes = [x.strip() for x in remotes.splitlines() if x.strip()]
    if not isinstance(remotes, list):
        remotes = []
    remotes = [str(x).strip() for x in remotes if str(x).strip()]
    disabled = bool(payload.get("disabled", False))
    balance = str(payload.get("balance") or "roundrobin").strip()
    protocol = str(payload.get("protocol") or "tcp+udp").strip() or "tcp+udp"

    wss = payload.get("wss") or {}
    if not isinstance(wss, dict):
        wss = {}
    wss_host = str(wss.get("host") or "").strip()
    wss_path = str(wss.get("path") or "").strip()
    wss_sni = str(wss.get("sni") or "").strip()
    wss_tls = bool(wss.get("tls", True))
    wss_insecure = bool(wss.get("insecure", False))

    # UI may leave WSS Host/Path/SNI empty. Auto-fill with random params so
    # users can quickly create a tunnel without understanding every field.
    if (not wss_host) or (not wss_path) or (not wss_sni):
        rh, rp, rs = _random_wss_params()
        if not wss_host:
            # if user only filled SNI, treat it as host
            wss_host = wss_sni or rh
        if not wss_path:
            wss_path = rp
        # Normalize
        if wss_path and not wss_path.startswith("/"):
            wss_path = "/" + wss_path
        if not wss_sni:
            wss_sni = wss_host or rs

    # Always normalize: path must start with '/'
    if wss_path and not wss_path.startswith("/"):
        wss_path = "/" + wss_path
    if not wss_sni:
        wss_sni = wss_host

    if not listen:
        return JSONResponse({"ok": False, "error": "listen 不能为空"}, status_code=400)
    if not remotes:
        return JSONResponse({"ok": False, "error": "目标地址不能为空"}, status_code=400)
    if not wss_host or not wss_path:
        return JSONResponse({"ok": False, "error": "WSS Host / Path 不能为空"}, status_code=400)

    sync_id = str(payload.get("sync_id") or "").strip() or uuid.uuid4().hex

    # If editing an existing synced rule and switching receiver node,
    # proactively remove the old receiver-side rule to avoid leaving stale rules behind.
    # (Bugfix: previously the old receiver kept the synced rule forever.)
    sender_pool = await _load_pool_for_node(sender)
    old_receiver_id: int = 0
    try:
        for ep in sender_pool.get("endpoints") or []:
            if not isinstance(ep, dict):
                continue
            ex0 = ep.get("extra_config") or {}
            if not isinstance(ex0, dict):
                continue
            if str(ex0.get("sync_id") or "") != str(sync_id):
                continue
            if str(ex0.get("sync_role") or "") != "sender":
                continue
            old_receiver_id = int(ex0.get("sync_peer_node_id") or 0)
            break
    except Exception:
        old_receiver_id = 0

    old_receiver: Optional[Dict[str, Any]] = None
    old_receiver_pool: Optional[Dict[str, Any]] = None
    if old_receiver_id > 0 and old_receiver_id != receiver_id:
        old_receiver = get_node(old_receiver_id)
        if old_receiver:
            try:
                old_receiver_pool = await _load_pool_for_node(old_receiver)
                _remove_endpoints_by_sync_id(old_receiver_pool, sync_id)
                set_desired_pool(old_receiver_id, old_receiver_pool)
            except Exception:
                old_receiver = None
                old_receiver_pool = None

    # Receiver port policy:
    #   - If receiver_port is explicitly provided (UI input / toggle), treat it as FIXED.
    #   - If this sync_id already exists on receiver, keep its existing port (stable across enable/disable).
    #   - Otherwise, default to sender listen port, and auto-pick a free one if conflicted.
    receiver_pool = await _load_pool_for_node(receiver)
    existing_receiver_port = _find_sync_listen_port(receiver_pool, sync_id, role="receiver")

    raw_receiver_port = payload.get("receiver_port")
    explicit_receiver_port = raw_receiver_port is not None and raw_receiver_port != ""
    receiver_port: Optional[int] = None
    if explicit_receiver_port:
        try:
            receiver_port = int(raw_receiver_port)
        except Exception:
            return JSONResponse({"ok": False, "error": "receiver_port 必须是数字"}, status_code=400)

    # preferred port = sender listen port
    _, sender_listen_port = _split_host_port(listen)
    if sender_listen_port is None:
        return JSONResponse({"ok": False, "error": "listen 格式不正确，请使用 0.0.0.0:端口"}, status_code=400)

    if receiver_port is None:
        receiver_port = existing_receiver_port
    if receiver_port is None:
        receiver_port = sender_listen_port

    if receiver_port <= 0 or receiver_port > 65535:
        return JSONResponse({"ok": False, "error": "receiver_port 端口范围必须是 1-65535"}, status_code=400)

    port_fixed = explicit_receiver_port or (existing_receiver_port is not None)
    if port_fixed:
        if _port_used_by_other_sync(receiver_pool, receiver_port, sync_id):
            return JSONResponse(
                {"ok": False, "error": f"接收机端口 {receiver_port} 已被其他规则占用，请换一个端口"},
                status_code=400,
            )
    else:
        receiver_port = _choose_receiver_port(receiver_pool, receiver_port, ignore_sync_id=sync_id)

    receiver_host = _node_host_for_realm(receiver)
    if not receiver_host:
        return JSONResponse({"ok": False, "error": "接收机 base_url 无法解析主机名，请检查节点地址"}, status_code=400)
    sender_to_receiver = _format_addr(receiver_host, receiver_port)

    now_iso = datetime.utcnow().isoformat() + "Z"

    sender_ep = {
        "listen": listen,
        "disabled": disabled,
        "balance": balance,
        "protocol": protocol,
        "remotes": [sender_to_receiver],
        "extra_config": {
            "remote_transport": "ws",
            "remote_ws_host": wss_host,
            "remote_ws_path": wss_path,
            "remote_tls_enabled": bool(wss_tls),
            "remote_tls_insecure": bool(wss_insecure),
            "remote_tls_sni": wss_sni,
            # sync meta
            "sync_id": sync_id,
            "sync_role": "sender",
            "sync_peer_node_id": receiver_id,
            "sync_peer_node_name": receiver.get("name"),
            "sync_receiver_port": receiver_port,
            "sync_original_remotes": remotes,
            "sync_updated_at": now_iso,
        },
    }

    receiver_ep = {
        "listen": _format_addr("0.0.0.0", receiver_port),
        "disabled": disabled,
        "balance": balance,
        "protocol": protocol,
        "remotes": remotes,
        "extra_config": {
            "listen_transport": "ws",
            "listen_ws_host": wss_host,
            "listen_ws_path": wss_path,
            "listen_tls_enabled": bool(wss_tls),
            "listen_tls_insecure": bool(wss_insecure),
            "listen_tls_servername": wss_sni,
            # sync meta
            "sync_id": sync_id,
            "sync_role": "receiver",
            "sync_lock": True,
            "sync_from_node_id": sender_id,
            "sync_from_node_name": sender.get("name"),
            "sync_sender_listen": listen,
            "sync_original_remotes": remotes,
            "sync_updated_at": now_iso,
        },
    }

    # upsert by sync_id (preserve original ordering to avoid UI/stat mismatch)
    _upsert_endpoint_by_sync_id(sender_pool, sync_id, sender_ep)
    _upsert_endpoint_by_sync_id(receiver_pool, sync_id, receiver_ep)

    # persist desired pools on panel
    s_ver, _ = set_desired_pool(sender_id, sender_pool)
    r_ver, _ = set_desired_pool(receiver_id, receiver_pool)

    # best-effort immediate apply to both agents
    async def _apply(node: Dict[str, Any], pool: Dict[str, Any]):
        try:
            data = await agent_post(node["base_url"], node["api_key"], "/api/v1/pool", {"pool": pool}, _node_verify_tls(node))
            if isinstance(data, dict) and data.get("ok", True):
                await agent_post(node["base_url"], node["api_key"], "/api/v1/apply", {}, _node_verify_tls(node))
        except Exception:
            pass

    await _apply(sender, sender_pool)
    await _apply(receiver, receiver_pool)

    # Best-effort: apply cleanup on the old receiver node (if receiver changed)
    if old_receiver and isinstance(old_receiver_pool, dict):
        await _apply(old_receiver, old_receiver_pool)

    return {
        "ok": True,
        "sync_id": sync_id,
        "receiver_port": receiver_port,
        "sender_pool": sender_pool,
        "receiver_pool": receiver_pool,
        "sender_desired_version": s_ver,
        "receiver_desired_version": r_ver,
    }


@app.post("/api/wss_tunnel/delete")
async def api_wss_tunnel_delete(payload: Dict[str, Any], user: str = Depends(require_login)):
    sync_id = str(payload.get("sync_id") or "").strip()
    if not sync_id:
        return JSONResponse({"ok": False, "error": "sync_id 不能为空"}, status_code=400)

    try:
        sender_id = int(payload.get("sender_node_id") or 0)
        receiver_id = int(payload.get("receiver_node_id") or 0)
    except Exception:
        sender_id = 0
        receiver_id = 0

    if sender_id <= 0 or receiver_id <= 0 or sender_id == receiver_id:
        return JSONResponse({"ok": False, "error": "sender_node_id / receiver_node_id 无效"}, status_code=400)

    sender = get_node(sender_id)
    receiver = get_node(receiver_id)
    if not sender or not receiver:
        return JSONResponse({"ok": False, "error": "节点不存在"}, status_code=404)

    sender_pool = await _load_pool_for_node(sender)
    receiver_pool = await _load_pool_for_node(receiver)

    _remove_endpoints_by_sync_id(sender_pool, sync_id)
    _remove_endpoints_by_sync_id(receiver_pool, sync_id)

    s_ver, _ = set_desired_pool(sender_id, sender_pool)
    r_ver, _ = set_desired_pool(receiver_id, receiver_pool)

    async def _apply(node: Dict[str, Any], pool: Dict[str, Any]):
        try:
            data = await agent_post(node["base_url"], node["api_key"], "/api/v1/pool", {"pool": pool}, _node_verify_tls(node))
            if isinstance(data, dict) and data.get("ok", True):
                await agent_post(node["base_url"], node["api_key"], "/api/v1/apply", {}, _node_verify_tls(node))
        except Exception:
            pass

    await _apply(sender, sender_pool)
    await _apply(receiver, receiver_pool)

    return {
        "ok": True,
        "sync_id": sync_id,
        "sender_pool": sender_pool,
        "receiver_pool": receiver_pool,
        "sender_desired_version": s_ver,
        "receiver_desired_version": r_ver,
    }


@app.post("/api/intranet_tunnel/save")
async def api_intranet_tunnel_save(payload: Dict[str, Any], user: str = Depends(require_login)):
    try:
        sender_id = int(payload.get("sender_node_id") or 0)
        receiver_id = int(payload.get("receiver_node_id") or 0)
    except Exception:
        sender_id = 0
        receiver_id = 0

    if sender_id <= 0 or receiver_id <= 0 or sender_id == receiver_id:
        return JSONResponse({"ok": False, "error": "sender_node_id / receiver_node_id 无效"}, status_code=400)

    sender = get_node(sender_id)
    receiver = get_node(receiver_id)
    if not sender or not receiver:
        return JSONResponse({"ok": False, "error": "节点不存在"}, status_code=404)

    # receiver must be marked as LAN/private node
    if not bool(receiver.get("is_private") or False):
        return JSONResponse({"ok": False, "error": "所选节点未标记为内网机器，请在节点设置中勾选“内网机器”"}, status_code=400)

    listen = str(payload.get("listen") or "").strip()
    remotes = payload.get("remotes") or []
    if isinstance(remotes, str):
        remotes = [x.strip() for x in remotes.splitlines() if x.strip()]
    if not isinstance(remotes, list):
        remotes = []
    remotes = [str(x).strip() for x in remotes if str(x).strip()]
    disabled = bool(payload.get("disabled", False))
    balance = str(payload.get("balance") or "roundrobin").strip() or "roundrobin"
    protocol = str(payload.get("protocol") or "tcp+udp").strip() or "tcp+udp"

    try:
        server_port = int(payload.get("server_port") or 18443)
    except Exception:
        server_port = 18443
    if server_port <= 0 or server_port > 65535:
        return JSONResponse({"ok": False, "error": "隧道端口无效"}, status_code=400)

    if not listen:
        return JSONResponse({"ok": False, "error": "listen 不能为空"}, status_code=400)
    if not remotes:
        return JSONResponse({"ok": False, "error": "目标地址不能为空"}, status_code=400)

    sync_id = str(payload.get("sync_id") or "").strip() or uuid.uuid4().hex
    token = str(payload.get("token") or "").strip() or uuid.uuid4().hex

    # If editing an existing intranet tunnel and switching the peer node,
    # proactively remove the old peer-side rule to avoid leaving stale synced rules behind.
    sender_pool = await _load_pool_for_node(sender)
    old_receiver_id: int = 0
    try:
        for ep in sender_pool.get("endpoints") or []:
            if not isinstance(ep, dict):
                continue
            ex0 = ep.get("extra_config") or {}
            if not isinstance(ex0, dict):
                continue
            if str(ex0.get("sync_id") or "") != str(sync_id):
                continue
            if str(ex0.get("intranet_role") or "") != "server":
                continue
            old_receiver_id = int(ex0.get("intranet_peer_node_id") or 0)
            break
    except Exception:
        old_receiver_id = 0

    old_receiver: Optional[Dict[str, Any]] = None
    old_receiver_pool: Optional[Dict[str, Any]] = None
    if old_receiver_id > 0 and old_receiver_id != receiver_id:
        old_receiver = get_node(old_receiver_id)
        if old_receiver:
            try:
                old_receiver_pool = await _load_pool_for_node(old_receiver)
                _remove_endpoints_by_sync_id(old_receiver_pool, sync_id)
                set_desired_pool(old_receiver_id, old_receiver_pool)
            except Exception:
                old_receiver = None
                old_receiver_pool = None

    # A-side public host that B can reach. Default: sender base_url hostname. Allow override from UI.
    def _norm_host(h: str) -> str:
        h = (h or '').strip()
        if not h:
            return ''
        # allow user to paste URL or host:port
        try:
            if '://' in h:
                return urlparse(h).hostname or ''
        except Exception:
            pass
        # strip port if provided
        if h.startswith('[') and ']' in h:
            return h.split(']')[0][1:]
        if ':' in h:
            return h.rsplit(':', 1)[0]
        return h

    override_host = _norm_host(str(payload.get('server_host') or ''))
    sender_host = override_host or _node_host_for_realm(sender)
    if not sender_host:
        return JSONResponse({"ok": False, "error": "公网入口地址为空。请检查节点 base_url 或在内网穿透中填写“公网入口地址(A)”。"}, status_code=400)

    # Best-effort: fetch A-side tunnel server cert and embed into B config for TLS verification.
    server_cert_pem = ""
    try:
        cert = await agent_get(sender.get("base_url", ""), sender.get("api_key", ""), "/api/v1/intranet/cert", _node_verify_tls(sender))
        if isinstance(cert, dict) and cert.get("ok") is True:
            server_cert_pem = str(cert.get("cert_pem") or "").strip()
    except Exception:
        server_cert_pem = ""

    now_iso = datetime.utcnow().isoformat() + "Z"

    sender_ep = {
        "listen": listen,
        "disabled": disabled,
        "balance": balance,
        "protocol": protocol,
        "remotes": remotes,
        "extra_config": {
            "intranet_role": "server",
            "intranet_peer_node_id": receiver_id,
            "intranet_peer_node_name": receiver.get("name"),
            "intranet_public_host": sender_host,
            "intranet_server_port": server_port,
            "intranet_token": token,
            "intranet_original_remotes": remotes,
            "sync_id": sync_id,
            "intranet_updated_at": now_iso,
        },
    }

    receiver_ep = {
        # placeholder listen; actual reverse tunnel is initiated outbound by receiver
        "listen": _format_addr("0.0.0.0", 0),
        "disabled": disabled,
        "balance": balance,
        "protocol": protocol,
        "remotes": remotes,
        "extra_config": {
            "intranet_role": "client",
            "intranet_lock": True,
            "intranet_peer_node_id": sender_id,
            "intranet_peer_node_name": sender.get("name"),
            "intranet_peer_host": sender_host,
            "intranet_server_port": server_port,
            "intranet_token": token,
            "intranet_server_cert_pem": server_cert_pem,
            "intranet_tls_verify": bool(server_cert_pem),
            "intranet_sender_listen": listen,
            "intranet_original_remotes": remotes,
            "sync_id": sync_id,
            "intranet_updated_at": now_iso,
        },
    }

    receiver_pool = await _load_pool_for_node(receiver)

    # upsert by sync_id (preserve original ordering to avoid UI/stat mismatch)
    _upsert_endpoint_by_sync_id(sender_pool, sync_id, sender_ep)
    _upsert_endpoint_by_sync_id(receiver_pool, sync_id, receiver_ep)

    s_ver, _ = set_desired_pool(sender_id, sender_pool)
    r_ver, _ = set_desired_pool(receiver_id, receiver_pool)

    async def _apply(node: Dict[str, Any], pool: Dict[str, Any]):
        try:
            data = await agent_post(node["base_url"], node["api_key"], "/api/v1/pool", {"pool": pool}, _node_verify_tls(node))
            if isinstance(data, dict) and data.get("ok", True):
                await agent_post(node["base_url"], node["api_key"], "/api/v1/apply", {}, _node_verify_tls(node))
        except Exception:
            pass

    await _apply(sender, sender_pool)
    await _apply(receiver, receiver_pool)

    # Best-effort: apply cleanup on the old peer node (if peer changed)
    if old_receiver and isinstance(old_receiver_pool, dict):
        await _apply(old_receiver, old_receiver_pool)

    return {
        "ok": True,
        "sync_id": sync_id,
        "sender_pool": sender_pool,
        "receiver_pool": receiver_pool,
        "sender_desired_version": s_ver,
        "receiver_desired_version": r_ver,
    }


@app.post("/api/intranet_tunnel/delete")
async def api_intranet_tunnel_delete(payload: Dict[str, Any], user: str = Depends(require_login)):
    sync_id = str(payload.get("sync_id") or "").strip()
    if not sync_id:
        return JSONResponse({"ok": False, "error": "sync_id 不能为空"}, status_code=400)

    try:
        sender_id = int(payload.get("sender_node_id") or 0)
        receiver_id = int(payload.get("receiver_node_id") or 0)
    except Exception:
        sender_id = 0
        receiver_id = 0

    if sender_id <= 0 or receiver_id <= 0 or sender_id == receiver_id:
        return JSONResponse({"ok": False, "error": "sender_node_id / receiver_node_id 无效"}, status_code=400)

    sender = get_node(sender_id)
    receiver = get_node(receiver_id)
    if not sender or not receiver:
        return JSONResponse({"ok": False, "error": "节点不存在"}, status_code=404)

    sender_pool = await _load_pool_for_node(sender)
    receiver_pool = await _load_pool_for_node(receiver)

    _remove_endpoints_by_sync_id(sender_pool, sync_id)
    _remove_endpoints_by_sync_id(receiver_pool, sync_id)

    s_ver, _ = set_desired_pool(sender_id, sender_pool)
    r_ver, _ = set_desired_pool(receiver_id, receiver_pool)

    async def _apply(node: Dict[str, Any], pool: Dict[str, Any]):
        try:
            data = await agent_post(node["base_url"], node["api_key"], "/api/v1/pool", {"pool": pool}, _node_verify_tls(node))
            if isinstance(data, dict) and data.get("ok", True):
                await agent_post(node["base_url"], node["api_key"], "/api/v1/apply", {}, _node_verify_tls(node))
        except Exception:
            pass

    await _apply(sender, sender_pool)
    await _apply(receiver, receiver_pool)

    return {
        "ok": True,
        "sync_id": sync_id,
        "sender_pool": sender_pool,
        "receiver_pool": receiver_pool,
        "sender_desired_version": s_ver,
        "receiver_desired_version": r_ver,
    }



@app.post("/api/nodes/{node_id}/apply")
async def api_apply(request: Request, node_id: int, user: str = Depends(require_login)):
    node = get_node(node_id)
    if not node:
        return JSONResponse({"ok": False, "error": "节点不存在"}, status_code=404)
    try:
        data = await agent_post(
            node["base_url"],
            node["api_key"],
            "/api/v1/apply",
            {},
            _node_verify_tls(node),
        )
        if not data.get("ok", True):
            return JSONResponse({"ok": False, "error": data.get("error", "Agent 应用配置失败")}, status_code=502)
        return data
    except Exception:
        # Push-report fallback: bump desired version to trigger a re-sync/apply on agent
        desired_ver, desired_pool = get_desired_pool(node_id)
        if isinstance(desired_pool, dict):
            new_ver, _ = set_desired_pool(node_id, desired_pool)
            return {"ok": True, "queued": True, "desired_version": new_ver}
        return {"ok": False, "error": "Agent 无法访问，且面板无缓存规则（请检查网络或等待 Agent 上报）"}


@app.get("/api/nodes/{node_id}/stats")
async def api_stats(request: Request, node_id: int, user: str = Depends(require_login)):
    node = get_node(node_id)
    if not node:
        return JSONResponse({"ok": False, "error": "节点不存在"}, status_code=404)

    # Push-report cache
    if _is_report_fresh(node):
        rep = get_last_report(node_id)
        if isinstance(rep, dict) and isinstance(rep.get("stats"), dict):
            out = rep["stats"]
            out["source"] = "report"
            return out
    try:
        data = await agent_get(node["base_url"], node["api_key"], "/api/v1/stats", _node_verify_tls(node))
        return data
    except Exception as exc:
        # 注意：这里不要返回 502。
        # 1) 浏览器端 fetch 会把非 2xx 视为失败，导致只能显示“HTTP 502”这类笼统信息；
        # 2) 部分反代会把 502 的 body 替换为空/HTML，进一步丢失真实原因。
        # 因此用 200 + ok=false 的方式，把失败原因稳定传给前端。
        return {"ok": False, "error": str(exc), "rules": []}




@app.get("/api/nodes/{node_id}/sys")
async def api_sys(request: Request, node_id: int, cached: int = 0, user: str = Depends(require_login)):
    """节点系统信息：CPU/内存/硬盘/交换/在线时长/流量/实时速率。

    返回格式统一为：{ ok: true, sys: {...} }
    前端会据此渲染节点详情页的系统信息卡片。
    """
    node = get_node(node_id)
    if not node:
        return JSONResponse({"ok": False, "error": "节点不存在"}, status_code=404)

    sys_data = None
    source = None

    # 1) Push-report cache（更快、更稳定）
    # cached=1：即便不是“新鲜上报”，也优先返回最后一次上报的数据，避免前端长时间等待。
    if cached:
        rep = get_last_report(node_id)
        if isinstance(rep, dict) and isinstance(rep.get("sys"), dict):
            sys_data = dict(rep["sys"])  # copy
            sys_data["stale"] = not _is_report_fresh(node)
            source = "report"
    else:
        if _is_report_fresh(node):
            rep = get_last_report(node_id)
            if isinstance(rep, dict) and isinstance(rep.get("sys"), dict):
                sys_data = dict(rep["sys"])  # copy
                source = "report"

    # 2) Fallback：直连 Agent
    # 说明：控制台首页（Dashboard）会带 cached=1 来避免直连 Agent。
    # 因为在 Push 模式下，Panel 可能无法直接访问 Agent 的 base_url（私网/防火墙等）。
    # 若 cached=1 且 report 中没有 sys 数据，直接返回占位信息，避免前端“长时间加载中”。
    if sys_data is None:
        if cached:
            return {
                "ok": True,
                "sys": {
                    "ok": False,
                    "error": "Agent 尚未上报系统信息（请升级 Agent 或稍后重试）",
                    "source": "report",
                },
            }

        try:
            data = await agent_get(node["base_url"], node["api_key"], "/api/v1/sys", _node_verify_tls(node))
            if isinstance(data, dict) and data.get("ok") is True:
                sys_data = dict(data)  # copy
                source = "agent"
            else:
                return {"ok": False, "error": (data.get("error") if isinstance(data, dict) else "响应格式异常")}
        except Exception as exc:
            return {"ok": False, "error": str(exc)}

    sys_data["source"] = source or "unknown"
    return {"ok": True, "sys": sys_data}


@app.get("/api/nodes/{node_id}/graph")
async def api_graph(request: Request, node_id: int, user: str = Depends(require_login)):
    node = get_node(node_id)
    if not node:
        return JSONResponse({"ok": False, "error": "节点不存在"}, status_code=404)
    desired_ver, desired_pool = get_desired_pool(node_id)
    pool = desired_pool if isinstance(desired_pool, dict) else None

    if pool is None and _is_report_fresh(node):
        rep = get_last_report(node_id)
        if isinstance(rep, dict) and isinstance(rep.get("pool"), dict):
            pool = rep["pool"]

    if pool is None:
        try:
            data = await agent_get(node["base_url"], node["api_key"], "/api/v1/pool", _node_verify_tls(node))
            pool = data.get("pool") if isinstance(data, dict) else None
        except Exception as exc:
            return JSONResponse({"ok": False, "error": str(exc)}, status_code=502)
    endpoints = pool.get("endpoints", []) if isinstance(pool, dict) else []
    elements: list[dict[str, Any]] = []
    for idx, endpoint in enumerate(endpoints):
        listen = endpoint.get("listen", f"listen-{idx}")
        listen_id = f"listen-{idx}"
        classes = ["listen"]
        if endpoint.get("disabled"):
            classes.append("disabled")
        elements.append({"data": {"id": listen_id, "label": listen}, "classes": " ".join(classes)})
        remotes = endpoint.get("remotes") or ([endpoint.get("remote")] if endpoint.get("remote") else [])
        for r_idx, remote in enumerate(remotes):
            remote_id = f"remote-{idx}-{r_idx}"
            elements.append(
                {
                    "data": {"id": remote_id, "label": remote},
                    "classes": "remote" + (" disabled" if endpoint.get("disabled") else ""),
                }
            )
            ex = endpoint.get("extra_config") or {}
            edge_label = "WSS" if ex.get("listen_transport") == "ws" or ex.get("remote_transport") == "ws" else ""
            elements.append(
                {
                    "data": {"source": listen_id, "target": remote_id, "label": edge_label},
                    "classes": "disabled" if endpoint.get("disabled") else "",
                }
            )
    return {"ok": True, "elements": elements}
