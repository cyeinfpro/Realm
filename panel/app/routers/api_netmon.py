from __future__ import annotations

import asyncio
import time
from typing import Any, Dict, List, Optional
from urllib.parse import urlencode

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import JSONResponse

from ..clients.agent import agent_post
from ..core.deps import require_login
from ..core.share import is_share_public_enabled, make_share_token, require_login_or_share_api
from ..db import (
    add_netmon_monitor,
    delete_netmon_monitor,
    get_netmon_monitor,
    get_node,
    insert_netmon_samples,
    list_netmon_monitors,
    list_netmon_samples,
    list_netmon_samples_range,
    list_netmon_samples_rollup,
    list_nodes,
    update_netmon_monitor,
)
from ..services.apply import node_verify_tls
from ..services.assets import panel_public_base_url
from ..services.node_status import is_report_fresh
from ..utils.normalize import extract_ip_for_display, safe_int_list

router = APIRouter()


@router.get("/api/netmon/snapshot")
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
        # Default tiers:
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
            "name": n.get("name") or extract_ip_for_display(n.get("base_url", "")),
            "group_name": str(n.get("group_name") or "").strip() or "默认分组",
            "display_ip": extract_ip_for_display(n.get("base_url", "")),
            "online": is_report_fresh(n, max_age_sec=90),
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
                "node_ids": [
                    int(x)
                    for x in (m.get("node_ids") or [])
                    if isinstance(x, int) or str(x).isdigit()
                ],
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


@router.get("/api/netmon/range")
async def api_netmon_range(request: Request, user: str = Depends(require_login_or_share_api)):
    """Return raw samples for one monitor within a time range."""
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

        if from_ms < allow_from:
            from_ms = allow_from
        if to_ms > allow_to:
            to_ms = allow_to
        if to_ms <= from_ms:
            return JSONResponse({"ok": False, "error": "range 超出分享窗口"}, status_code=403)

    # Safety: cap maximum range (default 6h)
    max_span_ms = 6 * 3600 * 1000
    if (to_ms - from_ms) > max_span_ms:
        from_ms = to_ms - max_span_ms

    mon = get_netmon_monitor(mid)
    if not mon:
        return JSONResponse({"ok": False, "error": "monitor 不存在"}, status_code=404)

    nodes = list_nodes()
    nodes_meta: Dict[str, Any] = {}
    for n in nodes:
        nid = int(n.get("id") or 0)
        if nid <= 0:
            continue
        nodes_meta[str(nid)] = {
            "id": nid,
            "name": n.get("name") or extract_ip_for_display(n.get("base_url", "")),
            "group_name": str(n.get("group_name") or "").strip() or "默认分组",
            "display_ip": extract_ip_for_display(n.get("base_url", "")),
            "online": is_report_fresh(n, max_age_sec=90),
        }

    rows = list_netmon_samples_range(mid, from_ms, to_ms, limit=80000)
    series: Dict[str, List[Dict[str, Any]]] = {}

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
            "node_ids": [
                int(x)
                for x in (mon.get("node_ids") or [])
                if isinstance(x, int) or str(x).isdigit()
            ],
        },
        "from": int(from_ms),
        "to": int(to_ms),
        "nodes": nodes_meta,
        "series": series,
    }


@router.post("/api/netmon/share")
async def api_netmon_share(request: Request, user: str = Depends(require_login)):
    if not is_share_public_enabled():
        raise HTTPException(status_code=403, detail="Sharing disabled")

    """Create a signed share link for read-only NetMon page."""
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
    hidden: List[str] = []
    if isinstance(hidden_in, str):
        hidden_in = [x for x in hidden_in.split(",") if x.strip()]
    if isinstance(hidden_in, list):
        allow = set(
            str(int(x))
            for x in ((mon.get("node_ids") or []) if mon else [])
            if str(x).isdigit()
        )
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

    token_payload: Dict[str, Any] = {"page": page, "mode": mode}
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

    token = make_share_token(token_payload)

    base = panel_public_base_url(request)
    path = "/netmon/view" if page == "view" else "/netmon/wall"
    q: Dict[str, Any] = {"ro": "1", "v": "1", "t": token}

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


@router.get("/api/netmon/monitors")
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
                "node_ids": [
                    int(x)
                    for x in (m.get("node_ids") or [])
                    if isinstance(x, int) or str(x).isdigit()
                ],
                "last_run_ts_ms": int(m.get("last_run_ts_ms") or 0),
                "last_run_msg": str(m.get("last_run_msg") or ""),
            }
        )
    return {"ok": True, "monitors": out}


@router.post("/api/netmon/monitors")
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

    mid = add_netmon_monitor(
        target,
        mode,
        tcp_port_i,
        interval_i,
        cleaned,
        warn_ms=warn_i,
        crit_ms=crit_i,
        enabled=enabled,
    )
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


@router.post("/api/netmon/monitors/{monitor_id}")
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
            "node_ids": [nid for nid in safe_int_list(mon2.get("node_ids") or []) if nid > 0],
            "last_run_ts_ms": int(mon2.get("last_run_ts_ms") or 0),
            "last_run_msg": str(mon2.get("last_run_msg") or ""),
        },
    }


@router.post("/api/netmon/monitors/{monitor_id}/delete")
async def api_netmon_monitors_delete(monitor_id: int, user: str = Depends(require_login)):
    mon = get_netmon_monitor(int(monitor_id))
    if not mon:
        return JSONResponse({"ok": False, "error": "monitor 不存在"}, status_code=404)
    delete_netmon_monitor(int(monitor_id))
    return {"ok": True}


@router.post("/api/netmon/probe")
async def api_netmon_probe(request: Request, user: str = Depends(require_login)):
    """Probe one or more targets from one or more nodes."""
    try:
        payload = await request.json()
    except Exception:
        payload = {}

    node_ids = payload.get("node_ids") or payload.get("nodes") or []
    targets = payload.get("targets") or []
    mode = str(payload.get("mode") or "ping").strip().lower()
    tcp_port = payload.get("tcp_port")
    timeout = payload.get("timeout")

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
        s = str(t or "").strip()
        if not s:
            continue
        if len(s) > 128:
            continue
        if s not in cleaned_targets:
            cleaned_targets.append(s)
    targets = cleaned_targets[:20]

    if mode not in ("ping", "tcping"):
        mode = "ping"

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

    nodes = []
    for nid in node_ids:
        n = get_node(nid)
        if n:
            nodes.append(n)
    if not nodes:
        return JSONResponse({"ok": False, "error": "节点不存在"}, status_code=404)

    body = {"mode": mode, "targets": targets, "tcp_port": tcp_port_i, "timeout": timeout_f}

    async def _call_one(n: Dict[str, Any]):
        nid = int(n.get("id") or 0)
        try:
            http_timeout = max(2.5, timeout_f + 1.0)
            data = await agent_post(
                n.get("base_url", ""),
                n.get("api_key", ""),
                "/api/v1/netprobe",
                body,
                node_verify_tls(n),
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
        if not isinstance(data, dict) or data.get("ok") is not True:
            err = str((data or {}).get("error") or "agent_failed")
            node_errors[nid_s] = err
            for t in targets:
                matrix[t][nid_s] = {"ok": False, "latency_ms": None, "error": err}
            continue

        res_map = data.get("results") if isinstance(data.get("results"), dict) else {}
        for t in targets:
            item = res_map.get(t)
            if not isinstance(item, dict):
                matrix[t][nid_s] = {"ok": False, "latency_ms": None, "error": "no_data"}
                continue
            out_item: Dict[str, Any] = {"ok": bool(item.get("ok"))}
            if item.get("latency_ms") is not None:
                out_item["latency_ms"] = item.get("latency_ms")
            else:
                out_item["latency_ms"] = None
            if item.get("error"):
                out_item["error"] = str(item.get("error"))
            matrix[t][nid_s] = out_item

    nodes_meta = []
    for n in nodes:
        nodes_meta.append(
            {
                "id": int(n.get("id") or 0),
                "name": n.get("name") or extract_ip_for_display(n.get("base_url", "")),
                "group_name": str(n.get("group_name") or "").strip() or "默认分组",
            }
        )

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
