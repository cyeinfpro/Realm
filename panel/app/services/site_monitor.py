from __future__ import annotations

import asyncio
import os
import time
from typing import Any, Dict, List

from fastapi import FastAPI

from ..clients.agent import agent_post
from ..db import (
    add_site_check,
    add_site_event,
    list_nodes,
    list_sites,
    prune_site_checks,
    update_site_health,
)
from .apply import node_verify_tls

_SITE_MONITOR_ENABLED = (os.getenv("REALM_SITE_MONITOR_ENABLED") or "1").strip() not in ("0", "false", "False")
try:
    _SITE_MONITOR_INTERVAL = int((os.getenv("REALM_SITE_MONITOR_INTERVAL") or "60").strip() or 60)
except Exception:
    _SITE_MONITOR_INTERVAL = 60
if _SITE_MONITOR_INTERVAL < 15:
    _SITE_MONITOR_INTERVAL = 15
if _SITE_MONITOR_INTERVAL > 600:
    _SITE_MONITOR_INTERVAL = 600

try:
    _SITE_MONITOR_TIMEOUT = float((os.getenv("REALM_SITE_MONITOR_TIMEOUT") or "8").strip() or 8)
except Exception:
    _SITE_MONITOR_TIMEOUT = 8
if _SITE_MONITOR_TIMEOUT < 2:
    _SITE_MONITOR_TIMEOUT = 2
if _SITE_MONITOR_TIMEOUT > 20:
    _SITE_MONITOR_TIMEOUT = 20

try:
    _SITE_MONITOR_CONCURRENCY = int((os.getenv("REALM_SITE_MONITOR_CONCURRENCY") or "12").strip() or 12)
except Exception:
    _SITE_MONITOR_CONCURRENCY = 12
if _SITE_MONITOR_CONCURRENCY < 2:
    _SITE_MONITOR_CONCURRENCY = 2
if _SITE_MONITOR_CONCURRENCY > 80:
    _SITE_MONITOR_CONCURRENCY = 80

try:
    _SITE_MONITOR_RETENTION_DAYS = int((os.getenv("REALM_SITE_MONITOR_RETENTION_DAYS") or "7").strip() or 7)
except Exception:
    _SITE_MONITOR_RETENTION_DAYS = 7
if _SITE_MONITOR_RETENTION_DAYS < 1:
    _SITE_MONITOR_RETENTION_DAYS = 1
if _SITE_MONITOR_RETENTION_DAYS > 90:
    _SITE_MONITOR_RETENTION_DAYS = 90

_SEM = asyncio.Semaphore(_SITE_MONITOR_CONCURRENCY)
_LAST_RUN: Dict[int, float] = {}


def enabled() -> bool:
    return bool(_SITE_MONITOR_ENABLED)


async def _check_site(site: Dict[str, Any], node: Dict[str, Any]) -> None:
    async with _SEM:
        payload = {
            "domains": site.get("domains") or [],
            "type": site.get("type") or "static",
            "root_path": site.get("root_path") or "",
            "proxy_target": site.get("proxy_target") or "",
            "root_base": node.get("website_root_base") or "",
        }
        ok = False
        status_code = 0
        latency_ms = 0
        error = ""
        try:
            data = await agent_post(
                node.get("base_url", ""),
                node.get("api_key", ""),
                "/api/v1/website/health",
                payload,
                node_verify_tls(node),
                timeout=_SITE_MONITOR_TIMEOUT,
            )
            ok = bool(data.get("ok"))
            status_code = int(data.get("status_code") or 0)
            latency_ms = int(data.get("latency_ms") or 0)
            error = str(data.get("error") or "").strip()
        except Exception as exc:
            ok = False
            status_code = 0
            latency_ms = 0
            error = str(exc)

        new_status = "ok" if ok else "fail"
        update_site_health(
            int(site.get("id") or 0),
            new_status,
            health_code=status_code,
            health_latency_ms=latency_ms,
            health_error=error,
        )
        add_site_check(int(site.get("id") or 0), ok, status_code=status_code, latency_ms=latency_ms, error=error)

        # status change alerts
        prev = str(site.get("health_status") or "").strip()
        if prev and prev != new_status:
            if new_status == "fail":
                add_site_event(int(site.get("id") or 0), "health_alert", status="failed", error=error)
            elif new_status == "ok":
                add_site_event(int(site.get("id") or 0), "health_recovered", status="success")


async def _site_monitor_loop() -> None:
    while True:
        if not enabled():
            await asyncio.sleep(10)
            continue
        try:
            sites = list_sites()
            nodes = list_nodes()
            nodes_map = {int(n.get("id") or 0): n for n in nodes}
            now = time.time()
            due: List[Dict[str, Any]] = []
            for s in sites:
                sid = int(s.get("id") or 0)
                last = _LAST_RUN.get(sid, 0.0)
                if (now - last) < _SITE_MONITOR_INTERVAL:
                    continue
                node = nodes_map.get(int(s.get("node_id") or 0))
                if not node:
                    continue
                due.append(s)
                _LAST_RUN[sid] = now

            if due:
                tasks = []
                for s in due:
                    node = nodes_map.get(int(s.get("node_id") or 0))
                    if not node:
                        continue
                    tasks.append(_check_site(s, node))
                if tasks:
                    await asyncio.gather(*tasks)

            # prune old checks occasionally
            try:
                prune_site_checks(_SITE_MONITOR_RETENTION_DAYS)
            except Exception:
                pass
        except Exception:
            pass
        await asyncio.sleep(5)


async def start_background(app: FastAPI) -> None:
    if getattr(app.state, "site_monitor_started", False):
        return
    app.state.site_monitor_started = True
    if enabled():
        asyncio.create_task(_site_monitor_loop())
