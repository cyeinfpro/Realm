from __future__ import annotations

import uuid
from typing import Any, Dict, Optional
from urllib.parse import urlparse

from ..clients.agent import agent_get
from ..db import get_desired_pool, get_last_report
from ..utils.normalize import format_addr, split_host_port
from .apply import node_verify_tls


def node_host_for_realm(node: Dict[str, Any]) -> str:
    """Extract hostname for generating realm config.

    - Accepts base_url with/without scheme.
    - Ensures IPv6 is bracketed.
    """
    base = (node.get("base_url") or "").strip()
    if not base:
        return ""
    raw = base
    if "://" not in base:
        base = "http://" + base
    try:
        u = urlparse(base)
        host = u.hostname or ""
    except Exception:
        host = ""
    if not host:
        # fallback: take the first path segment and strip port if any
        host = raw.split("/")[0].strip()
    if ":" in host and not (host.startswith("[") and host.endswith("]")):
        host = f"[{host}]"
    return host


async def load_pool_for_node(node: Dict[str, Any]) -> Dict[str, Any]:
    """Load a node pool snapshot.

    Priority:
      1) panel desired pool
      2) last report cache
      3) pull from agent
    """
    nid = int(node.get("id") or 0)
    _ver, desired = get_desired_pool(nid)
    if isinstance(desired, dict):
        pool = desired
    else:
        rep = get_last_report(nid)
        if isinstance(rep, dict) and isinstance(rep.get("pool"), dict):
            pool = rep.get("pool")
        else:
            try:
                data = await agent_get(node["base_url"], node["api_key"], "/api/v1/pool", node_verify_tls(node))
                pool = data.get("pool") if isinstance(data, dict) else None
            except Exception:
                pool = None

    if not isinstance(pool, dict):
        pool = {}
    if not isinstance(pool.get("endpoints"), list):
        pool["endpoints"] = []
    return pool


def remove_endpoints_by_sync_id(pool: Dict[str, Any], sync_id: str) -> None:
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


def upsert_endpoint_by_sync_id(pool: Dict[str, Any], sync_id: str, endpoint: Dict[str, Any]) -> None:
    """Upsert an endpoint by extra_config.sync_id while preserving original ordering."""
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


def find_sync_listen_port(pool: Dict[str, Any], sync_id: str, role: Optional[str] = None) -> Optional[int]:
    """Find listen port for an endpoint identified by extra_config.sync_id."""
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
        _h, p = split_host_port(str(ep.get("listen") or ""))
        if p:
            try:
                return int(p)
            except Exception:
                return None
    return None


def port_used_by_other_sync(receiver_pool: Dict[str, Any], port: int, sync_id: str) -> bool:
    """Return True if `port` is already used by another endpoint (different sync_id)."""
    if not isinstance(receiver_pool, dict):
        return False
    for ep in receiver_pool.get("endpoints") or []:
        if not isinstance(ep, dict):
            continue
        _h, p = split_host_port(str(ep.get("listen") or ""))
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


def choose_receiver_port(receiver_pool: Dict[str, Any], preferred: Optional[int], ignore_sync_id: Optional[str] = None) -> int:
    used = set()
    for ep in receiver_pool.get("endpoints") or []:
        if not isinstance(ep, dict):
            continue
        ex = ep.get("extra_config") or {}
        sid = ex.get("sync_id") if isinstance(ex, dict) else None
        if ignore_sync_id and sid and str(sid) == str(ignore_sync_id):
            # allow reusing the same port for the same sync tunnel
            continue
        _h, p = split_host_port(str(ep.get("listen") or ""))
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
