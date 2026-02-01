from __future__ import annotations

from typing import Any, Dict

from ..clients.agent import agent_get
from ..db import get_desired_pool, get_last_report
from .apply import node_verify_tls


async def get_pool_for_backup(node: Dict[str, Any]) -> Dict[str, Any]:
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
        data = await agent_get(node.get("base_url", ""), node.get("api_key", ""), "/api/v1/pool", node_verify_tls(node))
        # keep consistent shape
        if isinstance(data, dict) and isinstance(data.get("pool"), dict):
            return {"ok": True, "pool": data.get("pool"), "source": "agent_pull"}
        return data if isinstance(data, dict) else {"ok": False, "error": "agent_return_invalid"}
    except Exception as exc:
        return {"ok": False, "error": str(exc), "source": "agent_pull"}
