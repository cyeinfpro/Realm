from __future__ import annotations

import asyncio
from typing import Any, Dict

from ..clients.agent import agent_post


def node_verify_tls(node: Dict[str, Any]) -> bool:
    return bool(node.get("verify_tls", 0))


async def bg_apply_pool(node: Dict[str, Any], pool: Dict[str, Any]) -> None:
    """Best-effort: push pool to agent and apply in background (do not block HTTP responses)."""
    try:
        data = await agent_post(
            node["base_url"],
            node["api_key"],
            "/api/v1/pool",
            {"pool": pool},
            node_verify_tls(node),
        )
        if isinstance(data, dict) and data.get("ok", True):
            await agent_post(node["base_url"], node["api_key"], "/api/v1/apply", {}, node_verify_tls(node))
    except Exception:
        return


def schedule_apply_pool(node: Dict[str, Any], pool: Dict[str, Any]) -> None:
    """Schedule best-effort agent apply without blocking the request.

    Compatibility:
      - If there is a running event loop: create_task
      - Otherwise: try run_coroutine_threadsafe on existing loop
    """
    try:
        loop = asyncio.get_running_loop()
        loop.create_task(bg_apply_pool(node, pool))
        return
    except RuntimeError:
        # no running loop in this thread
        pass
    except Exception:
        return

    try:
        loop = asyncio.get_event_loop()
        asyncio.run_coroutine_threadsafe(bg_apply_pool(node, pool), loop)
    except Exception:
        return
