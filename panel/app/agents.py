import asyncio
from typing import Any, Dict, Optional

import httpx

DEFAULT_TIMEOUT = 6.0


async def agent_get(base_url: str, api_key: str, path: str) -> Dict[str, Any]:
    headers = {"X-API-Key": api_key}
    url = f"{base_url.rstrip('/')}{path}"
    async with httpx.AsyncClient(timeout=DEFAULT_TIMEOUT) as client:
        r = await client.get(url, headers=headers)
        r.raise_for_status()
        return r.json()


async def agent_post(base_url: str, api_key: str, path: str, data: Any) -> Dict[str, Any]:
    headers = {"X-API-Key": api_key}
    url = f"{base_url.rstrip('/')}{path}"
    async with httpx.AsyncClient(timeout=DEFAULT_TIMEOUT) as client:
        r = await client.post(url, headers=headers, json=data)
        r.raise_for_status()
        return r.json()


async def agent_ping(base_url: str, api_key: str) -> Dict[str, Any]:
    try:
        return await agent_get(base_url, api_key, "/api/v1/info")
    except Exception as e:
        return {"ok": False, "error": str(e)}
