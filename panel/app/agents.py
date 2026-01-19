import asyncio
from typing import Any, Dict, Optional

import httpx

DEFAULT_TIMEOUT = 6.0


async def agent_get(base_url: str, api_key: str, path: str, verify_tls: bool) -> Dict[str, Any]:
    headers = {"X-API-Key": api_key}
    url = f"{base_url.rstrip('/')}{path}"
    async with httpx.AsyncClient(timeout=DEFAULT_TIMEOUT, verify=verify_tls) as client:
        r = await client.get(url, headers=headers)
        if r.status_code >= 400:
            raise RuntimeError(_format_agent_error(r))
        return _parse_agent_json(r)


async def agent_post(
    base_url: str,
    api_key: str,
    path: str,
    data: Any,
    verify_tls: bool,
) -> Dict[str, Any]:
    headers = {"X-API-Key": api_key}
    url = f"{base_url.rstrip('/')}{path}"
    async with httpx.AsyncClient(timeout=DEFAULT_TIMEOUT, verify=verify_tls) as client:
        r = await client.post(url, headers=headers, json=data)
        if r.status_code >= 400:
            raise RuntimeError(_format_agent_error(r))
        return _parse_agent_json(r)


async def agent_ping(base_url: str, api_key: str, verify_tls: bool) -> Dict[str, Any]:
    try:
        return await agent_get(base_url, api_key, "/api/v1/info", verify_tls)
    except Exception as e:
        return {"ok": False, "error": str(e)}


def _parse_agent_json(response: httpx.Response) -> Dict[str, Any]:
    try:
        data = response.json()
    except Exception:
        return {"ok": False, "error": response.text}
    if isinstance(data, dict):
        return data
    return {"ok": False, "error": data}


def _format_agent_error(response: httpx.Response) -> str:
    data = _parse_agent_json(response)
    error = data.get("error") if isinstance(data, dict) else None
    if not error:
        error = data.get("detail") if isinstance(data, dict) else None
    if not error:
        error = response.text.strip()
    if not error:
        error = f"HTTP {response.status_code}"
    return f"Agent请求失败({response.status_code}) {response.url}: {error}"
