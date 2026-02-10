from __future__ import annotations

import asyncio
import json
import re
import shutil
import threading
import time
from typing import Any, Dict, Optional, Tuple
from urllib.parse import urlparse

import httpx

from ..core.settings import DEFAULT_AGENT_PORT

DEFAULT_TIMEOUT = 6.0
TCPING_TIMEOUT = 3.0
_HTTP_LIMITS = httpx.Limits(max_connections=200, max_keepalive_connections=80, keepalive_expiry=20.0)
_CLIENTS: Dict[bool, httpx.AsyncClient] = {}
_CLIENTS_LOCK = threading.Lock()
_TRANSPORT_RETRY_COUNT = 3
_TRANSPORT_RETRY_BACKOFF_BASE_SEC = 0.35


class AgentError(RuntimeError):
    """Raised when panel <-> agent request failed."""


async def _get_client(verify_tls: bool) -> httpx.AsyncClient:
    key = bool(verify_tls)
    cli = _CLIENTS.get(key)
    if cli is not None and not cli.is_closed:
        return cli
    with _CLIENTS_LOCK:
        cli = _CLIENTS.get(key)
        if cli is not None and not cli.is_closed:
            return cli
        cli = httpx.AsyncClient(
            verify=key,
            limits=_HTTP_LIMITS,
            timeout=DEFAULT_TIMEOUT,
        )
        _CLIENTS[key] = cli
        return cli


async def _drop_client(verify_tls: bool) -> None:
    key = bool(verify_tls)
    cli: Optional[httpx.AsyncClient] = None
    with _CLIENTS_LOCK:
        cli = _CLIENTS.pop(key, None)
    if cli is not None:
        try:
            await cli.aclose()
        except Exception:
            pass


async def close_agent_clients() -> None:
    """Close shared keep-alive clients (called at app shutdown)."""
    with _CLIENTS_LOCK:
        items = list(_CLIENTS.values())
        _CLIENTS.clear()
    for cli in items:
        try:
            await cli.aclose()
        except Exception:
            pass


def _retry_backoff_sec(attempt_no: int) -> float:
    n = max(1, int(attempt_no or 1))
    return min(2.5, _TRANSPORT_RETRY_BACKOFF_BASE_SEC * (2 ** (n - 1)))


async def _agent_request(
    method: str,
    base_url: str,
    api_key: str,
    path: str,
    verify_tls: bool,
    data: Any = None,
    timeout: Optional[float] = None,
) -> Dict[str, Any]:
    headers = {"X-API-Key": api_key}
    url = f"{base_url.rstrip('/')}{path}"
    req_timeout = float(timeout or DEFAULT_TIMEOUT)
    method_u = str(method or "GET").upper()

    # Retry transient transport errors (stale keep-alive / short network jitter).
    for attempt in range(_TRANSPORT_RETRY_COUNT):
        client = await _get_client(verify_tls)
        try:
            if method_u == "GET":
                r = await client.get(url, headers=headers, timeout=req_timeout)
            else:
                r = await client.post(url, headers=headers, json=data, timeout=req_timeout)
        except httpx.TransportError:
            if attempt + 1 < _TRANSPORT_RETRY_COUNT:
                await _drop_client(verify_tls)
                await asyncio.sleep(_retry_backoff_sec(attempt + 1))
                continue
            raise

        if not (200 <= r.status_code < 300):
            raise AgentError(_format_agent_error(r))
        return _parse_agent_json(r)

    return {"ok": False, "error": "unreachable"}


async def agent_get_raw(
    base_url: str,
    api_key: str,
    path: str,
    verify_tls: bool,
    params: Optional[Dict[str, Any]] = None,
    timeout: Optional[float] = None,
) -> httpx.Response:
    headers = {"X-API-Key": api_key}
    url = f"{base_url.rstrip('/')}{path}"
    req_timeout = float(timeout or DEFAULT_TIMEOUT)
    query = params or {}

    for attempt in range(_TRANSPORT_RETRY_COUNT):
        client = await _get_client(verify_tls)
        try:
            return await client.get(url, params=query, headers=headers, timeout=req_timeout)
        except httpx.TransportError:
            if attempt + 1 < _TRANSPORT_RETRY_COUNT:
                await _drop_client(verify_tls)
                await asyncio.sleep(_retry_backoff_sec(attempt + 1))
                continue
            raise
    raise RuntimeError("Agent raw request failed")


async def agent_get_raw_stream(
    base_url: str,
    api_key: str,
    path: str,
    verify_tls: bool,
    params: Optional[Dict[str, Any]] = None,
    timeout: Optional[float] = None,
) -> httpx.Response:
    headers = {"X-API-Key": api_key}
    url = f"{base_url.rstrip('/')}{path}"
    req_timeout = float(timeout or DEFAULT_TIMEOUT)
    query = params or {}

    for attempt in range(_TRANSPORT_RETRY_COUNT):
        client = await _get_client(verify_tls)
        try:
            req = client.build_request("GET", url, params=query, headers=headers, timeout=req_timeout)
            return await client.send(req, stream=True)
        except httpx.TransportError:
            if attempt + 1 < _TRANSPORT_RETRY_COUNT:
                await _drop_client(verify_tls)
                await asyncio.sleep(_retry_backoff_sec(attempt + 1))
                continue
            raise
    raise RuntimeError("Agent raw stream request failed")


async def agent_get(
    base_url: str,
    api_key: str,
    path: str,
    verify_tls: bool,
    timeout: Optional[float] = None,
) -> Dict[str, Any]:
    return await _agent_request(
        "GET",
        base_url,
        api_key,
        path,
        verify_tls,
        timeout=timeout,
    )


async def agent_post(
    base_url: str,
    api_key: str,
    path: str,
    data: Any,
    verify_tls: bool,
    timeout: Optional[float] = None,
) -> Dict[str, Any]:
    return await _agent_request(
        "POST",
        base_url,
        api_key,
        path,
        verify_tls,
        data=data,
        timeout=timeout,
    )


async def agent_ping(base_url: str, api_key: str, verify_tls: bool) -> Dict[str, Any]:
    host, port = _extract_host_port(base_url, DEFAULT_AGENT_PORT)
    if not host:
        return {"ok": False, "error": "Agent 地址无效"}
    try:
        latency_ms = await _tcp_ping(host, port)
        return {"ok": True, "latency_ms": latency_ms}
    except Exception as e:
        return {"ok": False, "error": str(e)}


def _parse_agent_json(response: httpx.Response) -> Dict[str, Any]:
    try:
        data = response.json()
    except Exception:
        return {"ok": False, "error": response.text}
    if isinstance(data, dict):
        return data
    return {"ok": False, "error": str(data)}


def _coerce_error(val: Any) -> str:
    """Coerce arbitrary error payload (str/dict/list/...) into a readable string."""
    if val is None:
        return ""
    if isinstance(val, str):
        return val.strip()
    try:
        return json.dumps(val, ensure_ascii=False)
    except Exception:
        return str(val)


def _format_agent_error(response: httpx.Response) -> str:
    """把 Agent 的报错整理成更友好的提示。"""
    data = _parse_agent_json(response)
    error: Any = None
    detail: Any = None
    raw_text = (response.text or "").strip()
    low_raw = raw_text.lower()

    # Common misconfig: node base_url points to website nginx instead of realm-agent.
    # Symptom: HTML 404 page like "<center>nginx/1.18.0</center>".
    if (
        int(response.status_code or 0) == 404
        and ("<html" in low_raw or "text/html" in str(response.headers.get("content-type") or "").lower())
        and "nginx" in low_raw
    ):
        req_path = ""
        try:
            req_path = str(response.request.url.path or "")
        except Exception:
            req_path = ""
        path_hint = f"（path={req_path}）" if req_path else ""
        return (
            "Agent 请求失败（404）：命中了站点 Nginx 页面而不是 Agent API"
            f"{path_hint}。请检查该节点 base_url 是否指向 Agent 地址/端口（默认 :18700）。"
        )

    if isinstance(data, dict):
        error = data.get("error") or data.get("detail") or data.get("message")
        # detail 可能是更结构化的信息
        detail = data.get("detail")

    msg = _coerce_error(error)
    if not msg:
        msg = response.text.strip()
    if not msg:
        msg = f"HTTP {response.status_code}"

    # Older agents (or wrong route) may return 404 Not Found for website APIs.
    try:
        req_path = str(response.request.url.path or "")
    except Exception:
        req_path = ""
    if int(response.status_code or 0) == 404 and req_path.startswith("/api/v1/website/"):
        low_msg = str(msg or "").lower()
        if "not found" in low_msg:
            return (
                "Agent 请求失败（404）：节点不支持该网站 API（可能 Agent 版本过旧）"
                "，请升级 Agent 到最新版本。"
            )

    # 常见错误码翻译（优先匹配原始 error 码）
    code_map = {
        "jq_failed": "生成配置失败（规则格式异常或 jq 不可用）",
        "restart_failed": "重启 realm 服务失败",
        "invalid api key": "API Key 无效",
    }
    friendly = code_map.get(str(error).strip(), None) if error is not None else None
    msg = friendly or msg

    # 追加 detail（去重 & 截断）
    d = _coerce_error(detail)
    if d and d not in msg:
        if len(d) > 240:
            d = d[:240] + "…"
        msg = f"{msg}：{d}"

    # 避免把超长响应塞进 UI
    if len(msg) > 2000:
        msg = msg[:2000] + "…"

    return f"Agent 请求失败（{response.status_code}）：{msg}"


def _extract_host_port(base_url: str, fallback_port: int) -> Tuple[str, int]:
    target = (base_url or "").strip()
    if not target:
        return "", int(fallback_port)
    if "://" not in target:
        target = f"http://{target}"
    parsed = urlparse(target)
    host = parsed.hostname or ""
    port = parsed.port or int(fallback_port)
    return host, port


async def _tcp_ping(host: str, port: int) -> float:
    tcping = shutil.which("tcping")
    if tcping:
        output, _code = await _run_tcping(tcping, host, port)
        latency = _parse_tcping_latency(output)
        if latency is not None:
            return round(latency, 2)
    return await _tcp_ping_socket(host, port, TCPING_TIMEOUT)


async def _run_tcping(tcping: str, host: str, port: int) -> Tuple[str, int]:
    proc = await asyncio.create_subprocess_exec(
        tcping,
        "-c",
        "1",
        "-t",
        str(int(TCPING_TIMEOUT)),
        host,
        str(port),
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    try:
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=TCPING_TIMEOUT + 1)
    except asyncio.TimeoutError:
        proc.kill()
        return "tcping timeout", 1
    output = (stdout or b"") + (stderr or b"")
    return output.decode(errors="ignore"), proc.returncode or 0


def _parse_tcping_latency(output: str) -> Optional[float]:
    patterns = [
        r"time[=<]?\s*([0-9.]+)\s*ms",
        r"\bopen\b[^\n\r]*?([0-9.]+)\s*ms",
    ]
    for pattern in patterns:
        match = re.search(pattern, output, re.IGNORECASE)
        if match:
            try:
                return float(match.group(1))
            except Exception:
                return None
    return None


async def _tcp_ping_socket(host: str, port: int, timeout: float) -> float:
    start = time.monotonic()
    try:
        _reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=timeout)
    except Exception as exc:
        raise RuntimeError(str(exc)) from None
    try:
        latency = (time.monotonic() - start) * 1000
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
    return round(latency, 2)
