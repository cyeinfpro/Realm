from __future__ import annotations

import asyncio
import json
import re
import shutil
import time
from typing import Any, Dict, Optional, Tuple
from urllib.parse import urlparse

import httpx

from ..core.settings import DEFAULT_AGENT_PORT

DEFAULT_TIMEOUT = 6.0
TCPING_TIMEOUT = 3.0


class AgentError(RuntimeError):
    """Raised when panel <-> agent request failed."""


async def agent_get(
    base_url: str,
    api_key: str,
    path: str,
    verify_tls: bool,
    timeout: Optional[float] = None,
) -> Dict[str, Any]:
    headers = {"X-API-Key": api_key}
    url = f"{base_url.rstrip('/')}{path}"
    async with httpx.AsyncClient(timeout=(timeout or DEFAULT_TIMEOUT), verify=verify_tls) as client:
        r = await client.get(url, headers=headers)
        if not (200 <= r.status_code < 300):
            raise AgentError(_format_agent_error(r))
        return _parse_agent_json(r)


async def agent_post(
    base_url: str,
    api_key: str,
    path: str,
    data: Any,
    verify_tls: bool,
    timeout: Optional[float] = None,
) -> Dict[str, Any]:
    headers = {"X-API-Key": api_key}
    url = f"{base_url.rstrip('/')}{path}"
    async with httpx.AsyncClient(timeout=(timeout or DEFAULT_TIMEOUT), verify=verify_tls) as client:
        r = await client.post(url, headers=headers, json=data)
        if not (200 <= r.status_code < 300):
            raise AgentError(_format_agent_error(r))
        return _parse_agent_json(r)


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

    if isinstance(data, dict):
        error = data.get("error") or data.get("detail") or data.get("message")
        # detail 可能是更结构化的信息
        detail = data.get("detail")

    msg = _coerce_error(error)
    if not msg:
        msg = response.text.strip()
    if not msg:
        msg = f"HTTP {response.status_code}"

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
