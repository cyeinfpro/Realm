import asyncio
import re
import shutil
import time
from typing import Any, Dict, Optional, Tuple
from urllib.parse import urlparse

import httpx

DEFAULT_TIMEOUT = 6.0
DEFAULT_AGENT_PORT = 18700
TCPING_TIMEOUT = 3.0


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
    return {"ok": False, "error": data}


def _format_agent_error(response: httpx.Response) -> str:
    """把 Agent 的报错整理成更友好的提示。"""
    data = _parse_agent_json(response)
    error = data.get('error') if isinstance(data, dict) else None
    detail = data.get('detail') if isinstance(data, dict) else None
    if not error:
        error = data.get('detail') if isinstance(data, dict) else None
    if not error:
        error = response.text.strip()
    if not error:
        error = f"HTTP {response.status_code}"

    # 常见错误码翻译
    code_map = {
        'jq_failed': '生成配置失败（规则格式异常或 jq 不可用）',
        'restart_failed': '重启 realm 服务失败',
        'invalid api key': 'API Key 无效',
    }
    friendly = code_map.get(str(error).strip(), None)
    msg = friendly or str(error).strip()
    if detail and str(detail).strip() and str(detail).strip() not in msg:
        # detail 可能很长，做个简单截断
        d = str(detail).strip()
        if len(d) > 240:
            d = d[:240] + '…'
        msg = f"{msg}：{d}"
    return f"Agent 请求失败（{response.status_code}）：{msg}"


def _extract_host_port(base_url: str, fallback_port: int) -> Tuple[str, int]:
    target = base_url.strip()
    if not target:
        return "", fallback_port
    if "://" not in target:
        target = f"http://{target}"
    parsed = urlparse(target)
    host = parsed.hostname or ""
    port = parsed.port or fallback_port
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
            return float(match.group(1))
    return None


async def _tcp_ping_socket(host: str, port: int, timeout: float) -> float:
    start = time.monotonic()
    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=timeout)
    except Exception as exc:
        raise RuntimeError(str(exc)) from None
    try:
        latency = (time.monotonic() - start) * 1000
    finally:
        writer.close()
        await writer.wait_closed()
    return round(latency, 2)
