import json
import ssl
import urllib.request
from typing import Any, Dict, Optional


class AgentError(Exception):
    pass


def _request(
    method: str,
    url: str,
    api_key: str,
    body: Optional[Dict[str, Any]] = None,
    timeout: int = 6,
    verify_tls: bool = True,
) -> Any:
    data = None
    headers = {"X-API-Key": api_key, "Content-Type": "application/json"}
    if body is not None:
        data = json.dumps(body).encode("utf-8")
    req = urllib.request.Request(url, data=data, headers=headers, method=method)

    # urllib uses an SSLContext only for https:// URLs.
    ssl_ctx = None
    if str(url).lower().startswith('https://'):
        ssl_ctx = ssl.create_default_context()
        if not verify_tls:
            ssl_ctx = ssl._create_unverified_context()  # nosec - explicitly requested

    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ssl_ctx) as resp:
            raw = resp.read().decode("utf-8")
            if not raw:
                return None
            return json.loads(raw)
    except urllib.error.HTTPError as e:
        msg = e.read().decode("utf-8", errors="ignore")
        raise AgentError(f"HTTP {e.code}: {msg}")
    except Exception as e:
        raise AgentError(str(e))


def call_agent(
    base_url: str,
    api_key: str,
    path: str,
    method: str = "GET",
    body: Optional[Dict[str, Any]] = None,
    verify_tls: bool = True,
) -> Any:
    base = base_url.rstrip("/")
    return _request(method, base + path, api_key, body=body, verify_tls=verify_tls)
