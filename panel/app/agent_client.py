import json
import urllib.request
from typing import Any, Dict, Optional


class AgentError(Exception):
    pass


def _request(method: str, url: str, api_key: str, body: Optional[Dict[str, Any]] = None, timeout: int = 6) -> Any:
    data = None
    headers = {"X-API-Key": api_key, "Content-Type": "application/json"}
    if body is not None:
        data = json.dumps(body).encode("utf-8")
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read().decode("utf-8")
            if not raw:
                return None
            return json.loads(raw)
    except urllib.error.HTTPError as e:
        msg = e.read().decode("utf-8", errors="ignore")
        raise AgentError(f"HTTP {e.code}: {msg}")
    except Exception as e:
        raise AgentError(str(e))


def call_agent(base_url: str, api_key: str, path: str, method: str = "GET", body: Optional[Dict[str, Any]] = None) -> Any:
    base = base_url.rstrip("/")
    return _request(method, base + path, api_key, body=body)
