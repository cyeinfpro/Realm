import base64
import json
import os
import secrets
import subprocess
from typing import Any, Dict, Tuple


def sh(cmd: str, timeout: int = 10) -> Tuple[int, str, str]:
    """Run a shell command and return (code, stdout, stderr)."""
    p = subprocess.run(
        cmd,
        shell=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=timeout,
    )
    return p.returncode, p.stdout.strip(), p.stderr.strip()


def b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


def b64url_decode(s: str) -> bytes:
    s = s.strip()
    pad = "=" * ((4 - len(s) % 4) % 4)
    return base64.urlsafe_b64decode(s + pad)


def make_pair_code(payload: Dict[str, Any]) -> str:
    raw = json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode()
    return b64url_encode(raw)


def parse_pair_code(code: str) -> Dict[str, Any]:
    raw = b64url_decode(code)
    obj = json.loads(raw.decode())
    if not isinstance(obj, dict):
        raise ValueError("配对码内容不合法")
    return obj


def ensure_dir(path: str) -> None:
    os.makedirs(path, exist_ok=True)


def gen_api_key() -> str:
    return secrets.token_urlsafe(32)
