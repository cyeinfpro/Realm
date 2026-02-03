import base64
import json
import os
import secrets
import subprocess
from typing import Any, Dict, Tuple, Sequence, Union


def sh(cmd: Union[str, Sequence[str]], timeout: int = 10) -> Tuple[int, str, str]:
    """Run a command and return (code, stdout, stderr).

    - If `cmd` is a string, it will be executed via the shell (shell=True).
      This is kept for backwards compatibility because some call sites rely on
      pipes/redirections.
    - If `cmd` is a list/tuple of args, it will be executed without a shell
      (shell=False) which is safer.
    """
    use_shell = isinstance(cmd, str)
    p = subprocess.run(
        cmd,
        shell=use_shell,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=timeout,
    )
    return p.returncode, (p.stdout or '').strip(), (p.stderr or '').strip()


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
