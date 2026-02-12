from __future__ import annotations

import os
import shutil
import subprocess
from functools import lru_cache
from typing import Sequence, Tuple


def _resolve_override(raw: str) -> str:
    cand = str(raw or "").strip()
    if not cand:
        return ""
    if "/" in cand:
        if os.path.isfile(cand) and os.access(cand, os.X_OK):
            return cand
        return ""
    found = shutil.which(cand)
    return str(found or "")


@lru_cache(maxsize=1)
def iptables_command() -> str:
    env_cmd = _resolve_override(os.getenv("REALM_IPTABLES_BIN", ""))
    if env_cmd:
        return env_cmd
    for cand in ("iptables", "iptables-nft", "iptables-legacy"):
        found = shutil.which(cand)
        if found:
            return str(found)
    return ""


def iptables_available() -> bool:
    return bool(iptables_command())


def run_iptables(args: Sequence[str], timeout: float) -> Tuple[int, str, str]:
    cmd = iptables_command()
    if not cmd:
        return (
            127,
            "",
            "iptables command not found (tried REALM_IPTABLES_BIN/iptables/iptables-nft/iptables-legacy)",
        )
    try:
        proc = subprocess.run(
            [cmd, *list(args)],
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        return int(proc.returncode), str(proc.stdout or ""), str(proc.stderr or "")
    except Exception as exc:
        return 127, "", str(exc)
