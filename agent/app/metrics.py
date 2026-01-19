import re
import shutil
import socket
from typing import Any, Dict, List, Optional

from .utils import sh


def count_established_tcp(port: int) -> int:
    # local port established
    if not shutil.which("ss"):
        return 0
    code, out, _ = sh(f"ss -Hnt state established '( sport = :{port} )' 2>/dev/null | wc -l", timeout=5)
    try:
        return int(out.strip() or "0")
    except Exception:
        return 0


def tcp_check(host: str, port: int, timeout: float = 0.6) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except Exception:
        return False


def parse_hostport(s: str) -> Optional[tuple[str, int]]:
    # expects host:port
    if not isinstance(s, str) or ":" not in s:
        return None
    host, p = s.rsplit(":", 1)
    try:
        return host, int(p)
    except Exception:
        return None


def gather_metrics(rules: List[Dict[str, Any]]) -> Dict[str, Any]:
    res: Dict[str, Any] = {"rules": {}}
    for r in rules:
        rid = r.get("id")
        listen = r.get("listen", "")
        try:
            port = int(listen.rsplit(":", 1)[1])
        except Exception:
            port = 0
        conns = count_established_tcp(port) if port else 0

        # remote health for multi targets
        remotes: List[str] = []
        if isinstance(r.get("remote"), str):
            remotes.append(r["remote"])
        if isinstance(r.get("extra_remotes"), list):
            remotes += [x for x in r["extra_remotes"] if isinstance(x, str)]

        health = []
        for hp in remotes:
            parsed = parse_hostport(hp)
            ok = False
            if parsed:
                ok = tcp_check(parsed[0], parsed[1])
            health.append({"target": hp, "ok": ok})

        res["rules"][rid] = {
            "listen": listen,
            "connections": conns,
            "targets": health,
        }
    return res
