from __future__ import annotations

import os
import re
import shlex
import socket
import subprocess
import time
from typing import Dict, List, Optional, Tuple

import toml

from .config import CFG
from .models import Rule


def _run(cmd: List[str], timeout: int = 15) -> Tuple[int, str, str]:
    """Run a command and return (rc, stdout, stderr)."""
    if not CFG.allow_shell:
        return (1, "", "shell disabled")
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return (p.returncode, p.stdout, p.stderr)
    except Exception as e:
        return (1, "", str(e))


def _ensure_dir(path: str) -> None:
    os.makedirs(path, exist_ok=True)


def _parse_host_port(addr: str) -> Tuple[str, int]:
    # IPv6 in bracket not supported here; keep v4/hostname.
    if addr.count(":") == 1:
        host, port_s = addr.split(":", 1)
    else:
        # fallback: last colon
        host, port_s = addr.rsplit(":", 1)
        host = host.strip("[]")
    return host, int(port_s)


def tcp_probe(addr: str, timeout: float = 1.0) -> bool:
    host, port = _parse_host_port(addr)
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except Exception:
        return False


def ensure_wss_cert(rule_id: str, host_for_cn: str) -> Tuple[str, str]:
    """Generate a self-signed cert for WSS server rules if missing."""
    cert_dir = os.path.join(CFG.data_dir, "wss")
    _ensure_dir(cert_dir)
    cert_path = os.path.join(cert_dir, f"{rule_id}.crt")
    key_path = os.path.join(cert_dir, f"{rule_id}.key")

    if os.path.exists(cert_path) and os.path.exists(key_path):
        return cert_path, key_path

    # Use openssl to create a self-signed cert (1 year)
    subj = f"/CN={host_for_cn}"
    cmd = [
        "openssl",
        "req",
        "-x509",
        "-nodes",
        "-newkey",
        "rsa:2048",
        "-days",
        "365",
        "-keyout",
        key_path,
        "-out",
        cert_path,
        "-subj",
        subj,
    ]
    rc, _, err = _run(cmd, timeout=30)
    if rc != 0:
        raise RuntimeError(f"openssl failed: {err}")
    return cert_path, key_path


def build_realm_config(rules: List[Rule]) -> str:
    """Convert stored rules into realm.toml"""

    cfg: Dict[str, object] = {
        "log": {"level": "off", "output": "stdout"},
        "dns": {
            "mode": "ipv4_and_ipv6",
            "protocol": "tcp+udp",
            "min_ttl": 0,
            "max_ttl": 86400,
            "cache_size": 32,
            "servers": "system",
        },
        "network": {
            "no_tcp": False,
            "use_udp": False,
            "tcp_timeout": 5,
            "udp_timeout": 30,
            "send_proxy": False,
            "accept_proxy": False,
            "ipv6_only": False,
        },
        "endpoints": [],
    }

    endpoints: List[Dict[str, object]] = []

    for r in rules:
        if not r.enabled:
            continue
        if not r.targets:
            continue

        ep: Dict[str, object] = {
            "listen": r.listen,
            "protocol": r.protocol,
        }

        # remote: single string or list
        if len(r.targets) == 1:
            ep["remote"] = r.targets[0]
        else:
            ep["remote"] = r.targets[0]
            ep["extra_remotes"] = r.targets[1:]
            ep["balance"] = r.balance

        # per-endpoint network override
        net = {}
        if r.protocol == "udp":
            net["no_tcp"] = True
            net["use_udp"] = True
        elif r.protocol == "tcp":
            net["no_tcp"] = False
            net["use_udp"] = False
        else:  # tcp+udp
            net["no_tcp"] = False
            net["use_udp"] = True

        # WSS transports
        if r.type == "wss_client":
            # connect via WSS to the remote server address
            # remote_transport: ws with tls + sni; note: host/path are HTTP layer values.
            wss_host = r.wss_host or "www.bing.com"
            wss_path = r.wss_path or "/ws"
            wss_sni = r.wss_sni or wss_host
            parts = [
                "ws",
                f"host={wss_host}",
                f"path={wss_path}",
                "tls",
                f"sni={wss_sni}",
            ]
            if r.wss_insecure:
                parts.append("insecure")
            ep["remote_transport"] = ";".join(parts)

        elif r.type == "wss_server":
            # accept incoming WSS on listen, forward to targets
            wss_host = r.wss_host or "example.com"
            wss_path = r.wss_path or "/ws"
            cert, key = (r.wss_cert, r.wss_key)
            if not cert or not key:
                cert, key = ensure_wss_cert(r.id, wss_host)
            parts = [
                "ws",
                f"host={wss_host}",
                f"path={wss_path}",
                "tls",
                f"cert={cert}",
                f"key={key}",
            ]
            ep["listen_transport"] = ";".join(parts)

        if net:
            ep["network"] = net

        endpoints.append(ep)

    cfg["endpoints"] = endpoints

    return toml.dumps(cfg)


def write_realm_config(toml_text: str) -> None:
    os.makedirs(os.path.dirname(CFG.realm_config_file), exist_ok=True)
    tmp = CFG.realm_config_file + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        f.write(toml_text)
    os.replace(tmp, CFG.realm_config_file)


def restart_realm() -> Tuple[bool, str]:
    rc, out, err = _run(["systemctl", "restart", CFG.realm_service], timeout=20)
    if rc != 0:
        return False, err or out or "failed"
    return True, "restarted"


def realm_status() -> Tuple[bool, str]:
    rc, out, err = _run(["systemctl", "is-active", CFG.realm_service])
    active = (out.strip() == "active")
    return active, out.strip() or err.strip()


def journal_tail(unit: str, lines: int = 200) -> List[str]:
    rc, out, err = _run(["journalctl", "-u", unit, "--no-pager", f"-n", str(lines)], timeout=15)
    text = out if rc == 0 else (err or out)
    return text.splitlines()[-lines:]


def _parse_ss_realm() -> List[Tuple[str, int, str, int]]:
    """Return list of (local_ip, local_port, remote_ip, remote_port) for realm-established TCP conns."""
    rc, out, _ = _run(["ss", "-Htnp", "state", "established"], timeout=10)
    if rc != 0:
        return []
    conns = []
    for line in out.splitlines():
        if "\"realm\"" not in line and "(\"realm\"" not in line and " users:(" not in line:
            continue
        # split by spaces; local and peer are 3rd and 4th? depends
        parts = line.split()
        if len(parts) < 5:
            continue
        # local addr at index 3, peer at 4
        local = parts[3]
        peer = parts[4]
        try:
            lhost, lport = _parse_host_port(local)
            rhost, rport = _parse_host_port(peer)
            conns.append((lhost, lport, rhost, rport))
        except Exception:
            continue
    return conns


def connection_counts_for_rule(rule: Rule) -> Dict[str, int]:
    """Best-effort connection counts.

    - inbound: established connections where local port == listen_port
    - outbound_per_target: established connections where remote endpoint matches target host/port
    """
    try:
        _, listen_port = _parse_host_port(rule.listen)
    except Exception:
        listen_port = 0

    conns = _parse_ss_realm()
    inbound = 0
    outbound = 0

    targets = set()
    for t in rule.targets:
        try:
            thost, tport = _parse_host_port(t)
            targets.add((thost, tport))
        except Exception:
            pass

    for lhost, lport, rhost, rport in conns:
        if listen_port and lport == listen_port:
            inbound += 1
        if (rhost, rport) in targets:
            outbound += 1

    return {"inbound": inbound, "outbound": outbound}


def status_snapshot(rules: List[Rule]) -> Dict[str, object]:
    active, st = realm_status()
    enabled_rules = [r for r in rules if r.enabled]
    # probe targets
    target_status: Dict[str, Dict[str, bool]] = {}
    for r in enabled_rules:
        target_status[r.id] = {}
        for t in r.targets:
            target_status[r.id][t] = tcp_probe(t)

    conn_counts = {r.id: connection_counts_for_rule(r) for r in rules}

    return {
        "realm_active": active,
        "realm_status": st,
        "rules_total": len(rules),
        "rules_enabled": len(enabled_rules),
        "target_status": target_status,
        "conn_counts": conn_counts,
    }
