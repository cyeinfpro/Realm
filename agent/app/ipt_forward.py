from __future__ import annotations

import hashlib
import ipaddress
import logging
import os
import socket
import subprocess
import threading
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse

from .iptables_cmd import iptables_available, run_iptables

logger = logging.getLogger(__name__)

IPTABLES_TIMEOUT = float(str(os.getenv("REALM_IPTABLES_FWD_TIMEOUT", "2.0")).strip() or "2.0")
NAT_CHAIN = str(os.getenv("REALM_IPTABLES_FWD_NAT_CHAIN", "REALMFWD_PREROUTE") or "REALMFWD_PREROUTE").strip()
FILTER_CHAIN = str(os.getenv("REALM_IPTABLES_FWD_FILTER_CHAIN", "REALMFWD_FORWARD") or "REALMFWD_FORWARD").strip()


def _run_iptables(args: List[str]) -> Tuple[int, str, str]:
    return run_iptables(args, timeout=max(0.2, IPTABLES_TIMEOUT))


def _iptables_available() -> bool:
    return iptables_available()


def _normalize_protocol(raw: Any) -> str:
    p = str(raw or "tcp+udp").strip().lower()
    if p == "tcp":
        return "tcp"
    if p == "udp":
        return "udp"
    return "tcp+udp"


def _normalize_algo(raw: Any) -> str:
    a = str(raw or "roundrobin").strip().lower()
    for ch in ("_", "-", " "):
        a = a.replace(ch, "")
    return "iphash" if a == "iphash" else "roundrobin"


def _parse_balance(balance: Any, remotes_count: int) -> Tuple[str, List[int]]:
    txt = str(balance or "roundrobin").strip()
    if not txt:
        txt = "roundrobin"
    if ":" not in txt:
        return _normalize_algo(txt), [1] * max(0, remotes_count)

    left, right = txt.split(":", 1)
    algo = _normalize_algo(left)
    raw = [x.strip() for x in right.replace("，", ",").split(",") if x.strip()]
    ws: List[int] = []
    for it in raw:
        if not it.isdigit():
            return algo, [1] * max(0, remotes_count)
        n = int(it)
        if n <= 0:
            return algo, [1] * max(0, remotes_count)
        ws.append(n)
    if len(ws) != remotes_count:
        return algo, [1] * max(0, remotes_count)
    return algo, ws


def _normalize_forward_tool(raw: Any) -> str:
    t = str(raw or "").strip().lower()
    if t in ("ipt", "iptables"):
        return "iptables"
    return "realm"


def _split_hostport(addr: str) -> Tuple[str, int]:
    s = str(addr or "").strip()
    if not s:
        raise ValueError("empty address")

    if "://" in s:
        u = urlparse(s)
        host = (u.hostname or "").strip()
        port = int(u.port or 0)
        if not host or port <= 0 or port > 65535:
            raise ValueError("address must include host and valid port")
        return host, port

    if s.startswith("["):
        if "]" not in s:
            raise ValueError("invalid IPv6 bracket address")
        host = s.split("]")[0][1:].strip()
        rest = s.split("]")[1]
        if not rest.startswith(":"):
            raise ValueError("missing port")
        p = rest[1:]
        if not p.isdigit():
            raise ValueError("invalid port")
        port = int(p)
        if port <= 0 or port > 65535:
            raise ValueError("invalid port")
        return host, port

    if s.count(":") > 1:
        raise ValueError("IPv6 must use [addr]:port")

    if ":" in s:
        host, p = s.rsplit(":", 1)
        if not p.isdigit():
            raise ValueError("invalid port")
        port = int(p)
        if port <= 0 or port > 65535:
            raise ValueError("invalid port")
        return host.strip(), port

    raise ValueError("missing port (expected host:port)")


def _is_ipv4(host: str) -> bool:
    try:
        ipaddress.IPv4Address(str(host or "").strip())
        return True
    except Exception:
        return False


def _resolve_ipv4(host: str) -> str:
    h = str(host or "").strip()
    if not h:
        raise ValueError("empty host")
    if _is_ipv4(h):
        return h
    if h == "localhost":
        return "127.0.0.1"
    infos = socket.getaddrinfo(h, None, socket.AF_INET, socket.SOCK_STREAM)
    for it in infos:
        try:
            ip = str(it[4][0] or "").strip()
        except Exception:
            ip = ""
        if _is_ipv4(ip):
            return ip
    raise ValueError(f"host cannot resolve to IPv4: {h}")


def _normalize_listen_host_for_match(host: str) -> str:
    h = str(host or "").strip()
    if h in ("", "*", "0.0.0.0"):
        return ""
    return _resolve_ipv4(h)


def _rule_sig(
    listen_host_match: str,
    listen_port: int,
    protocol: str,
    remotes: List[str],
    algo: str,
    weights: List[int],
) -> str:
    payload = {
        "listen_host_match": str(listen_host_match or ""),
        "listen_port": int(listen_port),
        "protocol": str(protocol or ""),
        "remotes": list(remotes or []),
        "algo": str(algo or ""),
        "weights": list(weights or []),
    }
    s = repr(payload).encode("utf-8", errors="ignore")
    return hashlib.sha1(s).hexdigest()


@dataclass
class _Target:
    raw: str
    ip: str
    port: int


@dataclass
class _IptablesRule:
    key: str
    listen: str
    listen_host_match: str
    listen_port: int
    protocol: str
    remotes: List[_Target]
    balance_algo: str
    weights: List[int]
    signature: str


class IptablesForwardManager:
    """Runtime manager for normal forwarding rules using Linux iptables."""

    def __init__(self):
        self._lock = threading.Lock()
        self._rules: Dict[str, _IptablesRule] = {}
        self._pending: Dict[str, _IptablesRule] = {}
        self._nat_entries = 0
        self._filter_entries = 0
        self._last_error = ""
        self._warnings: List[str] = []

    def status(self) -> Dict[str, Any]:
        with self._lock:
            return {
                "backend": "iptables",
                "available": _iptables_available(),
                "rules": len(self._rules),
                "pending_rules": len(self._pending),
                "nat_entries": int(self._nat_entries),
                "filter_entries": int(self._filter_entries),
                "last_error": str(self._last_error or ""),
                "warnings": list(self._warnings[-8:]),
            }

    def stop(self) -> None:
        with self._lock:
            try:
                if _iptables_available():
                    self._ensure_chains_and_jumps_locked()
                    self._flush_managed_chains_locked()
            except Exception as exc:
                self._last_error = str(exc)
            self._rules.clear()
            self._pending.clear()
            self._nat_entries = 0
            self._filter_entries = 0

    def prepare_for_pool(self, pool: Dict[str, Any]) -> None:
        rules = self._parse_rules(pool)
        with self._lock:
            self._pending = dict(rules)
            self._warnings = []
            if not _iptables_available():
                if rules:
                    self._last_error = "iptables not available"
                    raise RuntimeError(self._last_error)
                return
            if not rules:
                self._cleanup_no_rules_locked()
                self._nat_entries = 0
                self._filter_entries = 0
                self._last_error = ""
                return
            if rules:
                self._ensure_runtime_tuning_locked()
            self._ensure_chains_and_jumps_locked()
            # Pre-flush managed chains so realm/iptables switch has no overlap window.
            self._flush_managed_chains_locked()
            self._nat_entries = 0
            self._filter_entries = 0
            self._last_error = ""

    def apply_from_pool(self, pool: Dict[str, Any]) -> None:
        rules = self._parse_rules(pool)
        with self._lock:
            self._pending = dict(rules)
            self._warnings = []
            if not _iptables_available():
                if rules:
                    msg = "iptables not available"
                    self._last_error = msg
                    raise RuntimeError(msg)
                self._rules.clear()
                self._nat_entries = 0
                self._filter_entries = 0
                self._last_error = ""
                return
            if not rules:
                self._cleanup_no_rules_locked()
                self._rules.clear()
                self._nat_entries = 0
                self._filter_entries = 0
                self._last_error = ""
                return

            if rules:
                self._ensure_runtime_tuning_locked()
            self._ensure_chains_and_jumps_locked()
            self._flush_managed_chains_locked()

            nat_count = 0
            filter_count = 0
            for rule in rules.values():
                n, f = self._install_rule_locked(rule)
                nat_count += n
                filter_count += f

            self._rules = dict(rules)
            self._nat_entries = nat_count
            self._filter_entries = filter_count
            self._last_error = ""

    def _ensure_runtime_tuning_locked(self) -> None:
        # best-effort: keep kernel forwarding enabled
        try:
            subprocess.run(
                ["sysctl", "-w", "net.ipv4.ip_forward=1"],
                capture_output=True,
                text=True,
                timeout=max(0.2, IPTABLES_TIMEOUT),
                check=False,
            )
        except Exception:
            pass

        rc, _o, _e = _run_iptables([
            "-C",
            "FORWARD",
            "-m",
            "conntrack",
            "--ctstate",
            "RELATED,ESTABLISHED",
            "-j",
            "ACCEPT",
        ])
        if rc != 0:
            rc2, _o2, e2 = _run_iptables([
                "-A",
                "FORWARD",
                "-m",
                "conntrack",
                "--ctstate",
                "RELATED,ESTABLISHED",
                "-j",
                "ACCEPT",
            ])
            if rc2 != 0:
                raise RuntimeError(f"iptables ensure FORWARD related/established failed: {e2 or rc2}")

        rc, _o, _e = _run_iptables(["-t", "nat", "-C", "POSTROUTING", "-j", "MASQUERADE"])
        if rc != 0:
            rc2, _o2, e2 = _run_iptables(["-t", "nat", "-A", "POSTROUTING", "-j", "MASQUERADE"])
            if rc2 != 0:
                raise RuntimeError(f"iptables ensure POSTROUTING MASQUERADE failed: {e2 or rc2}")

    def _ensure_chains_and_jumps_locked(self) -> None:
        self._ensure_chain_locked("nat", NAT_CHAIN)
        self._ensure_chain_locked("filter", FILTER_CHAIN)
        self._ensure_jump_locked("nat", "PREROUTING", NAT_CHAIN)
        self._ensure_jump_locked("filter", "FORWARD", FILTER_CHAIN)

    def _ensure_chain_locked(self, table: str, chain: str) -> None:
        rc, _o, err = _run_iptables(["-t", table, "-N", chain])
        if rc == 0:
            return
        rc2, _o2, err2 = _run_iptables(["-t", table, "-L", chain])
        if rc2 == 0:
            return
        raise RuntimeError(f"iptables create chain failed: table={table} chain={chain} err={err or err2}")

    def _ensure_jump_locked(self, table: str, base_chain: str, target_chain: str) -> None:
        # Keep a single jump in base_chain -> target_chain to avoid duplicate traversals.
        rc, out, _e = _run_iptables(["-t", table, "-S", base_chain])
        if rc == 0:
            for ln in str(out or "").splitlines():
                s = str(ln or "").strip()
                if not s.startswith(f"-A {base_chain} "):
                    continue
                if f"-j {target_chain}" not in s:
                    continue
                toks = s.split()
                if len(toks) >= 2:
                    toks[0] = "-D"
                    _run_iptables(["-t", table, *toks])

        rc2, _o2, e2 = _run_iptables(["-t", table, "-I", base_chain, "1", "-j", target_chain])
        if rc2 != 0:
            raise RuntimeError(
                f"iptables insert jump failed: table={table} from={base_chain} to={target_chain} err={e2 or rc2}"
            )

    def _remove_jump_locked(self, table: str, base_chain: str, target_chain: str) -> None:
        rc, out, _e = _run_iptables(["-t", table, "-S", base_chain])
        if rc != 0:
            return
        for ln in str(out or "").splitlines():
            s = str(ln or "").strip()
            if not s.startswith(f"-A {base_chain} "):
                continue
            if f"-j {target_chain}" not in s:
                continue
            toks = s.split()
            if len(toks) >= 2:
                toks[0] = "-D"
                _run_iptables(["-t", table, *toks])

    def _flush_managed_chains_locked(self) -> None:
        rc, _o, e = _run_iptables(["-t", "nat", "-F", NAT_CHAIN])
        if rc != 0:
            raise RuntimeError(f"iptables flush chain failed: table=nat chain={NAT_CHAIN} err={e or rc}")
        rc, _o, e = _run_iptables(["-t", "filter", "-F", FILTER_CHAIN])
        if rc != 0:
            raise RuntimeError(f"iptables flush chain failed: table=filter chain={FILTER_CHAIN} err={e or rc}")

    def _cleanup_no_rules_locked(self) -> None:
        # Remove managed jumps and clear managed chains when there is no iptables forward rule.
        try:
            self._remove_jump_locked("nat", "PREROUTING", NAT_CHAIN)
        except Exception:
            pass
        try:
            self._remove_jump_locked("filter", "FORWARD", FILTER_CHAIN)
        except Exception:
            pass
        # Flush existing managed chains if present.
        rc, _o, _e = _run_iptables(["-t", "nat", "-L", NAT_CHAIN])
        if rc == 0:
            _run_iptables(["-t", "nat", "-F", NAT_CHAIN])
        rc, _o, _e = _run_iptables(["-t", "filter", "-L", FILTER_CHAIN])
        if rc == 0:
            _run_iptables(["-t", "filter", "-F", FILTER_CHAIN])

    def _run_or_raise(self, args: List[str], err_prefix: str) -> None:
        rc, _o, e = _run_iptables(args)
        if rc != 0:
            raise RuntimeError(f"{err_prefix}: {e or rc}")

    def _install_rule_locked(self, rule: _IptablesRule) -> Tuple[int, int]:
        nat_count = 0
        filter_count = 0
        protos = ["tcp", "udp"] if rule.protocol == "tcp+udp" else [rule.protocol]

        # filter/FORWARD accepts target side NEW packets
        for p in protos:
            for t in rule.remotes:
                args = [
                    "-t",
                    "filter",
                    "-A",
                    FILTER_CHAIN,
                    "-p",
                    p,
                    "-d",
                    t.ip,
                    "--dport",
                    str(int(t.port)),
                    "-m",
                    "conntrack",
                    "--ctstate",
                    "NEW",
                    "-j",
                    "ACCEPT",
                ]
                self._run_or_raise(args, "iptables add FORWARD failed")
                filter_count += 1

        # nat/PREROUTING DNAT rules with weighted random dispatch
        algo = rule.balance_algo
        if algo == "iphash":
            algo = "roundrobin"
            self._warnings.append(
                f"{rule.listen}: iphash is not natively supported by iptables DNAT; fallback to weighted random"
            )

        weights = list(rule.weights or [])
        if len(weights) != len(rule.remotes):
            weights = [1] * len(rule.remotes)

        for p in protos:
            nat_steps: List[Tuple[_Target, Optional[float]]] = []
            if len(rule.remotes) <= 1:
                nat_steps = [(rule.remotes[0], None)]
            else:
                remain = float(sum(max(1, int(w)) for w in weights))
                for idx, t in enumerate(rule.remotes):
                    if idx >= len(rule.remotes) - 1:
                        nat_steps.append((t, None))
                        continue
                    w = float(max(1, int(weights[idx])))
                    prob = w / remain if remain > 0 else 0.0
                    if prob <= 0.0:
                        prob = 0.0000000001
                    if prob >= 1.0:
                        prob = 0.9999999999
                    nat_steps.append((t, prob))
                    remain -= w

            for t, prob in nat_steps:
                args = [
                    "-t",
                    "nat",
                    "-A",
                    NAT_CHAIN,
                    "-p",
                    p,
                ]
                if rule.listen_host_match:
                    args += ["-d", rule.listen_host_match]
                args += ["--dport", str(int(rule.listen_port))]
                if prob is not None:
                    args += ["-m", "statistic", "--mode", "random", "--probability", f"{prob:.10f}"]
                args += ["-j", "DNAT", "--to-destination", f"{t.ip}:{int(t.port)}"]
                self._run_or_raise(args, "iptables add DNAT failed")
                nat_count += 1

        return nat_count, filter_count

    def _parse_rules(self, pool: Dict[str, Any]) -> Dict[str, _IptablesRule]:
        out: Dict[str, _IptablesRule] = {}
        eps = pool.get("endpoints") if isinstance(pool.get("endpoints"), list) else []
        for ep in eps:
            if not isinstance(ep, dict):
                continue
            if bool(ep.get("disabled")):
                continue

            ex = ep.get("extra_config") if isinstance(ep.get("extra_config"), dict) else {}
            if ex.get("intranet_role") or ex.get("intranet_token"):
                continue
            if ex.get("sync_role") in ("sender", "receiver") or ex.get("sync_lock"):
                continue

            tool_raw = ex.get("forward_tool")
            if tool_raw is None and ep.get("forward_tool") is not None:
                tool_raw = ep.get("forward_tool")
            tool = _normalize_forward_tool(tool_raw)
            if tool != "iptables":
                continue

            listen = str(ep.get("listen") or "").strip()
            if not listen:
                continue
            try:
                lhost, lport = _split_hostport(listen)
                lmatch = _normalize_listen_host_for_match(lhost)
            except Exception:
                logger.warning("iptables rule skipped (invalid listen): %s", listen)
                continue

            remotes_raw: List[str] = []
            if isinstance(ep.get("remote"), str) and str(ep.get("remote") or "").strip():
                remotes_raw.append(str(ep.get("remote") or "").strip())
            if isinstance(ep.get("remotes"), list):
                remotes_raw += [str(x).strip() for x in ep.get("remotes") if str(x).strip()]
            if isinstance(ep.get("extra_remotes"), list):
                remotes_raw += [str(x).strip() for x in ep.get("extra_remotes") if str(x).strip()]

            uniq_remotes: List[str] = []
            seen: set[str] = set()
            for r in remotes_raw:
                if r in seen:
                    continue
                seen.add(r)
                uniq_remotes.append(r)

            targets: List[_Target] = []
            for r in uniq_remotes:
                try:
                    rh, rp = _split_hostport(r)
                    rip = _resolve_ipv4(rh)
                    targets.append(_Target(raw=f"{rip}:{int(rp)}", ip=rip, port=int(rp)))
                except Exception:
                    logger.warning("iptables rule remote skipped (invalid): %s", r)
                    continue
            if not targets:
                logger.warning("iptables rule skipped (no valid remotes): listen=%s", listen)
                continue

            protocol = _normalize_protocol(ep.get("protocol"))
            algo, weights = _parse_balance(ep.get("balance"), len(targets))
            sig = _rule_sig(lmatch, lport, protocol, [t.raw for t in targets], algo, weights)

            sid = str(ex.get("sync_id") or "").strip()
            key_head = sid if sid else f"{lmatch or '0.0.0.0'}:{int(lport)}"
            key = f"{key_head}|{protocol}"

            out[key] = _IptablesRule(
                key=key,
                listen=f"{lmatch or '0.0.0.0'}:{int(lport)}",
                listen_host_match=lmatch,
                listen_port=int(lport),
                protocol=protocol,
                remotes=targets,
                balance_algo=algo,
                weights=weights,
                signature=sig,
            )
        return out


# Backward-compatible alias for older imports.
class IptForwardManager(IptablesForwardManager):
    pass
