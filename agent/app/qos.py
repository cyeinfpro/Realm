from __future__ import annotations

import json
import os
import re
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple

from .iptables_cmd import iptables_available, run_iptables


IPT_TABLE = os.getenv("REALM_QOS_IPT_TABLE", "filter").strip() or "filter"
IPT_CHAIN = os.getenv("REALM_QOS_IPT_CHAIN", "REALMQOS_IN").strip() or "REALMQOS_IN"
IPT_TIMEOUT = float(os.getenv("REALM_QOS_IPT_TIMEOUT", "1.5") or "1.5")

NFT_FAMILY = os.getenv("REALM_QOS_NFT_FAMILY", "inet").strip() or "inet"
NFT_TABLE = os.getenv("REALM_QOS_NFT_TABLE", "realm_qos").strip() or "realm_qos"
NFT_CHAIN = os.getenv("REALM_QOS_NFT_CHAIN", "input").strip() or "input"
NFT_PRIORITY = os.getenv("REALM_QOS_NFT_PRIORITY", "-90").strip() or "-90"
NFT_TIMEOUT = float(os.getenv("REALM_QOS_NFT_TIMEOUT", "1.5") or "1.5")

TC_TIMEOUT = float(os.getenv("REALM_QOS_TC_TIMEOUT", "1.5") or "1.5")
TC_PREF_BASE = int(os.getenv("REALM_QOS_TC_PREF_BASE", "41000") or "41000")
TC_BURST_MS = int(os.getenv("REALM_QOS_TC_BURST_MS", "100") or "100")
TC_STATE_FILE = Path(os.getenv("REALM_QOS_TC_STATE_FILE", "/etc/realm-agent/qos_tc_state.json"))


@dataclass
class QoSPolicy:
    port: int
    protocols: Set[str]
    bandwidth_kbps: Optional[int] = None
    max_conns: Optional[int] = None
    conn_rate: Optional[int] = None
    traffic_total_bytes: Optional[int] = None


def _now_ts() -> int:
    return int(time.time())


def _is_noexist_err(text: str) -> bool:
    s = str(text or "").strip().lower()
    if not s:
        return False
    keys = (
        "no such file",
        "does not exist",
        "not found",
        "can't find",
        "cannot find",
        "不存在",
    )
    return any(k in s for k in keys)


def _to_int(v: Any) -> Optional[int]:
    if isinstance(v, bool):
        return int(v)
    if isinstance(v, int):
        return int(v)
    if isinstance(v, float):
        if not (v == v):
            return None
        return int(v)

    s = str(v or "").strip()
    if not s:
        return None
    try:
        if re.match(r"^-?\d+$", s):
            return int(s)
        return int(float(s))
    except Exception:
        return None


def _parse_listen_port(listen: Any) -> int:
    s = str(listen or "").strip()
    if not s:
        return 0

    if s.startswith("[") and "]:" in s:
        try:
            return int(s.rsplit("]:", 1)[1])
        except Exception:
            return 0

    if ":" in s:
        try:
            return int(s.rsplit(":", 1)[1])
        except Exception:
            return 0
    return 0


def _proto_set(v: Any) -> Set[str]:
    p = str(v or "tcp+udp").strip().lower()
    if p == "tcp":
        return {"tcp"}
    if p == "udp":
        return {"udp"}
    return {"tcp", "udp"}


def _sanitize_positive(v: Optional[int]) -> Optional[int]:
    if v is None:
        return None
    if v <= 0:
        return None
    return int(v)


def _read_qos_number(src: Dict[str, Any], keys: Iterable[str]) -> Optional[int]:
    for k in keys:
        if k in src:
            return _to_int(src.get(k))
    return None


def _extract_qos(ep: Dict[str, Any]) -> Tuple[Optional[int], Optional[int], Optional[int], Optional[int]]:
    ex = ep.get("extra_config") if isinstance(ep.get("extra_config"), dict) else {}
    net = ep.get("network") if isinstance(ep.get("network"), dict) else {}
    ex_qos = ex.get("qos") if isinstance(ex.get("qos"), dict) else {}
    net_qos = net.get("qos") if isinstance(net.get("qos"), dict) else {}

    # Priority: extra_config.qos > network.qos > flat keys
    bw_mbps = _read_qos_number(ex_qos, ("bandwidth_mbps", "bandwidth_mb", "bandwidth_limit_mbps"))
    if bw_mbps is None:
        bw_mbps = _read_qos_number(net_qos, ("bandwidth_mbps", "bandwidth_mb", "bandwidth_limit_mbps"))
    if bw_mbps is None:
        bw_mbps = _read_qos_number(ex, ("qos_bandwidth_mbps", "bandwidth_mbps"))
    if bw_mbps is None:
        bw_mbps = _read_qos_number(net, ("qos_bandwidth_mbps", "bandwidth_mbps"))

    bw_kbps = _read_qos_number(ex_qos, ("bandwidth_kbps", "bandwidth_kbit", "bandwidth_limit_kbps"))
    if bw_kbps is None:
        bw_kbps = _read_qos_number(net_qos, ("bandwidth_kbps", "bandwidth_kbit", "bandwidth_limit_kbps"))
    if bw_kbps is None:
        bw_kbps = _read_qos_number(ex, ("qos_bandwidth_kbps", "bandwidth_kbps"))
    if bw_kbps is None:
        bw_kbps = _read_qos_number(net, ("qos_bandwidth_kbps", "bandwidth_kbps"))

    if bw_kbps is None and bw_mbps is not None:
        bw_kbps = int(bw_mbps) * 1024

    max_conns = _read_qos_number(ex_qos, ("max_conns", "max_connections", "max_conn"))
    if max_conns is None:
        max_conns = _read_qos_number(net_qos, ("max_conns", "max_connections", "max_conn"))
    if max_conns is None:
        max_conns = _read_qos_number(ex, ("qos_max_conns", "max_conns"))
    if max_conns is None:
        max_conns = _read_qos_number(net, ("qos_max_conns", "max_conns"))

    conn_rate = _read_qos_number(
        ex_qos,
        ("conn_rate", "new_conn_per_sec", "new_connections_per_sec", "conn_per_sec"),
    )
    if conn_rate is None:
        conn_rate = _read_qos_number(
            net_qos,
            ("conn_rate", "new_conn_per_sec", "new_connections_per_sec", "conn_per_sec"),
        )
    if conn_rate is None:
        conn_rate = _read_qos_number(ex, ("qos_conn_rate", "conn_rate", "new_conn_per_sec"))
    if conn_rate is None:
        conn_rate = _read_qos_number(net, ("qos_conn_rate", "conn_rate", "new_conn_per_sec"))

    traffic_total_bytes = _read_qos_number(
        ex_qos,
        ("traffic_total_bytes", "traffic_bytes", "traffic_limit_bytes"),
    )
    if traffic_total_bytes is None:
        traffic_total_bytes = _read_qos_number(
            net_qos,
            ("traffic_total_bytes", "traffic_bytes", "traffic_limit_bytes"),
        )
    if traffic_total_bytes is None:
        traffic_total_bytes = _read_qos_number(ex, ("qos_traffic_total_bytes", "traffic_total_bytes", "traffic_bytes"))
    if traffic_total_bytes is None:
        traffic_total_bytes = _read_qos_number(net, ("qos_traffic_total_bytes", "traffic_total_bytes", "traffic_bytes"))

    traffic_total_gb = _read_qos_number(
        ex_qos,
        ("traffic_total_gb", "traffic_gb", "traffic_limit_gb"),
    )
    if traffic_total_gb is None:
        traffic_total_gb = _read_qos_number(
            net_qos,
            ("traffic_total_gb", "traffic_gb", "traffic_limit_gb"),
        )
    if traffic_total_gb is None:
        traffic_total_gb = _read_qos_number(ex, ("qos_traffic_total_gb", "traffic_total_gb", "traffic_gb"))
    if traffic_total_gb is None:
        traffic_total_gb = _read_qos_number(net, ("qos_traffic_total_gb", "traffic_total_gb", "traffic_gb"))

    if traffic_total_bytes is None and traffic_total_gb is not None:
        try:
            traffic_total_bytes = int(traffic_total_gb) * 1024 * 1024 * 1024
        except Exception:
            traffic_total_bytes = None

    return (
        _sanitize_positive(bw_kbps),
        _sanitize_positive(max_conns),
        _sanitize_positive(conn_rate),
        _sanitize_positive(traffic_total_bytes),
    )


def policies_from_pool(pool: Dict[str, Any]) -> Tuple[List[QoSPolicy], List[str]]:
    warnings: List[str] = []
    if not isinstance(pool, dict):
        return [], ["pool 不是对象，跳过 QoS"]
    eps = pool.get("endpoints")
    if not isinstance(eps, list):
        return [], []

    by_port: Dict[int, QoSPolicy] = {}
    for idx, ep in enumerate(eps):
        if not isinstance(ep, dict):
            continue
        if bool(ep.get("disabled")):
            continue

        port = _parse_listen_port(ep.get("listen"))
        if port <= 0 or port > 65535:
            continue

        bw_kbps, max_conns, conn_rate, traffic_total_bytes = _extract_qos(ep)
        if bw_kbps is None and max_conns is None and conn_rate is None and traffic_total_bytes is None:
            continue

        pset = _proto_set(ep.get("protocol"))
        cur = by_port.get(port)
        if cur is None:
            by_port[port] = QoSPolicy(
                port=port,
                protocols=set(pset),
                bandwidth_kbps=bw_kbps,
                max_conns=max_conns,
                conn_rate=conn_rate,
                traffic_total_bytes=traffic_total_bytes,
            )
            continue

        # Same listen port cannot carry two independent QoS stacks. Merge using stricter values.
        cur.protocols |= set(pset)
        if bw_kbps is not None:
            cur.bandwidth_kbps = bw_kbps if cur.bandwidth_kbps is None else min(cur.bandwidth_kbps, bw_kbps)
        if max_conns is not None:
            cur.max_conns = max_conns if cur.max_conns is None else min(cur.max_conns, max_conns)
        if conn_rate is not None:
            cur.conn_rate = conn_rate if cur.conn_rate is None else min(cur.conn_rate, conn_rate)
        if traffic_total_bytes is not None:
            cur.traffic_total_bytes = (
                traffic_total_bytes
                if cur.traffic_total_bytes is None
                else min(cur.traffic_total_bytes, traffic_total_bytes)
            )
        warnings.append(f"端口 {port} 存在多条 QoS 规则，已自动合并为更严格限制（endpoints[{idx}]）")

    return sorted(by_port.values(), key=lambda x: x.port), warnings


def _copy_policy(
    p: QoSPolicy,
    *,
    keep_bandwidth: bool,
    keep_conn_controls: bool,
) -> QoSPolicy:
    return QoSPolicy(
        port=int(p.port),
        protocols=set(p.protocols),
        bandwidth_kbps=int(p.bandwidth_kbps) if (keep_bandwidth and p.bandwidth_kbps is not None) else None,
        max_conns=int(p.max_conns) if (keep_conn_controls and p.max_conns is not None) else None,
        conn_rate=int(p.conn_rate) if (keep_conn_controls and p.conn_rate is not None) else None,
        traffic_total_bytes=int(p.traffic_total_bytes) if p.traffic_total_bytes is not None else None,
    )


def _has_conn_controls(policies: List[QoSPolicy]) -> bool:
    return any((p.max_conns is not None) or (p.conn_rate is not None) for p in policies)


def _has_bandwidth_controls(policies: List[QoSPolicy]) -> bool:
    return any(p.bandwidth_kbps is not None for p in policies)


class _IptablesBackend:
    def __init__(self, table: str = IPT_TABLE, chain: str = IPT_CHAIN):
        self.table = table
        self.chain = chain

    @property
    def available(self) -> bool:
        return iptables_available()

    def _run(self, args: List[str]) -> Tuple[int, str, str]:
        return run_iptables(args, timeout=IPT_TIMEOUT)

    def _ensure_chain(self) -> None:
        self._run(["-t", self.table, "-N", self.chain])
        self._run(["-t", self.table, "-F", self.chain])

    def _delete_jump_rules(self, base_chain: str) -> None:
        rc, out, _ = self._run(["-t", self.table, "-S", base_chain])
        if rc == 0:
            lines = [ln.strip() for ln in (out or "").splitlines() if ln.strip()]
            for ln in lines:
                if not ln.startswith(f"-A {base_chain} "):
                    continue
                if f"-j {self.chain}" not in ln:
                    continue
                try:
                    toks = ln.split()
                    if toks[:2] != ["-A", base_chain]:
                        continue
                    toks[0] = "-D"
                    self._run(["-t", self.table, *toks])
                except Exception:
                    continue
            return

        while True:
            rc2, _, _ = self._run(["-t", self.table, "-D", base_chain, "-j", self.chain])
            if rc2 != 0:
                break

    def _ensure_jump(self) -> None:
        base_chain = "INPUT"
        self._delete_jump_rules(base_chain)
        self._run(["-t", self.table, "-I", base_chain, "1", "-j", self.chain])

    def clear(self) -> Dict[str, Any]:
        out = {"ok": True, "backend": "iptables", "warnings": [], "errors": []}
        self._delete_jump_rules("INPUT")

        for args in (
            ["-t", self.table, "-F", self.chain],
            ["-t", self.table, "-X", self.chain],
        ):
            rc, _o, err = self._run(args)
            if rc != 0 and not _is_noexist_err(err):
                out["ok"] = False
                out["errors"].append(err.strip() or "iptables clear 失败")
        return out

    def _hashlimit_name(self, prefix: str, port: int, proto: str) -> str:
        suffix = "t" if proto == "tcp" else "u"
        raw = f"rq{prefix}{port}{suffix}"
        return raw[:24]

    def _append(self, args: List[str]) -> Tuple[bool, str]:
        rc, _o, err = self._run(args)
        if rc == 0:
            return True, ""
        return False, (err.strip() or f"iptables rc={rc}")

    def _append_bandwidth_rule(self, proto: str, port: int, kbps: int) -> Tuple[bool, str]:
        name = self._hashlimit_name("bw", port, proto)
        rates = [f"{kbps}kb/s", f"{kbps}kb/sec", f"{kbps}kbit/s"]
        last_err = "unknown"
        for rate in rates:
            ok, err = self._append(
                [
                    "-t",
                    self.table,
                    "-A",
                    self.chain,
                    "-p",
                    proto,
                    "--dport",
                    str(port),
                    "-m",
                    "hashlimit",
                    "--hashlimit-mode",
                    "dstport",
                    "--hashlimit-name",
                    name,
                    "--hashlimit-above",
                    rate,
                    "-j",
                    "DROP",
                ]
            )
            if ok:
                return True, ""
            last_err = err
        return False, last_err

    def _append_connlimit_rule(self, port: int, max_conns: int) -> Tuple[bool, str]:
        common = [
            "-t",
            self.table,
            "-A",
            self.chain,
            "-p",
            "tcp",
            "--dport",
            str(port),
            "-m",
            "connlimit",
            "--connlimit-above",
            str(max_conns),
            "--connlimit-mask",
            "0",
        ]
        ok, err = self._append(common + ["-j", "REJECT", "--reject-with", "tcp-reset"])
        if ok:
            return True, ""
        ok2, err2 = self._append(common + ["-j", "DROP"])
        if ok2:
            return True, ""
        return False, err2 or err

    def _append_connrate_rule(self, proto: str, port: int, rate: int) -> Tuple[bool, str]:
        name = self._hashlimit_name("cr", port, proto)
        common = [
            "-t",
            self.table,
            "-A",
            self.chain,
            "-p",
            proto,
            "--dport",
            str(port),
            "-m",
            "conntrack",
            "--ctstate",
            "NEW",
            "-m",
            "hashlimit",
            "--hashlimit-mode",
            "dstport",
            "--hashlimit-name",
            name,
            "--hashlimit-above",
            f"{rate}/second",
            "--hashlimit-burst",
            str(max(rate, 1)),
            "-j",
            "DROP",
        ]
        return self._append(common)

    def apply(self, policies: List[QoSPolicy]) -> Dict[str, Any]:
        out: Dict[str, Any] = {
            "ok": True,
            "backend": "iptables",
            "table": self.table,
            "chain": self.chain,
            "warnings": [],
            "errors": [],
            "stats": {
                "ports": 0,
                "rules": 0,
                "bandwidth_rules": 0,
                "max_conns_rules": 0,
                "conn_rate_rules": 0,
            },
        }

        if not policies:
            clr = self.clear()
            out["ok"] = bool(clr.get("ok", False))
            out["warnings"].extend(list(clr.get("warnings") or []))
            out["errors"].extend(list(clr.get("errors") or []))
            return out

        self._ensure_chain()
        self._ensure_jump()

        for p in policies:
            out["stats"]["ports"] += 1
            protos = sorted([x for x in p.protocols if x in ("tcp", "udp")])
            if not protos:
                protos = ["tcp", "udp"]

            if p.max_conns is not None:
                if "tcp" not in protos:
                    out["warnings"].append(f"max_conns port {p.port} 仅支持 TCP，已跳过")
                else:
                    ok, err = self._append_connlimit_rule(p.port, p.max_conns)
                    if ok:
                        out["stats"]["rules"] += 1
                        out["stats"]["max_conns_rules"] += 1
                    else:
                        out["ok"] = False
                        out["errors"].append(f"max_conns port {p.port} 下发失败: {err}")

            if p.conn_rate is not None:
                for proto in protos:
                    ok, err = self._append_connrate_rule(proto, p.port, p.conn_rate)
                    if ok:
                        out["stats"]["rules"] += 1
                        out["stats"]["conn_rate_rules"] += 1
                    else:
                        out["ok"] = False
                        out["errors"].append(f"conn_rate port {p.port}/{proto} 下发失败: {err}")

            if p.bandwidth_kbps is not None:
                for proto in protos:
                    ok, err = self._append_bandwidth_rule(proto, p.port, p.bandwidth_kbps)
                    if ok:
                        out["stats"]["rules"] += 1
                        out["stats"]["bandwidth_rules"] += 1
                    else:
                        out["ok"] = False
                        out["errors"].append(f"bandwidth port {p.port}/{proto} 下发失败: {err}")

        return out


class _NftablesBackend:
    def __init__(
        self,
        family: str = NFT_FAMILY,
        table: str = NFT_TABLE,
        chain: str = NFT_CHAIN,
        priority: str = NFT_PRIORITY,
    ):
        self.family = family
        self.table = table
        self.chain = chain
        self.priority = priority

    @property
    def available(self) -> bool:
        return bool(shutil.which("nft"))

    def _run(self, args: List[str], stdin_text: Optional[str] = None) -> Tuple[int, str, str]:
        try:
            proc = subprocess.run(
                ["nft", *args],
                input=stdin_text,
                capture_output=True,
                text=True,
                timeout=NFT_TIMEOUT,
            )
            return proc.returncode, (proc.stdout or ""), (proc.stderr or "")
        except Exception as exc:
            return 127, "", str(exc)

    def clear(self) -> Dict[str, Any]:
        out = {"ok": True, "backend": "nftables", "warnings": [], "errors": []}
        rc, _o, err = self._run(["delete", "table", self.family, self.table])
        if rc != 0 and not _is_noexist_err(err):
            out["ok"] = False
            out["errors"].append(err.strip() or "nft delete table 失败")
        return out

    def _build_rules(
        self,
        policies: List[QoSPolicy],
        *,
        include_bandwidth: bool,
    ) -> Tuple[List[str], Dict[str, int], List[str]]:
        rules: List[str] = []
        warnings: List[str] = []
        stats = {
            "ports": 0,
            "rules": 0,
            "bandwidth_rules": 0,
            "max_conns_rules": 0,
            "conn_rate_rules": 0,
        }

        for p in policies:
            stats["ports"] += 1
            protos = sorted([x for x in p.protocols if x in ("tcp", "udp")])
            if not protos:
                protos = ["tcp", "udp"]

            if p.max_conns is not None:
                if "tcp" not in protos:
                    warnings.append(f"max_conns port {p.port} 仅支持 TCP，已跳过")
                else:
                    rules.append(f"tcp dport {p.port} ct count over {int(p.max_conns)} drop")
                    stats["rules"] += 1
                    stats["max_conns_rules"] += 1

            if p.conn_rate is not None:
                for proto in protos:
                    rules.append(
                        f"{proto} dport {p.port} ct state new limit rate over {int(p.conn_rate)}/second drop"
                    )
                    stats["rules"] += 1
                    stats["conn_rate_rules"] += 1

            if include_bandwidth and p.bandwidth_kbps is not None:
                bytes_per_sec = max(1, int(int(p.bandwidth_kbps) * 128))
                for proto in protos:
                    rules.append(f"{proto} dport {p.port} limit rate over {bytes_per_sec} bytes/second drop")
                    stats["rules"] += 1
                    stats["bandwidth_rules"] += 1

        return rules, stats, warnings

    def apply(self, policies: List[QoSPolicy], *, include_bandwidth: bool) -> Dict[str, Any]:
        out: Dict[str, Any] = {
            "ok": True,
            "backend": "nftables",
            "family": self.family,
            "table": self.table,
            "chain": self.chain,
            "warnings": [],
            "errors": [],
            "stats": {
                "ports": 0,
                "rules": 0,
                "bandwidth_rules": 0,
                "max_conns_rules": 0,
                "conn_rate_rules": 0,
            },
        }

        if not policies:
            clr = self.clear()
            out["ok"] = bool(clr.get("ok", False))
            out["warnings"].extend(list(clr.get("warnings") or []))
            out["errors"].extend(list(clr.get("errors") or []))
            return out

        # Ensure stale table is cleaned before recreate.
        clr = self.clear()
        if not clr.get("ok", True):
            out["warnings"].append("清理旧 nftables 规则失败，尝试继续覆盖")
            out["errors"].extend(list(clr.get("errors") or []))

        rules, stats, warns = self._build_rules(policies, include_bandwidth=include_bandwidth)
        out["stats"] = stats
        out["warnings"].extend(warns)

        lines: List[str] = [
            f"table {self.family} {self.table} {{",
            f"  chain {self.chain} {{",
            f"    type filter hook input priority {self.priority}; policy accept;",
        ]
        for r in rules:
            lines.append(f"    {r}")
        lines += ["  }", "}", ""]
        script = "\n".join(lines)

        rc, _o, err = self._run(["-f", "-"], stdin_text=script)
        if rc != 0:
            out["ok"] = False
            out["errors"].append(err.strip() or "nft apply 失败")

        return out


class _TcBackend:
    def __init__(self, state_file: Path = TC_STATE_FILE):
        self.state_file = state_file

    @property
    def available(self) -> bool:
        return bool(shutil.which("tc"))

    def _run(self, args: List[str]) -> Tuple[int, str, str]:
        try:
            proc = subprocess.run(
                ["tc", *args],
                capture_output=True,
                text=True,
                timeout=TC_TIMEOUT,
            )
            return proc.returncode, (proc.stdout or ""), (proc.stderr or "")
        except Exception as exc:
            return 127, "", str(exc)

    def _list_interfaces(self) -> List[str]:
        out: List[str] = []
        base = Path("/sys/class/net")
        if not base.exists():
            return out
        for p in sorted(base.iterdir(), key=lambda x: x.name):
            name = p.name
            if not name or name == "lo":
                continue
            out.append(name)
        return out

    def _load_state(self) -> Dict[str, Any]:
        try:
            data = json.loads(self.state_file.read_text(encoding="utf-8"))
            if isinstance(data, dict):
                return data
        except Exception:
            pass
        return {"interfaces": {}}

    def _save_state(self, data: Dict[str, Any]) -> None:
        try:
            self.state_file.parent.mkdir(parents=True, exist_ok=True)
            self.state_file.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
        except Exception:
            pass

    def clear(self) -> Dict[str, Any]:
        out = {"ok": True, "backend": "tc", "warnings": [], "errors": []}
        st = self._load_state()
        interfaces = st.get("interfaces") if isinstance(st.get("interfaces"), dict) else {}

        for iface, prefs in interfaces.items():
            if not iface:
                continue
            lst = prefs if isinstance(prefs, list) else []
            for pref in sorted({int(x) for x in lst if isinstance(x, int) or str(x).isdigit()}):
                rc, _o, err = self._run(["filter", "del", "dev", str(iface), "ingress", "pref", str(pref)])
                if rc != 0 and not _is_noexist_err(err):
                    out["ok"] = False
                    out["errors"].append(f"{iface} pref {pref}: {err.strip() or 'tc del 失败'}")

        self._save_state({"interfaces": {}, "updated_at": _now_ts()})
        return out

    def _ensure_clsact(self, iface: str) -> Tuple[bool, str]:
        rc, _o, err = self._run(["qdisc", "replace", "dev", iface, "clsact"])
        if rc == 0:
            return True, ""
        return False, err.strip() or "tc qdisc replace 失败"

    def _add_bandwidth_filter(self, iface: str, pref: int, proto: str, family: str, port: int, kbps: int) -> Tuple[bool, str]:
        burst_bytes = max(8192, int((int(kbps) * 128) * max(10, TC_BURST_MS) / 1000.0))
        cmd = [
            "filter",
            "add",
            "dev",
            iface,
            "ingress",
            "pref",
            str(pref),
            "protocol",
            family,
            "flower",
            "ip_proto",
            proto,
            "dst_port",
            str(port),
            "action",
            "police",
            "rate",
            f"{int(kbps)}kbit",
            "burst",
            str(burst_bytes),
            "drop",
        ]
        rc, _o, err = self._run(cmd)
        if rc == 0:
            return True, ""
        return False, err.strip() or "tc filter add 失败"

    def apply(self, policies: List[QoSPolicy]) -> Dict[str, Any]:
        out: Dict[str, Any] = {
            "ok": True,
            "backend": "tc",
            "warnings": [],
            "errors": [],
            "stats": {
                "ports": 0,
                "rules": 0,
                "bandwidth_rules": 0,
                "max_conns_rules": 0,
                "conn_rate_rules": 0,
            },
        }

        # Always clear previous tc filters first, then re-apply desired state.
        clr = self.clear()
        if not clr.get("ok", True):
            out["warnings"].append("清理旧 tc 规则失败，尝试继续覆盖")
            out["errors"].extend(list(clr.get("errors") or []))

        bw_policies = [p for p in policies if p.bandwidth_kbps is not None]
        if not bw_policies:
            return out

        ifaces = self._list_interfaces()
        if not ifaces:
            out["ok"] = False
            out["errors"].append("未找到可用网卡，无法应用 tc 带宽限速")
            return out

        pref = max(1000, int(TC_PREF_BASE))
        state_ifaces: Dict[str, List[int]] = {}

        for iface in ifaces:
            ok_qdisc, err_qdisc = self._ensure_clsact(iface)
            if not ok_qdisc:
                out["ok"] = False
                out["errors"].append(f"{iface}: {err_qdisc}")
                continue

            added: List[int] = []
            for p in bw_policies:
                out["stats"]["ports"] += 1
                protos = sorted([x for x in p.protocols if x in ("tcp", "udp")])
                if not protos:
                    protos = ["tcp", "udp"]

                for proto in protos:
                    for family in ("ip", "ipv6"):
                        pref += 1
                        ok_f, err_f = self._add_bandwidth_filter(
                            iface=iface,
                            pref=pref,
                            proto=proto,
                            family=family,
                            port=int(p.port),
                            kbps=int(p.bandwidth_kbps or 0),
                        )
                        if ok_f:
                            added.append(pref)
                            out["stats"]["rules"] += 1
                            out["stats"]["bandwidth_rules"] += 1
                        else:
                            out["ok"] = False
                            out["errors"].append(f"{iface} {proto}/{family} dport {p.port}: {err_f}")

            if added:
                state_ifaces[iface] = added

        self._save_state({"interfaces": state_ifaces, "updated_at": _now_ts()})
        return out


def _merge_backend_result(
    result: Dict[str, Any],
    backend_name: str,
    part: Dict[str, Any],
    *,
    strict: bool = True,
) -> None:
    if strict:
        result["ok"] = bool(result.get("ok", True)) and bool(part.get("ok", False))

    for w in (part.get("warnings") or []):
        s = str(w or "").strip()
        if s:
            result.setdefault("warnings", []).append(f"[{backend_name}] {s}")

    for e in (part.get("errors") or []):
        s = str(e or "").strip()
        if s:
            result.setdefault("errors", []).append(f"[{backend_name}] {s}")

    src_stats = part.get("stats") if isinstance(part.get("stats"), dict) else {}
    dst_stats = result.get("stats") if isinstance(result.get("stats"), dict) else {}
    for k in ("rules", "bandwidth_rules", "max_conns_rules", "conn_rate_rules"):
        dst_stats[k] = int(dst_stats.get(k) or 0) + int(src_stats.get(k) or 0)
    result["stats"] = dst_stats


def _strip_policies(
    policies: List[QoSPolicy],
    *,
    keep_bandwidth: bool,
    keep_conn_controls: bool,
) -> List[QoSPolicy]:
    out: List[QoSPolicy] = []
    for p in policies:
        cp = _copy_policy(p, keep_bandwidth=keep_bandwidth, keep_conn_controls=keep_conn_controls)
        if cp.bandwidth_kbps is None and cp.max_conns is None and cp.conn_rate is None:
            continue
        out.append(cp)
    return out


def apply_qos_from_pool(pool: Dict[str, Any]) -> Dict[str, Any]:
    policies, warnings = policies_from_pool(pool)

    ipt = _IptablesBackend()
    nft = _NftablesBackend()
    tc = _TcBackend()

    caps = {
        "iptables": ipt.available,
        "nftables": nft.available,
        "tc": tc.available,
    }

    result: Dict[str, Any] = {
        "ok": True,
        "ts": _now_ts(),
        "backend": "none",
        "caps": caps,
        "policies": [
            {
                "port": p.port,
                "protocols": sorted(list(p.protocols)),
                "bandwidth_kbps": p.bandwidth_kbps,
                "max_conns": p.max_conns,
                "conn_rate": p.conn_rate,
                "traffic_total_bytes": p.traffic_total_bytes,
            }
            for p in policies
        ],
        "warnings": list(warnings),
        "errors": [],
        "stats": {
            "ports": len(policies),
            "rules": 0,
            "bandwidth_rules": 0,
            "max_conns_rules": 0,
            "conn_rate_rules": 0,
        },
    }

    backends = {
        "iptables": ipt,
        "nftables": nft,
        "tc": tc,
    }

    # No QoS policy: clear all available backends.
    if not policies:
        for name in ("nftables", "iptables", "tc"):
            if not caps.get(name, False):
                continue
            part = backends[name].clear()
            _merge_backend_result(result, name, part)
        result["backend"] = "none"
        return result

    need_conn = _has_conn_controls(policies)
    need_bw = _has_bandwidth_controls(policies)

    conn_backend = "nftables" if caps["nftables"] else ("iptables" if caps["iptables"] else "")
    bw_backend = "tc" if caps["tc"] else conn_backend

    selected: Set[str] = set()

    if need_conn and not conn_backend:
        result["ok"] = False
        result["warnings"].append("连接并发/连接速率限制无可用后端（需 nftables 或 iptables）")
    if need_bw and not bw_backend:
        result["ok"] = False
        result["warnings"].append("带宽限速无可用后端（需 tc / nftables / iptables）")

    # Same backend handles both conn controls and bandwidth.
    if (
        need_conn
        and need_bw
        and conn_backend
        and bw_backend
        and conn_backend == bw_backend
        and conn_backend in ("nftables", "iptables")
    ):
        selected.add(conn_backend)
        if conn_backend == "nftables":
            part = nft.apply(policies, include_bandwidth=True)
        else:
            part = ipt.apply(policies)
        _merge_backend_result(result, conn_backend, part)
    else:
        if need_conn and conn_backend:
            selected.add(conn_backend)
            conn_only = _strip_policies(policies, keep_bandwidth=False, keep_conn_controls=True)
            if conn_backend == "nftables":
                part = nft.apply(conn_only, include_bandwidth=False)
            else:
                part = ipt.apply(conn_only)
            _merge_backend_result(result, conn_backend, part)

        if need_bw and bw_backend:
            selected.add(bw_backend)
            bw_only = _strip_policies(policies, keep_bandwidth=True, keep_conn_controls=False)
            if bw_backend == "tc":
                part = tc.apply(bw_only)
            elif bw_backend == "nftables":
                part = nft.apply(bw_only, include_bandwidth=True)
            else:
                part = ipt.apply(bw_only)
            _merge_backend_result(result, bw_backend, part)

    # Clear stale rules from backends that are currently not selected.
    for name in ("nftables", "iptables", "tc"):
        if not caps.get(name, False):
            continue
        if name in selected:
            continue
        part = backends[name].clear()
        _merge_backend_result(result, name, part, strict=False)

    if selected:
        ordered = [x for x in ("nftables", "iptables", "tc") if x in selected]
        result["backend"] = "+".join(ordered)
    else:
        result["backend"] = "none"

    return result
