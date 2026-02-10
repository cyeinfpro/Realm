from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import urlparse

from .normalize import format_addr, split_host_port


@dataclass
class PoolValidationIssue:
    """A single validation issue."""

    path: str
    message: str
    severity: str = "error"
    code: str = ""


class PoolValidationError(ValueError):
    def __init__(self, message: str, issues: Optional[List[PoolValidationIssue]] = None):
        super().__init__(message)
        self.issues = issues or []


def _proto_set(proto: Any) -> Set[str]:
    p = str(proto or "tcp+udp").strip().lower()
    if p == "tcp":
        return {"tcp"}
    if p == "udp":
        return {"udp"}
    # default (tcp+udp) or unknown
    return {"tcp", "udp"}


def _format_proto(pset: Set[str]) -> str:
    if pset == {"tcp"}:
        return "TCP"
    if pset == {"udp"}:
        return "UDP"
    return "TCP+UDP"


def _norm_algo(algo: str) -> str:
    a = (algo or "").strip().lower()
    for ch in ("_", "-", " "):
        a = a.replace(ch, "")
    return "iphash" if a == "iphash" else "roundrobin"


def _parse_balance_weights(balance: Any) -> Tuple[str, List[str]]:
    """Parse balance string, returning (algo, weights).

    - algo: 'roundrobin' or 'iphash'
    - weights: only returned when balance contains an explicit ':' part.
    """

    b = str(balance or "roundrobin").strip()
    if not b:
        return "roundrobin", []
    if ":" not in b:
        return _norm_algo(b), []
    left, right = b.split(":", 1)
    algo = _norm_algo(left)
    raw = [x.strip() for x in right.replace("，", ",").split(",")]
    weights = [x for x in raw if x]
    return algo, weights


def _is_positive_int(s: str) -> bool:
    if not s:
        return False
    if not s.isdigit():
        return False
    try:
        return int(s) > 0
    except Exception:
        return False


def _coerce_nonneg_int(raw: Any) -> Optional[int]:
    if raw is None:
        return None
    if isinstance(raw, bool):
        return int(raw)
    if isinstance(raw, int):
        return int(raw)
    if isinstance(raw, float):
        if not (raw == raw):  # NaN
            return None
        n = int(raw)
        if n < 0:
            return None
        return n
    s = str(raw).strip()
    if not s:
        return None
    try:
        if s.isdigit() or (s.startswith("-") and s[1:].isdigit()):
            n = int(s)
        else:
            n = int(float(s))
        if n < 0:
            return None
        return n
    except Exception:
        return None


def parse_host_port_str(value: Any) -> Tuple[str, int]:
    """Parse host:port into (host, port).

    Accepts:
      - host:port
      - [ipv6]:port
      - raw_ipv6:port (will be normalized later)
      - scheme://host:port/... (port required)
    """

    s = str(value or "").strip()
    if not s:
        raise ValueError("地址不能为空")

    if s.startswith("ws;") or s.startswith("wss;"):
        raise ValueError("地址格式错误：这里应填写 host:port，不应包含 ws; 参数")

    if "://" in s:
        try:
            u = urlparse(s)
            host = (u.hostname or "").strip()
            port = u.port
            if not host:
                raise ValueError("缺少主机名")
            if port is None:
                raise ValueError("缺少端口")
            return host, int(port)
        except Exception as exc:
            raise ValueError(f"URL 解析失败：{exc}")

    host, port = split_host_port(s)
    if port is None:
        raise ValueError("缺少端口或端口格式错误")
    host = str(host or "").strip()
    if not host:
        raise ValueError("缺少主机名")
    return host, int(port)


def normalize_host_port_str(value: Any) -> str:
    host, port = parse_host_port_str(value)
    if port < 1 or port > 65535:
        raise ValueError("端口范围必须是 1-65535")
    return format_addr(host, port)


def normalize_listen_str(value: Any, *, allow_zero_port: bool = False) -> Tuple[str, int]:
    """Normalize listen string to canonical host:port.

    - Missing host is treated as 0.0.0.0
    - Port must be 1-65535 unless allow_zero_port=True
    """

    s = str(value or "").strip()
    if not s:
        raise ValueError("listen 不能为空")
    host, port = split_host_port(s)
    if port is None:
        raise ValueError("listen 格式不正确，请使用 0.0.0.0:端口")
    host = str(host or "").strip() or "0.0.0.0"
    try:
        p = int(port)
    except Exception:
        raise ValueError("listen 端口必须是数字")

    if allow_zero_port and p == 0:
        return format_addr(host, 0), 0
    if p < 1 or p > 65535:
        raise ValueError("listen 端口范围必须是 1-65535")
    return format_addr(host, p), p


def _host_info(host: str) -> Tuple[str, bool, Optional[ipaddress._BaseAddress]]:
    """Return (family, is_wildcard, ip_obj_or_none)."""

    h = str(host or "").strip()
    if not h:
        return "unknown", True, None

    # Allow zone index for IPv6 literal: fe80::1%eth0
    core_nozone = h.split("%", 1)[0]
    try:
        ip = ipaddress.ip_address(core_nozone)
        fam = "v6" if ip.version == 6 else "v4"
        return fam, bool(ip.is_unspecified), ip
    except Exception:
        return "unknown", False, None


def _hosts_overlap(a_host: str, b_host: str) -> bool:
    """Best-effort overlap check for bind addresses."""

    fam_a, wild_a, ip_a = _host_info(a_host)
    fam_b, wild_b, ip_b = _host_info(b_host)

    # Unknown/hostname binds are treated conservatively.
    if fam_a == "unknown" or fam_b == "unknown":
        return True

    if fam_a != fam_b:
        # v4 vs v6: wildcard may overlap depending on OS dual-stack settings.
        return bool(wild_a or wild_b)

    # Same family
    if wild_a or wild_b:
        return True
    if ip_a is not None and ip_b is not None:
        return ip_a == ip_b
    return str(a_host).strip().lower() == str(b_host).strip().lower()


def _transport_tokens(transport: Any) -> List[str]:
    return [seg.strip() for seg in str(transport or "").split(";") if seg and str(seg).strip()]


def _transport_param(transport: Any, key: str) -> str:
    want = str(key or "").strip().lower()
    if not want:
        return ""
    for seg in _transport_tokens(transport):
        if "=" not in seg:
            continue
        k, v = seg.split("=", 1)
        if k.strip().lower() == want:
            return v.strip()
    return ""


def _transport_has_flag(transport: Any, flag: str) -> bool:
    want = str(flag or "").strip().lower()
    if not want:
        return False
    for seg in _transport_tokens(transport):
        s = seg.strip().lower()
        if not s or "=" in s:
            continue
        if s == want:
            return True
    return False


def _is_ws_transport(transport: Any) -> bool:
    toks = _transport_tokens(transport)
    if not toks:
        return False
    head = toks[0].strip().lower()
    return head in ("ws", "wss")


def _is_ip_literal(host: str) -> bool:
    h = str(host or "").strip()
    if not h:
        return False
    core = h.split("%", 1)[0]
    try:
        ipaddress.ip_address(core)
        return True
    except Exception:
        return False


def _looks_like_hostname(host: str) -> bool:
    h = str(host or "").strip().strip("[]")
    if not h:
        return False
    if _is_ip_literal(h):
        return False
    return any(ch.isalpha() for ch in h)


def _collect_endpoint_remotes(ep: Dict[str, Any]) -> List[str]:
    rems: List[str] = []
    if isinstance(ep.get("remote"), str) and str(ep.get("remote") or "").strip():
        rems.append(str(ep.get("remote") or "").strip())
    if isinstance(ep.get("remotes"), list):
        rems += [str(x).strip() for x in ep.get("remotes") or [] if str(x).strip()]
    if isinstance(ep.get("extra_remotes"), list):
        rems += [str(x).strip() for x in ep.get("extra_remotes") or [] if str(x).strip()]

    out: List[str] = []
    seen: Set[str] = set()
    for r in rems:
        if r in seen:
            continue
        seen.add(r)
        out.append(r)
    return out


def _warn(path: str, message: str, code: str) -> PoolValidationIssue:
    return PoolValidationIssue(path=path, message=message, severity="warning", code=code)


def validate_pool_inplace(pool: Dict[str, Any]) -> List[PoolValidationIssue]:
    """Validate a pool dict and normalize obvious formatting issues in-place.

    Checks:
      1) listen format + port range
      2) remote format (each host:port)
      3) weights count vs remotes count (when balance explicitly includes weights)
      4) listen port conflicts across endpoints

    Returns:
      - warning issues when validation passes.

    Raises:
      - PoolValidationError on blocking errors.
    """

    if not isinstance(pool, dict):
        raise PoolValidationError("pool 必须是对象")

    eps = pool.get("endpoints")
    if eps is None:
        pool["endpoints"] = []
        return []
    if not isinstance(eps, list):
        raise PoolValidationError("pool.endpoints 必须是数组")

    issues: List[PoolValidationIssue] = []
    warnings: List[PoolValidationIssue] = []

    # ---- Per-endpoint validation + normalization ----
    active_rule_count = 0
    active_udp_enabled = 0
    total_remote_count = 0
    common_tcp_ports = {21, 22, 25, 53, 80, 110, 143, 443, 465, 587, 993, 995, 3306, 5432, 6379, 8080, 8443}

    for idx, ep in enumerate(eps):
        if not isinstance(ep, dict):
            continue

        ex = ep.get("extra_config")
        if not isinstance(ex, dict):
            ex = {}
            ep["extra_config"] = ex

        intranet_role = str(ex.get("intranet_role") or "").strip()
        allow_zero_listen = intranet_role == "client"

        # listen
        try:
            listen_norm, _p = normalize_listen_str(ep.get("listen"), allow_zero_port=allow_zero_listen)
            ep["listen"] = listen_norm
        except Exception as exc:
            issues.append(PoolValidationIssue(path=f"endpoints[{idx}].listen", message=str(exc)))

        # Normalize remotes containers without altering structure.
        # remotes: list
        if isinstance(ep.get("remotes"), list):
            new_list: List[str] = []
            for j, item in enumerate(ep.get("remotes") or []):
                s = str(item or "").strip()
                if not s:
                    continue
                try:
                    new_list.append(normalize_host_port_str(s))
                except Exception as exc:
                    issues.append(
                        PoolValidationIssue(
                            path=f"endpoints[{idx}].remotes[{j}]",
                            message=f"目标地址格式错误（第 {idx+1} 条规则，第 {j+1} 行）：{exc}",
                        )
                    )
            ep["remotes"] = new_list

        # remote: string
        if isinstance(ep.get("remote"), str) and str(ep.get("remote") or "").strip():
            try:
                ep["remote"] = normalize_host_port_str(ep.get("remote"))
            except Exception as exc:
                issues.append(
                    PoolValidationIssue(
                        path=f"endpoints[{idx}].remote",
                        message=f"目标地址格式错误（第 {idx+1} 条规则）：{exc}",
                    )
                )

        # extra_remotes: list
        if isinstance(ep.get("extra_remotes"), list):
            new_list2: List[str] = []
            for j, item in enumerate(ep.get("extra_remotes") or []):
                s = str(item or "").strip()
                if not s:
                    continue
                try:
                    new_list2.append(normalize_host_port_str(s))
                except Exception as exc:
                    issues.append(
                        PoolValidationIssue(
                            path=f"endpoints[{idx}].extra_remotes[{j}]",
                            message=f"目标地址格式错误（第 {idx+1} 条规则，extra_remotes 第 {j+1} 个）：{exc}",
                            )
                        )
            ep["extra_remotes"] = new_list2

        # WSS params / TLS pre-check
        listen_transport = str(ep.get("listen_transport") or ex.get("listen_transport") or "").strip()
        listen_ws_enabled = _is_ws_transport(listen_transport) or bool(ex.get("listen_ws_host") or ex.get("listen_ws_path"))
        if listen_ws_enabled:
            ws_host = str(ex.get("listen_ws_host") or _transport_param(listen_transport, "host") or "").strip()
            ws_path = str(ex.get("listen_ws_path") or _transport_param(listen_transport, "path") or "").strip()
            tls = bool(ex.get("listen_tls_enabled")) or _transport_has_flag(listen_transport, "tls") or str(
                listen_transport
            ).strip().lower().startswith("wss")
            insecure = bool(ex.get("listen_tls_insecure")) or _transport_has_flag(listen_transport, "insecure")
            sni = str(
                ex.get("listen_tls_servername")
                or _transport_param(listen_transport, "servername")
                or _transport_param(listen_transport, "sni")
                or ""
            ).strip()

            if not ws_host or not ws_path:
                miss: List[str] = []
                if not ws_host:
                    miss.append("Host")
                if not ws_path:
                    miss.append("Path")
                issues.append(
                    PoolValidationIssue(
                        path=f"endpoints[{idx}].extra_config",
                        message=f"WSS 参数缺失（第 {idx+1} 条规则，listen 侧）：{' / '.join(miss)} 不能为空",
                        code="wss_param_missing",
                    )
                )
            if tls and insecure:
                warnings.append(
                    _warn(
                        f"endpoints[{idx}].extra_config",
                        f"TLS 校验已关闭（第 {idx+1} 条规则，listen 侧 insecure=true），存在中间人风险",
                        "tls_insecure",
                    )
                )
            if tls and not sni and _looks_like_hostname(ws_host):
                warnings.append(
                    _warn(
                        f"endpoints[{idx}].extra_config",
                        f"TLS 未设置 ServerName（第 {idx+1} 条规则，listen 侧），证书校验可能失败",
                        "tls_sni_missing",
                    )
                )

        remote_transport = str(ep.get("remote_transport") or ex.get("remote_transport") or "").strip()
        remote_ws_enabled = _is_ws_transport(remote_transport) or bool(ex.get("remote_ws_host") or ex.get("remote_ws_path"))
        if remote_ws_enabled:
            ws_host = str(ex.get("remote_ws_host") or _transport_param(remote_transport, "host") or "").strip()
            ws_path = str(ex.get("remote_ws_path") or _transport_param(remote_transport, "path") or "").strip()
            tls = bool(ex.get("remote_tls_enabled")) or _transport_has_flag(remote_transport, "tls") or str(
                remote_transport
            ).strip().lower().startswith("wss")
            insecure = bool(ex.get("remote_tls_insecure")) or _transport_has_flag(remote_transport, "insecure")
            sni = str(
                ex.get("remote_tls_sni")
                or _transport_param(remote_transport, "sni")
                or _transport_param(remote_transport, "servername")
                or ""
            ).strip()

            if not ws_host or not ws_path:
                miss = []
                if not ws_host:
                    miss.append("Host")
                if not ws_path:
                    miss.append("Path")
                issues.append(
                    PoolValidationIssue(
                        path=f"endpoints[{idx}].extra_config",
                        message=f"WSS 参数缺失（第 {idx+1} 条规则，remote 侧）：{' / '.join(miss)} 不能为空",
                        code="wss_param_missing",
                    )
                )
            if tls and insecure:
                warnings.append(
                    _warn(
                        f"endpoints[{idx}].extra_config",
                        f"TLS 校验已关闭（第 {idx+1} 条规则，remote 侧 insecure=true），存在中间人风险",
                        "tls_insecure",
                    )
                )
            if tls and not sni and _looks_like_hostname(ws_host):
                warnings.append(
                    _warn(
                        f"endpoints[{idx}].extra_config",
                        f"TLS 未设置 SNI（第 {idx+1} 条规则，remote 侧），证书校验可能失败",
                        "tls_sni_missing",
                    )
                )

        # weights count check (only when balance explicitly provides weights)
        rems = _collect_endpoint_remotes(ep)
        n = len(rems)
        if n > 1:
            algo, weights = _parse_balance_weights(ep.get("balance"))
            if algo == "roundrobin" and weights:
                if len(weights) != n:
                    issues.append(
                        PoolValidationIssue(
                            path=f"endpoints[{idx}].balance",
                            message=f"权重数量必须与目标行数一致：目标 {n} 行，权重 {len(weights)} 个",
                        )
                    )
                else:
                    bad = [w for w in weights if not _is_positive_int(w)]
                    if bad:
                        issues.append(
                            PoolValidationIssue(
                                path=f"endpoints[{idx}].balance",
                                message=f"权重必须是正整数（非法：{', '.join(bad[:5])}{'…' if len(bad) > 5 else ''}）",
                            )
                        )

        # UDP mis-open hint
        proto = _proto_set(ep.get("protocol"))
        if "udp" in proto and "tcp" in proto:
            ports: List[int] = []
            for r in rems[:16]:
                _h, p = split_host_port(r)
                if p is not None and int(p) > 0:
                    ports.append(int(p))
            if ports and all(p in common_tcp_ports for p in ports):
                warnings.append(
                    _warn(
                        f"endpoints[{idx}].protocol",
                        f"第 {idx+1} 条规则启用了 UDP（TCP+UDP），但目标端口看起来是典型 TCP 端口，可能误开 UDP",
                        "udp_maybe_unintended",
                    )
                )

        # QoS (stored in extra_config.qos, mirrored to network.qos for compatibility)
        net_obj = ep.get("network")
        if not isinstance(net_obj, dict):
            net_obj = {}
        ex_qos = ex.get("qos") if isinstance(ex.get("qos"), dict) else {}
        net_qos = net_obj.get("qos") if isinstance(net_obj.get("qos"), dict) else {}

        def _pick_qos_raw(keys: Tuple[str, ...]) -> Any:
            for src in (ex_qos, net_qos, ex, net_obj, ep):
                if not isinstance(src, dict):
                    continue
                for k in keys:
                    if k in src:
                        return src.get(k)
            return None

        bw_kbps_raw = _pick_qos_raw(("bandwidth_kbps", "bandwidth_kbit", "bandwidth_limit_kbps", "qos_bandwidth_kbps"))
        bw_mbps_raw = _pick_qos_raw(("bandwidth_mbps", "bandwidth_mb", "bandwidth_limit_mbps", "qos_bandwidth_mbps"))
        max_conns_raw = _pick_qos_raw(("max_conns", "max_conn", "max_connections", "qos_max_conns"))
        conn_rate_raw = _pick_qos_raw(
            ("conn_rate", "conn_per_sec", "new_conn_per_sec", "new_connections_per_sec", "qos_conn_rate")
        )
        traffic_bytes_raw = _pick_qos_raw(
            ("traffic_total_bytes", "traffic_bytes", "traffic_limit_bytes", "qos_traffic_total_bytes")
        )
        traffic_gb_raw = _pick_qos_raw(
            ("traffic_total_gb", "traffic_gb", "traffic_limit_gb", "qos_traffic_total_gb")
        )

        bw_kbps = _coerce_nonneg_int(bw_kbps_raw)
        bw_mbps = _coerce_nonneg_int(bw_mbps_raw)
        max_conns = _coerce_nonneg_int(max_conns_raw)
        conn_rate = _coerce_nonneg_int(conn_rate_raw)
        traffic_bytes = _coerce_nonneg_int(traffic_bytes_raw)
        traffic_gb = _coerce_nonneg_int(traffic_gb_raw)

        if bw_kbps is None and (bw_kbps_raw is not None and str(bw_kbps_raw).strip()):
            issues.append(
                PoolValidationIssue(path=f"endpoints[{idx}].extra_config.qos.bandwidth_kbps", message="QoS 带宽必须是非负整数")
            )
        if bw_mbps is None and (bw_mbps_raw is not None and str(bw_mbps_raw).strip()):
            issues.append(
                PoolValidationIssue(path=f"endpoints[{idx}].extra_config.qos.bandwidth_mbps", message="QoS 带宽(Mbps)必须是非负整数")
            )
        if max_conns is None and (max_conns_raw is not None and str(max_conns_raw).strip()):
            issues.append(
                PoolValidationIssue(path=f"endpoints[{idx}].extra_config.qos.max_conns", message="QoS 最大并发必须是非负整数")
            )
        if conn_rate is None and (conn_rate_raw is not None and str(conn_rate_raw).strip()):
            issues.append(
                PoolValidationIssue(path=f"endpoints[{idx}].extra_config.qos.conn_rate", message="QoS 每秒新建连接上限必须是非负整数")
            )
        if traffic_bytes is None and (traffic_bytes_raw is not None and str(traffic_bytes_raw).strip()):
            issues.append(
                PoolValidationIssue(
                    path=f"endpoints[{idx}].extra_config.qos.traffic_total_bytes",
                    message="QoS 总流量上限(bytes)必须是非负整数",
                )
            )
        if traffic_gb is None and (traffic_gb_raw is not None and str(traffic_gb_raw).strip()):
            issues.append(
                PoolValidationIssue(
                    path=f"endpoints[{idx}].extra_config.qos.traffic_total_gb",
                    message="QoS 总流量上限(GB)必须是非负整数",
                )
            )

        if bw_kbps is None and bw_mbps is not None:
            bw_kbps = int(bw_mbps) * 1024
        if traffic_bytes is None and traffic_gb is not None:
            traffic_bytes = int(traffic_gb) * 1024 * 1024 * 1024

        qos_norm: Dict[str, int] = {}
        if bw_kbps is not None and bw_kbps > 0:
            qos_norm["bandwidth_kbps"] = int(bw_kbps)
        if max_conns is not None and max_conns > 0:
            qos_norm["max_conns"] = int(max_conns)
        if conn_rate is not None and conn_rate > 0:
            qos_norm["conn_rate"] = int(conn_rate)
        if traffic_bytes is not None and traffic_bytes > 0:
            qos_norm["traffic_total_bytes"] = int(traffic_bytes)

        if qos_norm:
            ex["qos"] = dict(qos_norm)
            ep["extra_config"] = ex

            net_copy = dict(net_obj)
            net_copy["qos"] = dict(qos_norm)
            ep["network"] = net_copy

            if "tcp" not in proto and "max_conns" in qos_norm:
                warnings.append(
                    _warn(
                        f"endpoints[{idx}].extra_config.qos.max_conns",
                        f"第 {idx+1} 条规则配置了 QoS 最大并发，但该规则未启用 TCP，参数不会生效",
                        "qos_tcp_only",
                    )
                )
        else:
            if "qos" in ex:
                ex.pop("qos", None)
                ep["extra_config"] = ex
            if isinstance(net_obj, dict) and "qos" in net_obj:
                net_copy = dict(net_obj)
                net_copy.pop("qos", None)
                if net_copy:
                    ep["network"] = net_copy
                else:
                    ep.pop("network", None)

        if not bool(ep.get("disabled")) and intranet_role != "client":
            active_rule_count += 1
            total_remote_count += n
            if "udp" in proto:
                active_udp_enabled += 1

    if issues:
        raise PoolValidationError(issues[0].message, issues)

    # ---- Port conflict detection (after normalization) ----
    by_port: Dict[int, List[Tuple[int, str, str, Set[str]]]] = {}
    # (idx, listen, host, proto_set)

    for idx, ep in enumerate(eps):
        if not isinstance(ep, dict):
            continue
        ex = ep.get("extra_config")
        if not isinstance(ex, dict):
            ex = {}

        intranet_role = str(ex.get("intranet_role") or "").strip()
        if intranet_role == "client":
            # placeholder listen 0.0.0.0:0, not bound
            continue

        listen = str(ep.get("listen") or "").strip()
        if not listen:
            continue
        host, port = split_host_port(listen)
        if port is None:
            continue
        try:
            p = int(port)
        except Exception:
            continue
        if p <= 0:
            continue

        host = str(host or "").strip() or "0.0.0.0"
        ps = _proto_set(ep.get("protocol"))
        by_port.setdefault(p, []).append((idx, listen, host, ps))

    conflict_issues: List[PoolValidationIssue] = []
    for port, items in by_port.items():
        if len(items) <= 1:
            continue
        for i in range(len(items)):
            idx_a, listen_a, host_a, ps_a = items[i]
            for j in range(i + 1, len(items)):
                idx_b, listen_b, host_b, ps_b = items[j]
                overlap_proto = ps_a & ps_b
                if not overlap_proto:
                    continue
                if not _hosts_overlap(host_a, host_b):
                    continue
                prot_txt = _format_proto(overlap_proto)
                msg = (
                    f"端口冲突：第 {idx_a+1} 条规则（{listen_a}）与第 {idx_b+1} 条规则（{listen_b}）"
                    f" 同时监听 {prot_txt}，请修改监听端口或协议。"
                )
                conflict_issues.append(PoolValidationIssue(path="endpoints", message=msg))
                if len(conflict_issues) >= 10:
                    break
            if len(conflict_issues) >= 10:
                break
        if conflict_issues:
            break

    if conflict_issues:
        raise PoolValidationError(conflict_issues[0].message, conflict_issues)

    # ---- Performance risk hints ----
    if active_rule_count >= 80:
        warnings.append(
            _warn(
                "endpoints",
                (
                    f"性能风险提示：当前启用规则 {active_rule_count} 条，建议在节点上调优 "
                    "sysctl（net.core.somaxconn、net.ipv4.ip_local_port_range、net.core.rmem_max、net.core.wmem_max）"
                ),
                "sysctl_tuning_recommended",
            )
        )
    if total_remote_count >= 240:
        warnings.append(
            _warn(
                "endpoints",
                f"性能风险提示：总目标地址 {total_remote_count} 个，建议适当拆分规则并检查连接跟踪与端口范围配置",
                "too_many_remotes",
            )
        )
    if active_udp_enabled >= 16:
        warnings.append(
            _warn(
                "endpoints",
                (
                    "性能风险提示：启用 UDP 的规则较多，建议提高 net.core.rmem_max/net.core.wmem_max，"
                    "并检查 net.core.netdev_max_backlog"
                ),
                "udp_sysctl_recommended",
            )
        )

    return warnings
