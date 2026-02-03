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


def validate_pool_inplace(pool: Dict[str, Any]) -> None:
    """Validate a pool dict and normalize obvious formatting issues in-place.

    Checks:
      1) listen format + port range
      2) remote format (each host:port)
      3) weights count vs remotes count (when balance explicitly includes weights)
      4) listen port conflicts across endpoints

    Raises PoolValidationError on failure.
    """

    if not isinstance(pool, dict):
        raise PoolValidationError("pool 必须是对象")

    eps = pool.get("endpoints")
    if eps is None:
        pool["endpoints"] = []
        return
    if not isinstance(eps, list):
        raise PoolValidationError("pool.endpoints 必须是数组")

    issues: List[PoolValidationIssue] = []

    # ---- Per-endpoint validation + normalization ----
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

        # weights count check (only when balance explicitly provides weights)
        rems: List[str] = []
        if isinstance(ep.get("remote"), str) and str(ep.get("remote") or "").strip():
            rems.append(str(ep.get("remote") or "").strip())
        if isinstance(ep.get("remotes"), list):
            rems += [str(x).strip() for x in ep.get("remotes") or [] if str(x).strip()]
        if isinstance(ep.get("extra_remotes"), list):
            rems += [str(x).strip() for x in ep.get("extra_remotes") or [] if str(x).strip()]
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
