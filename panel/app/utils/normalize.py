from __future__ import annotations

import ipaddress
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse


def split_host_and_port(value: str, fallback_port: int) -> Tuple[str, int, bool, str]:
    """Parse an input string into (host, port, has_port, scheme).

    Accepts:
      - http://host:port
      - https://host
      - host
      - host:port
      - [IPv6]:port

    Notes:
      - If scheme is missing, returns scheme='http'.
      - If port is missing, returns fallback_port.
    """
    raw = (value or "").strip()
    if not raw:
        return "", int(fallback_port), False, "http"

    if "://" in raw:
        parsed = urlparse(raw)
        host = parsed.hostname or ""
        port = parsed.port or int(fallback_port)
        scheme = (parsed.scheme or "http").lower()
        return host, int(port), parsed.port is not None, scheme

    # Bracketed IPv6 literal
    if raw.startswith("[") and "]" in raw:
        host_part, rest = raw.split("]", 1)
        host = host_part[1:].strip()
        rest = rest.strip()
        if rest.startswith(":") and rest[1:].isdigit():
            return host, int(rest[1:]), True, "http"
        return host, int(fallback_port), False, "http"

    # host:port (only one ':' so we don't break IPv6)
    if raw.count(":") == 1 and raw.rsplit(":", 1)[1].isdigit():
        host, port_s = raw.rsplit(":", 1)
        return host.strip(), int(port_s), True, "http"

    return raw, int(fallback_port), False, "http"


def format_host_for_url(host: str) -> str:
    """Format host part for URL.

    - Wrap IPv6 literals in brackets: 2001:db8::1 -> [2001:db8::1]
    - Do NOT wrap hostname:port like example.com:443
    """
    h = (host or "").strip()
    if not h:
        return h
    if h.startswith("[") and h.endswith("]"):
        return h

    # host:port (single colon with numeric port) should NOT be wrapped.
    if h.count(":") == 1 and h.rsplit(":", 1)[1].isdigit():
        return h

    if ":" in h:
        # Strip zone index for validation (e.g. fe80::1%eth0)
        core = h.split("%", 1)[0]
        try:
            ip = ipaddress.ip_address(core)
            if ip.version == 6:
                return f"[{h}]"
        except ValueError:
            # Not a pure IP address; if it has multiple colons it's very likely an IPv6 literal.
            if h.count(":") > 1:
                return f"[{h}]"

    return h


def safe_filename_part(name: str, default: str = "node", max_len: int = 60) -> str:
    """Make a filesystem-friendly filename part (keeps Chinese/letters/numbers/_-)."""
    raw = (name or "").strip()
    if not raw:
        return default
    out: list[str] = []
    for ch in raw:
        if ch.isalnum() or ch in ("-", "_") or ("\u4e00" <= ch <= "\u9fff"):
            out.append(ch)
        elif ch in (" ", "."):
            out.append("-")
        # else: drop
    s = "".join(out).strip("-")
    s = s or default
    return s[:max_len]


def extract_ip_for_display(base_url: str) -> str:
    """UI 只展示纯 IP/Host（不展示端口、不展示协议）。"""
    raw = (base_url or "").strip()
    if not raw:
        return ""
    if "://" not in raw:
        raw = f"http://{raw}"
    try:
        parsed = urlparse(raw)
        return parsed.hostname or (base_url or "").strip()
    except Exception:
        return (base_url or "").strip()


def split_host_port(addr: str) -> Tuple[str, Optional[int]]:
    """Split host:port (or [ipv6]:port) for realm listen/remote strings."""
    addr = (addr or "").strip()
    if not addr:
        return "", None
    if addr.startswith("["):
        # [IPv6]:port
        if "]" in addr:
            host = addr[1 : addr.index("]")]
            rest = addr[addr.index("]") + 1 :]
            if rest.startswith(":"):
                try:
                    return host, int(rest[1:])
                except Exception:
                    return host, None
            return host, None
        return addr, None
    if ":" in addr:
        host, p = addr.rsplit(":", 1)
        try:
            return host, int(p)
        except Exception:
            return addr, None
    return addr, None


def format_addr(host: str, port: int) -> str:
    host = (host or "").strip()
    if ":" in host and not host.startswith("["):
        host = f"[{host}]"
    return f"{host}:{int(port)}"


def normalize_host_input(h: str) -> str:
    """Normalize host input and strip optional port without breaking IPv6.

    Allows user to paste:
      - URL (http://..)
      - host:port
      - [ipv6]:port
      - raw host

    Returns a host string without port.
    """
    h = (h or "").strip()
    if not h:
        return ""

    # allow user to paste URL
    try:
        if "://" in h:
            u = urlparse(h)
            return u.hostname or ""
    except Exception:
        pass

    host, _port, _has_port, _scheme = split_host_and_port(h, 0)
    return host


def safe_int_list(values: Any) -> List[int]:
    """Convert an iterable of values to a list of ints; drop invalid items."""
    out: List[int] = []
    if not isinstance(values, (list, tuple, set)):
        return out
    for v in values:
        try:
            out.append(int(v))
        except Exception:
            continue
    return out


def sanitize_pool_fields(pool: Dict[str, Any]) -> None:
    """Best-effort: trim common string fields in a pool dict (in-place).

    This avoids subtle mismatches caused by leading/trailing spaces or invisible chars.
    """
    if not isinstance(pool, dict):
        return

    try:
        eps = pool.get("endpoints")
        if isinstance(eps, list):
            for e in eps:
                if not isinstance(e, dict):
                    continue

                if e.get("listen") is not None:
                    e["listen"] = str(e.get("listen") or "").strip()
                if e.get("remote") is not None:
                    e["remote"] = str(e.get("remote") or "").strip()

                if isinstance(e.get("remotes"), list):
                    e["remotes"] = [str(x).strip() for x in e.get("remotes") if str(x).strip()]
                if isinstance(e.get("extra_remotes"), list):
                    e["extra_remotes"] = [str(x).strip() for x in e.get("extra_remotes") if str(x).strip()]

                # common optional string fields
                for k in (
                    "through",
                    "interface",
                    "listen_interface",
                    "listen_transport",
                    "remote_transport",
                    "protocol",
                    "balance",
                ):
                    if e.get(k) is not None and isinstance(e.get(k), str):
                        e[k] = e[k].strip()

                # Panel-only meta fields
                if e.get("remark") is not None:
                    v = str(e.get("remark") or "").strip()
                    if v:
                        e["remark"] = v
                    else:
                        e.pop("remark", None)

                if "favorite" in e:
                    raw = e.get("favorite")
                    fav = raw if isinstance(raw, bool) else str(raw or "").strip().lower() in (
                        "1",
                        "true",
                        "yes",
                        "y",
                        "on",
                    )
                    if fav:
                        e["favorite"] = True
                    else:
                        e.pop("favorite", None)
    except Exception:
        # Never break the caller.
        return

# Backward-compatible alias
sanitize_pool = sanitize_pool_fields

