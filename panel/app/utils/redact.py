from __future__ import annotations

import ipaddress
import re
from typing import Any
from urllib.parse import urlsplit, urlunsplit

_SECRET_KEY_HINTS = (
    "token",
    "secret",
    "password",
    "passwd",
    "api_key",
    "apikey",
    "authorization",
    "cookie",
    "session",
    "sig",
)
_URL_KEY_HINTS = ("url", "base", "host", "ip", "addr", "endpoint", "path")

_PATH_TOKEN_RE = re.compile(r"(?P<prefix>/(?:join|uninstall)/)(?P<token>[A-Za-z0-9._~-]{6,})")
_QUERY_TOKEN_RE = re.compile(
    r"(?P<prefix>[?&](?:token|api_key|apikey|key|t)=)(?P<token>[^&\s]+)",
    re.IGNORECASE,
)
_HEADER_TOKEN_RE = re.compile(
    r"(?P<prefix>(?:X-Join-Token|X-API-Key)\s*[:=]\s*)(?P<token>[^\s,;\"']+)",
    re.IGNORECASE,
)
_BEARER_RE = re.compile(r"(?P<prefix>Bearer\s+)(?P<token>[A-Za-z0-9._~+/=-]{8,})", re.IGNORECASE)
_KV_SECRET_RE = re.compile(
    r"(?P<prefix>(?:\"|')?(?:api[_-]?key|token|secret|password|passwd|authorization|cookie)(?:\"|')?\s*[:=]\s*(?:\"|')?)(?P<token>[^\s,\"'}]+)",
    re.IGNORECASE,
)


def _mask_middle(value: str, keep_start: int = 2, keep_end: int = 2, min_mask: int = 3) -> str:
    s = str(value or "")
    if not s:
        return ""
    total = len(s)
    if total <= 2:
        return "*" * total
    ks = max(0, int(keep_start))
    ke = max(0, int(keep_end))
    if ks + ke >= total:
        ks = min(1, total)
        ke = 0 if total <= 3 else 1
    hidden = max(1, total - ks - ke)
    if total >= (ks + ke + int(min_mask)):
        hidden = max(hidden, int(min_mask))
    head = s[:ks] if ks > 0 else ""
    tail = s[-ke:] if ke > 0 else ""
    return f"{head}{'*' * hidden}{tail}"


def mask_secret(value: Any, keep_start: int = 3, keep_end: int = 2) -> str:
    s = str(value or "").strip()
    if not s:
        return ""
    return _mask_middle(s, keep_start=keep_start, keep_end=keep_end, min_mask=4)


def _mask_ipv4(core: str) -> str:
    parts = core.split(".")
    if len(parts) != 4:
        return _mask_middle(core, keep_start=2, keep_end=0, min_mask=3)
    return f"{parts[0]}.{parts[1]}.*.*"


def _mask_ipv6(core: str) -> str:
    try:
        expanded = ipaddress.ip_address(core).exploded.split(":")
    except Exception:
        expanded = core.split(":")
    head = expanded[:2] if len(expanded) >= 2 else expanded[:1]
    if not head:
        head = ["*"]
    return ":".join(head + ["*"] * max(2, 8 - len(head)))


def mask_host(value: Any) -> str:
    host = str(value or "").strip()
    if not host:
        return ""
    if host.startswith("[") and host.endswith("]"):
        host = host[1:-1]

    core, zone = (host.split("%", 1) + [""])[:2]
    zone_suffix = f"%{_mask_middle(zone, keep_start=1, keep_end=0, min_mask=2)}" if zone else ""

    try:
        ip_obj = ipaddress.ip_address(core)
        if ip_obj.version == 4:
            return _mask_ipv4(core) + zone_suffix
        return _mask_ipv6(core) + zone_suffix
    except Exception:
        pass

    labels = [seg for seg in core.split(".") if seg]
    if len(labels) <= 1:
        return _mask_middle(core, keep_start=1, keep_end=1, min_mask=3)

    masked: list[str] = []
    for i, seg in enumerate(labels):
        if i == len(labels) - 1:
            masked.append(seg)
        elif i == 0:
            masked.append(_mask_middle(seg, keep_start=1, keep_end=1, min_mask=3))
        else:
            masked.append("*")
    return ".".join(masked) + zone_suffix


def _mask_path(path: str) -> str:
    p = str(path or "")
    if not p:
        return ""
    if p == "/":
        return "/"
    segs = [x for x in p.split("/") if x]
    if not segs:
        return "/"
    first = _mask_middle(segs[0], keep_start=1, keep_end=1, min_mask=3)
    if len(segs) > 1:
        return f"/{first}/..."
    return f"/{first}"


def mask_url(value: Any) -> str:
    raw = str(value or "").strip()
    if not raw:
        return ""

    has_scheme = "://" in raw
    parsed = urlsplit(raw if has_scheme else f"//{raw}")
    host = str(parsed.hostname or "").strip()
    if not host:
        return _mask_middle(raw, keep_start=2, keep_end=2, min_mask=4)

    masked_host = mask_host(host)
    host_for_url = f"[{masked_host}]" if ":" in masked_host else masked_host

    user_part = ""
    if parsed.username:
        user_part = mask_secret(parsed.username, keep_start=1, keep_end=0)
        if parsed.password:
            user_part = f"{user_part}:{mask_secret(parsed.password, keep_start=1, keep_end=0)}"
        user_part = f"{user_part}@"

    netloc = f"{user_part}{host_for_url}"
    try:
        parsed_port = parsed.port
    except Exception:
        parsed_port = None
    if parsed_port is not None:
        netloc = f"{netloc}:{int(parsed_port)}"

    masked_path = _mask_path(parsed.path)
    query = "***" if parsed.query else ""
    frag = "***" if parsed.fragment else ""
    scheme = parsed.scheme if has_scheme else ""

    out = urlunsplit((scheme, netloc, masked_path, query, frag))
    if not has_scheme and out.startswith("//"):
        out = out[2:]
    return out


def redact_log_text(value: Any) -> str:
    text = str(value or "")
    if not text:
        return ""

    text = _PATH_TOKEN_RE.sub(lambda m: f"{m.group('prefix')}{mask_secret(m.group('token'))}", text)
    text = _QUERY_TOKEN_RE.sub(lambda m: f"{m.group('prefix')}{mask_secret(m.group('token'))}", text)
    text = _HEADER_TOKEN_RE.sub(lambda m: f"{m.group('prefix')}{mask_secret(m.group('token'))}", text)
    text = _BEARER_RE.sub(lambda m: f"{m.group('prefix')}{mask_secret(m.group('token'))}", text)
    text = _KV_SECRET_RE.sub(lambda m: f"{m.group('prefix')}{mask_secret(m.group('token'))}", text)
    return text


def _looks_like_urlish(text: str) -> bool:
    s = str(text or "").strip()
    if not s:
        return False
    if "://" in s:
        return True
    if "/" in s and "." in s:
        return True
    if s.count(".") >= 1 and ":" in s:
        return True
    return False


def _key_has_hint(key: str, hints: tuple[str, ...]) -> bool:
    k = str(key or "").strip().lower()
    if not k:
        return False
    return any(h in k for h in hints)


def redact_for_log(value: Any, *, key_hint: str = "") -> Any:
    if isinstance(value, dict):
        return {str(k): redact_for_log(v, key_hint=str(k)) for k, v in value.items()}
    if isinstance(value, list):
        return [redact_for_log(v, key_hint=key_hint) for v in value]
    if isinstance(value, tuple):
        return tuple(redact_for_log(v, key_hint=key_hint) for v in value)
    if isinstance(value, set):
        return {redact_for_log(v, key_hint=key_hint) for v in value}

    if _key_has_hint(key_hint, _SECRET_KEY_HINTS):
        return mask_secret(value)

    if isinstance(value, str):
        s = str(value or "")
        if _key_has_hint(key_hint, _URL_KEY_HINTS) and _looks_like_urlish(s):
            return mask_url(s)
        return redact_log_text(s)

    if _key_has_hint(key_hint, _URL_KEY_HINTS):
        s = str(value or "")
        return mask_url(s) if _looks_like_urlish(s) else s
    return value
