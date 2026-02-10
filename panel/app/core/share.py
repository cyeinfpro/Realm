from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import time
from typing import Any, Dict, Optional

from fastapi import HTTPException, Request

from ..auth import get_session_user, has_permission
from .session import SECRET_KEY


# NetMon share token (read-only, no-login)
_NETMON_SHARE_PUBLIC = (os.getenv("REALM_NETMON_SHARE_PUBLIC") or "1").strip() not in ("0", "false", "False")
try:
    _NETMON_SHARE_TTL_SEC = int((os.getenv("REALM_NETMON_SHARE_TTL_SEC") or "604800").strip() or 604800)  # default 7d
except Exception:
    _NETMON_SHARE_TTL_SEC = 604800
if _NETMON_SHARE_TTL_SEC < 300:
    _NETMON_SHARE_TTL_SEC = 300
if _NETMON_SHARE_TTL_SEC > 30 * 86400:
    _NETMON_SHARE_TTL_SEC = 30 * 86400


def is_share_public_enabled() -> bool:
    return bool(_NETMON_SHARE_PUBLIC)

netmon_share_enabled = is_share_public_enabled


def _b64url_encode(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode("utf-8").rstrip("=")


def _b64url_decode(s: str) -> bytes:
    s = str(s or "").strip()
    if not s:
        return b""
    pad = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + pad)


def _share_canon(obj: Any) -> str:
    return json.dumps(obj, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _clamp_share_ttl_sec(ttl_sec: Optional[int]) -> int:
    if ttl_sec is None:
        return int(_NETMON_SHARE_TTL_SEC)
    try:
        ttl = int(ttl_sec)
    except Exception:
        ttl = int(_NETMON_SHARE_TTL_SEC)
    if ttl < 300:
        ttl = 300
    if ttl > 30 * 86400:
        ttl = 30 * 86400
    return ttl


def make_share_token(payload: Dict[str, Any], ttl_sec: Optional[int] = None) -> str:
    try:
        exp = int(time.time()) + int(_clamp_share_ttl_sec(ttl_sec))
    except Exception:
        exp = int(time.time()) + 86400
    p = dict(payload or {})
    p["exp"] = exp
    raw = _share_canon(p).encode("utf-8")
    sig = hmac.new(SECRET_KEY.encode("utf-8"), raw, hashlib.sha256).hexdigest()
    return f"{_b64url_encode(raw)}.{sig}"


def _verify_share_token(token: str, check_expire: bool = True) -> Optional[Dict[str, Any]]:
    try:
        tok = str(token or "").strip()
        if not tok or "." not in tok:
            return None
        b64, sig = tok.split(".", 1)
        raw = _b64url_decode(b64)
        if not raw:
            return None
        exp_sig = hmac.new(SECRET_KEY.encode("utf-8"), raw, hashlib.sha256).hexdigest()
        if not hmac.compare_digest(exp_sig, str(sig or "").strip()):
            return None
        obj = json.loads(raw.decode("utf-8", errors="ignore"))
        if not isinstance(obj, dict):
            return None
        exp = int(obj.get("exp") or 0)
        if check_expire and exp and int(time.time()) > exp:
            return None
        return obj
    except Exception:
        return None


def verify_share_token(token: str) -> Optional[Dict[str, Any]]:
    return _verify_share_token(token, check_expire=True)


def verify_share_token_allow_expired(token: str) -> Optional[Dict[str, Any]]:
    return _verify_share_token(token, check_expire=False)


def require_login_or_share_page(request: Request, allow_page: str) -> str:
    """Allow either a logged-in session OR a valid share token for a given page."""

    auth_user = get_session_user(request.session)
    if auth_user and has_permission(auth_user, "netmon.read"):
        request.state.auth_user = auth_user
        return str(auth_user.username)

    if not _NETMON_SHARE_PUBLIC:
        raise HTTPException(status_code=302, headers={"Location": "/login"})

    payload = verify_share_token(request.query_params.get("t") or "")
    if payload and str(payload.get("page") or "") == str(allow_page):
        request.state.share = payload
        return ""

    raise HTTPException(status_code=302, headers={"Location": "/login"})


def require_login_or_share_view_page(request: Request) -> str:
    return require_login_or_share_page(request, "view")


def require_login_or_share_wall_page(request: Request) -> str:
    return require_login_or_share_page(request, "wall")


def require_login_or_share_api(request: Request) -> str:
    """Allow either a logged-in session OR a valid share token for API calls."""

    auth_user = get_session_user(request.session)
    if auth_user and has_permission(auth_user, "netmon.read"):
        request.state.auth_user = auth_user
        return str(auth_user.username)

    if not _NETMON_SHARE_PUBLIC:
        raise HTTPException(status_code=401, detail="Not logged in")

    token = request.query_params.get("t") or request.headers.get("X-Share-Token") or ""
    payload = verify_share_token(token)
    if payload:
        request.state.share = payload
        return "__share__"

    raise HTTPException(status_code=401, detail="Not logged in")
