from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import time
from typing import Any, Dict, Optional

from fastapi import HTTPException, Request

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


def make_share_token(payload: Dict[str, Any]) -> str:
    try:
        exp = int(time.time()) + int(_NETMON_SHARE_TTL_SEC)
    except Exception:
        exp = int(time.time()) + 86400
    p = dict(payload or {})
    p["exp"] = exp
    raw = _share_canon(p).encode("utf-8")
    sig = hmac.new(SECRET_KEY.encode("utf-8"), raw, hashlib.sha256).hexdigest()
    return f"{_b64url_encode(raw)}.{sig}"


def verify_share_token(token: str) -> Optional[Dict[str, Any]]:
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
        if exp and int(time.time()) > exp:
            return None
        return obj
    except Exception:
        return None


def require_login_or_share_page(request: Request, allow_page: str) -> str:
    """Allow either a logged-in session OR a valid share token for a given page."""

    user = request.session.get("user")
    if user:
        return str(user)

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

    user = request.session.get("user")
    if user:
        return str(user)

    if not _NETMON_SHARE_PUBLIC:
        raise HTTPException(status_code=401, detail="Not logged in")

    token = request.query_params.get("t") or request.headers.get("X-Share-Token") or ""
    payload = verify_share_token(token)
    if payload:
        request.state.share = payload
        return "__share__"

    raise HTTPException(status_code=401, detail="Not logged in")
