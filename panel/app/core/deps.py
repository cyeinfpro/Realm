from __future__ import annotations

from fastapi import HTTPException, Request


def require_login(request: Request) -> str:
    user = request.session.get("user")
    if not user:
        raise HTTPException(status_code=401, detail="Not logged in")
    return str(user)


def require_login_page(request: Request) -> str:
    user = request.session.get("user")
    if not user:
        raise HTTPException(status_code=302, headers={"Location": "/login"})
    return str(user)
