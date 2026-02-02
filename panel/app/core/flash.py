from __future__ import annotations

from typing import Optional

from fastapi import Request


def flash(request: Request) -> Optional[str]:
    return request.session.pop("flash", None)


def set_flash(request: Request, msg: str) -> None:
    request.session["flash"] = msg
