from __future__ import annotations

from fastapi import APIRouter, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse

from ..auth import save_credentials, verify_login
from ..core.flash import flash, set_flash
from ..core.templates import templates
from ..services.auth_service import has_credentials

router = APIRouter()


@router.get("/login", response_class=HTMLResponse)
async def login_page(request: Request):
    if not has_credentials():
        return RedirectResponse(url="/setup", status_code=303)
    return templates.TemplateResponse(
        "login.html",
        {"request": request, "user": None, "flash": flash(request), "title": "登录"},
    )


@router.post("/login")
async def login_action(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
):
    if not has_credentials():
        set_flash(request, "请先初始化面板账号")
        return RedirectResponse(url="/setup", status_code=303)

    if verify_login(username, password):
        request.session["user"] = username
        set_flash(request, "登录成功")
        return RedirectResponse(url="/", status_code=303)

    set_flash(request, "账号或密码错误")
    return RedirectResponse(url="/login", status_code=303)


@router.get("/logout")
async def logout(request: Request):
    request.session.clear()
    return RedirectResponse(url="/login", status_code=303)


@router.get("/setup", response_class=HTMLResponse)
async def setup_page(request: Request):
    if has_credentials():
        return RedirectResponse(url="/login", status_code=303)
    return templates.TemplateResponse(
        "setup.html",
        {"request": request, "user": None, "flash": flash(request), "title": "初始化账号"},
    )


@router.post("/setup")
async def setup_action(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    confirm: str = Form(...),
):
    if has_credentials():
        return RedirectResponse(url="/login", status_code=303)
    if password != confirm:
        set_flash(request, "两次输入的密码不一致")
        return RedirectResponse(url="/setup", status_code=303)
    try:
        save_credentials(username, password)
    except ValueError as exc:
        set_flash(request, str(exc))
        return RedirectResponse(url="/setup", status_code=303)

    set_flash(request, "账号已初始化，请登录")
    return RedirectResponse(url="/login", status_code=303)
