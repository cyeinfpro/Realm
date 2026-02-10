from __future__ import annotations

from typing import Any, Dict, Optional

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse

from ..auth import (
    authenticate_user,
    create_user_account,
    delete_user_account,
    list_roles_public,
    list_users_public,
    normalize_user_policy,
    setup_initial_owner,
    update_user_account,
)
from ..core.deps import require_role, require_role_page
from ..core.flash import flash, set_flash
from ..core.templates import templates
from ..db import list_nodes
from ..services.auth_service import has_credentials

router = APIRouter()


def _to_bool(value: Any, default: bool = False) -> bool:
    if isinstance(value, bool):
        return value
    if value is None:
        return bool(default)
    s = str(value).strip().lower()
    if not s:
        return bool(default)
    return s in ("1", "true", "yes", "on", "y")


def _extract_policy(payload: Dict[str, Any]) -> Dict[str, Any]:
    p0 = payload.get("policy") if isinstance(payload.get("policy"), dict) else {}
    raw: Dict[str, Any] = dict(p0)
    if "allowed_node_ids" in payload:
        raw["allowed_node_ids"] = payload.get("allowed_node_ids")
    if "allowed_tunnel_types" in payload:
        raw["allowed_tunnel_types"] = payload.get("allowed_tunnel_types")
    if "tunnel_limit_enabled" in payload:
        raw["tunnel_limit_enabled"] = payload.get("tunnel_limit_enabled")
    elif "allowed_tunnel_types" in payload:
        # Frontend may only submit allowed_tunnel_types for explicit tunnel policy edits.
        raw["tunnel_limit_enabled"] = True
    if "max_monthly_traffic_bytes" in payload:
        raw["max_monthly_traffic_bytes"] = payload.get("max_monthly_traffic_bytes")
    if "max_monthly_traffic_gb" in payload:
        try:
            gb = float(payload.get("max_monthly_traffic_gb") or 0.0)
        except Exception:
            gb = 0.0
        raw["max_monthly_traffic_bytes"] = int(max(0.0, gb) * (1024 ** 3))
    return normalize_user_policy(raw)


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

    user = authenticate_user(username, password)
    if user is not None:
        request.session.clear()
        request.session["user"] = user.username
        request.session["user_id"] = int(user.id)
        request.session["user_role"] = user.role_name
        request.session["user_permissions"] = sorted(list(user.permissions))
        request.session["user_policy"] = dict(normalize_user_policy(user.policy))
        set_flash(request, "登录成功")
        return RedirectResponse(url="/", status_code=303)

    set_flash(request, "账号或密码错误，或账号已禁用/过期")
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
        setup_initial_owner(username, password)
    except ValueError as exc:
        set_flash(request, str(exc))
        return RedirectResponse(url="/setup", status_code=303)
    except Exception as exc:
        set_flash(request, f"初始化失败：{exc}")
        return RedirectResponse(url="/setup", status_code=303)

    set_flash(request, "账号已初始化，请登录")
    return RedirectResponse(url="/login", status_code=303)


@router.get("/users", response_class=HTMLResponse)
async def users_page(request: Request, user: str = Depends(require_role_page("users.manage"))):
    nodes = list_nodes()
    return templates.TemplateResponse(
        "users.html",
        {
            "request": request,
            "user": user,
            "nodes": nodes,
            "flash": flash(request),
            "title": "用户与权限",
        },
    )


@router.get("/api/roles")
async def api_roles(user: str = Depends(require_role("users.manage"))):
    _ = user
    return {"ok": True, "roles": list_roles_public()}


@router.get("/api/users")
async def api_users(user: str = Depends(require_role("users.manage"))):
    _ = user
    return {"ok": True, "users": list_users_public(include_usage=True)}


@router.post("/api/users/create")
async def api_users_create(payload: Dict[str, Any], user: str = Depends(require_role("users.manage"))):
    try:
        username = str(payload.get("username") or "").strip()
        password = str(payload.get("password") or "")
        role_name = str(payload.get("role_name") or payload.get("role") or "viewer").strip() or "viewer"
        enabled = _to_bool(payload.get("enabled"), default=True)
        expires_at = payload.get("expires_at")
        policy = _extract_policy(payload)
        created = create_user_account(
            actor=user,
            username=username,
            password=password,
            role_name=role_name,
            enabled=enabled,
            expires_at=expires_at,
            policy=policy,
        )
        return {"ok": True, "user": created}
    except ValueError as exc:
        return JSONResponse({"ok": False, "error": str(exc)}, status_code=400)
    except Exception as exc:
        return JSONResponse({"ok": False, "error": f"创建用户失败：{exc}"}, status_code=500)


@router.post("/api/users/{user_id}/update")
async def api_users_update(user_id: int, payload: Dict[str, Any], user: str = Depends(require_role("users.manage"))):
    try:
        username: Optional[str] = None
        if "username" in payload:
            username = str(payload.get("username") or "").strip()

        password: Optional[str] = None
        if "password" in payload:
            pw = str(payload.get("password") or "")
            password = pw if pw.strip() else None

        role_name: Optional[str] = None
        if "role_name" in payload or "role" in payload:
            role_name = str(payload.get("role_name") or payload.get("role") or "").strip() or None

        enabled: Optional[bool] = None
        if "enabled" in payload:
            enabled = _to_bool(payload.get("enabled"), default=True)

        expires_at: Optional[str] = None
        if "expires_at" in payload:
            expires_at = str(payload.get("expires_at") or "").strip()

        policy: Optional[Dict[str, Any]] = None
        if (
            "policy" in payload
            or "allowed_node_ids" in payload
            or "allowed_tunnel_types" in payload
            or "tunnel_limit_enabled" in payload
            or "max_monthly_traffic_bytes" in payload
            or "max_monthly_traffic_gb" in payload
        ):
            policy = _extract_policy(payload)

        updated = update_user_account(
            actor=user,
            user_id=int(user_id),
            username=username,
            password=password,
            role_name=role_name,
            enabled=enabled,
            expires_at=expires_at,
            policy=policy,
        )
        return {"ok": True, "user": updated}
    except ValueError as exc:
        return JSONResponse({"ok": False, "error": str(exc)}, status_code=400)
    except Exception as exc:
        return JSONResponse({"ok": False, "error": f"更新用户失败：{exc}"}, status_code=500)


@router.post("/api/users/{user_id}/delete")
async def api_users_delete(user_id: int, user: str = Depends(require_role("users.manage"))):
    try:
        delete_user_account(actor=user, user_id=int(user_id))
        return {"ok": True}
    except ValueError as exc:
        return JSONResponse({"ok": False, "error": str(exc)}, status_code=400)
    except Exception as exc:
        return JSONResponse({"ok": False, "error": f"删除用户失败：{exc}"}, status_code=500)
