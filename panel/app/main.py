from __future__ import annotations

import os
import secrets
from pathlib import Path
from typing import Any, Dict, Optional

from fastapi import Depends, FastAPI, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.middleware.sessions import SessionMiddleware

from .auth import ensure_secret_key, load_credentials, save_credentials, verify_login
from .db import add_node, delete_node, ensure_db, get_node, list_nodes
from .agents import agent_get, agent_post, agent_ping

BASE_DIR = Path(__file__).resolve().parent.parent
TEMPLATES_DIR = BASE_DIR / "templates"
STATIC_DIR = BASE_DIR / "static"

app = FastAPI(title="Realm Pro Panel", version="33")

# Session
secret = ensure_secret_key()
app.add_middleware(SessionMiddleware, secret_key=secret, session_cookie="realm_panel_sess")

# Static + templates
app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")
templates = Jinja2Templates(directory=str(TEMPLATES_DIR))

# DB init
ensure_db()


def _flash(request: Request) -> Optional[str]:
    msg = request.session.pop("flash", None)
    return msg


def _set_flash(request: Request, msg: str) -> None:
    request.session["flash"] = msg


def _has_credentials() -> bool:
    return load_credentials() is not None


def _generate_api_key() -> str:
    return secrets.token_hex(16)


def require_login(request: Request) -> str:
    user = request.session.get("user")
    if not user:
        raise HTTPException(status_code=401, detail="Not logged in")
    return user


def require_login_page(request: Request) -> str:
    user = request.session.get("user")
    if not user:
        raise HTTPException(status_code=302, headers={"Location": "/login"})
    return user


@app.get("/login", response_class=HTMLResponse)
async def login_page(request: Request):
    if not _has_credentials():
        return RedirectResponse(url="/setup", status_code=303)
    return templates.TemplateResponse(
        "login.html",
        {"request": request, "user": None, "flash": _flash(request), "title": "登录"},
    )


@app.post("/login")
async def login_action(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
):
    if not _has_credentials():
        _set_flash(request, "请先初始化面板账号")
        return RedirectResponse(url="/setup", status_code=303)
    if verify_login(username, password):
        request.session["user"] = username
        _set_flash(request, "登录成功")
        return RedirectResponse(url="/", status_code=303)
    _set_flash(request, "账号或密码错误")
    return RedirectResponse(url="/login", status_code=303)


@app.get("/logout")
async def logout(request: Request):
    request.session.clear()
    return RedirectResponse(url="/login", status_code=303)


@app.get("/setup", response_class=HTMLResponse)
async def setup_page(request: Request):
    if _has_credentials():
        return RedirectResponse(url="/login", status_code=303)
    return templates.TemplateResponse(
        "setup.html",
        {"request": request, "user": None, "flash": _flash(request), "title": "初始化账号"},
    )


@app.post("/setup")
async def setup_action(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    confirm: str = Form(...),
):
    if _has_credentials():
        return RedirectResponse(url="/login", status_code=303)
    if password != confirm:
        _set_flash(request, "两次输入的密码不一致")
        return RedirectResponse(url="/setup", status_code=303)
    try:
        save_credentials(username, password)
    except ValueError as exc:
        _set_flash(request, str(exc))
        return RedirectResponse(url="/setup", status_code=303)
    _set_flash(request, "账号已初始化，请登录")
    return RedirectResponse(url="/login", status_code=303)


@app.get("/", response_class=HTMLResponse)
async def index(request: Request, user: str = Depends(require_login_page)):
    nodes = list_nodes()
    return templates.TemplateResponse(
        "index.html",
        {"request": request, "user": user, "nodes": nodes, "flash": _flash(request), "title": "控制台"},
    )


@app.get("/nodes/new", response_class=HTMLResponse)
async def node_new_page(request: Request, user: str = Depends(require_login_page)):
    api_key = _generate_api_key()
    return templates.TemplateResponse(
        "nodes_new.html",
        {
            "request": request,
            "user": user,
            "flash": _flash(request),
            "title": "添加机器",
            "api_key": api_key,
            "default_port": 18700,
        },
    )


@app.post("/nodes/new")
async def node_new_action(
    request: Request,
    name: str = Form(""),
    ip_address: str = Form(...),
    api_key: str = Form(""),
):
    user = request.session.get("user")
    if not user:
        return RedirectResponse(url="/login", status_code=303)

    ip_address = ip_address.strip()
    api_key = api_key.strip() or _generate_api_key()
    if not ip_address:
        _set_flash(request, "IP 地址不能为空")
        return RedirectResponse(url="/nodes/new", status_code=303)
    base_url = f"http://{ip_address}:18700"

    node_id = add_node(name or base_url, base_url, api_key)
    request.session["show_install_cmd"] = True
    _set_flash(request, "已添加机器")
    return RedirectResponse(url=f"/nodes/{node_id}", status_code=303)


@app.post("/nodes/{node_id}/delete")
async def node_delete(request: Request, node_id: int):
    if not request.session.get("user"):
        return RedirectResponse(url="/login", status_code=303)
    delete_node(node_id)
    _set_flash(request, "已删除机器")
    return RedirectResponse(url="/", status_code=303)


@app.get("/nodes/{node_id}", response_class=HTMLResponse)
async def node_detail(request: Request, node_id: int, user: str = Depends(require_login_page)):
    node = get_node(node_id)
    if not node:
        _set_flash(request, "机器不存在")
        return RedirectResponse(url="/", status_code=303)
    show_install_cmd = bool(request.session.pop("show_install_cmd", False))
    base_url = str(request.base_url).rstrip("/")
    repo_zip_url = f"{base_url}/static/realm-agent.zip"
    install_cmd = (
        "sudo -E bash -c \""
        "mkdir -p /etc/realm-agent && "
        f"echo '{node['api_key']}' > /etc/realm-agent/api.key && "
        f"curl -fsSL {base_url}/static/realm_agent.sh | "
        f"REALM_AGENT_REPO_ZIP_URL={repo_zip_url} "
        "REALM_AGENT_MODE=1 REALM_AGENT_PORT=18700 REALM_AGENT_ASSUME_YES=1 bash"
        "\""
    )
    return templates.TemplateResponse(
        "node.html",
        {
            "request": request,
            "user": user,
            "node": node,
            "flash": _flash(request),
            "title": node["name"],
            "install_cmd": install_cmd,
            "show_install_cmd": show_install_cmd,
        },
    )


# ------------------------ API (needs login) ------------------------

@app.get("/api/nodes/{node_id}/ping")
async def api_ping(request: Request, node_id: int, user: str = Depends(require_login)):
    node = get_node(node_id)
    if not node:
        return JSONResponse({"ok": False, "error": "node not found"}, status_code=404)
    info = await agent_ping(node["base_url"], node["api_key"])
    if info.get("error"):
        return {"ok": False, "error": info["error"]}
    info["ok"] = True
    return info


@app.get("/api/nodes/{node_id}/pool")
async def api_pool_get(request: Request, node_id: int, user: str = Depends(require_login)):
    node = get_node(node_id)
    if not node:
        return JSONResponse({"ok": False, "error": "node not found"}, status_code=404)
    try:
        data = await agent_get(node["base_url"], node["api_key"], "/api/v1/pool")
        return data
    except Exception as exc:
        return JSONResponse({"ok": False, "error": str(exc)}, status_code=502)


@app.post("/api/nodes/{node_id}/pool")
async def api_pool_set(request: Request, node_id: int, payload: Dict[str, Any], user: str = Depends(require_login)):
    node = get_node(node_id)
    if not node:
        return JSONResponse({"ok": False, "error": "node not found"}, status_code=404)
    try:
        data = await agent_post(node["base_url"], node["api_key"], "/api/v1/pool", payload)
        return data
    except Exception as exc:
        return JSONResponse({"ok": False, "error": str(exc)}, status_code=502)


@app.post("/api/nodes/{node_id}/apply")
async def api_apply(request: Request, node_id: int, user: str = Depends(require_login)):
    node = get_node(node_id)
    if not node:
        return JSONResponse({"ok": False, "error": "node not found"}, status_code=404)
    try:
        data = await agent_post(node["base_url"], node["api_key"], "/api/v1/apply", {})
        return data
    except Exception as exc:
        return JSONResponse({"ok": False, "error": str(exc)}, status_code=502)


@app.get("/api/nodes/{node_id}/stats")
async def api_stats(request: Request, node_id: int, user: str = Depends(require_login)):
    node = get_node(node_id)
    if not node:
        return JSONResponse({"ok": False, "error": "node not found"}, status_code=404)
    try:
        data = await agent_get(node["base_url"], node["api_key"], "/api/v1/stats")
        return data
    except Exception as exc:
        return JSONResponse({"ok": False, "error": str(exc)}, status_code=502)


@app.get("/api/nodes/{node_id}/graph")
async def api_graph(request: Request, node_id: int, user: str = Depends(require_login)):
    node = get_node(node_id)
    if not node:
        return JSONResponse({"ok": False, "error": "node not found"}, status_code=404)
    try:
        data = await agent_get(node["base_url"], node["api_key"], "/api/v1/pool")
    except Exception as exc:
        return JSONResponse({"ok": False, "error": str(exc)}, status_code=502)

    pool = data.get("pool") if isinstance(data, dict) else None
    endpoints = pool.get("endpoints", []) if isinstance(pool, dict) else []
    elements: list[dict[str, Any]] = []
    for idx, endpoint in enumerate(endpoints):
        listen = endpoint.get("listen", f"listen-{idx}")
        listen_id = f"listen-{idx}"
        classes = ["listen"]
        if endpoint.get("disabled"):
            classes.append("disabled")
        elements.append({"data": {"id": listen_id, "label": listen}, "classes": " ".join(classes)})
        remotes = endpoint.get("remotes") or ([endpoint.get("remote")] if endpoint.get("remote") else [])
        for r_idx, remote in enumerate(remotes):
            remote_id = f"remote-{idx}-{r_idx}"
            elements.append(
                {
                    "data": {"id": remote_id, "label": remote},
                    "classes": "remote" + (" disabled" if endpoint.get("disabled") else ""),
                }
            )
            ex = endpoint.get("extra_config") or {}
            edge_label = "WSS" if ex.get("listen_transport") == "ws" or ex.get("remote_transport") == "ws" else ""
            elements.append(
                {
                    "data": {"source": listen_id, "target": remote_id, "label": edge_label},
                    "classes": "disabled" if endpoint.get("disabled") else "",
                }
            )
    return {"ok": True, "elements": elements}
