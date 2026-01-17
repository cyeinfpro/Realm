from __future__ import annotations

import os
import secrets
import time
from typing import Any, Dict, Optional

import httpx
from fastapi import Depends, FastAPI, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from starlette.middleware.sessions import SessionMiddleware
from fastapi.templating import Jinja2Templates

from .db import (
    claim_pair_code,
    create_pair_code,
    delete_agent,
    get_agent,
    init_db,
    list_agents,
    list_pair_codes,
    now,
    update_last_seen,
    upsert_agent,
)

APP_VERSION = "14.0"

PANEL_SECRET_KEY = os.getenv("REALM_PANEL_SECRET", "changeme-panel-secret")
ADMIN_USER = os.getenv("REALM_PANEL_ADMIN_USER", "admin")
ADMIN_PASS = os.getenv("REALM_PANEL_ADMIN_PASS", "admin")

BASE_DIR = os.path.dirname(__file__)
TEMPLATES_DIR = os.path.join(BASE_DIR, "templates")
STATIC_DIR = os.path.join(BASE_DIR, "static")

templates = Jinja2Templates(directory=TEMPLATES_DIR)

app = FastAPI(title="Realm Pro Web Panel", version=APP_VERSION)
app.add_middleware(SessionMiddleware, secret_key=PANEL_SECRET_KEY, same_site="lax")
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")


# ---------------- Auth ----------------

def is_logged_in(request: Request) -> bool:
    return bool(request.session.get("logged_in"))


def require_login(request: Request) -> None:
    if not is_logged_in(request):
        raise HTTPException(status_code=401, detail="not logged in")


def login_required(request: Request):
    require_login(request)
    return True


@app.get("/login", response_class=HTMLResponse)
async def login_page(request: Request):
    return templates.TemplateResponse(
        "login.html",
        {
            "request": request,
            "version": APP_VERSION,
        },
    )


@app.post("/login")
async def login_action(request: Request, username: str = Form(...), password: str = Form(...)):
    if username == ADMIN_USER and password == ADMIN_PASS:
        request.session["logged_in"] = True
        return RedirectResponse(url="/", status_code=302)
    return templates.TemplateResponse(
        "login.html",
        {
            "request": request,
            "version": APP_VERSION,
            "error": "用户名或密码错误",
        },
        status_code=401,
    )


@app.get("/logout")
async def logout(request: Request):
    request.session.clear()
    return RedirectResponse(url="/login", status_code=302)


# ---------------- UI Pages ----------------

@app.get("/", response_class=HTMLResponse)
async def dashboard(request: Request, _: bool = Depends(login_required)):
    init_db()
    agents = list_agents()
    online_cnt = 0
    for a in agents:
        if (now() - int(a.get("last_seen", 0))) <= 120:
            online_cnt += 1
    stats = {
        "agents_total": len(agents),
        "agents_online": online_cnt,
        "pair_codes": list_pair_codes(10),
    }
    return templates.TemplateResponse(
        "dashboard.html",
        {"request": request, "agents": agents, "stats": stats, "version": APP_VERSION},
    )


@app.get("/agents/{agent_id}", response_class=HTMLResponse)
async def agent_detail(request: Request, agent_id: str, _: bool = Depends(login_required)):
    agent = get_agent(agent_id)
    if not agent:
        return RedirectResponse(url="/", status_code=302)
    return templates.TemplateResponse(
        "agent_detail.html",
        {"request": request, "agent": agent, "version": APP_VERSION},
    )


# ---------------- Panel API ----------------

@app.post("/api/pair_codes")
async def api_create_pair_code(request: Request, ttl: int = 600, _: bool = Depends(login_required)):
    return create_pair_code(ttl_seconds=int(ttl))


@app.get("/api/agents")
async def api_agents(_: bool = Depends(login_required)):
    return list_agents()


@app.delete("/api/agents/{agent_id}")
async def api_delete_agent(agent_id: str, _: bool = Depends(login_required)):
    delete_agent(agent_id)
    return {"ok": True}


# Agent calls this to claim pairing code
@app.post("/api/pair/claim")
async def api_pair_claim(payload: Dict[str, Any]):
    code = str(payload.get("code", "")).strip()
    agent_name = str(payload.get("agent_name", "agent")).strip() or "agent"
    api_url = str(payload.get("api_url", "")).strip()
    verify_tls = bool(payload.get("verify_tls", False))

    if not api_url:
        raise HTTPException(status_code=400, detail="missing api_url")

    if not claim_pair_code(code):
        raise HTTPException(status_code=400, detail="invalid or expired code")

    agent_id = secrets.token_hex(8)
    token = secrets.token_urlsafe(32)

    upsert_agent(agent_id, agent_name, api_url, token, verify_tls=verify_tls)

    return {"ok": True, "agent_id": agent_id, "token": token}


# Agent heartbeat
@app.post("/api/agent/heartbeat")
async def api_agent_heartbeat(request: Request, payload: Dict[str, Any]):
    agent_id = str(payload.get("agent_id", "")).strip()
    ts = int(payload.get("ts", int(time.time())))
    if not agent_id:
        raise HTTPException(status_code=400, detail="missing agent_id")

    agent = get_agent(agent_id)
    if not agent:
        raise HTTPException(status_code=404, detail="agent not found")

    # authenticate
    hdr = request.headers.get("authorization", "")
    if not hdr.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="missing bearer")
    tok = hdr.split(" ", 1)[1].strip()
    if tok != agent.get("token"):
        raise HTTPException(status_code=403, detail="invalid token")

    update_last_seen(agent_id, ts)
    return {"ok": True}


# ---------------- Proxy to Agent ----------------

async def _agent_client(agent: Dict[str, Any]) -> httpx.AsyncClient:
    return httpx.AsyncClient(
        base_url=agent["api_url"].rstrip("/"),
        verify=bool(agent.get("verify_tls", 0)),
        timeout=12.0,
        headers={"Authorization": f"Bearer {agent['token']}"},
    )


async def _proxy(agent_id: str, method: str, path: str, json: Optional[Dict[str, Any]] = None) -> Any:
    agent = get_agent(agent_id)
    if not agent:
        raise HTTPException(status_code=404, detail="agent not found")

    async with await _agent_client(agent) as client:
        r = await client.request(method, path, json=json)
        if r.status_code >= 400:
            raise HTTPException(status_code=r.status_code, detail=r.text)
        ct = r.headers.get("content-type", "")
        if "application/json" in ct:
            return r.json()
        return {"text": r.text}


@app.get("/api/agents/{agent_id}/status")
async def api_agent_status(agent_id: str, _: bool = Depends(login_required)):
    return await _proxy(agent_id, "GET", "/api/status")


@app.get("/api/agents/{agent_id}/rules")
async def api_agent_rules(agent_id: str, _: bool = Depends(login_required)):
    return await _proxy(agent_id, "GET", "/api/rules")


@app.post("/api/agents/{agent_id}/rules")
async def api_agent_rule_add(agent_id: str, payload: Dict[str, Any], _: bool = Depends(login_required)):
    return await _proxy(agent_id, "POST", "/api/rules", json=payload)


@app.put("/api/agents/{agent_id}/rules/{rule_id}")
async def api_agent_rule_edit(agent_id: str, rule_id: str, payload: Dict[str, Any], _: bool = Depends(login_required)):
    return await _proxy(agent_id, "PUT", f"/api/rules/{rule_id}", json=payload)


@app.delete("/api/agents/{agent_id}/rules/{rule_id}")
async def api_agent_rule_del(agent_id: str, rule_id: str, _: bool = Depends(login_required)):
    return await _proxy(agent_id, "DELETE", f"/api/rules/{rule_id}")


@app.post("/api/agents/{agent_id}/rules/{rule_id}/toggle")
async def api_agent_rule_toggle(agent_id: str, rule_id: str, enabled: bool, _: bool = Depends(login_required)):
    return await _proxy(agent_id, "POST", f"/api/rules/{rule_id}/toggle", json={"enabled": enabled})


@app.post("/api/agents/{agent_id}/apply")
async def api_agent_apply(agent_id: str, _: bool = Depends(login_required)):
    return await _proxy(agent_id, "POST", "/api/apply")


@app.get("/api/agents/{agent_id}/logs/{unit}")
async def api_agent_logs(agent_id: str, unit: str, lines: int = 200, _: bool = Depends(login_required)):
    return await _proxy(agent_id, "GET", f"/api/logs/{unit}?lines={int(lines)}")


@app.exception_handler(Exception)
async def handle_uncaught(request: Request, exc: Exception):
    # Don't leak HTML stack traces into the UI
    return JSONResponse(status_code=500, content={"detail": str(exc)})

