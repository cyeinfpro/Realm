import base64
import json
import os
import secrets
from typing import Any, Dict, List

from fastapi import Depends, FastAPI, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.middleware.sessions import SessionMiddleware

from .agent_client import AgentError, call_agent
from .auth import authenticate
from .db import (
    add_node,
    delete_node,
    get_node,
    init_db,
    list_nodes,
    update_node,
)

APP_DIR = os.path.dirname(os.path.abspath(__file__))
TEMPLATE_DIR = os.path.join(APP_DIR, "..", "templates")
STATIC_DIR = os.path.join(APP_DIR, "..", "static")

app = FastAPI(title="Realm Pro Panel")

secret_key = os.environ.get("PANEL_SECRET_KEY") or secrets.token_hex(32)
app.add_middleware(SessionMiddleware, secret_key=secret_key, same_site="lax")

app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")
templates = Jinja2Templates(directory=TEMPLATE_DIR)


@app.on_event("startup")
def _startup() -> None:
    init_db()


# -------------------------
# Auth helpers
# -------------------------

def require_login(request: Request) -> None:
    if not request.session.get("user"):
        raise HTTPException(status_code=401, detail="login required")


def ui_guard(request: Request):
    if not request.session.get("user"):
        return RedirectResponse("/login", status_code=302)
    return None


# -------------------------
# UI pages
# -------------------------

@app.get("/login", response_class=HTMLResponse)
def login_page(request: Request):
    return templates.TemplateResponse("login.html", {"request": request})


@app.post("/login")
def login_action(request: Request, username: str = Form(...), password: str = Form(...)):
    if authenticate(username, password):
        request.session["user"] = username
        return RedirectResponse("/", status_code=302)
    return templates.TemplateResponse(
        "login.html", {"request": request, "error": "用户名或密码错误"}, status_code=401
    )


@app.get("/logout")
def logout(request: Request):
    request.session.clear()
    return RedirectResponse("/login", status_code=302)


@app.get("/", response_class=HTMLResponse)
def home(request: Request):
    if not request.session.get("user"):
        return RedirectResponse("/login", status_code=302)
    nodes = list_nodes()
    return templates.TemplateResponse("index.html", {"request": request, "nodes": nodes})


@app.get("/nodes/{node_id}", response_class=HTMLResponse)
def node_page(request: Request, node_id: int):
    if not request.session.get("user"):
        return RedirectResponse("/login", status_code=302)
    node = get_node(node_id)
    if not node:
        return RedirectResponse("/", status_code=302)
    return templates.TemplateResponse("node.html", {"request": request, "node": node})


@app.get("/topology", response_class=HTMLResponse)
def topology_page(request: Request):
    if not request.session.get("user"):
        return RedirectResponse("/login", status_code=302)
    return templates.TemplateResponse("topology.html", {"request": request, "nodes": list_nodes()})


# -------------------------
# Panel API - nodes
# -------------------------

@app.get("/api/nodes")
def api_nodes(request: Request):
    require_login(request)
    return list_nodes()


@app.post("/api/nodes")
def api_add_node(request: Request, payload: Dict[str, Any]):
    require_login(request)
    name = (payload.get("name") or "").strip() or "Node"
    base_url = (payload.get("base_url") or "").strip()
    api_key = (payload.get("api_key") or "").strip()
    if not base_url or not api_key:
        raise HTTPException(status_code=400, detail="base_url/api_key required")
    node_id = add_node(name, base_url, api_key)
    return {"id": node_id}


@app.put("/api/nodes/{node_id}")
def api_update_node(request: Request, node_id: int, payload: Dict[str, Any]):
    require_login(request)
    if not update_node(node_id, payload.get("name"), payload.get("base_url"), payload.get("api_key")):
        raise HTTPException(status_code=404, detail="not found")
    return {"ok": True}


@app.delete("/api/nodes/{node_id}")
def api_delete_node(request: Request, node_id: int):
    require_login(request)
    if not delete_node(node_id):
        raise HTTPException(status_code=404, detail="not found")
    return {"ok": True}


# -------------------------
# Panel API - proxy to agents
# -------------------------

def _node_or_404(node_id: int) -> Dict[str, Any]:
    node = get_node(node_id)
    if not node:
        raise HTTPException(status_code=404, detail="node not found")
    return node


def proxy(node_id: int, path: str, method: str = "GET", body: Dict[str, Any] | None = None) -> Any:
    node = _node_or_404(node_id)
    try:
        return call_agent(node["base_url"], node["api_key"], path, method=method, body=body)
    except AgentError as e:
        raise HTTPException(status_code=502, detail=str(e))


@app.get("/api/nodes/{node_id}/status")
def api_node_status(request: Request, node_id: int):
    require_login(request)
    return proxy(node_id, "/api/status")


@app.get("/api/nodes/{node_id}/rules")
def api_node_rules(request: Request, node_id: int):
    require_login(request)
    return proxy(node_id, "/api/rules")


@app.post("/api/nodes/{node_id}/rules")
def api_add_rule(request: Request, node_id: int, payload: Dict[str, Any]):
    require_login(request)
    return proxy(node_id, "/api/rules", method="POST", body=payload)


@app.put("/api/nodes/{node_id}/rules/{rule_id}")
def api_update_rule(request: Request, node_id: int, rule_id: str, payload: Dict[str, Any]):
    require_login(request)
    return proxy(node_id, f"/api/rules/{rule_id}", method="PUT", body=payload)


@app.delete("/api/nodes/{node_id}/rules/{rule_id}")
def api_del_rule(request: Request, node_id: int, rule_id: str):
    require_login(request)
    return proxy(node_id, f"/api/rules/{rule_id}", method="DELETE")


@app.post("/api/nodes/{node_id}/rules/{rule_id}/toggle")
def api_toggle_rule(request: Request, node_id: int, rule_id: str, payload: Dict[str, Any]):
    require_login(request)
    return proxy(node_id, f"/api/rules/{rule_id}/toggle", method="POST", body=payload)


@app.post("/api/nodes/{node_id}/apply")
def api_apply(request: Request, node_id: int):
    require_login(request)
    return proxy(node_id, "/api/apply", method="POST", body={})


@app.get("/api/nodes/{node_id}/metrics")
def api_metrics(request: Request, node_id: int):
    require_login(request)
    return proxy(node_id, "/api/metrics")


# -------------------------
# Pair-code helpers (Panel-side)
# -------------------------

def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def _b64url_dec(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "==")


@app.post("/api/pair/encode")
def api_pair_encode(request: Request, payload: Dict[str, Any]):
    require_login(request)
    raw = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    return {"code": "RP1." + _b64url(raw)}


@app.post("/api/pair/decode")
def api_pair_decode(request: Request, payload: Dict[str, Any]):
    require_login(request)
    code = (payload.get("code") or "").strip()
    if not code.startswith("RP1."):
        raise HTTPException(status_code=400, detail="invalid pair code")
    try:
        raw = _b64url_dec(code[4:])
        return json.loads(raw.decode("utf-8"))
    except Exception:
        raise HTTPException(status_code=400, detail="invalid pair code")


# -------------------------
# Topology graph data
# -------------------------

@app.get("/api/topology")
def api_topology(request: Request):
    require_login(request)
    nodes = list_nodes()
    graph_nodes: List[Dict[str, Any]] = []
    graph_edges: List[Dict[str, Any]] = []

    for n in nodes:
        nid = f"node:{n['id']}"
        graph_nodes.append({"id": nid, "label": n["name"], "group": "node"})
        try:
            rules = call_agent(n["base_url"], n["api_key"], "/api/rules")
        except Exception:
            continue
        for r in rules.get("endpoints", []):
            rid = f"rule:{n['id']}:{r.get('id','')}"
            lp = r.get("listen", "")
            graph_nodes.append({"id": rid, "label": lp, "group": "rule"})
            graph_edges.append({"from": nid, "to": rid})
            remotes = []
            if r.get("remote"):
                remotes = [r["remote"]]
            elif r.get("remotes"):
                remotes = list(r["remotes"])
            elif r.get("extra_remotes"):
                remotes = list(r["extra_remotes"])
            for rm in remotes:
                tid = f"target:{rm}"
                graph_nodes.append({"id": tid, "label": rm, "group": "target"})
                graph_edges.append({"from": rid, "to": tid})

    # Deduplicate nodes by id
    uniq = {}
    for gn in graph_nodes:
        uniq[gn["id"]] = gn

    return {"nodes": list(uniq.values()), "edges": graph_edges}
