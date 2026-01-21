from __future__ import annotations

import json
import os
import time
import hmac
import hashlib
import secrets
from datetime import datetime
from urllib.parse import urlparse
from pathlib import Path
from typing import Any, Dict, Optional

from fastapi import Depends, FastAPI, File, Form, HTTPException, Request, UploadFile
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse, Response, PlainTextResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.middleware.sessions import SessionMiddleware

from .auth import ensure_secret_key, load_credentials, save_credentials, verify_login
from .db import (
    add_node,
    delete_node,
    ensure_db,
    get_node,
    get_node_by_api_key,
    get_desired_pool,
    get_last_report,
    list_nodes,
    set_desired_pool,
    update_node_report,
)
from .agents import agent_get, agent_post, agent_ping

BASE_DIR = Path(__file__).resolve().parent.parent
TEMPLATES_DIR = BASE_DIR / "templates"
STATIC_DIR = BASE_DIR / "static"

DEFAULT_AGENT_PORT = 18700

app = FastAPI(title="Realm Pro Panel", version="33")

# Session
secret = ensure_secret_key()
app.add_middleware(SessionMiddleware, secret_key=secret, session_cookie="realm_panel_sess")

# Static + templates
app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")
templates = Jinja2Templates(directory=str(TEMPLATES_DIR))

# DB init
ensure_db()


# ------------------------ Command signing (HMAC-SHA256) ------------------------


def _canonical_json(obj: Any) -> str:
    return json.dumps(obj, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _cmd_signature(secret: str, cmd: Dict[str, Any]) -> str:
    """Return hex HMAC-SHA256 signature for cmd (excluding sig field)."""
    data = {k: v for k, v in cmd.items() if k != "sig"}
    msg = _canonical_json(data).encode("utf-8")
    return hmac.new(secret.encode("utf-8"), msg, hashlib.sha256).hexdigest()


def _sign_cmd(secret: str, cmd: Dict[str, Any]) -> Dict[str, Any]:
    out = dict(cmd)
    # always include ts so signature cannot be replayed across long time windows
    out.setdefault("ts", int(time.time()))
    out["sig"] = _cmd_signature(secret, out)
    return out


# ------------------------ Pool diff: single-rule incremental patch ------------------------


def _single_rule_ops(base_pool: Dict[str, Any], desired_pool: Dict[str, Any]) -> Optional[list[Dict[str, Any]]]:
    """Return ops when there is exactly ONE rule change between base_pool and desired_pool.

    ops format:
      - {op: 'upsert', endpoint: {...}}
      - {op: 'remove', listen: '0.0.0.0:443'}

    If there are 0 changes -> returns []
    If changes > 1 -> returns None
    """

    def key_of(ep: Any) -> str:
        if not isinstance(ep, dict):
            return ""
        return str(ep.get("listen") or "").strip()

    base_eps = base_pool.get("endpoints") if isinstance(base_pool, dict) else None
    desired_eps = desired_pool.get("endpoints") if isinstance(desired_pool, dict) else None
    if not isinstance(base_eps, list) or not isinstance(desired_eps, list):
        return None

    base_map = {key_of(e): e for e in base_eps if key_of(e)}
    desired_map = {key_of(e): e for e in desired_eps if key_of(e)}

    changes: list[tuple[str, Any]] = []

    # add or update
    for listen, ep in desired_map.items():
        if listen not in base_map:
            changes.append(("upsert", ep))
        else:
            if _canonical_json(ep) != _canonical_json(base_map[listen]):
                changes.append(("upsert", ep))

    # remove
    for listen in base_map.keys():
        if listen not in desired_map:
            changes.append(("remove", listen))

    if len(changes) == 0:
        return []
    if len(changes) != 1:
        return None

    op, payload = changes[0]
    if op == "upsert":
        return [{"op": "upsert", "endpoint": payload}]
    return [{"op": "remove", "listen": payload}]


def _is_report_fresh(node: Dict[str, Any], max_age_sec: int = 15) -> bool:
    ts = node.get("last_seen_at")
    if not ts:
        return False
    try:
        dt = datetime.strptime(str(ts), "%Y-%m-%d %H:%M:%S")
        return (datetime.now() - dt).total_seconds() <= max_age_sec
    except Exception:
        return False


def _flash(request: Request) -> Optional[str]:
    msg = request.session.pop("flash", None)
    return msg


def _set_flash(request: Request, msg: str) -> None:
    request.session["flash"] = msg


def _has_credentials() -> bool:
    return load_credentials() is not None


def _generate_api_key() -> str:
    return secrets.token_hex(16)


def _split_host_and_port(value: str, fallback_port: int) -> tuple[str, int, bool, str]:
    raw = value.strip()
    if not raw:
        return "", fallback_port, False, "http"
    if "://" in raw:
        parsed = urlparse(raw)
        host = parsed.hostname or ""
        port = parsed.port or fallback_port
        scheme = parsed.scheme or "http"
        return host, port, parsed.port is not None, scheme
    if raw.startswith("[") and "]" in raw:
        host_part, rest = raw.split("]", 1)
        host = host_part[1:].strip()
        rest = rest.strip()
        if rest.startswith(":") and rest[1:].isdigit():
            return host, int(rest[1:]), True, "http"
        return host, fallback_port, False, "http"
    if raw.count(":") == 1 and raw.rsplit(":", 1)[1].isdigit():
        host, port_s = raw.rsplit(":", 1)
        return host.strip(), int(port_s), True, "http"
    return raw, fallback_port, False, "http"


def _format_host_for_url(host: str) -> str:
    if ":" in host and not host.startswith("["):
        return f"[{host}]"
    return host


def _extract_port_from_url(base_url: str, fallback_port: int) -> int:
    target = base_url.strip()
    if "://" not in target:
        target = f"http://{target}"
    parsed = urlparse(target)
    return parsed.port or fallback_port


def _extract_ip_for_display(base_url: str) -> str:
    """UI 只展示纯 IP/Host（不展示端口、不展示协议）。"""
    raw = (base_url or "").strip()
    if not raw:
        return ""
    if "://" not in raw:
        raw = f"http://{raw}"
    try:
        parsed = urlparse(raw)
        return parsed.hostname or (base_url or "").strip()
    except Exception:
        return (base_url or "").strip()


def _node_verify_tls(node: Dict[str, Any]) -> bool:
    return bool(node.get("verify_tls", 0))


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
    for n in nodes:
        n["display_ip"] = _extract_ip_for_display(n.get("base_url", ""))
        n["online"] = _is_report_fresh(n)
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
            "default_port": DEFAULT_AGENT_PORT,
        },
    )


@app.post("/nodes/new")
async def node_new_action(
    request: Request,
    name: str = Form(""),
    ip_address: str = Form(...),
    scheme: str = Form("http"),
    api_key: str = Form(""),
    verify_tls: Optional[str] = Form(None),
):
    user = request.session.get("user")
    if not user:
        return RedirectResponse(url="/login", status_code=303)

    ip_address = ip_address.strip()
    api_key = api_key.strip() or _generate_api_key()
    scheme = scheme.strip().lower() or "http"
    if scheme not in ("http", "https"):
        _set_flash(request, "协议仅支持 http 或 https")
        return RedirectResponse(url="/nodes/new", status_code=303)
    if not ip_address:
        _set_flash(request, "IP 地址不能为空")
        return RedirectResponse(url="/nodes/new", status_code=303)
    if "://" not in ip_address:
        ip_address = f"{scheme}://{ip_address}"

    # 端口在 UI 中隐藏：
    # - 默认使用 Agent 标准端口 18700
    # - 如用户在 IP 中自带 :port，则仍可解析并写入 base_url（兼容特殊环境）
    port_value = DEFAULT_AGENT_PORT
    host, parsed_port, has_port, scheme = _split_host_and_port(ip_address, port_value)
    if not host:
        _set_flash(request, "IP 地址不能为空")
        return RedirectResponse(url="/nodes/new", status_code=303)
    if has_port:
        port_value = parsed_port

    base_url = f"{scheme}://{_format_host_for_url(host)}"  # 不在 UI 展示端口

    # name 为空则默认使用“纯 IP/Host”
    display_name = (name or "").strip() or _extract_ip_for_display(base_url)

    node_id = add_node(display_name, base_url, api_key, verify_tls=bool(verify_tls))
    request.session["show_install_cmd"] = True
    _set_flash(request, "已添加机器")
    return RedirectResponse(url=f"/nodes/{node_id}", status_code=303)


@app.post("/nodes/add")
async def node_add_action(
    request: Request,
    name: str = Form(""),
    base_url: str = Form(...),
    api_key: str = Form(...),
    verify_tls: Optional[str] = Form(None),
):
    if not request.session.get("user"):
        return RedirectResponse(url="/login", status_code=303)

    base_url = base_url.strip()
    api_key = api_key.strip()
    if not base_url or not api_key:
        _set_flash(request, "API 地址与 Token 不能为空")
        return RedirectResponse(url="/", status_code=303)

    node_id = add_node(name or base_url, base_url, api_key, verify_tls=bool(verify_tls))
    _set_flash(request, "已添加节点")
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
    node["display_ip"] = _extract_ip_for_display(node.get("base_url", ""))

    # ✅ 一键接入 / 卸载命令（短命令，避免超长）
    # 说明：使用 node.api_key 作为 join token，脚本由面板返回并带参数执行。
    install_cmd = f"curl -fsSL {base_url}/join/{node['api_key']} | bash"
    uninstall_cmd = f"curl -fsSL {base_url}/uninstall/{node['api_key']} | bash"

    # 兼容旧字段（模板里可能还引用 node_port）
    agent_port = DEFAULT_AGENT_PORT
    return templates.TemplateResponse(
        "node.html",
        {
            "request": request,
            "user": user,
            "node": node,
            "flash": _flash(request),
            "title": node["name"],
            "node_port": agent_port,
            "install_cmd": install_cmd,
            "uninstall_cmd": uninstall_cmd,
            "show_install_cmd": show_install_cmd,
        },
    )


# ------------------------ Short join / uninstall scripts (no login) ------------------------


@app.get("/join/{token}", response_class=PlainTextResponse)
async def join_script(request: Request, token: str):
    """短命令接入脚本：curl .../join/<token> | bash

    token = node.api_key（用于定位节点），脚本内部会写入 /etc/realm-agent/api.key，
    并从面板 /static 拉取 realm_agent.sh 以及 realm-agent.zip。
    """

    node = get_node_by_api_key(token)
    if not node:
        return PlainTextResponse("echo '[ERR] invalid token'\n", status_code=404)

    base_url = str(request.base_url).rstrip("/")
    node_id = int(node.get("id"))
    api_key = str(node.get("api_key"))
    repo_zip_url = f"{base_url}/static/realm-agent.zip"

    script = f"""#!/usr/bin/env bash
set -euo pipefail

PANEL_URL=\"{base_url}\"
NODE_ID=\"{node_id}\"
API_KEY=\"{api_key}\"

if [[ \"$(id -u)\" -ne 0 ]]; then
  if command -v sudo >/dev/null 2>&1; then
    echo \"[提示] 需要 root，自动尝试 sudo...\" >&2
    exec sudo -E bash -c \"curl -fsSL $PANEL_URL/join/{api_key} | bash\"
  fi
  echo \"[ERR ] 需要 root 权限运行（当前机器无 sudo）。请先 su - 后重试。\" >&2
  exit 1
fi

mkdir -p /etc/realm-agent
echo \"$API_KEY\" > /etc/realm-agent/api.key

echo \"[提示] 正在安装/更新 Agent...\" >&2
curl -fsSL $PANEL_URL/static/realm_agent.sh | \
  REALM_AGENT_REPO_ZIP_URL=\"{repo_zip_url}\" \
  REALM_AGENT_FORCE_UPDATE=1 \
  REALM_AGENT_MODE=1 \
  REALM_AGENT_PORT={DEFAULT_AGENT_PORT} \
  REALM_AGENT_ASSUME_YES=1 \
  REALM_PANEL_URL=\"$PANEL_URL\" \
  REALM_AGENT_ID=\"$NODE_ID\" \
  REALM_AGENT_HEARTBEAT_INTERVAL=3 \
  bash
"""
    return PlainTextResponse(script, media_type="text/plain; charset=utf-8")


@app.get("/uninstall/{token}", response_class=PlainTextResponse)
async def uninstall_script(request: Request, token: str):
    """短命令卸载脚本：curl .../uninstall/<token> | bash"""

    node = get_node_by_api_key(token)
    if not node:
        return PlainTextResponse("echo '[ERR] invalid token'\n", status_code=404)

    base_url = str(request.base_url).rstrip("/")
    api_key = str(node.get("api_key"))
    script = f"""#!/usr/bin/env bash
set -euo pipefail

PANEL_URL=\"{base_url}\"

if [[ \"$(id -u)\" -ne 0 ]]; then
  if command -v sudo >/dev/null 2>&1; then
    echo \"[提示] 需要 root，自动尝试 sudo...\" >&2
    exec sudo -E bash -c \"curl -fsSL $PANEL_URL/uninstall/{api_key} | bash\"
  fi
  echo \"[ERR ] 需要 root 权限运行（当前机器无 sudo）。请先 su - 后重试。\" >&2
  exit 1
fi

echo \"[提示] 卸载 Agent / Realm...\" >&2
systemctl disable --now realm-agent.service realm-agent-https.service realm.service realm \
  >/dev/null 2>&1 || true
rm -f /etc/systemd/system/realm-agent.service /etc/systemd/system/realm-agent-https.service \
  /etc/systemd/system/realm.service || true
systemctl daemon-reload || true

rm -rf /opt/realm-agent /etc/realm-agent /etc/realm /opt/realm || true
rm -f /usr/local/bin/realm /usr/bin/realm || true

echo \"[OK] 已卸载\" >&2
"""
    return PlainTextResponse(script, media_type="text/plain; charset=utf-8")


# ------------------------ Agent push-report API (no login) ------------------------


@app.post("/api/agent/report")
async def api_agent_report(request: Request, payload: Dict[str, Any]):
    """Agent主动上报接口。

    认证：HTTP Header `X-API-Key: <node.api_key>`。
    载荷：至少包含 node_id 字段。

    返回：commands（例如同步规则池）。
    """

    api_key = (request.headers.get("x-api-key") or request.headers.get("X-API-Key") or "").strip()
    node_id_raw = payload.get("node_id")
    try:
        node_id = int(node_id_raw)
    except Exception:
        return JSONResponse({"ok": False, "error": "invalid node_id"}, status_code=400)

    node = get_node(node_id)
    if not node:
        return JSONResponse({"ok": False, "error": "node not found"}, status_code=404)
    if not api_key or api_key != node.get("api_key"):
        return JSONResponse({"ok": False, "error": "unauthorized"}, status_code=403)

    # report_json：尽量只保存 report 字段（更干净），但也兼容直接上报全量
    report = payload.get("report") if isinstance(payload, dict) else None
    if report is None:
        report = payload
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    ack_version = payload.get("ack_version")
    try:
        update_node_report(
            node_id=node_id,
            report_json=json.dumps(report, ensure_ascii=False),
            last_seen_at=now,
            agent_ack_version=int(ack_version) if ack_version is not None else None,
        )
    except Exception:
        # 不要让写库失败影响 agent
        pass

    # 若面板尚无 desired_pool，则尝试把 agent 当前 pool 作为初始 desired_pool
    desired_ver, desired_pool = get_desired_pool(node_id)
    if desired_pool is None:
        rep_pool = None
        if isinstance(report, dict):
            rep_pool = report.get("pool")
        if isinstance(rep_pool, dict):
            desired_ver, desired_pool = set_desired_pool(node_id, rep_pool)

    # 下发命令：规则池同步
    cmds: list[dict[str, Any]] = []
    try:
        agent_ack = int(ack_version) if ack_version is not None else 0
    except Exception:
        agent_ack = 0
    if isinstance(desired_pool, dict) and desired_ver > agent_ack:
        # ✅ 单条规则增量下发：仅当 agent 落后 1 个版本，且报告中存在当前 pool 时才尝试 patch
        base_pool = None
        if isinstance(report, dict):
            base_pool = report.get("pool") if isinstance(report.get("pool"), dict) else None

        cmd: Dict[str, Any]
        ops = None
        if desired_ver == agent_ack + 1 and isinstance(base_pool, dict):
            ops = _single_rule_ops(base_pool, desired_pool)

        if isinstance(ops, list) and len(ops) == 1:
            cmd = {
                "type": "pool_patch",
                "version": desired_ver,
                "base_version": agent_ack,
                "ops": ops,
                "apply": True,
            }
        else:
            cmd = {
                "type": "sync_pool",
                "version": desired_ver,
                "pool": desired_pool,
                "apply": True,
            }

        cmds.append(_sign_cmd(str(node.get("api_key") or ""), cmd))

    return {"ok": True, "server_time": now, "desired_version": desired_ver, "commands": cmds}


# ------------------------ API (needs login) ------------------------

@app.get("/api/nodes/{node_id}/ping")
async def api_ping(request: Request, node_id: int, user: str = Depends(require_login)):
    node = get_node(node_id)
    if not node:
        return JSONResponse({"ok": False, "error": "node not found"}, status_code=404)

    # Push-report mode: agent has reported recently -> online (no need panel->agent reachability)
    if _is_report_fresh(node):
        rep = get_last_report(node_id)
        info = rep.get("info") if isinstance(rep, dict) else None
        # keep兼容旧前端：ping 只关心 ok + latency_ms
        return {
            "ok": True,
            "source": "report",
            "last_seen_at": node.get("last_seen_at"),
            "info": info,
        }

    info = await agent_ping(node["base_url"], node["api_key"], _node_verify_tls(node))
    if not info.get("ok"):
        return {"ok": False, "error": info.get("error", "offline")}
    return info


@app.get("/api/nodes/{node_id}/pool")
async def api_pool_get(request: Request, node_id: int, user: str = Depends(require_login)):
    node = get_node(node_id)
    if not node:
        return JSONResponse({"ok": False, "error": "node not found"}, status_code=404)

    # Push-report mode: prefer desired pool stored on panel
    desired_ver, desired_pool = get_desired_pool(node_id)
    if isinstance(desired_pool, dict):
        return {"ok": True, "pool": desired_pool, "desired_version": desired_ver, "source": "panel_desired"}

    # If no desired pool, try last report snapshot
    rep = get_last_report(node_id)
    if isinstance(rep, dict) and isinstance(rep.get("pool"), dict):
        return {"ok": True, "pool": rep.get("pool"), "source": "report_cache"}
    try:
        data = await agent_get(node["base_url"], node["api_key"], "/api/v1/pool", _node_verify_tls(node))
        return data
    except Exception as exc:
        return JSONResponse({"ok": False, "error": str(exc)}, status_code=502)


@app.get("/api/nodes/{node_id}/backup")
async def api_backup(request: Request, node_id: int, user: str = Depends(require_login)):
    node = get_node(node_id)
    if not node:
        return JSONResponse({"ok": False, "error": "node not found"}, status_code=404)
    # Prefer panel-desired pool (push mode), then cached report, then pull from agent
    desired_ver, desired_pool = get_desired_pool(node_id)
    if isinstance(desired_pool, dict):
        data = {"ok": True, "pool": desired_pool, "desired_version": desired_ver, "source": "panel_desired"}
    else:
        rep = get_last_report(node_id)
        if isinstance(rep, dict) and isinstance(rep.get("pool"), dict):
            data = {"ok": True, "pool": rep.get("pool"), "source": "report_cache"}
        else:
            try:
                data = await agent_get(node["base_url"], node["api_key"], "/api/v1/pool", _node_verify_tls(node))
            except Exception as exc:
                return JSONResponse({"ok": False, "error": str(exc)}, status_code=502)
    filename = f"realm-rules-node-{node_id}.json"
    payload = json.dumps(data, ensure_ascii=False, indent=2)
    headers = {"Content-Disposition": f'attachment; filename="{filename}"'}
    return Response(content=payload, media_type="application/json", headers=headers)


@app.post("/api/nodes/{node_id}/restore")
async def api_restore(
    request: Request,
    node_id: int,
    file: UploadFile = File(...),
    user: str = Depends(require_login),
):
    node = get_node(node_id)
    if not node:
        return JSONResponse({"ok": False, "error": "node not found"}, status_code=404)
    try:
        raw = await file.read()
        payload = json.loads(raw.decode("utf-8"))
    except Exception as exc:
        return JSONResponse({"ok": False, "error": f"invalid backup file: {exc}"}, status_code=400)
    pool = payload.get("pool") if isinstance(payload, dict) else None
    if pool is None:
        pool = payload
    if not isinstance(pool, dict):
        return JSONResponse({"ok": False, "error": "backup missing pool data"}, status_code=400)
    # Store on panel and attempt immediate apply if agent reachable.
    desired_ver, _ = set_desired_pool(node_id, pool)
    try:
        data = await agent_post(
            node["base_url"],
            node["api_key"],
            "/api/v1/pool",
            {"pool": pool},
            _node_verify_tls(node),
        )
        if data.get("ok", True):
            await agent_post(node["base_url"], node["api_key"], "/api/v1/apply", {}, _node_verify_tls(node))
        return {"ok": True, "desired_version": desired_ver, "queued": True}
    except Exception:
        return {"ok": True, "desired_version": desired_ver, "queued": True}


@app.post("/api/nodes/{node_id}/pool")
async def api_pool_set(request: Request, node_id: int, payload: Dict[str, Any], user: str = Depends(require_login)):
    node = get_node(node_id)
    if not node:
        return JSONResponse({"ok": False, "error": "node not found"}, status_code=404)
    pool = payload.get("pool") if isinstance(payload, dict) else None
    if pool is None and isinstance(payload, dict):
        # some callers may post the pool dict directly
        pool = payload
    if not isinstance(pool, dict):
        return JSONResponse({"ok": False, "error": "missing pool"}, status_code=400)

    # Store desired pool on panel. Agent will pull it on next report.
    desired_ver, _ = set_desired_pool(node_id, pool)

    # Best-effort immediate apply if panel can still reach agent
    try:
        data = await agent_post(node["base_url"], node["api_key"], "/api/v1/pool", {"pool": pool}, _node_verify_tls(node))
        if data.get("ok", True):
            await agent_post(node["base_url"], node["api_key"], "/api/v1/apply", {}, _node_verify_tls(node))
            return {"ok": True, "pool": pool, "desired_version": desired_ver, "applied": True}
    except Exception:
        pass

    return {"ok": True, "pool": pool, "desired_version": desired_ver, "queued": True, "note": "waiting agent report"}


@app.post("/api/nodes/{node_id}/apply")
async def api_apply(request: Request, node_id: int, user: str = Depends(require_login)):
    node = get_node(node_id)
    if not node:
        return JSONResponse({"ok": False, "error": "node not found"}, status_code=404)
    try:
        data = await agent_post(
            node["base_url"],
            node["api_key"],
            "/api/v1/apply",
            {},
            _node_verify_tls(node),
        )
        if not data.get("ok", True):
            return JSONResponse({"ok": False, "error": data.get("error", "agent apply failed")}, status_code=502)
        return data
    except Exception:
        # Push-report fallback: bump desired version to trigger a re-sync/apply on agent
        desired_ver, desired_pool = get_desired_pool(node_id)
        if isinstance(desired_pool, dict):
            new_ver, _ = set_desired_pool(node_id, desired_pool)
            return {"ok": True, "queued": True, "desired_version": new_ver}
        return {"ok": False, "error": "agent unreachable and no desired pool found"}


@app.get("/api/nodes/{node_id}/stats")
async def api_stats(request: Request, node_id: int, user: str = Depends(require_login)):
    node = get_node(node_id)
    if not node:
        return JSONResponse({"ok": False, "error": "node not found"}, status_code=404)

    # Push-report cache
    if _is_report_fresh(node):
        rep = get_last_report(node_id)
        if isinstance(rep, dict) and isinstance(rep.get("stats"), dict):
            out = rep["stats"]
            out["source"] = "report"
            return out
    try:
        data = await agent_get(node["base_url"], node["api_key"], "/api/v1/stats", _node_verify_tls(node))
        return data
    except Exception as exc:
        # 注意：这里不要返回 502。
        # 1) 浏览器端 fetch 会把非 2xx 视为失败，导致只能显示“HTTP 502”这类笼统信息；
        # 2) 部分反代会把 502 的 body 替换为空/HTML，进一步丢失真实原因。
        # 因此用 200 + ok=false 的方式，把失败原因稳定传给前端。
        return {"ok": False, "error": str(exc), "rules": []}


@app.get("/api/nodes/{node_id}/graph")
async def api_graph(request: Request, node_id: int, user: str = Depends(require_login)):
    node = get_node(node_id)
    if not node:
        return JSONResponse({"ok": False, "error": "node not found"}, status_code=404)
    desired_ver, desired_pool = get_desired_pool(node_id)
    pool = desired_pool if isinstance(desired_pool, dict) else None

    if pool is None and _is_report_fresh(node):
        rep = get_last_report(node_id)
        if isinstance(rep, dict) and isinstance(rep.get("pool"), dict):
            pool = rep["pool"]

    if pool is None:
        try:
            data = await agent_get(node["base_url"], node["api_key"], "/api/v1/pool", _node_verify_tls(node))
            pool = data.get("pool") if isinstance(data, dict) else None
        except Exception as exc:
            return JSONResponse({"ok": False, "error": str(exc)}, status_code=502)
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
