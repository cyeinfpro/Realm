from __future__ import annotations

import asyncio
import json
import os
import time
import hmac
import hashlib
import secrets
import uuid
import io
import zipfile
from datetime import datetime
from urllib.parse import urlparse
from pathlib import Path
from typing import Any, Dict, Optional, List

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
    get_node_by_base_url,
    get_desired_pool,
    get_last_report,
    list_nodes,
    set_desired_pool,
    set_desired_pool_exact,
    set_desired_pool_version_exact,
    update_node_basic,
    update_node_report,
)
from .agents import agent_get, agent_post, agent_ping

BASE_DIR = Path(__file__).resolve().parent.parent
TEMPLATES_DIR = BASE_DIR / "templates"
STATIC_DIR = BASE_DIR / "static"

DEFAULT_AGENT_PORT = 18700

def _panel_public_base_url(request: Request) -> str:
    """Return panel public base URL for generating scripts/links.

    If REALM_PANEL_PUBLIC_URL is set, it takes precedence.
    """
    cfg = (os.getenv("REALM_PANEL_PUBLIC_URL") or os.getenv("REALM_PANEL_URL") or "").strip()
    if cfg:
        cfg = cfg.rstrip('/')
        if '://' not in cfg:
            # When user only provides domain/host, default to https (typical reverse-proxy setup).
            cfg = 'https://' + cfg
        return cfg
    return str(request.base_url).rstrip('/')


app = FastAPI(title="Realm Pro Panel", version="33")

# Session
secret = ensure_secret_key()
app.add_middleware(SessionMiddleware, secret_key=secret, session_cookie="realm_panel_sess")

# Static + templates
app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")
templates = Jinja2Templates(directory=str(TEMPLATES_DIR))

# DB init
ensure_db()


# ------------------------ Backup helpers ------------------------


async def _get_pool_for_backup(node: Dict[str, Any]) -> Dict[str, Any]:
    """Get pool data for backup.

    Prefer panel-desired (push mode), then cached report, then pull from agent.
    """
    node_id = int(node.get("id") or 0)
    desired_ver, desired_pool = get_desired_pool(node_id)
    if isinstance(desired_pool, dict):
        return {
            "ok": True,
            "pool": desired_pool,
            "desired_version": desired_ver,
            "source": "panel_desired",
        }

    rep = get_last_report(node_id)
    if isinstance(rep, dict) and isinstance(rep.get("pool"), dict):
        return {"ok": True, "pool": rep.get("pool"), "source": "report_cache"}

    try:
        data = await agent_get(node.get("base_url", ""), node.get("api_key", ""), "/api/v1/pool", _node_verify_tls(node))
        # keep consistent shape
        if isinstance(data, dict) and isinstance(data.get("pool"), dict):
            return {"ok": True, "pool": data.get("pool"), "source": "agent_pull"}
        return data if isinstance(data, dict) else {"ok": False, "error": "agent_return_invalid"}
    except Exception as exc:
        return {"ok": False, "error": str(exc), "source": "agent_pull"}


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


def _is_report_fresh(node: Dict[str, Any], max_age_sec: int = 90) -> bool:
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


def _safe_filename_part(name: str, default: str = "node", max_len: int = 60) -> str:
    """Make a filesystem-friendly filename part (keeps Chinese/letters/numbers/_-)."""
    raw = (name or "").strip()
    if not raw:
        return default
    out = []
    for ch in raw:
        if ch.isalnum() or ch in ("-", "_") or ("\u4e00" <= ch <= "\u9fff"):
            out.append(ch)
        elif ch in (" ", "."):
            out.append("-")
        # else: drop
    s = "".join(out).strip("-")
    s = s or default
    return s[:max_len]


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



async def _bg_apply_pool(node: Dict[str, Any], pool: Dict[str, Any]) -> None:
    """Best-effort: push pool to agent and apply in background (do not block HTTP responses)."""
    try:
        data = await agent_post(
            node["base_url"],
            node["api_key"],
            "/api/v1/pool",
            {"pool": pool},
            _node_verify_tls(node),
        )
        if isinstance(data, dict) and data.get("ok", True):
            await agent_post(node["base_url"], node["api_key"], "/api/v1/apply", {}, _node_verify_tls(node))
    except Exception:
        return


def _schedule_apply_pool(node: Dict[str, Any], pool: Dict[str, Any]) -> None:
    """Schedule best-effort agent apply without blocking the request."""
    try:
        asyncio.create_task(_bg_apply_pool(node, pool))
    except Exception:
        pass

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
    group_name: str = Form("默认分组"),
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

    base_url = f"{scheme}://{_format_host_for_url(host)}:{port_value}"  # 不在 UI 展示端口

    # name 为空则默认使用“纯 IP/Host”
    display_name = (name or "").strip() or _extract_ip_for_display(base_url)

    node_id = add_node(display_name, base_url, api_key, verify_tls=bool(verify_tls), group_name=group_name)
    request.session["show_install_cmd"] = True
    _set_flash(request, "已添加机器")
    return RedirectResponse(url=f"/nodes/{node_id}", status_code=303)


@app.post("/nodes/add")
async def node_add_action(
    request: Request,
    name: str = Form(""),
    group_name: str = Form("默认分组"),
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

    node_id = add_node(name or base_url, base_url, api_key, verify_tls=bool(verify_tls), group_name=group_name)
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

    # 用于节点页左侧快速切换列表
    nodes = list_nodes()
    for n in nodes:
        n["display_ip"] = _extract_ip_for_display(n.get("base_url", ""))
        # 用更宽松的阈值显示在线状态（避免轻微抖动导致频繁显示离线）
        n["online"] = _is_report_fresh(n, max_age_sec=90)

    # 节点页左侧列表：按分组聚合展示
    # - 分组名为空时统一归入“默认分组”
    # - 组内排序：在线优先，其次按 id 倒序
    def _gn(x: Dict[str, Any]) -> str:
        g = str(x.get("group_name") or "").strip()
        return g or "默认分组"

    for n in nodes:
        n["group_name"] = _gn(n)

    nodes_sorted = sorted(
        nodes,
        key=lambda x: (
            _gn(x),
            0 if bool(x.get("online")) else 1,
            -int(x.get("id") or 0),
        ),
    )
    node_groups: List[Dict[str, Any]] = []
    cur = None
    buf: List[Dict[str, Any]] = []
    for n in nodes_sorted:
        g = _gn(n)
        if cur is None:
            cur = g
        if g != cur:
            node_groups.append(
                {
                    "name": cur,
                    "nodes": buf,
                    "online": sum(1 for i in buf if i.get("online")),
                    "total": len(buf),
                }
            )
            cur = g
            buf = []
        buf.append(n)
    if cur is not None:
        node_groups.append(
            {
                "name": cur,
                "nodes": buf,
                "online": sum(1 for i in buf if i.get("online")),
                "total": len(buf),
            }
        )
    show_install_cmd = bool(request.session.pop("show_install_cmd", False))
    show_edit_node = str(request.query_params.get("edit") or "").strip() in ("1", "true", "yes")
    base_url = _panel_public_base_url(request)
    node["display_ip"] = _extract_ip_for_display(node.get("base_url", ""))

    # 在线判定：默认心跳 30s，取 3 倍窗口避免误判
    node["online"] = _is_report_fresh(node, max_age_sec=90)

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
            "nodes": nodes,
            "node_groups": node_groups,
            "node": node,
            "flash": _flash(request),
            "title": node["name"],
            "node_port": agent_port,
            "install_cmd": install_cmd,
            "uninstall_cmd": uninstall_cmd,
            "show_install_cmd": show_install_cmd,
            "show_edit_node": show_edit_node,
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
        return PlainTextResponse("""echo '[错误] 接入链接无效：token 不存在或已失效' >&2
exit 1
""", status_code=404)

    base_url = _panel_public_base_url(request)
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
  echo \"[错误] 需要 root 权限运行，但系统未安装 sudo。请切换到 root 后重试（sudo -i / su -）。\" >&2
  exit 1
fi

mkdir -p /etc/realm-agent
echo \"$API_KEY\" > /etc/realm-agent/api.key

echo \"[提示] 正在安装/更新 Realm Agent…\" >&2
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
        return PlainTextResponse("""echo '[错误] 接入链接无效：token 不存在或已失效' >&2
exit 1
""", status_code=404)

    base_url = _panel_public_base_url(request)
    api_key = str(node.get("api_key"))
    script = f"""#!/usr/bin/env bash
set -euo pipefail

PANEL_URL=\"{base_url}\"

if [[ \"$(id -u)\" -ne 0 ]]; then
  if command -v sudo >/dev/null 2>&1; then
    echo \"[提示] 需要 root，自动尝试 sudo...\" >&2
    exec sudo -E bash -c \"curl -fsSL $PANEL_URL/uninstall/{api_key} | bash\"
  fi
  echo \"[错误] 需要 root 权限运行，但系统未安装 sudo。请切换到 root 后重试（sudo -i / su -）。\" >&2
  exit 1
fi

echo \"[提示] 正在卸载 Realm Agent / Realm…\" >&2
systemctl disable --now realm-agent.service realm-agent-https.service realm.service realm \
  >/dev/null 2>&1 || true
rm -f /etc/systemd/system/realm-agent.service /etc/systemd/system/realm-agent-https.service \
  /etc/systemd/system/realm.service || true
systemctl daemon-reload || true

rm -rf /opt/realm-agent /etc/realm-agent /etc/realm /opt/realm || true
rm -f /usr/local/bin/realm /usr/bin/realm || true

echo \"[OK] 卸载完成\" >&2
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
        return JSONResponse({"ok": False, "error": "节点 ID 无效"}, status_code=400)

    node = get_node(node_id)
    if not node:
        return JSONResponse({"ok": False, "error": "节点不存在"}, status_code=404)
    if not api_key or api_key != node.get("api_key"):
        return JSONResponse({"ok": False, "error": "无权限（API Key 不正确）"}, status_code=403)

    # report_json：尽量只保存 report 字段（更干净），但也兼容直接上报全量
    report = payload.get("report") if isinstance(payload, dict) else None
    if report is None:
        report = payload
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    ack_version = payload.get("ack_version")

    # Parse agent ack version early (used for version realignment)
    try:
        agent_ack = int(ack_version) if ack_version is not None else 0
    except Exception:
        agent_ack = 0
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

    # 若面板尚无 desired_pool，则尝试把 agent 当前 pool 作为初始 desired_pool。
    # ⚠️ 关键：当面板重装/恢复后，Agent 可能还保留旧的 ack_version（例如 33），
    # 如果面板把 desired_pool_version 从 1 开始，后续新增规则会一直小于 ack_version，
    # 导致面板永远不下发 commands，看起来像“不同步”。
    # 这里将面板 desired_pool_version 对齐到 agent_ack（至少 1），避免版本回退。
    desired_ver, desired_pool = get_desired_pool(node_id)
    if desired_pool is None:
        rep_pool = None
        if isinstance(report, dict):
            rep_pool = report.get("pool")
        if isinstance(rep_pool, dict):
            init_ver = max(1, agent_ack)
            desired_ver, desired_pool = set_desired_pool_exact(node_id, rep_pool, init_ver)
    else:
        # Desired exists but version is behind agent ack (panel DB reset or migrated)
        if agent_ack > desired_ver:
            desired_ver = set_desired_pool_version_exact(node_id, agent_ack)

    # 下发命令：规则池同步
    cmds: list[dict[str, Any]] = []
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
        return JSONResponse({"ok": False, "error": "节点不存在"}, status_code=404)

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
        return JSONResponse({"ok": False, "error": "节点不存在"}, status_code=404)

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
        return JSONResponse({"ok": False, "error": "节点不存在"}, status_code=404)
    data = await _get_pool_for_backup(node)
    # 规则文件名包含节点名，便于区分
    safe = _safe_filename_part(node.get("name") or f"node-{node_id}")
    filename = f"realm-rules-{safe}-id{node_id}.json"
    payload = json.dumps(data, ensure_ascii=False, indent=2)
    headers = {"Content-Disposition": f'attachment; filename="{filename}"'}
    return Response(content=payload, media_type="application/json", headers=headers)


@app.get("/api/backup/full")
async def api_backup_full(request: Request, user: str = Depends(require_login)):
    """Download a full backup zip: nodes list + per-node rules."""
    nodes = list_nodes()
    ts = datetime.now().strftime("%Y%m%d-%H%M%S")

    # Build backup payloads (fetch missing pools concurrently)
    async def build_one(n: Dict[str, Any]) -> tuple[str, Dict[str, Any]]:
        node_id = int(n.get("id") or 0)
        data = await _get_pool_for_backup(n)
        data.setdefault("node", {"id": node_id, "name": n.get("name"), "base_url": n.get("base_url")})
        safe = _safe_filename_part(n.get("name") or f"node-{node_id}")
        path = f"rules/realm-rules-{safe}-id{node_id}.json"
        return path, data

    rules_entries: list[tuple[str, Dict[str, Any]]] = []
    if nodes:
        # Avoid unbounded parallelism
        import asyncio

        sem = asyncio.Semaphore(12)

        async def guarded(n: Dict[str, Any]):
            async with sem:
                return await build_one(n)

        rules_entries = list(await asyncio.gather(*[guarded(n) for n in nodes]))

    nodes_payload = {
        "kind": "realm_full_backup",
        "created_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "panel_public_url": _panel_public_base_url(request),
        "nodes": [
            {
                "source_id": int(n.get("id") or 0),
                "name": n.get("name"),
                "base_url": n.get("base_url"),
                "api_key": n.get("api_key"),
                "verify_tls": bool(n.get("verify_tls", 0)),
                "group_name": n.get("group_name") or "默认分组",
            }
            for n in nodes
        ],
    }

    meta_payload = {
        "kind": "realm_backup_meta",
        "created_at": nodes_payload["created_at"],
        "nodes": len(nodes),
        "files": 2 + len(rules_entries),
    }

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as z:
        z.writestr("backup_meta.json", json.dumps(meta_payload, ensure_ascii=False, indent=2))
        z.writestr("nodes.json", json.dumps(nodes_payload, ensure_ascii=False, indent=2))
        for path, data in rules_entries:
            z.writestr(path, json.dumps(data, ensure_ascii=False, indent=2))
        z.writestr(
            "README.txt",
            "Realm 全量备份说明\n\n"
            "1) 恢复节点列表：登录面板 → 控制台 → 点击『恢复节点列表』，上传本压缩包（或解压后的 nodes.json）。\n"
            "2) 恢复单节点规则：进入节点页面 → 更多 → 恢复规则，把 rules/ 目录下对应节点的规则文件上传/粘贴即可。\n",
        )

    filename = f"realm-backup-{ts}.zip"
    headers = {"Content-Disposition": f'attachment; filename="{filename}"'}
    return Response(content=buf.getvalue(), media_type="application/zip", headers=headers)


@app.post("/api/restore/nodes")
async def api_restore_nodes(
    request: Request,
    file: UploadFile = File(...),
    user: str = Depends(require_login),
):
    """Restore nodes list from nodes.json or full backup zip."""
    try:
        raw = await file.read()
    except Exception as exc:
        return JSONResponse({"ok": False, "error": f"读取文件失败：{exc}"}, status_code=400)

    payload = None
    # Zip?
    if raw[:2] == b"PK":
        try:
            z = zipfile.ZipFile(io.BytesIO(raw))
            # find nodes.json
            name = None
            for n in z.namelist():
                if n.lower().endswith("nodes.json"):
                    name = n
                    break
            if not name:
                return JSONResponse({"ok": False, "error": "压缩包中未找到 nodes.json"}, status_code=400)
            payload = json.loads(z.read(name).decode("utf-8"))
        except Exception as exc:
            return JSONResponse({"ok": False, "error": f"压缩包解析失败：{exc}"}, status_code=400)
    else:
        try:
            payload = json.loads(raw.decode("utf-8"))
        except Exception as exc:
            return JSONResponse({"ok": False, "error": f"JSON 解析失败：{exc}"}, status_code=400)

    # Accept: {nodes:[...]} or plain list
    nodes_list = None
    if isinstance(payload, dict) and isinstance(payload.get("nodes"), list):
        nodes_list = payload.get("nodes")
    elif isinstance(payload, list):
        nodes_list = payload

    if not isinstance(nodes_list, list):
        return JSONResponse({"ok": False, "error": "备份内容缺少 nodes 列表"}, status_code=400)

    added = 0
    updated = 0
    skipped = 0
    mapping: Dict[str, int] = {}

    for item in nodes_list:
        if not isinstance(item, dict):
            skipped += 1
            continue
        name = (item.get("name") or "").strip()
        base_url = (item.get("base_url") or "").strip().rstrip('/')
        api_key = (item.get("api_key") or "").strip()
        verify_tls = bool(item.get("verify_tls", False))
        group_name = (item.get("group_name") or "默认分组").strip() if isinstance(item.get("group_name"), str) else ("默认分组" if not item.get("group_name") else str(item.get("group_name")))
        group_name = (group_name or "默认分组").strip() or "默认分组"
        source_id = item.get("source_id")
        try:
            source_id_i = int(source_id) if source_id is not None else None
        except Exception:
            source_id_i = None

        if not base_url or not api_key:
            skipped += 1
            continue

        existing = get_node_by_api_key(api_key) or get_node_by_base_url(base_url)
        if existing:
            update_node_basic(
                existing["id"],
                name or existing.get("name") or _extract_ip_for_display(base_url),
                base_url,
                api_key,
                verify_tls=verify_tls,
                group_name=group_name,
            )
            updated += 1
            if source_id_i is not None:
                mapping[str(source_id_i)] = int(existing["id"])
        else:
            new_id = add_node(name or _extract_ip_for_display(base_url), base_url, api_key, verify_tls=verify_tls, group_name=group_name)
            added += 1
            if source_id_i is not None:
                mapping[str(source_id_i)] = int(new_id)

    return {
        "ok": True,
        "added": added,
        "updated": updated,
        "skipped": skipped,
        "mapping": mapping,
    }




@app.post("/api/restore/full")
async def api_restore_full(
    request: Request,
    file: UploadFile = File(...),
    user: str = Depends(require_login),
):
    """Restore nodes list + per-node rules from full backup zip."""
    try:
        raw = await file.read()
    except Exception as exc:
        return JSONResponse({"ok": False, "error": f"读取文件失败：{exc}"}, status_code=400)

    if not raw or raw[:2] != b"PK":
        return JSONResponse({"ok": False, "error": "请上传 realm-backup-*.zip（全量备份包）"}, status_code=400)

    try:
        z = zipfile.ZipFile(io.BytesIO(raw))
    except Exception as exc:
        return JSONResponse({"ok": False, "error": f"压缩包解析失败：{exc}"}, status_code=400)

    # ---- read nodes.json ----
    nodes_payload = None
    nodes_name = None
    for n in z.namelist():
        if n.lower().endswith('nodes.json'):
            nodes_name = n
            break
    if not nodes_name:
        return JSONResponse({"ok": False, "error": "压缩包中未找到 nodes.json"}, status_code=400)

    try:
        nodes_payload = json.loads(z.read(nodes_name).decode('utf-8'))
    except Exception as exc:
        return JSONResponse({"ok": False, "error": f"nodes.json 解析失败：{exc}"}, status_code=400)

    # Accept: {nodes:[...]} or plain list
    nodes_list = None
    if isinstance(nodes_payload, dict) and isinstance(nodes_payload.get('nodes'), list):
        nodes_list = nodes_payload.get('nodes')
    elif isinstance(nodes_payload, list):
        nodes_list = nodes_payload

    if not isinstance(nodes_list, list):
        return JSONResponse({"ok": False, "error": "备份内容缺少 nodes 列表"}, status_code=400)

    # ---- restore nodes ----
    added = 0
    updated = 0
    skipped = 0
    mapping: Dict[str, int] = {}
    srcid_to_baseurl: Dict[str, str] = {}
    baseurl_to_nodeid: Dict[str, int] = {}

    for item in nodes_list:
        if not isinstance(item, dict):
            skipped += 1
            continue
        name = (item.get('name') or '').strip()
        base_url = (item.get('base_url') or '').strip().rstrip('/')
        api_key = (item.get('api_key') or '').strip()
        verify_tls = bool(item.get('verify_tls', False))
        group_name = (item.get('group_name') or '默认分组')
        group_name = (str(group_name).strip() or '默认分组')
        source_id = item.get('source_id')
        try:
            source_id_i = int(source_id) if source_id is not None else None
        except Exception:
            source_id_i = None

        if base_url and source_id_i is not None:
            srcid_to_baseurl[str(source_id_i)] = base_url

        if not base_url or not api_key:
            skipped += 1
            continue

        existing = get_node_by_api_key(api_key) or get_node_by_base_url(base_url)
        if existing:
            update_node_basic(
                existing['id'],
                name or existing.get('name') or _extract_ip_for_display(base_url),
                base_url,
                api_key,
                verify_tls=verify_tls,
                group_name=group_name,
            )
            updated += 1
            node_id = int(existing['id'])
        else:
            node_id = int(add_node(name or _extract_ip_for_display(base_url), base_url, api_key, verify_tls=verify_tls, group_name=group_name))
            added += 1

        baseurl_to_nodeid[base_url] = node_id
        if source_id_i is not None:
            mapping[str(source_id_i)] = node_id

    # ---- restore rules (batch) ----
    rule_paths = [
        n for n in z.namelist()
        if n.lower().startswith('rules/') and n.lower().endswith('.json')
    ]

    import re as _re
    import asyncio

    async def apply_pool_to_node(target_id: int, pool: Dict[str, Any]) -> Dict[str, Any]:
        node = get_node(int(target_id))
        if not node:
            raise RuntimeError('节点不存在')
        # store desired on panel
        desired_ver, _ = set_desired_pool(int(target_id), pool)

        # best-effort immediate apply
        applied = False
        try:
            data = await agent_post(
                node['base_url'],
                node['api_key'],
                '/api/v1/pool',
                {'pool': pool},
                _node_verify_tls(node),
            )
            if isinstance(data, dict) and data.get('ok', True):
                await agent_post(node['base_url'], node['api_key'], '/api/v1/apply', {}, _node_verify_tls(node))
                applied = True
        except Exception:
            applied = False

        return {"node_id": int(target_id), "desired_version": desired_ver, "applied": applied}

    sem = asyncio.Semaphore(6)

    async def guarded_apply(target_id: int, pool: Dict[str, Any]) -> Dict[str, Any]:
        async with sem:
            return await apply_pool_to_node(target_id, pool)

    total_rules = len(rule_paths)
    restored_rules = 0
    failed_rules = 0
    unmatched_rules = 0
    rule_failed: list[Dict[str, Any]] = []
    rule_unmatched: list[Dict[str, Any]] = []

    tasks = []
    task_meta = []

    for p in rule_paths:
        try:
            payload = json.loads(z.read(p).decode('utf-8'))
        except Exception as exc:
            failed_rules += 1
            rule_failed.append({"path": p, "error": f"JSON 解析失败：{exc}"})
            continue

        pool = payload.get('pool') if isinstance(payload, dict) else None
        if pool is None:
            pool = payload
        if not isinstance(pool, dict):
            failed_rules += 1
            rule_failed.append({"path": p, "error": "备份内容缺少 pool 数据"})
            continue
        if not isinstance(pool.get('endpoints'), list):
            pool.setdefault('endpoints', [])

        # resolve source_id / base_url
        node_meta = payload.get('node') if isinstance(payload, dict) else None
        source_id = None
        base_url = None
        if isinstance(node_meta, dict):
            try:
                if node_meta.get('id') is not None:
                    source_id = int(node_meta.get('id'))
            except Exception:
                source_id = None
            base_url = (node_meta.get('base_url') or '').strip().rstrip('/') or None

        if source_id is None:
            m = _re.search(r'id(\d+)\.json$', p)
            if m:
                try:
                    source_id = int(m.group(1))
                except Exception:
                    source_id = None

        if base_url is None and source_id is not None:
            base_url = srcid_to_baseurl.get(str(source_id))

        target_id = None
        if source_id is not None:
            target_id = mapping.get(str(source_id))
        if target_id is None and base_url:
            target_id = baseurl_to_nodeid.get(base_url)
        if target_id is None and base_url:
            ex = get_node_by_base_url(base_url)
            if ex:
                target_id = int(ex.get('id'))

        if target_id is None:
            unmatched_rules += 1
            rule_unmatched.append({"path": p, "source_id": source_id, "base_url": base_url, "error": "未找到对应节点"})
            continue

        tasks.append(guarded_apply(int(target_id), pool))
        task_meta.append({"path": p, "target_id": int(target_id), "source_id": source_id, "base_url": base_url})

    if tasks:
        results = await asyncio.gather(*tasks, return_exceptions=True)
        for meta, res in zip(task_meta, results):
            if isinstance(res, Exception):
                failed_rules += 1
                rule_failed.append({"path": meta.get('path'), "target_id": meta.get('target_id'), "error": str(res)})
            else:
                restored_rules += 1

    return {
        "ok": True,
        "nodes": {"added": added, "updated": updated, "skipped": skipped, "mapping": mapping},
        "rules": {
            "total": total_rules,
            "restored": restored_rules,
            "unmatched": unmatched_rules,
            "failed": failed_rules,
        },
        "rule_unmatched": rule_unmatched[:50],
        "rule_failed": rule_failed[:50],
    }

@app.post("/api/nodes/{node_id}/restore")
async def api_restore(
    request: Request,
    node_id: int,
    file: UploadFile = File(...),
    user: str = Depends(require_login),
):
    node = get_node(node_id)
    if not node:
        return JSONResponse({"ok": False, "error": "节点不存在"}, status_code=404)
    try:
        raw = await file.read()
        payload = json.loads(raw.decode("utf-8"))
    except Exception as exc:
        return JSONResponse({"ok": False, "error": f"备份文件解析失败：{exc}"}, status_code=400)
    pool = payload.get("pool") if isinstance(payload, dict) else None
    if pool is None:
        pool = payload
    if not isinstance(pool, dict):
        return JSONResponse({"ok": False, "error": "备份内容缺少 pool 数据"}, status_code=400)

    # sanitize (trim spaces)
    try:
        eps = pool.get("endpoints")
        if isinstance(eps, list):
            for e in eps:
                if not isinstance(e, dict):
                    continue
                if e.get("listen") is not None:
                    e["listen"] = str(e.get("listen") or "").strip()
                if e.get("remote") is not None:
                    e["remote"] = str(e.get("remote") or "").strip()
                if isinstance(e.get("remotes"), list):
                    e["remotes"] = [str(x).strip() for x in e.get("remotes") if str(x).strip()]
                if isinstance(e.get("extra_remotes"), list):
                    e["extra_remotes"] = [str(x).strip() for x in e.get("extra_remotes") if str(x).strip()]
    except Exception:
        pass
    # Store on panel; apply will be done asynchronously (avoid blocking / proxy timeouts).
    desired_ver, _ = set_desired_pool(node_id, pool)
    _schedule_apply_pool(node, pool)
    return {"ok": True, "desired_version": desired_ver, "queued": True}


@app.post("/api/nodes/{node_id}/pool")
async def api_pool_set(request: Request, node_id: int, payload: Dict[str, Any], user: str = Depends(require_login)):
    node = get_node(node_id)
    if not node:
        return JSONResponse({"ok": False, "error": "节点不存在"}, status_code=404)
    pool = payload.get("pool") if isinstance(payload, dict) else None
    if pool is None and isinstance(payload, dict):
        # some callers may post the pool dict directly
        pool = payload
    if not isinstance(pool, dict):
        return JSONResponse({"ok": False, "error": "请求缺少 pool 字段"}, status_code=400)

    # --- Sanitize pool fields (trim spaces) ---
    # 说明：Agent 侧会对 listen 做 strip()，如果面板保存了带空格/不可见字符的 listen，
    # 前端按 listen 精确匹配 stats 时会出现“暂无检测数据”。
    try:
        eps = pool.get("endpoints")
        if isinstance(eps, list):
            for e in eps:
                if not isinstance(e, dict):
                    continue
                if e.get("listen") is not None:
                    e["listen"] = str(e.get("listen") or "").strip()
                if e.get("remote") is not None:
                    e["remote"] = str(e.get("remote") or "").strip()
                if isinstance(e.get("remotes"), list):
                    e["remotes"] = [str(x).strip() for x in e.get("remotes") if str(x).strip()]
                if isinstance(e.get("extra_remotes"), list):
                    e["extra_remotes"] = [str(x).strip() for x in e.get("extra_remotes") if str(x).strip()]
                # common optional string fields
                for k in ("through", "interface", "listen_interface", "listen_transport", "remote_transport", "protocol", "balance"):
                    if e.get(k) is not None and isinstance(e.get(k), str):
                        e[k] = e[k].strip()
    except Exception:
        pass


    # Prevent editing/deleting synced receiver rules from UI
    try:
        _, existing_desired = get_desired_pool(node_id)
        existing_pool = existing_desired
        if not isinstance(existing_pool, dict):
            rep = get_last_report(node_id)
            if isinstance(rep, dict) and isinstance(rep.get("pool"), dict):
                existing_pool = rep.get("pool")
        locked: Dict[str, Any] = {}
        if isinstance(existing_pool, dict):
            for ep in existing_pool.get("endpoints") or []:
                if not isinstance(ep, dict):
                    continue
                ex0 = ep.get("extra_config") or {}
                if not isinstance(ex0, dict):
                    ex0 = {}
                sid = ex0.get("sync_id")
                if sid and (ex0.get("sync_lock") is True or ex0.get("sync_role") == "receiver"):
                    locked[str(sid)] = ep

        if locked:
            posted: Dict[str, Any] = {}
            for ep in pool.get("endpoints") or []:
                if not isinstance(ep, dict):
                    continue
                ex0 = ep.get("extra_config") or {}
                if not isinstance(ex0, dict):
                    ex0 = {}
                sid = ex0.get("sync_id")
                if sid:
                    posted[str(sid)] = ep

            def _canon(e: Dict[str, Any]) -> Dict[str, Any]:
                ex = dict(e.get("extra_config") or {})
                ex.pop("last_sync_at", None)
                ex.pop("sync_updated_at", None)
                return {
                    "listen": e.get("listen"),
                    "remotes": e.get("remotes") or [],
                    "disabled": bool(e.get("disabled", False)),
                    "balance": e.get("balance"),
                    "protocol": e.get("protocol"),
                    "extra_config": ex,
                }

            for sid, old_ep in locked.items():
                new_ep = posted.get(sid)
                if not new_ep:
                    return JSONResponse(
                        {"ok": False, "error": "该节点存在由发送机同步的锁定规则，无法手动删除/修改（请在发送机上操作）"},
                        status_code=403,
                    )
                if _canon(old_ep) != _canon(new_ep):
                    return JSONResponse(
                        {"ok": False, "error": "该节点存在由发送机同步的锁定规则，无法手动删除/修改（请在发送机上操作）"},
                        status_code=403,
                    )
    except Exception:
        pass

    # Store desired pool on panel. Agent will pull it on next report.
    desired_ver, _ = set_desired_pool(node_id, pool)

    # Apply in background: do not block HTTP response (prevents frontend seeing “Load failed” under proxy timeouts).
    _schedule_apply_pool(node, pool)

    return {"ok": True, "pool": pool, "desired_version": desired_ver, "queued": True, "note": "waiting agent report"}



# -------------------- WSS tunnel node-to-node sync --------------------

def _split_host_port(addr: str) -> tuple[str, Optional[int]]:
    addr = (addr or "").strip()
    if not addr:
        return "", None
    if addr.startswith("["):
        # [IPv6]:port
        if "]" in addr:
            host = addr[1: addr.index("]")]
            rest = addr[addr.index("]") + 1 :]
            if rest.startswith(":"):
                try:
                    return host, int(rest[1:])
                except Exception:
                    return host, None
            return host, None
        return addr, None
    if ":" in addr:
        host, p = addr.rsplit(":", 1)
        try:
            return host, int(p)
        except Exception:
            return addr, None
    return addr, None


def _format_addr(host: str, port: int) -> str:
    host = (host or "").strip()
    if ":" in host and not host.startswith("["):
        host = f"[{host}]"
    return f"{host}:{int(port)}"


def _node_host_for_realm(node: Dict[str, Any]) -> str:
    base = (node.get("base_url") or "").strip()
    if not base:
        return ""
    if "://" not in base:
        base = "http://" + base
    u = urlparse(base)
    return u.hostname or ""


async def _load_pool_for_node(node: Dict[str, Any]) -> Dict[str, Any]:
    nid = int(node.get("id") or 0)
    _, desired = get_desired_pool(nid)
    if isinstance(desired, dict):
        pool = desired
    else:
        rep = get_last_report(nid)
        if isinstance(rep, dict) and isinstance(rep.get("pool"), dict):
            pool = rep.get("pool")
        else:
            try:
                data = await agent_get(node["base_url"], node["api_key"], "/api/v1/pool", _node_verify_tls(node))
                pool = data.get("pool") if isinstance(data, dict) else None
            except Exception:
                pool = None
    if not isinstance(pool, dict):
        pool = {}
    if not isinstance(pool.get("endpoints"), list):
        pool["endpoints"] = []
    return pool


def _remove_endpoints_by_sync_id(pool: Dict[str, Any], sync_id: str) -> None:
    if not isinstance(pool, dict):
        return
    eps = pool.get("endpoints")
    if not isinstance(eps, list):
        pool["endpoints"] = []
        return
    new_eps = []
    for ep in eps:
        if not isinstance(ep, dict):
            continue
        ex = ep.get("extra_config") or {}
        sid = ex.get("sync_id") if isinstance(ex, dict) else None
        if sid and str(sid) == str(sync_id):
            continue
        new_eps.append(ep)
    pool["endpoints"] = new_eps


def _choose_receiver_port(receiver_pool: Dict[str, Any], preferred: Optional[int]) -> int:
    used = set()
    for ep in receiver_pool.get("endpoints") or []:
        if not isinstance(ep, dict):
            continue
        h, p = _split_host_port(str(ep.get("listen") or ""))
        if p:
            used.add(int(p))
    if preferred and 1 <= int(preferred) <= 65535 and int(preferred) not in used:
        return int(preferred)
    # pick a random-ish high port
    seed = int(uuid.uuid4().int % 20000)
    port = 20000 + seed
    for _ in range(20000):
        if port not in used and 1 <= port <= 65535:
            return port
        port += 1
        if port > 65535:
            port = 20000
    # fallback
    return 33394



@app.post("/api/nodes/create")
async def api_nodes_create(request: Request, user: str = Depends(require_login)):
    """Dashboard 快速接入节点（弹窗模式）。返回 JSON，前端可直接跳转节点详情页。"""
    try:
        data = await request.json()
    except Exception:
        data = {}
    name = str(data.get("name") or "").strip()
    ip_address = str(data.get("ip_address") or "").strip()
    scheme = str(data.get("scheme") or "http").strip().lower()
    verify_tls = bool(data.get("verify_tls") or False)
    group_name = str(data.get("group_name") or "").strip() or "默认分组"

    if scheme not in ("http", "https"):
        return JSONResponse({"ok": False, "error": "协议仅支持 http 或 https"}, status_code=400)
    if not ip_address:
        return JSONResponse({"ok": False, "error": "节点地址不能为空"}, status_code=400)

    # 端口在 UI 中隐藏：默认 18700；如用户自带 :port 则兼容解析（仍不展示）
    if "://" not in ip_address:
        ip_address = f"{scheme}://{ip_address}"

    port_value = DEFAULT_AGENT_PORT
    host, parsed_port, has_port, scheme = _split_host_and_port(ip_address, port_value)
    if not host:
        return JSONResponse({"ok": False, "error": "节点地址不能为空"}, status_code=400)
    if has_port:
        port_value = parsed_port

    base_url = f"{scheme}://{_format_host_for_url(host)}:{port_value}"
    api_key = _generate_api_key()

    display_name = name or _extract_ip_for_display(base_url)
    node_id = add_node(display_name, base_url, api_key, verify_tls=verify_tls, group_name=group_name)
    return JSONResponse({"ok": True, "node_id": node_id, "redirect_url": f"/nodes/{node_id}"})

@app.post("/api/nodes/{node_id}/update")
async def api_nodes_update(node_id: int, request: Request, user: str = Depends(require_login)):
    """编辑节点：修改名称 / 地址 / 分组（不改 api_key）。"""
    try:
        data = await request.json()
    except Exception:
        data = {}

    node = get_node(int(node_id))
    if not node:
        return JSONResponse({"ok": False, "error": "节点不存在"}, status_code=404)

    name_in = data.get("name", None)
    ip_in = data.get("ip_address", None)
    scheme_in = data.get("scheme", None)
    group_in = data.get("group_name", None)

    # verify_tls: only update when provided
    if "verify_tls" in data:
        verify_tls = bool(data.get("verify_tls") or False)
    else:
        verify_tls = bool(node.get("verify_tls", 0))

    # group name
    if group_in is None:
        group_name = str(node.get("group_name") or "默认分组").strip() or "默认分组"
    else:
        group_name = str(group_in or "").strip() or "默认分组"

    # parse existing base_url
    raw_old = str(node.get("base_url") or "").strip()
    if not raw_old:
        return JSONResponse({"ok": False, "error": "节点地址异常"}, status_code=400)
    if "://" not in raw_old:
        raw_old = "http://" + raw_old
    parsed_old = urlparse(raw_old)
    old_scheme = (parsed_old.scheme or "http").lower()
    old_host = parsed_old.hostname or ""
    old_port = parsed_old.port
    old_has_port = parsed_old.port is not None

    scheme = str(scheme_in or old_scheme).strip().lower() or "http"
    if scheme not in ("http", "https"):
        return JSONResponse({"ok": False, "error": "协议仅支持 http 或 https"}, status_code=400)

    host = old_host
    port_value = old_port
    has_port = old_has_port

    if ip_in is not None:
        ip_address = str(ip_in or "").strip()
        if not ip_address:
            return JSONResponse({"ok": False, "error": "节点地址不能为空"}, status_code=400)

        # allow user paste full url
        ip_full = ip_address
        if "://" not in ip_full:
            ip_full = f"{scheme}://{ip_full}"

        fallback_port = int(old_port) if old_has_port and old_port else DEFAULT_AGENT_PORT
        h, p, has_p, parsed_scheme = _split_host_and_port(ip_full, fallback_port)
        if not h:
            return JSONResponse({"ok": False, "error": "节点地址不能为空"}, status_code=400)

        # only override scheme when user explicitly provided scheme
        if "://" in ip_address:
            scheme = (parsed_scheme or scheme).lower()
        host = h

        if has_p:
            port_value = int(p)
            has_port = True
        else:
            # preserve old explicit port; otherwise keep no-port
            if old_has_port and old_port:
                port_value = int(old_port)
                has_port = True
            else:
                port_value = None
                has_port = False

    base_url = f"{scheme}://{_format_host_for_url(host)}"
    if has_port and port_value:
        base_url += f":{int(port_value)}"

    # prevent duplicates
    other = get_node_by_base_url(base_url)
    if other and int(other.get("id") or 0) != int(node_id):
        return JSONResponse({"ok": False, "error": "该节点地址已被其他节点使用"}, status_code=400)

    # name
    if name_in is None:
        name = str(node.get("name") or "").strip() or _extract_ip_for_display(base_url)
    else:
        name = str(name_in or "").strip() or _extract_ip_for_display(base_url)

    update_node_basic(int(node_id), name, base_url, str(node.get("api_key") or ""), verify_tls=verify_tls, group_name=group_name)

    # Return updated fields for client-side UI refresh (avoid full page reload)
    updated = get_node(int(node_id)) or {}
    display_ip = _extract_ip_for_display(str(updated.get("base_url") or base_url))
    return JSONResponse(
        {
            "ok": True,
            "node": {
                "id": int(node_id),
                "name": str(updated.get("name") or name),
                "base_url": str(updated.get("base_url") or base_url),
                "group_name": str(updated.get("group_name") or group_name),
                "display_ip": display_ip,
                "verify_tls": bool(updated.get("verify_tls") or verify_tls),
            },
        }
    )



@app.get("/api/nodes")
async def api_nodes_list(user: str = Depends(require_login)):
    out = []
    for n in list_nodes():
        out.append({"id": int(n["id"]), "name": n["name"], "base_url": n["base_url"], "group_name": n.get("group_name")})
    return {"ok": True, "nodes": out}


@app.post("/api/wss_tunnel/save")
async def api_wss_tunnel_save(payload: Dict[str, Any], user: str = Depends(require_login)):
    try:
        sender_id = int(payload.get("sender_node_id") or 0)
        receiver_id = int(payload.get("receiver_node_id") or 0)
    except Exception:
        sender_id = 0
        receiver_id = 0

    if sender_id <= 0 or receiver_id <= 0 or sender_id == receiver_id:
        return JSONResponse({"ok": False, "error": "sender_node_id / receiver_node_id 无效"}, status_code=400)

    sender = get_node(sender_id)
    receiver = get_node(receiver_id)
    if not sender or not receiver:
        return JSONResponse({"ok": False, "error": "节点不存在"}, status_code=404)

    listen = str(payload.get("listen") or "").strip()
    remotes = payload.get("remotes") or []
    if isinstance(remotes, str):
        remotes = [x.strip() for x in remotes.splitlines() if x.strip()]
    if not isinstance(remotes, list):
        remotes = []
    remotes = [str(x).strip() for x in remotes if str(x).strip()]
    disabled = bool(payload.get("disabled", False))
    balance = str(payload.get("balance") or "roundrobin").strip()
    protocol = str(payload.get("protocol") or "tcp+udp").strip() or "tcp+udp"

    wss = payload.get("wss") or {}
    if not isinstance(wss, dict):
        wss = {}
    wss_host = str(wss.get("host") or "").strip()
    wss_path = str(wss.get("path") or "").strip()
    wss_sni = str(wss.get("sni") or "").strip()
    wss_tls = bool(wss.get("tls", True))
    wss_insecure = bool(wss.get("insecure", False))

    if not listen:
        return JSONResponse({"ok": False, "error": "listen 不能为空"}, status_code=400)
    if not remotes:
        return JSONResponse({"ok": False, "error": "目标地址不能为空"}, status_code=400)
    if not wss_host or not wss_path:
        return JSONResponse({"ok": False, "error": "WSS Host / Path 不能为空"}, status_code=400)

    sync_id = str(payload.get("sync_id") or "").strip() or uuid.uuid4().hex

    receiver_port = payload.get("receiver_port")
    try:
        receiver_port = int(receiver_port) if receiver_port is not None and receiver_port != "" else None
    except Exception:
        receiver_port = None

    # preferred port = sender listen port
    _, sender_listen_port = _split_host_port(listen)
    preferred_port = receiver_port or sender_listen_port
    receiver_pool = await _load_pool_for_node(receiver)
    receiver_port = _choose_receiver_port(receiver_pool, preferred_port)

    receiver_host = _node_host_for_realm(receiver)
    if not receiver_host:
        return JSONResponse({"ok": False, "error": "接收机 base_url 无法解析主机名，请检查节点地址"}, status_code=400)
    sender_to_receiver = _format_addr(receiver_host, receiver_port)

    now_iso = datetime.utcnow().isoformat() + "Z"

    sender_ep = {
        "listen": listen,
        "disabled": disabled,
        "balance": balance,
        "protocol": protocol,
        "remotes": [sender_to_receiver],
        "extra_config": {
            "remote_transport": "ws",
            "remote_ws_host": wss_host,
            "remote_ws_path": wss_path,
            "remote_tls_enabled": bool(wss_tls),
            "remote_tls_insecure": bool(wss_insecure),
            "remote_tls_sni": wss_sni,
            # sync meta
            "sync_id": sync_id,
            "sync_role": "sender",
            "sync_peer_node_id": receiver_id,
            "sync_peer_node_name": receiver.get("name"),
            "sync_receiver_port": receiver_port,
            "sync_original_remotes": remotes,
            "sync_updated_at": now_iso,
        },
    }

    receiver_ep = {
        "listen": _format_addr("0.0.0.0", receiver_port),
        "disabled": disabled,
        "balance": balance,
        "protocol": protocol,
        "remotes": remotes,
        "extra_config": {
            "listen_transport": "ws",
            "listen_ws_host": wss_host,
            "listen_ws_path": wss_path,
            "listen_tls_enabled": bool(wss_tls),
            "listen_tls_insecure": bool(wss_insecure),
            "listen_tls_servername": wss_sni,
            # sync meta
            "sync_id": sync_id,
            "sync_role": "receiver",
            "sync_lock": True,
            "sync_from_node_id": sender_id,
            "sync_from_node_name": sender.get("name"),
            "sync_sender_listen": listen,
            "sync_original_remotes": remotes,
            "sync_updated_at": now_iso,
        },
    }

    sender_pool = await _load_pool_for_node(sender)

    # upsert by sync_id
    _remove_endpoints_by_sync_id(sender_pool, sync_id)
    _remove_endpoints_by_sync_id(receiver_pool, sync_id)
    sender_pool["endpoints"].append(sender_ep)
    receiver_pool["endpoints"].append(receiver_ep)

    # persist desired pools on panel
    s_ver, _ = set_desired_pool(sender_id, sender_pool)
    r_ver, _ = set_desired_pool(receiver_id, receiver_pool)

    # best-effort immediate apply to both agents
    async def _apply(node: Dict[str, Any], pool: Dict[str, Any]):
        try:
            data = await agent_post(node["base_url"], node["api_key"], "/api/v1/pool", {"pool": pool}, _node_verify_tls(node))
            if isinstance(data, dict) and data.get("ok", True):
                await agent_post(node["base_url"], node["api_key"], "/api/v1/apply", {}, _node_verify_tls(node))
        except Exception:
            pass

    await _apply(sender, sender_pool)
    await _apply(receiver, receiver_pool)

    return {
        "ok": True,
        "sync_id": sync_id,
        "receiver_port": receiver_port,
        "sender_pool": sender_pool,
        "receiver_pool": receiver_pool,
        "sender_desired_version": s_ver,
        "receiver_desired_version": r_ver,
    }


@app.post("/api/wss_tunnel/delete")
async def api_wss_tunnel_delete(payload: Dict[str, Any], user: str = Depends(require_login)):
    sync_id = str(payload.get("sync_id") or "").strip()
    if not sync_id:
        return JSONResponse({"ok": False, "error": "sync_id 不能为空"}, status_code=400)

    try:
        sender_id = int(payload.get("sender_node_id") or 0)
        receiver_id = int(payload.get("receiver_node_id") or 0)
    except Exception:
        sender_id = 0
        receiver_id = 0

    if sender_id <= 0 or receiver_id <= 0 or sender_id == receiver_id:
        return JSONResponse({"ok": False, "error": "sender_node_id / receiver_node_id 无效"}, status_code=400)

    sender = get_node(sender_id)
    receiver = get_node(receiver_id)
    if not sender or not receiver:
        return JSONResponse({"ok": False, "error": "节点不存在"}, status_code=404)

    sender_pool = await _load_pool_for_node(sender)
    receiver_pool = await _load_pool_for_node(receiver)

    _remove_endpoints_by_sync_id(sender_pool, sync_id)
    _remove_endpoints_by_sync_id(receiver_pool, sync_id)

    s_ver, _ = set_desired_pool(sender_id, sender_pool)
    r_ver, _ = set_desired_pool(receiver_id, receiver_pool)

    async def _apply(node: Dict[str, Any], pool: Dict[str, Any]):
        try:
            data = await agent_post(node["base_url"], node["api_key"], "/api/v1/pool", {"pool": pool}, _node_verify_tls(node))
            if isinstance(data, dict) and data.get("ok", True):
                await agent_post(node["base_url"], node["api_key"], "/api/v1/apply", {}, _node_verify_tls(node))
        except Exception:
            pass

    await _apply(sender, sender_pool)
    await _apply(receiver, receiver_pool)

    return {
        "ok": True,
        "sync_id": sync_id,
        "sender_pool": sender_pool,
        "receiver_pool": receiver_pool,
        "sender_desired_version": s_ver,
        "receiver_desired_version": r_ver,
    }



@app.post("/api/nodes/{node_id}/apply")
async def api_apply(request: Request, node_id: int, user: str = Depends(require_login)):
    node = get_node(node_id)
    if not node:
        return JSONResponse({"ok": False, "error": "节点不存在"}, status_code=404)
    try:
        data = await agent_post(
            node["base_url"],
            node["api_key"],
            "/api/v1/apply",
            {},
            _node_verify_tls(node),
        )
        if not data.get("ok", True):
            return JSONResponse({"ok": False, "error": data.get("error", "Agent 应用配置失败")}, status_code=502)
        return data
    except Exception:
        # Push-report fallback: bump desired version to trigger a re-sync/apply on agent
        desired_ver, desired_pool = get_desired_pool(node_id)
        if isinstance(desired_pool, dict):
            new_ver, _ = set_desired_pool(node_id, desired_pool)
            return {"ok": True, "queued": True, "desired_version": new_ver}
        return {"ok": False, "error": "Agent 无法访问，且面板无缓存规则（请检查网络或等待 Agent 上报）"}


@app.get("/api/nodes/{node_id}/stats")
async def api_stats(request: Request, node_id: int, user: str = Depends(require_login)):
    node = get_node(node_id)
    if not node:
        return JSONResponse({"ok": False, "error": "节点不存在"}, status_code=404)

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




@app.get("/api/nodes/{node_id}/sys")
async def api_sys(request: Request, node_id: int, cached: int = 0, user: str = Depends(require_login)):
    """节点系统信息：CPU/内存/硬盘/交换/在线时长/流量/实时速率。

    返回格式统一为：{ ok: true, sys: {...} }
    前端会据此渲染节点详情页的系统信息卡片。
    """
    node = get_node(node_id)
    if not node:
        return JSONResponse({"ok": False, "error": "节点不存在"}, status_code=404)

    sys_data = None
    source = None

    # 1) Push-report cache（更快、更稳定）
    # cached=1：即便不是“新鲜上报”，也优先返回最后一次上报的数据，避免前端长时间等待。
    if cached:
        rep = get_last_report(node_id)
        if isinstance(rep, dict) and isinstance(rep.get("sys"), dict):
            sys_data = dict(rep["sys"])  # copy
            sys_data["stale"] = not _is_report_fresh(node)
            source = "report"
    else:
        if _is_report_fresh(node):
            rep = get_last_report(node_id)
            if isinstance(rep, dict) and isinstance(rep.get("sys"), dict):
                sys_data = dict(rep["sys"])  # copy
                source = "report"

    # 2) Fallback：直连 Agent
    # 说明：控制台首页（Dashboard）会带 cached=1 来避免直连 Agent。
    # 因为在 Push 模式下，Panel 可能无法直接访问 Agent 的 base_url（私网/防火墙等）。
    # 若 cached=1 且 report 中没有 sys 数据，直接返回占位信息，避免前端“长时间加载中”。
    if sys_data is None:
        if cached:
            return {
                "ok": True,
                "sys": {
                    "ok": False,
                    "error": "Agent 尚未上报系统信息（请升级 Agent 或稍后重试）",
                    "source": "report",
                },
            }

        try:
            data = await agent_get(node["base_url"], node["api_key"], "/api/v1/sys", _node_verify_tls(node))
            if isinstance(data, dict) and data.get("ok") is True:
                sys_data = dict(data)  # copy
                source = "agent"
            else:
                return {"ok": False, "error": (data.get("error") if isinstance(data, dict) else "响应格式异常")}
        except Exception as exc:
            return {"ok": False, "error": str(exc)}

    sys_data["source"] = source or "unknown"
    return {"ok": True, "sys": sys_data}


@app.get("/api/nodes/{node_id}/graph")
async def api_graph(request: Request, node_id: int, user: str = Depends(require_login)):
    node = get_node(node_id)
    if not node:
        return JSONResponse({"ok": False, "error": "节点不存在"}, status_code=404)
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
