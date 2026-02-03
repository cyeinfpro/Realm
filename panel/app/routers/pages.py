from __future__ import annotations

from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse

from ..core.deps import require_login_page
from ..core.flash import flash, set_flash
from ..core.settings import DEFAULT_AGENT_PORT
from ..core.share import require_login_or_share_view_page, require_login_or_share_wall_page
from ..core.templates import templates
from ..db import add_node, delete_node, get_group_orders, get_node, list_nodes
from ..services.assets import panel_public_base_url
from ..services.node_status import is_report_fresh
from ..utils.crypto import generate_api_key
from ..utils.normalize import extract_ip_for_display, format_host_for_url, split_host_and_port

router = APIRouter()


@router.get("/", response_class=HTMLResponse)
async def index(request: Request, user: str = Depends(require_login_page)):
    nodes = list_nodes()

    group_orders = get_group_orders()

    def _gk(name: str) -> tuple[int, str]:
        """Group sort key: user-defined sort_order (smaller first), then name."""
        n = (name or "").strip() or "默认分组"
        try:
            order = int(group_orders.get(n, 1000))
        except Exception:
            order = 1000
        return (order, n)

    def _gn(x: dict) -> str:
        g = str(x.get("group_name") or "").strip()
        return g or "默认分组"

    for n in nodes:
        n["display_ip"] = extract_ip_for_display(n.get("base_url", ""))
        n["online"] = is_report_fresh(n)
        # 分组名为空时统一归入“默认分组”
        n["group_name"] = _gn(n)
        # For UI display
        if "agent_version" not in n:
            n["agent_version"] = str(n.get("agent_reported_version") or "").strip()

    # 控制台卡片：按分组聚合展示
    # - 组内排序：在线优先，其次按 id 倒序
    nodes_sorted = sorted(
        nodes,
        key=lambda x: (
            _gk(_gn(x)),
            0 if bool(x.get("online")) else 1,
            -int(x.get("id") or 0),
        ),
    )

    dashboard_groups = []
    cur = None
    buf = []
    for n in nodes_sorted:
        g = _gn(n)
        if cur is None:
            cur = g
        if g != cur:
            dashboard_groups.append(
                {
                    "name": cur,
                    "sort_order": _gk(cur)[0],
                    "nodes": buf,
                    "online": sum(1 for i in buf if i.get("online")),
                    "total": len(buf),
                }
            )
            cur = g
            buf = []
        buf.append(n)

    if cur is not None:
        dashboard_groups.append(
            {
                "name": cur,
                "sort_order": _gk(cur)[0],
                "nodes": buf,
                "online": sum(1 for i in buf if i.get("online")),
                "total": len(buf),
            }
        )

    return templates.TemplateResponse(
        "index.html",
        {
            "request": request,
            "user": (user or None),
            "nodes": nodes,
            "dashboard_groups": dashboard_groups,
            "flash": flash(request),
            "title": "控制台",
        },
    )


@router.get("/netmon", response_class=HTMLResponse)
async def netmon_page(request: Request, user: str = Depends(require_login_page)):
    """Network fluctuation monitoring page."""
    nodes = list_nodes()

    group_orders = get_group_orders()

    def _gk(name: str) -> tuple[int, str]:
        n = (name or "").strip() or "默认分组"
        try:
            order = int(group_orders.get(n, 1000))
        except Exception:
            order = 1000
        return (order, n)

    def _gn(x: Dict[str, Any]) -> str:
        g = str(x.get("group_name") or "").strip()
        return g or "默认分组"

    for n in nodes:
        n["display_ip"] = extract_ip_for_display(n.get("base_url", ""))
        # 用更宽松的阈值显示在线状态（避免轻微抖动导致频繁显示离线）
        n["online"] = is_report_fresh(n, max_age_sec=90)
        n["group_name"] = _gn(n)

    nodes_sorted = sorted(
        nodes,
        key=lambda x: (
            _gk(_gn(x)),
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
                    "sort_order": _gk(cur)[0],
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
                "sort_order": _gk(cur)[0],
                "nodes": buf,
                "online": sum(1 for i in buf if i.get("online")),
                "total": len(buf),
            }
        )

    return templates.TemplateResponse(
        "netmon.html",
        {
            "request": request,
            "user": (user or None),
            "node_groups": node_groups,
            "flash": flash(request),
            "title": "网络波动监控",
        },
    )


@router.get("/netmon/view", response_class=HTMLResponse)
async def netmon_view_page(request: Request, user: str = Depends(require_login_or_share_view_page)):
    """Read-only NetMon display page (for sharing / wallboard)."""
    return templates.TemplateResponse(
        "netmon_view.html",
        {
            "request": request,
            "user": (user or None),
            "flash": flash(request),
            "title": "网络波动 · 只读展示",
        },
    )


@router.get("/netmon/wall", response_class=HTMLResponse)
async def netmon_wall_page(request: Request, user: str = Depends(require_login_or_share_wall_page)):
    """NetMon wallboard (read-only)."""
    return templates.TemplateResponse(
        "netmon_wall.html",
        {
            "request": request,
            "user": (user or None),
            "flash": flash(request),
            "title": "网络波动 · 大屏展示",
        },
    )


@router.get("/nodes/new", response_class=HTMLResponse)
async def node_new_page(request: Request, user: str = Depends(require_login_page)):
    api_key = generate_api_key()
    return templates.TemplateResponse(
        "nodes_new.html",
        {
            "request": request,
            "user": user,
            "flash": flash(request),
            "title": "添加机器",
            "api_key": api_key,
            "default_port": DEFAULT_AGENT_PORT,
        },
    )


@router.post("/nodes/new")
async def node_new_action(
    request: Request,
    name: str = Form(""),
    group_name: str = Form("默认分组"),
    is_private: Optional[str] = Form(None),
    is_website: Optional[str] = Form(None),
    website_root_base: str = Form(""),
    ip_address: str = Form(...),
    scheme: str = Form("http"),
    api_key: str = Form(""),
    verify_tls: Optional[str] = Form(None),
):
    user = request.session.get("user")
    if not user:
        return RedirectResponse(url="/login", status_code=303)

    ip_address = ip_address.strip()
    api_key = api_key.strip() or generate_api_key()
    scheme = scheme.strip().lower() or "http"
    if scheme not in ("http", "https"):
        set_flash(request, "协议仅支持 http 或 https")
        return RedirectResponse(url="/nodes/new", status_code=303)
    if not ip_address:
        set_flash(request, "IP 地址不能为空")
        return RedirectResponse(url="/nodes/new", status_code=303)
    if "://" not in ip_address:
        ip_address = f"{scheme}://{ip_address}"

    # 端口在 UI 中隐藏：
    # - 默认使用 Agent 标准端口 18700
    # - 如用户在 IP 中自带 :port，则仍可解析并写入 base_url（兼容特殊环境）
    port_value = DEFAULT_AGENT_PORT
    host, parsed_port, has_port, scheme = split_host_and_port(ip_address, port_value)
    if verify_tls is None:
        verify_tls = (scheme == "https")
    if not host:
        set_flash(request, "IP 地址不能为空")
        return RedirectResponse(url="/nodes/new", status_code=303)
    if has_port:
        port_value = parsed_port

    base_url = f"{scheme}://{format_host_for_url(host)}:{port_value}"  # 不在 UI 展示端口

    # name 为空则默认使用“纯 IP/Host”
    display_name = (name or "").strip() or extract_ip_for_display(base_url)

    verify_tls_flag = bool(verify_tls) if verify_tls is not None else (scheme == "https")
    role = "website" if is_website else "normal"
    root_base = (website_root_base or "").strip()
    if role == "website" and not root_base:
        root_base = "/www"
    if role != "website":
        root_base = ""

    node_id = add_node(
        display_name,
        base_url,
        api_key,
        verify_tls=verify_tls_flag,
        is_private=bool(is_private),
        group_name=group_name,
        role=role,
        website_root_base=root_base,
    )
    request.session["show_install_cmd"] = True
    set_flash(request, "已添加机器")
    return RedirectResponse(url=f"/nodes/{node_id}", status_code=303)


@router.post("/nodes/add")
async def node_add_action(
    request: Request,
    name: str = Form(""),
    group_name: str = Form("默认分组"),
    is_private: Optional[str] = Form(None),
    is_website: Optional[str] = Form(None),
    website_root_base: str = Form(""),
    base_url: str = Form(...),
    api_key: str = Form(...),
    verify_tls: Optional[str] = Form(None),
):
    if not request.session.get("user"):
        return RedirectResponse(url="/login", status_code=303)

    base_url = base_url.strip()
    api_key = api_key.strip()
    if not base_url or not api_key:
        set_flash(request, "API 地址与 Token 不能为空")
        return RedirectResponse(url="/", status_code=303)

    # Default to TLS verification for https:// URLs when checkbox is omitted.
    scheme2 = (urlparse(base_url).scheme or "http").lower()
    verify_tls_flag = bool(verify_tls) if verify_tls is not None else (scheme2 == "https")

    node_id = add_node(
        name or base_url,
        base_url,
        api_key,
        verify_tls=verify_tls_flag,
        is_private=bool(is_private),
        group_name=group_name,
        role="website" if is_website else "normal",
        website_root_base=(website_root_base or "").strip() if is_website else "",
    )
    set_flash(request, "已添加节点")
    return RedirectResponse(url=f"/nodes/{node_id}", status_code=303)


@router.post("/nodes/{node_id}/delete")
async def node_delete(request: Request, node_id: int):
    if not request.session.get("user"):
        return RedirectResponse(url="/login", status_code=303)
    delete_node(node_id)
    set_flash(request, "已删除机器")
    return RedirectResponse(url="/", status_code=303)


@router.get("/nodes/{node_id}", response_class=HTMLResponse)
async def node_detail(request: Request, node_id: int, user: str = Depends(require_login_page)):
    node = get_node(node_id)
    if not node:
        set_flash(request, "机器不存在")
        return RedirectResponse(url="/", status_code=303)

    # 用于节点页左侧快速切换列表
    nodes = list_nodes()

    group_orders = get_group_orders()

    def _gk(name: str) -> tuple[int, str]:
        n = (name or "").strip() or "默认分组"
        try:
            order = int(group_orders.get(n, 1000))
        except Exception:
            order = 1000
        return (order, n)

    for n in nodes:
        n["display_ip"] = extract_ip_for_display(n.get("base_url", ""))
        # 用更宽松的阈值显示在线状态（避免轻微抖动导致频繁显示离线）
        n["online"] = is_report_fresh(n, max_age_sec=90)

    # 节点页左侧列表：按分组聚合展示
    def _gn(x: Dict[str, Any]) -> str:
        g = str(x.get("group_name") or "").strip()
        return g or "默认分组"

    for n in nodes:
        n["group_name"] = _gn(n)

    nodes_sorted = sorted(
        nodes,
        key=lambda x: (
            _gk(_gn(x)),
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
                    "sort_order": _gk(cur)[0],
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
                "sort_order": _gk(cur)[0],
                "nodes": buf,
                "online": sum(1 for i in buf if i.get("online")),
                "total": len(buf),
            }
        )

    show_install_cmd = bool(request.session.pop("show_install_cmd", False))
    show_edit_node = str(request.query_params.get("edit") or "").strip() in ("1", "true", "yes")

    base_url = panel_public_base_url(request)
    node["display_ip"] = extract_ip_for_display(node.get("base_url", ""))

    # 在线判定：默认心跳 30s，取 3 倍窗口避免误判
    node["online"] = is_report_fresh(node, max_age_sec=90)

    # ✅ 一键接入 / 卸载命令（短命令，避免超长）
    # 说明：使用 node.api_key 作为 join token，脚本由面板返回并带参数执行。
    token = node["api_key"]
    install_cmd = f"curl -fsSL -H \"X-Join-Token: {token}\" {base_url}/join | bash"
    uninstall_cmd = f"curl -fsSL -H \"X-Join-Token: {token}\" {base_url}/uninstall | bash"

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
            "flash": flash(request),
            "title": node["name"],
            "node_port": agent_port,
            "install_cmd": install_cmd,
            "uninstall_cmd": uninstall_cmd,
            "show_install_cmd": show_install_cmd,
            "show_edit_node": show_edit_node,
        },
    )
