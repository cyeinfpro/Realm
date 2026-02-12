from __future__ import annotations

import os
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse

from ..auth import filter_nodes_for_user
from ..core.deps import require_login_page, require_role_page
from ..core.flash import flash, set_flash
from ..core.settings import DEFAULT_AGENT_PORT
from ..core.share import require_login_or_share_view_page, require_login_or_share_wall_page
from ..core.templates import templates
from ..db import add_node, delete_node, get_group_orders, get_node, get_panel_setting, list_nodes, set_panel_setting
from ..services.assets import (
    panel_asset_source,
    panel_bootstrap_base_url,
    panel_bootstrap_insecure_tls,
    panel_public_base_url,
)
try:
    from ..services.panel_config import parse_bool_loose, setting_float, setting_int
except Exception:
    _TRUE_SET = {"1", "true", "yes", "on", "y"}
    _FALSE_SET = {"0", "false", "no", "off", "n"}

    def _cfg_env(names: Optional[list[str]]) -> str:
        for n in (names or []):
            name = str(n or "").strip()
            if not name:
                continue
            v = str(os.getenv(name) or "").strip()
            if v:
                return v
        return ""

    def parse_bool_loose(raw: Any, default: bool = False) -> bool:
        if raw is None:
            return bool(default)
        s = str(raw).strip().lower()
        if not s:
            return bool(default)
        if s in _TRUE_SET:
            return True
        if s in _FALSE_SET:
            return False
        return bool(default)

    def setting_int(
        key: str,
        default: int,
        lo: int,
        hi: int,
        env_names: Optional[list[str]] = None,
    ) -> int:
        raw = get_panel_setting(str(key or "").strip())
        v_raw: Any = raw
        if raw is None or str(raw).strip() == "":
            env_v = _cfg_env(env_names)
            v_raw = env_v if env_v else default
        try:
            v = int(float(str(v_raw).strip() or default))
        except Exception:
            v = int(default)
        if v < int(lo):
            v = int(lo)
        if v > int(hi):
            v = int(hi)
        return int(v)

    def setting_float(
        key: str,
        default: float,
        lo: float,
        hi: float,
        env_names: Optional[list[str]] = None,
    ) -> float:
        raw = get_panel_setting(str(key or "").strip())
        v_raw: Any = raw
        if raw is None or str(raw).strip() == "":
            env_v = _cfg_env(env_names)
            v_raw = env_v if env_v else default
        try:
            v = float(str(v_raw).strip() or default)
        except Exception:
            v = float(default)
        if v < float(lo):
            v = float(lo)
        if v > float(hi):
            v = float(hi)
        return float(v)
from ..services.node_status import is_report_fresh
from ..utils.crypto import generate_api_key
from ..utils.normalize import extract_ip_for_display, format_host_for_url, split_host_and_port

router = APIRouter()


def _as_bool(raw: Optional[str], default: bool = False) -> bool:
    if raw is None:
        return bool(default)
    s = str(raw).strip().lower()
    if not s:
        return bool(default)
    return s in ("1", "true", "yes", "on", "y")


def _clamp_int_text(raw: Any, lo: int, hi: int) -> str:
    s = str(raw or "").strip()
    if not s:
        return ""
    try:
        v = int(float(s))
    except Exception:
        return ""
    if v < int(lo):
        v = int(lo)
    if v > int(hi):
        v = int(hi)
    return str(int(v))


def _clamp_float_text(raw: Any, lo: float, hi: float) -> str:
    s = str(raw or "").strip()
    if not s:
        return ""
    try:
        v = float(s)
    except Exception:
        return ""
    if v < float(lo):
        v = float(lo)
    if v > float(hi):
        v = float(hi)
    return f"{float(v):g}"


@router.get("/", response_class=HTMLResponse)
async def index(request: Request, user: str = Depends(require_login_page)):
    nodes = filter_nodes_for_user(user, list_nodes())

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


@router.get("/settings", response_class=HTMLResponse)
async def settings_page(request: Request, user: str = Depends(require_role_page("users.manage"))):
    configured_url = str(get_panel_setting("agent_bootstrap_url", "") or "").strip()
    configured_insecure_raw = get_panel_setting("agent_bootstrap_insecure_tls")
    insecure_tls = (
        _as_bool(configured_insecure_raw, default=True)
        if configured_insecure_raw is not None and str(configured_insecure_raw).strip() != ""
        else panel_bootstrap_insecure_tls(default=True)
    )
    configured_public_url = str(get_panel_setting("panel_public_url", "") or "").strip()
    configured_asset_source = str(get_panel_setting("panel_asset_source", "") or "").strip().lower()
    if configured_asset_source not in ("panel", "github"):
        configured_asset_source = ""
    configured_agent_sh_url = str(get_panel_setting("panel_agent_sh_url", "") or "").strip()
    configured_agent_zip_url = str(get_panel_setting("panel_agent_zip_url", "") or "").strip()
    configured_bootstrap_scheme = str(get_panel_setting("agent_bootstrap_default_scheme", "") or "").strip().lower()
    if configured_bootstrap_scheme not in ("http", "https"):
        configured_bootstrap_scheme = ""
    configured_panel_ip_fallback_port = str(get_panel_setting("agent_panel_ip_fallback_port", "") or "").strip()

    configured_ssl_direct_first = parse_bool_loose(get_panel_setting("ssl_direct_first"), default=True)
    configured_ssl_direct_timeout = _clamp_float_text(get_panel_setting("ssl_direct_timeout_sec", ""), 30.0, 1200.0)
    configured_ssl_direct_max_attempts = _clamp_int_text(get_panel_setting("ssl_direct_max_attempts", ""), 1, 30)
    configured_ssl_fallback_to_queue = parse_bool_loose(get_panel_setting("ssl_fallback_to_queue"), default=True)

    configured_save_precheck_enabled = parse_bool_loose(get_panel_setting("save_precheck_enabled"), default=True)
    configured_save_precheck_http_timeout = _clamp_float_text(
        get_panel_setting("save_precheck_http_timeout", ""),
        2.0,
        20.0,
    )
    configured_save_precheck_probe_timeout = _clamp_float_text(
        get_panel_setting("save_precheck_probe_timeout", ""),
        0.2,
        6.0,
    )
    configured_save_precheck_max_issues = _clamp_int_text(
        get_panel_setting("save_precheck_max_issues", ""),
        5,
        120,
    )

    configured_sync_precheck_enabled = parse_bool_loose(get_panel_setting("sync_precheck_enabled"), default=True)
    configured_sync_precheck_http_timeout = _clamp_float_text(
        get_panel_setting("sync_precheck_http_timeout", ""),
        2.0,
        20.0,
    )
    configured_sync_precheck_probe_timeout = _clamp_float_text(
        get_panel_setting("sync_precheck_probe_timeout", ""),
        0.2,
        6.0,
    )
    configured_sync_apply_timeout = _clamp_float_text(
        get_panel_setting("sync_apply_timeout", ""),
        0.5,
        20.0,
    )

    effective_bootstrap_url = panel_bootstrap_base_url(request)
    effective_public_url = panel_public_base_url(request)
    effective_asset_source = panel_asset_source()
    effective_ssl_direct_timeout = setting_float("ssl_direct_timeout_sec", default=240.0, lo=30.0, hi=1200.0)
    effective_ssl_direct_max_attempts = setting_int("ssl_direct_max_attempts", default=1, lo=1, hi=30)
    effective_panel_ip_fallback_port = setting_int(
        "agent_panel_ip_fallback_port",
        default=6080,
        lo=1,
        hi=65535,
        env_names=["REALM_PANEL_IP_FALLBACK_PORT"],
    )
    return templates.TemplateResponse(
        "settings.html",
        {
            "request": request,
            "user": user,
            "flash": flash(request),
            "title": "面板设置",
            "agent_bootstrap_url": configured_url,
            "agent_bootstrap_insecure_tls": bool(insecure_tls),
            "effective_bootstrap_url": effective_bootstrap_url,
            "panel_public_url": configured_public_url,
            "panel_asset_source": configured_asset_source,
            "panel_agent_sh_url": configured_agent_sh_url,
            "panel_agent_zip_url": configured_agent_zip_url,
            "agent_bootstrap_default_scheme": configured_bootstrap_scheme,
            "agent_panel_ip_fallback_port": configured_panel_ip_fallback_port,
            "ssl_direct_first": bool(configured_ssl_direct_first),
            "ssl_direct_timeout_sec": configured_ssl_direct_timeout,
            "ssl_direct_max_attempts": configured_ssl_direct_max_attempts,
            "ssl_fallback_to_queue": bool(configured_ssl_fallback_to_queue),
            "save_precheck_enabled": bool(configured_save_precheck_enabled),
            "save_precheck_http_timeout": configured_save_precheck_http_timeout,
            "save_precheck_probe_timeout": configured_save_precheck_probe_timeout,
            "save_precheck_max_issues": configured_save_precheck_max_issues,
            "sync_precheck_enabled": bool(configured_sync_precheck_enabled),
            "sync_precheck_http_timeout": configured_sync_precheck_http_timeout,
            "sync_precheck_probe_timeout": configured_sync_precheck_probe_timeout,
            "sync_apply_timeout": configured_sync_apply_timeout,
            "effective_public_url": effective_public_url,
            "effective_asset_source": effective_asset_source,
            "effective_ssl_direct_timeout": f"{float(effective_ssl_direct_timeout):g}",
            "effective_ssl_direct_max_attempts": int(effective_ssl_direct_max_attempts),
            "effective_panel_ip_fallback_port": int(effective_panel_ip_fallback_port),
        },
    )


@router.post("/settings")
async def settings_save(
    request: Request,
    user: str = Depends(require_role_page("users.manage")),
    agent_bootstrap_url: str = Form(""),
    agent_bootstrap_insecure_tls: Optional[str] = Form(None),
    panel_public_url: str = Form(""),
    panel_asset_source: str = Form("panel"),
    panel_agent_sh_url: str = Form(""),
    panel_agent_zip_url: str = Form(""),
    agent_bootstrap_default_scheme: str = Form(""),
    agent_panel_ip_fallback_port: str = Form(""),
    ssl_direct_first: Optional[str] = Form(None),
    ssl_direct_timeout_sec: str = Form(""),
    ssl_direct_max_attempts: str = Form(""),
    ssl_fallback_to_queue: Optional[str] = Form(None),
    save_precheck_enabled: Optional[str] = Form(None),
    save_precheck_http_timeout: str = Form(""),
    save_precheck_probe_timeout: str = Form(""),
    save_precheck_max_issues: str = Form(""),
    sync_precheck_enabled: Optional[str] = Form(None),
    sync_precheck_http_timeout: str = Form(""),
    sync_precheck_probe_timeout: str = Form(""),
    sync_apply_timeout: str = Form(""),
):
    _ = user
    set_panel_setting("agent_bootstrap_url", str(agent_bootstrap_url or "").strip())
    set_panel_setting("agent_bootstrap_insecure_tls", "1" if _as_bool(agent_bootstrap_insecure_tls, default=False) else "0")
    set_panel_setting("panel_public_url", str(panel_public_url or "").strip())

    asset_src = str(panel_asset_source or "").strip().lower()
    if asset_src not in ("panel", "github"):
        asset_src = "panel"
    set_panel_setting("panel_asset_source", asset_src)
    set_panel_setting("panel_agent_sh_url", str(panel_agent_sh_url or "").strip())
    set_panel_setting("panel_agent_zip_url", str(panel_agent_zip_url or "").strip())

    bootstrap_scheme = str(agent_bootstrap_default_scheme or "").strip().lower()
    if bootstrap_scheme not in ("http", "https"):
        bootstrap_scheme = ""
    set_panel_setting("agent_bootstrap_default_scheme", bootstrap_scheme)
    set_panel_setting("agent_panel_ip_fallback_port", _clamp_int_text(agent_panel_ip_fallback_port, 1, 65535))

    set_panel_setting("ssl_direct_first", "1" if _as_bool(ssl_direct_first, default=False) else "0")
    set_panel_setting("ssl_direct_timeout_sec", _clamp_float_text(ssl_direct_timeout_sec, 30.0, 1200.0))
    set_panel_setting("ssl_direct_max_attempts", _clamp_int_text(ssl_direct_max_attempts, 1, 30))
    set_panel_setting("ssl_fallback_to_queue", "1" if _as_bool(ssl_fallback_to_queue, default=False) else "0")

    set_panel_setting("save_precheck_enabled", "1" if _as_bool(save_precheck_enabled, default=False) else "0")
    set_panel_setting("save_precheck_http_timeout", _clamp_float_text(save_precheck_http_timeout, 2.0, 20.0))
    set_panel_setting("save_precheck_probe_timeout", _clamp_float_text(save_precheck_probe_timeout, 0.2, 6.0))
    set_panel_setting("save_precheck_max_issues", _clamp_int_text(save_precheck_max_issues, 5, 120))

    set_panel_setting("sync_precheck_enabled", "1" if _as_bool(sync_precheck_enabled, default=False) else "0")
    set_panel_setting("sync_precheck_http_timeout", _clamp_float_text(sync_precheck_http_timeout, 2.0, 20.0))
    set_panel_setting("sync_precheck_probe_timeout", _clamp_float_text(sync_precheck_probe_timeout, 0.2, 6.0))
    set_panel_setting("sync_apply_timeout", _clamp_float_text(sync_apply_timeout, 0.5, 20.0))
    set_flash(request, "面板设置已保存")
    return RedirectResponse(url="/settings", status_code=303)


@router.get("/netmon", response_class=HTMLResponse)
async def netmon_page(request: Request, user: str = Depends(require_login_page)):
    """Network fluctuation monitoring page."""
    nodes = filter_nodes_for_user(user, list_nodes())

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
    user: str = Depends(require_role_page("nodes.write")),
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
    _ = user

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
    user: str = Depends(require_role_page("nodes.write")),
    name: str = Form(""),
    group_name: str = Form("默认分组"),
    is_private: Optional[str] = Form(None),
    is_website: Optional[str] = Form(None),
    website_root_base: str = Form(""),
    base_url: str = Form(...),
    api_key: str = Form(...),
    verify_tls: Optional[str] = Form(None),
):
    _ = user

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
async def node_delete(request: Request, node_id: int, user: str = Depends(require_role_page("nodes.delete"))):
    _ = user
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
    nodes = filter_nodes_for_user(user, list_nodes())
    if int(node.get("id") or 0) not in {int(n.get("id") or 0) for n in nodes}:
        set_flash(request, "机器不存在或无权限")
        return RedirectResponse(url="/", status_code=303)

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

    base_url = panel_bootstrap_base_url(request)
    node["display_ip"] = extract_ip_for_display(node.get("base_url", ""))
    curl_tls_opt = "-k " if (panel_bootstrap_insecure_tls(default=True) and str(base_url).lower().startswith("https://")) else ""

    # 在线判定：默认心跳 30s，取 3 倍窗口避免误判
    node["online"] = is_report_fresh(node, max_age_sec=90)

    # ✅ 一键接入 / 卸载命令（短命令，避免超长）
    # 说明：使用 node.api_key 作为 join token，脚本由面板返回并带参数执行。
    token = node["api_key"]
    curl_retry_opt_probe = (
        "CURL_RETRY_ALL_ERRORS=''; "
        "curl --help all 2>/dev/null | grep -q -- '--retry-all-errors' "
        "&& CURL_RETRY_ALL_ERRORS='--retry-all-errors'; "
    )
    install_cmd = (
        f"{curl_retry_opt_probe}"
        f"curl {curl_tls_opt}-fL --retry 5 $CURL_RETRY_ALL_ERRORS --connect-timeout 10 "
        f"-H \"X-Join-Token: {token}\" -o /tmp/realm-join.sh {base_url}/join "
        f"&& bash /tmp/realm-join.sh && rm -f /tmp/realm-join.sh"
    )
    uninstall_cmd = (
        f"{curl_retry_opt_probe}"
        f"curl {curl_tls_opt}-fL --retry 5 $CURL_RETRY_ALL_ERRORS --connect-timeout 10 "
        f"-H \"X-Join-Token: {token}\" -o /tmp/realm-uninstall.sh {base_url}/uninstall "
        f"&& bash /tmp/realm-uninstall.sh && rm -f /tmp/realm-uninstall.sh"
    )

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
