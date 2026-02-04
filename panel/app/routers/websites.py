from __future__ import annotations

import base64
import hashlib
import os
import uuid
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlencode

from fastapi import APIRouter, Depends, File, Form, Request, UploadFile
from fastapi.responses import HTMLResponse, RedirectResponse, Response

from ..clients.agent import agent_get, agent_post, AgentError
from ..core.deps import require_login_page
from ..core.flash import flash, set_flash
from ..core.templates import templates
from ..db import (
    add_certificate,
    add_site,
    add_site_event,
    add_task,
    delete_certificates_by_node,
    delete_certificates_by_site,
    delete_site,
    delete_sites_by_node,
    get_node,
    get_site,
    list_certificates,
    list_site_checks,
    list_site_events,
    list_nodes,
    list_sites,
    update_certificate,
    update_site,
    update_task,
)
from ..services.apply import node_verify_tls

router = APIRouter()
UPLOAD_CHUNK_SIZE = 1024 * 512
UPLOAD_MAX_BYTES = 1024 * 1024 * 200


def _parse_domains(raw: str) -> List[str]:
    if not raw:
        return []
    parts: List[str] = []
    for chunk in raw.replace(";", ",").replace("\n", ",").split(","):
        item = (chunk or "").strip()
        if not item:
            continue
        # split by whitespace too
        sub = [x for x in item.split() if x.strip()]
        if sub:
            parts.extend(sub)
        else:
            parts.append(item)
    cleaned: List[str] = []
    for d in parts:
        d2 = d.strip().lower().strip(".")
        if d2 and d2 not in cleaned:
            cleaned.append(d2)
    return cleaned


def _normalize_proxy_target(target: str) -> str:
    t = (target or "").strip()
    if not t:
        return ""
    if t.startswith("unix:"):
        return t
    if "://" in t:
        return t
    return f"http://{t}"


def _format_bytes(num: int) -> str:
    try:
        n = float(num)
    except Exception:
        return "-"
    if n < 1024:
        return f"{int(n)} B"
    for unit in ("KB", "MB", "GB", "TB"):
        n /= 1024.0
        if n < 1024:
            return f"{n:.1f} {unit}"
    return f"{n:.1f} PB"


def _agent_payload_root(site: Dict[str, Any], node: Dict[str, Any]) -> str:
    root = str(site.get("root_path") or "").strip()
    if not root:
        return ""
    # Ensure root is under node root base when possible
    base = str(node.get("website_root_base") or "").strip()
    if base and not root.startswith(base.rstrip("/") + "/") and root != base.rstrip("/"):
        return root
    return root


def _node_root_base(node: Dict[str, Any]) -> str:
    return str(node.get("website_root_base") or "").strip()


@router.get("/websites", response_class=HTMLResponse)
async def websites_index(request: Request, user: str = Depends(require_login_page)):
    nodes = [n for n in list_nodes() if str(n.get("role") or "") == "website"]
    sites = list_sites()
    node_map = {int(n["id"]): n for n in nodes}

    for s in sites:
        nid = int(s.get("node_id") or 0)
        s["node"] = node_map.get(nid)
        s["domains_text"] = ", ".join(s.get("domains") or [])

    return templates.TemplateResponse(
        "websites.html",
        {
            "request": request,
            "user": user,
            "flash": flash(request),
            "title": "网站管理",
            "nodes": nodes,
            "sites": sites,
        },
    )


@router.get("/websites/new", response_class=HTMLResponse)
async def websites_new(request: Request, user: str = Depends(require_login_page)):
    nodes = [n for n in list_nodes() if str(n.get("role") or "") == "website"]
    return templates.TemplateResponse(
        "site_new.html",
        {
            "request": request,
            "user": user,
            "flash": flash(request),
            "title": "新建网站",
            "nodes": nodes,
        },
    )


@router.post("/websites/new")
async def websites_new_action(
    request: Request,
    node_id: int = Form(...),
    name: str = Form(""),
    domains: str = Form(""),
    site_type: str = Form("static"),
    web_server: str = Form("nginx"),
    root_path: str = Form(""),
    proxy_target: str = Form(""),
    https_redirect: Optional[str] = Form(None),
    gzip_enabled: Optional[str] = Form(None),
    nginx_tpl: str = Form(""),
    user: str = Depends(require_login_page),
):
    node = get_node(int(node_id))
    if not node or str(node.get("role") or "") != "website":
        set_flash(request, "请选择网站机节点")
        return RedirectResponse(url="/websites/new", status_code=303)

    domains_list = _parse_domains(domains)
    if not domains_list:
        set_flash(request, "域名不能为空")
        return RedirectResponse(url="/websites/new", status_code=303)

    site_type = (site_type or "static").strip()
    if site_type not in ("static", "php", "reverse_proxy"):
        site_type = "static"

    web_server = (web_server or "nginx").strip() or "nginx"
    if web_server != "nginx":
        set_flash(request, "当前仅支持 nginx")
        return RedirectResponse(url="/websites/new", status_code=303)

    # prevent duplicate domains on same node
    existing = list_sites(node_id=int(node_id))
    for s in existing:
        if str(s.get("status") or "").strip().lower() == "error":
            continue
        s_domains = set([str(x).lower() for x in (s.get("domains") or [])])
        if s_domains.intersection(set(domains_list)):
            set_flash(request, "该节点已有重复域名的站点")
            return RedirectResponse(url="/websites/new", status_code=303)

    root_base = str(node.get("website_root_base") or "").strip() or "/www"
    root_path = (root_path or "").strip()
    if not root_path and site_type != "reverse_proxy":
        root_path = f"{root_base.rstrip('/')}/wwwroot/{domains_list[0]}"
    proxy_target = _normalize_proxy_target(proxy_target or "")
    if site_type == "reverse_proxy" and not proxy_target.strip():
        set_flash(request, "反向代理必须填写目标地址")
        return RedirectResponse(url="/websites/new", status_code=303)

    https_flag = bool(https_redirect)
    gzip_flag = bool(gzip_enabled)
    tpl = (nginx_tpl or "").strip()

    # Ensure environment before creating site
    try:
        ensure_payload = {
            "need_nginx": True,
            "need_php": site_type == "php",
            "need_acme": True,
        }
        data = await agent_post(
            node["base_url"],
            node["api_key"],
            "/api/v1/website/env/ensure",
            ensure_payload,
            node_verify_tls(node),
            timeout=300,
        )
        if not data.get("ok", True):
            raise AgentError(str(data.get("error") or "环境安装失败"))
    except Exception as exc:
        set_flash(request, f"环境安装失败：{exc}")
        return RedirectResponse(url="/websites/new", status_code=303)

    display_name = (name or "").strip() or domains_list[0]

    site_id = add_site(
        node_id=int(node_id),
        name=display_name,
        domains=domains_list,
        root_path=root_path,
        proxy_target=proxy_target,
        site_type=site_type,
        web_server=web_server,
        nginx_tpl=tpl,
        https_redirect=https_flag,
        gzip_enabled=gzip_flag,
        status="creating",
    )
    add_site_event(
        site_id,
        "site_create",
        status="running",
        actor=str(user or ""),
        payload={
            "node_id": int(node_id),
            "domains": domains_list,
            "root_path": root_path,
            "type": site_type,
            "web_server": web_server,
            "proxy_target": proxy_target,
        },
    )

    task_id = add_task(
        node_id=int(node_id),
        task_type="create_site",
        payload={
            "site_id": site_id,
            "domains": domains_list,
            "root_path": root_path,
            "type": site_type,
            "web_server": web_server,
            "proxy_target": proxy_target,
            "https_redirect": https_flag,
            "gzip_enabled": gzip_flag,
            "nginx_tpl": tpl,
        },
        status="running",
        progress=10,
    )

    try:
        payload = {
            "name": display_name,
            "domains": domains_list,
            "root_path": root_path,
            "type": site_type,
            "web_server": web_server,
            "proxy_target": proxy_target,
            "https_redirect": https_flag,
            "gzip_enabled": gzip_flag,
            "nginx_tpl": tpl,
            "root_base": _node_root_base(node),
        }
        data = await agent_post(
            node["base_url"],
            node["api_key"],
            "/api/v1/website/site/create",
            payload,
            node_verify_tls(node),
            timeout=30,
        )
        if not data.get("ok", True):
            raise AgentError(str(data.get("error") or "创建站点失败"))
        update_site(site_id, status="running")
        update_task(task_id, status="success", progress=100, result=data)
        add_site_event(site_id, "site_create", status="success", actor=str(user or ""), result=data)
        set_flash(request, "站点创建成功")
        return RedirectResponse(url=f"/websites/{site_id}", status_code=303)
    except Exception as exc:
        update_site(site_id, status="error")
        update_task(task_id, status="failed", progress=100, error=str(exc))
        add_site_event(site_id, "site_create", status="failed", actor=str(user or ""), error=str(exc))
        set_flash(request, f"站点创建失败：{exc}")
        return RedirectResponse(url=f"/websites/{site_id}", status_code=303)


@router.get("/websites/{site_id}", response_class=HTMLResponse)
async def website_detail(request: Request, site_id: int, user: str = Depends(require_login_page)):
    site = get_site(int(site_id))
    if not site:
        set_flash(request, "站点不存在")
        return RedirectResponse(url="/websites", status_code=303)
    node = get_node(int(site.get("node_id") or 0))
    certs = list_certificates(site_id=int(site_id))
    for c in certs:
        c["domains_text"] = ", ".join(c.get("domains") or [])
    events = list_site_events(int(site_id), limit=60)
    checks = list_site_checks(int(site_id), limit=30)
    return templates.TemplateResponse(
        "site_detail.html",
        {
            "request": request,
            "user": user,
            "flash": flash(request),
            "title": site.get("name") or "站点详情",
            "site": site,
            "node": node,
            "certs": certs,
            "events": events,
            "checks": checks,
        },
    )


@router.get("/websites/{site_id}/diagnose", response_class=HTMLResponse)
async def website_diagnose(request: Request, site_id: int, user: str = Depends(require_login_page)):
    site = get_site(int(site_id))
    if not site:
        set_flash(request, "站点不存在")
        return RedirectResponse(url="/websites", status_code=303)
    node = get_node(int(site.get("node_id") or 0))
    if not node:
        set_flash(request, "节点不存在")
        return RedirectResponse(url=f"/websites/{site_id}", status_code=303)

    payload = {
        "domains": site.get("domains") or [],
        "type": site.get("type") or "static",
        "root_path": site.get("root_path") or "",
        "proxy_target": site.get("proxy_target") or "",
        "root_base": _node_root_base(node),
    }

    diag: Dict[str, Any] = {}
    err_msg = ""
    try:
        data = await agent_post(
            node["base_url"],
            node["api_key"],
            "/api/v1/website/diagnose",
            payload,
            node_verify_tls(node),
            timeout=15,
        )
        diag = data if isinstance(data, dict) else {}
        if not diag.get("ok", True):
            err_msg = str(diag.get("error") or "诊断失败")
    except Exception as exc:
        err_msg = str(exc)

    events = list_site_events(int(site_id), limit=80)
    checks = list_site_checks(int(site_id), limit=40)

    return templates.TemplateResponse(
        "site_diagnose.html",
        {
            "request": request,
            "user": user,
            "flash": flash(request),
            "title": f"诊断 · {site.get('name')}",
            "site": site,
            "node": node,
            "diag": diag,
            "diag_error": err_msg,
            "events": events,
            "checks": checks,
        },
    )


@router.post("/websites/{site_id}/ssl/issue")
async def website_ssl_issue(request: Request, site_id: int, user: str = Depends(require_login_page)):
    site = get_site(int(site_id))
    if not site:
        set_flash(request, "站点不存在")
        return RedirectResponse(url="/websites", status_code=303)
    node = get_node(int(site.get("node_id") or 0))
    if not node:
        set_flash(request, "节点不存在")
        return RedirectResponse(url=f"/websites/{site_id}", status_code=303)

    domains = site.get("domains") or []
    if not domains:
        set_flash(request, "站点域名为空")
        return RedirectResponse(url=f"/websites/{site_id}", status_code=303)

    cert_id = None
    existing = list_certificates(site_id=int(site_id))
    if existing:
        cert_id = int(existing[0].get("id") or 0)

    task_id = add_task(
        node_id=int(site.get("node_id") or 0),
        task_type="ssl_issue",
        payload={"site_id": site_id, "domains": domains},
        status="running",
        progress=10,
    )
    add_site_event(site_id, "ssl_issue", status="running", actor=str(user or ""), payload={"domains": domains})

    try:
        data = await agent_post(
            node["base_url"],
            node["api_key"],
            "/api/v1/website/ssl/issue",
            {
                "domains": domains,
                "root_path": site.get("root_path") or "",
                "root_base": _node_root_base(node),
                "update_conf": {
                    "type": site.get("type") or "static",
                    "root_path": site.get("root_path") or "",
                    "proxy_target": _normalize_proxy_target(site.get("proxy_target") or ""),
                    "https_redirect": bool(site.get("https_redirect") or False),
                    "gzip_enabled": True if site.get("gzip_enabled") is None else bool(site.get("gzip_enabled")),
                    "nginx_tpl": site.get("nginx_tpl") or "",
                },
            },
            node_verify_tls(node),
            timeout=20,
        )
        if not data.get("ok", True):
            raise AgentError(str(data.get("error") or "证书申请失败"))

        if cert_id:
            update_certificate(
                cert_id,
                status="valid",
                not_before=data.get("not_before"),
                not_after=data.get("not_after"),
                renew_at=data.get("renew_at"),
                last_error="",
            )
        else:
            add_certificate(
                node_id=int(site.get("node_id") or 0),
                site_id=int(site_id),
                domains=domains,
                status="valid",
                not_before=data.get("not_before"),
                not_after=data.get("not_after"),
                renew_at=data.get("renew_at"),
                last_error="",
            )
        update_task(task_id, status="success", progress=100, result=data)
        warn = str(data.get("warning") or "").strip() if isinstance(data, dict) else ""
        add_site_event(site_id, "ssl_issue", status="success", actor=str(user or ""), result=data)
        if warn:
            set_flash(request, f"证书申请成功，但有警告：{warn}")
        else:
            set_flash(request, "证书申请成功")
    except Exception as exc:
        if cert_id:
            update_certificate(cert_id, status="failed", last_error=str(exc))
        else:
            add_certificate(
                node_id=int(site.get("node_id") or 0),
                site_id=int(site_id),
                domains=domains,
                status="failed",
                last_error=str(exc),
            )
        update_task(task_id, status="failed", progress=100, error=str(exc))
        add_site_event(site_id, "ssl_issue", status="failed", actor=str(user or ""), error=str(exc))
        set_flash(request, f"证书申请失败：{exc}")

    return RedirectResponse(url=f"/websites/{site_id}", status_code=303)


@router.post("/websites/{site_id}/ssl/renew")
async def website_ssl_renew(request: Request, site_id: int, user: str = Depends(require_login_page)):
    site = get_site(int(site_id))
    if not site:
        set_flash(request, "站点不存在")
        return RedirectResponse(url="/websites", status_code=303)
    node = get_node(int(site.get("node_id") or 0))
    if not node:
        set_flash(request, "节点不存在")
        return RedirectResponse(url=f"/websites/{site_id}", status_code=303)

    domains = site.get("domains") or []
    if not domains:
        set_flash(request, "站点域名为空")
        return RedirectResponse(url=f"/websites/{site_id}", status_code=303)

    existing = list_certificates(site_id=int(site_id))
    cert_id = int(existing[0].get("id") or 0) if existing else None

    task_id = add_task(
        node_id=int(site.get("node_id") or 0),
        task_type="ssl_renew",
        payload={"site_id": site_id, "domains": domains},
        status="running",
        progress=10,
    )
    add_site_event(site_id, "ssl_renew", status="running", actor=str(user or ""), payload={"domains": domains})

    try:
        data = await agent_post(
            node["base_url"],
            node["api_key"],
            "/api/v1/website/ssl/renew",
            {
                "domains": domains,
                "root_path": site.get("root_path") or "",
                "root_base": _node_root_base(node),
                "update_conf": {
                    "type": site.get("type") or "static",
                    "root_path": site.get("root_path") or "",
                    "proxy_target": _normalize_proxy_target(site.get("proxy_target") or ""),
                    "https_redirect": bool(site.get("https_redirect") or False),
                    "gzip_enabled": True if site.get("gzip_enabled") is None else bool(site.get("gzip_enabled")),
                    "nginx_tpl": site.get("nginx_tpl") or "",
                },
            },
            node_verify_tls(node),
            timeout=20,
        )
        if not data.get("ok", True):
            raise AgentError(str(data.get("error") or "证书续期失败"))

        if cert_id:
            update_certificate(
                cert_id,
                status="valid",
                not_before=data.get("not_before"),
                not_after=data.get("not_after"),
                renew_at=data.get("renew_at"),
                last_error="",
            )
        else:
            add_certificate(
                node_id=int(site.get("node_id") or 0),
                site_id=int(site_id),
                domains=domains,
                status="valid",
                not_before=data.get("not_before"),
                not_after=data.get("not_after"),
                renew_at=data.get("renew_at"),
                last_error="",
            )

        update_task(task_id, status="success", progress=100, result=data)
        warn = str(data.get("warning") or "").strip() if isinstance(data, dict) else ""
        add_site_event(site_id, "ssl_renew", status="success", actor=str(user or ""), result=data)
        if warn:
            set_flash(request, f"证书续期成功，但有警告：{warn}")
        else:
            set_flash(request, "证书续期成功")
    except Exception as exc:
        if cert_id:
            update_certificate(cert_id, status="failed", last_error=str(exc))
        else:
            add_certificate(
                node_id=int(site.get("node_id") or 0),
                site_id=int(site_id),
                domains=domains,
                status="failed",
                last_error=str(exc),
            )
        update_task(task_id, status="failed", progress=100, error=str(exc))
        add_site_event(site_id, "ssl_renew", status="failed", actor=str(user or ""), error=str(exc))
        set_flash(request, f"证书续期失败：{exc}")
    return RedirectResponse(url=f"/websites/{site_id}", status_code=303)


@router.post("/websites/{site_id}/delete")
async def website_delete(
    request: Request,
    site_id: int,
    delete_files: Optional[str] = Form(None),
    delete_cert: Optional[str] = Form(None),
    user: str = Depends(require_login_page),
):
    site = get_site(int(site_id))
    if not site:
        set_flash(request, "站点不存在")
        return RedirectResponse(url="/websites", status_code=303)
    node = get_node(int(site.get("node_id") or 0))
    if not node:
        set_flash(request, "节点不存在")
        return RedirectResponse(url=f"/websites/{site_id}", status_code=303)

    domains = site.get("domains") or []
    if not domains:
        delete_certificates_by_site(int(site_id))
        delete_site(int(site_id))
        set_flash(request, "站点已删除（未找到域名，跳过节点清理）")
        return RedirectResponse(url="/websites", status_code=303)

    payload = {
        "domains": domains,
        "root_path": site.get("root_path") or "",
        "delete_root": bool(delete_files),
        "delete_cert": bool(delete_cert),
        "root_base": _node_root_base(node),
    }
    add_site_event(
        int(site_id),
        "site_delete",
        status="running",
        actor=str(user or ""),
        payload=payload,
    )
    try:
        data = await agent_post(
            node["base_url"],
            node["api_key"],
            "/api/v1/website/site/delete",
            payload,
            node_verify_tls(node),
            timeout=20,
        )
        if not data.get("ok", True):
            raise AgentError(str(data.get("error") or "删除站点失败"))
        delete_certificates_by_site(int(site_id))
        delete_site(int(site_id))
        warn = data.get("warnings") if isinstance(data, dict) else None
        add_site_event(int(site_id), "site_delete", status="success", actor=str(user or ""), result=data)
        if isinstance(warn, list) and warn:
            set_flash(request, f"站点已删除，但有警告：{'；'.join([str(x) for x in warn])}")
        else:
            set_flash(request, "站点已删除")
        return RedirectResponse(url="/websites", status_code=303)
    except Exception as exc:
        add_site_event(int(site_id), "site_delete", status="failed", actor=str(user or ""), error=str(exc))
        set_flash(request, f"删除站点失败：{exc}")
        return RedirectResponse(url=f"/websites/{site_id}", status_code=303)


@router.post("/websites/nodes/{node_id}/env/uninstall")
async def website_env_uninstall(
    request: Request,
    node_id: int,
    purge_data: Optional[str] = Form(None),
    deep_uninstall: Optional[str] = Form(None),
    user: str = Depends(require_login_page),
):
    node = get_node(int(node_id))
    if not node or str(node.get("role") or "") != "website":
        set_flash(request, "节点不存在或不是网站机")
        return RedirectResponse(url="/websites", status_code=303)

    sites = list_sites(node_id=int(node_id))
    payload = {
        "purge_data": bool(purge_data),
        "deep_uninstall": bool(deep_uninstall),
        "sites": [
            {
                "domains": s.get("domains") or [],
                "root_path": s.get("root_path") or "",
                "root_base": _node_root_base(node),
            }
            for s in sites
        ],
    }

    try:
        data = await agent_post(
            node["base_url"],
            node["api_key"],
            "/api/v1/website/env/uninstall",
            payload,
            node_verify_tls(node),
            timeout=30,
        )
        if not data.get("ok", True):
            raise AgentError(str(data.get("error") or "卸载失败"))
        if purge_data:
            delete_certificates_by_node(int(node_id))
            delete_sites_by_node(int(node_id))
        errors = data.get("errors") if isinstance(data, dict) else None
        if isinstance(errors, list) and errors:
            set_flash(request, f"卸载完成，但有警告：{'；'.join([str(x) for x in errors])}")
        else:
            set_flash(request, "网站环境已卸载")
    except Exception as exc:
        set_flash(request, f"卸载失败：{exc}")
    return RedirectResponse(url="/websites", status_code=303)


@router.post("/websites/nodes/{node_id}/env/ensure")
async def website_env_ensure(
    request: Request,
    node_id: int,
    include_php: Optional[str] = Form(None),
    user: str = Depends(require_login_page),
):
    node = get_node(int(node_id))
    if not node or str(node.get("role") or "") != "website":
        set_flash(request, "节点不存在或不是网站机")
        return RedirectResponse(url="/websites", status_code=303)

    payload = {
        "need_nginx": True,
        "need_php": bool(include_php),
        "need_acme": True,
    }
    try:
        data = await agent_post(
            node["base_url"],
            node["api_key"],
            "/api/v1/website/env/ensure",
            payload,
            node_verify_tls(node),
            timeout=300,
        )
        if not data.get("ok", True):
            raise AgentError(str(data.get("error") or "安装失败"))
        installed = data.get("installed") if isinstance(data, dict) else None
        already = data.get("already") if isinstance(data, dict) else None
        msg = "环境安装完成"
        if installed:
            msg += f"（新安装：{', '.join([str(x) for x in installed])}）"
        if already:
            msg += f"（已存在：{', '.join([str(x) for x in already])}）"
        set_flash(request, msg)
    except Exception as exc:
        set_flash(request, f"环境安装失败：{exc}")
    return RedirectResponse(url="/websites", status_code=303)


@router.get("/websites/{site_id}/files", response_class=HTMLResponse)
async def website_files(request: Request, site_id: int, path: str = "", user: str = Depends(require_login_page)):
    site = get_site(int(site_id))
    if not site:
        set_flash(request, "站点不存在")
        return RedirectResponse(url="/websites", status_code=303)
    node = get_node(int(site.get("node_id") or 0))
    if not node:
        set_flash(request, "节点不存在")
        return RedirectResponse(url=f"/websites/{site_id}", status_code=303)

    root = _agent_payload_root(site, node)
    if not root:
        set_flash(request, "该站点没有可管理的根目录")
        return RedirectResponse(url=f"/websites/{site_id}", status_code=303)

    err_msg = ""
    items: List[Dict[str, Any]] = []
    try:
        q = urlencode({"root": root, "path": path, "root_base": _node_root_base(node)})
        data = await agent_get(
            node["base_url"],
            node["api_key"],
            f"/api/v1/website/files/list?{q}",
            node_verify_tls(node),
            timeout=10,
        )
        if not data.get("ok", True):
            raise AgentError(str(data.get("error") or "读取目录失败"))
        items = data.get("items") or []
    except Exception as exc:
        err_msg = str(exc)

    for it in items:
        it["size_h"] = _format_bytes(int(it.get("size") or 0))

    # build breadcrumbs
    crumbs: List[Tuple[str, str]] = [("根目录", "")]
    if path:
        segs = [s for s in path.split("/") if s]
        accum = []
        for s in segs:
            accum.append(s)
            crumbs.append((s, "/".join(accum)))

    return templates.TemplateResponse(
        "site_files.html",
        {
            "request": request,
            "user": user,
            "flash": flash(request),
            "title": f"文件管理 · {site.get('name')}",
            "site": site,
            "node": node,
            "path": path,
            "root": root,
            "items": items,
            "breadcrumbs": crumbs,
            "error": err_msg,
        },
    )


@router.post("/websites/{site_id}/files/upload_chunk")
async def website_files_upload_chunk(
    request: Request,
    site_id: int,
    user: str = Depends(require_login_page),
):
    try:
        data = await request.json()
    except Exception:
        data = {}
    site = get_site(int(site_id))
    node = get_node(int(site.get("node_id") or 0)) if site else None
    if not site or not node:
        return {"ok": False, "error": "站点不存在"}

    root = _agent_payload_root(site, node)
    if not root:
        return {"ok": False, "error": "该站点没有可管理的根目录"}

    payload = {
        "root": root,
        "path": str(data.get("path") or ""),
        "filename": str(data.get("filename") or "upload.bin"),
        "upload_id": str(data.get("upload_id") or ""),
        "offset": int(data.get("offset") or 0),
        "done": bool(data.get("done")),
        "content_b64": str(data.get("content_b64") or ""),
        "chunk_sha256": str(data.get("chunk_sha256") or ""),
        "root_base": _node_root_base(node),
    }
    try:
        resp = await agent_post(
            node["base_url"],
            node["api_key"],
            "/api/v1/website/files/upload_chunk",
            payload,
            node_verify_tls(node),
            timeout=30,
        )
        return resp
    except Exception as exc:
        return {"ok": False, "error": str(exc)}


@router.post("/websites/{site_id}/files/upload_status")
async def website_files_upload_status(
    request: Request,
    site_id: int,
    user: str = Depends(require_login_page),
):
    try:
        data = await request.json()
    except Exception:
        data = {}
    site = get_site(int(site_id))
    node = get_node(int(site.get("node_id") or 0)) if site else None
    if not site or not node:
        return {"ok": False, "error": "站点不存在"}

    root = _agent_payload_root(site, node)
    if not root:
        return {"ok": False, "error": "该站点没有可管理的根目录"}

    payload = {
        "root": root,
        "path": str(data.get("path") or ""),
        "filename": str(data.get("filename") or "upload.bin"),
        "upload_id": str(data.get("upload_id") or ""),
        "root_base": _node_root_base(node),
    }
    try:
        resp = await agent_post(
            node["base_url"],
            node["api_key"],
            "/api/v1/website/files/upload_status",
            payload,
            node_verify_tls(node),
            timeout=10,
        )
        return resp
    except Exception as exc:
        return {"ok": False, "error": str(exc)}


@router.post("/websites/{site_id}/files/mkdir")
async def website_files_mkdir(
    request: Request,
    site_id: int,
    path: str = Form(""),
    name: str = Form(""),
    user: str = Depends(require_login_page),
):
    site = get_site(int(site_id))
    node = get_node(int(site.get("node_id") or 0)) if site else None
    if not site or not node:
        set_flash(request, "站点不存在")
        return RedirectResponse(url="/websites", status_code=303)

    root = _agent_payload_root(site, node)
    if not root:
        set_flash(request, "该站点没有可管理的根目录")
        return RedirectResponse(url=f"/websites/{site_id}", status_code=303)

    name = (name or "").strip()
    if not name:
        set_flash(request, "目录名不能为空")
        return RedirectResponse(url=f"/websites/{site_id}/files?path={path}", status_code=303)

    try:
        await agent_post(
            node["base_url"],
            node["api_key"],
            "/api/v1/website/files/mkdir",
            {"root": root, "path": path, "name": name, "root_base": _node_root_base(node)},
            node_verify_tls(node),
            timeout=10,
        )
        set_flash(request, "目录创建成功")
    except Exception as exc:
        set_flash(request, f"创建目录失败：{exc}")
    return RedirectResponse(url=f"/websites/{site_id}/files?path={path}", status_code=303)


@router.post("/websites/{site_id}/files/upload")
async def website_files_upload(
    request: Request,
    site_id: int,
    path: str = Form(""),
    file: UploadFile = File(...),
    user: str = Depends(require_login_page),
):
    site = get_site(int(site_id))
    node = get_node(int(site.get("node_id") or 0)) if site else None
    if not site or not node:
        set_flash(request, "站点不存在")
        return RedirectResponse(url="/websites", status_code=303)

    root = _agent_payload_root(site, node)
    if not root:
        set_flash(request, "该站点没有可管理的根目录")
        return RedirectResponse(url=f"/websites/{site_id}", status_code=303)

    try:
        filename = os.path.basename(file.filename or "upload.bin")
        upload_id = uuid.uuid4().hex
        offset = 0
        total = 0
        chunk = await file.read(UPLOAD_CHUNK_SIZE)
        if not chunk:
            raise RuntimeError("空文件")
        while True:
            next_chunk = await file.read(UPLOAD_CHUNK_SIZE)
            done = not next_chunk
            total += len(chunk)
            if total > UPLOAD_MAX_BYTES:
                raise RuntimeError("文件过大（当前限制 200MB）")
            payload = {
                "root": root,
                "path": path,
                "filename": filename,
                "upload_id": upload_id,
                "offset": offset,
                "done": done,
                "content_b64": base64.b64encode(chunk).decode("ascii"),
                "chunk_sha256": hashlib.sha256(chunk).hexdigest(),
                "root_base": _node_root_base(node),
            }
            resp = await agent_post(
                node["base_url"],
                node["api_key"],
                "/api/v1/website/files/upload_chunk",
                payload,
                node_verify_tls(node),
                timeout=30,
            )
            if not resp.get("ok", True):
                raise AgentError(str(resp.get("error") or "上传失败"))
            offset += len(chunk)
            if done:
                break
            chunk = next_chunk
        set_flash(request, "上传成功")
    except Exception as exc:
        set_flash(request, f"上传失败：{exc}")

    return RedirectResponse(url=f"/websites/{site_id}/files?path={path}", status_code=303)


@router.get("/websites/{site_id}/files/edit", response_class=HTMLResponse)
async def website_files_edit(
    request: Request,
    site_id: int,
    path: str,
    user: str = Depends(require_login_page),
):
    site = get_site(int(site_id))
    node = get_node(int(site.get("node_id") or 0)) if site else None
    if not site or not node:
        set_flash(request, "站点不存在")
        return RedirectResponse(url="/websites", status_code=303)

    root = _agent_payload_root(site, node)
    if not root:
        set_flash(request, "该站点没有可管理的根目录")
        return RedirectResponse(url=f"/websites/{site_id}", status_code=303)

    content = ""
    error = ""
    try:
        q = urlencode({"root": root, "path": path, "root_base": _node_root_base(node)})
        data = await agent_get(
            node["base_url"],
            node["api_key"],
            f"/api/v1/website/files/read?{q}",
            node_verify_tls(node),
            timeout=10,
        )
        if not data.get("ok", True):
            raise AgentError(str(data.get("error") or "读取文件失败"))
        content = str(data.get("content") or "")
    except Exception as exc:
        error = str(exc)

    return templates.TemplateResponse(
        "site_file_edit.html",
        {
            "request": request,
            "user": user,
            "flash": flash(request),
            "title": f"编辑文件 · {site.get('name')}",
            "site": site,
            "node": node,
            "path": path,
            "content": content,
            "error": error,
        },
    )


@router.post("/websites/{site_id}/files/save")
async def website_files_save(
    request: Request,
    site_id: int,
    path: str = Form(""),
    content: str = Form(""),
    user: str = Depends(require_login_page),
):
    site = get_site(int(site_id))
    node = get_node(int(site.get("node_id") or 0)) if site else None
    if not site or not node:
        set_flash(request, "站点不存在")
        return RedirectResponse(url="/websites", status_code=303)

    root = _agent_payload_root(site, node)
    if not root:
        set_flash(request, "该站点没有可管理的根目录")
        return RedirectResponse(url=f"/websites/{site_id}", status_code=303)

    try:
        await agent_post(
            node["base_url"],
            node["api_key"],
            "/api/v1/website/files/write",
            {"root": root, "path": path, "content": content, "root_base": _node_root_base(node)},
            node_verify_tls(node),
            timeout=10,
        )
        set_flash(request, "保存成功")
    except Exception as exc:
        set_flash(request, f"保存失败：{exc}")
    return RedirectResponse(url=f"/websites/{site_id}/files?path={'/'.join(path.split('/')[:-1])}", status_code=303)


@router.post("/websites/{site_id}/files/delete")
async def website_files_delete(
    request: Request,
    site_id: int,
    path: str = Form(""),
    user: str = Depends(require_login_page),
):
    site = get_site(int(site_id))
    node = get_node(int(site.get("node_id") or 0)) if site else None
    if not site or not node:
        set_flash(request, "站点不存在")
        return RedirectResponse(url="/websites", status_code=303)

    root = _agent_payload_root(site, node)
    if not root:
        set_flash(request, "该站点没有可管理的根目录")
        return RedirectResponse(url=f"/websites/{site_id}", status_code=303)

    try:
        await agent_post(
            node["base_url"],
            node["api_key"],
            "/api/v1/website/files/delete",
            {"root": root, "path": path, "root_base": _node_root_base(node)},
            node_verify_tls(node),
            timeout=10,
        )
        set_flash(request, "删除成功")
    except Exception as exc:
        set_flash(request, f"删除失败：{exc}")
    return RedirectResponse(url=f"/websites/{site_id}/files?path={'/'.join(path.split('/')[:-1])}", status_code=303)


@router.get("/websites/{site_id}/files/download")
async def website_files_download(
    request: Request,
    site_id: int,
    path: str,
    user: str = Depends(require_login_page),
):
    site = get_site(int(site_id))
    node = get_node(int(site.get("node_id") or 0)) if site else None
    if not site or not node:
        set_flash(request, "站点不存在")
        return RedirectResponse(url="/websites", status_code=303)

    root = _agent_payload_root(site, node)
    if not root:
        set_flash(request, "该站点没有可管理的根目录")
        return RedirectResponse(url=f"/websites/{site_id}", status_code=303)

    # Lightweight proxy: fetch file bytes from agent and return
    import httpx

    url = f"{node['base_url'].rstrip('/')}/api/v1/website/files/raw"
    params = {"root": root, "path": path, "root_base": _node_root_base(node)}
    headers = {"X-API-Key": node.get("api_key") or ""}
    async with httpx.AsyncClient(timeout=20, verify=node_verify_tls(node)) as client:
        r = await client.get(url, params=params, headers=headers)
    if r.status_code != 200:
        set_flash(request, f"下载失败（HTTP {r.status_code}）")
        return RedirectResponse(url=f"/websites/{site_id}/files?path={'/'.join(path.split('/')[:-1])}", status_code=303)

    filename = path.split("/")[-1] or "download.bin"
    headers = {"Content-Disposition": f'attachment; filename="{filename}"'}
    return Response(content=r.content, media_type="application/octet-stream", headers=headers)
