from __future__ import annotations

from typing import Callable, List

from fastapi import HTTPException, Request

from ..auth import AuthUser, can_access_node, get_session_user, has_permission
from ..db import get_site


def _path_permissions(path: str, method: str) -> List[str]:
    p = str(path or "").strip() or "/"
    m = str(method or "GET").strip().upper()

    if p == "/users" or p.startswith("/api/users") or p.startswith("/api/roles"):
        return ["users.manage"]

    if p.startswith("/api/groups/"):
        return ["groups.write"]

    if p.startswith("/api/agents/"):
        if p.endswith("/latest") or p.endswith("/update_progress"):
            return ["agents.read"]
        return ["agents.write"]

    if p.startswith("/api/netmon/"):
        if m == "GET":
            return ["netmon.read"]
        return ["netmon.write"]

    if p.startswith("/api/logs/"):
        return ["panel.view"]

    if p.startswith("/api/wss_tunnel/"):
        if "delete" in p:
            return ["publish.apply", "sync.wss", "sync.delete"]
        return ["publish.apply", "sync.wss"]

    if p.startswith("/api/intranet_tunnel/"):
        if "delete" in p:
            return ["publish.apply", "sync.intranet", "sync.delete"]
        return ["publish.apply", "sync.intranet"]

    if p.startswith("/api/sync_jobs/"):
        if m == "GET":
            return ["sync.job.read"]
        return ["sync.job.read", "publish.apply"]

    if p.startswith("/api/backup/full"):
        return ["backup.manage"]

    if p.startswith("/api/restore/"):
        return ["restore.manage"]

    if p.startswith("/api/traffic/reset_all"):
        return ["nodes.write"]

    if p.startswith("/api/nodes/"):
        if p.endswith("/trace"):
            return ["nodes.read"]
        if "/restore" in p:
            return ["restore.manage"]
        if p.endswith("/backup"):
            return ["backup.manage"]
        if m == "GET":
            return ["nodes.read"]
        if "/pool" in p or "/rule_delete" in p or "/apply" in p or "/traffic/reset" in p or "/purge" in p:
            return ["publish.apply"]
        if "/stats_history/clear" in p:
            return ["nodes.write"]
        return ["nodes.write"]

    if p == "/api/nodes":
        return ["nodes.read"] if m == "GET" else ["nodes.write"]

    if p.startswith("/websites"):
        if "/ssl/" in p:
            return ["cert.manage"]
        if "/files" in p:
            if m == "GET":
                if p.endswith("/files/edit"):
                    return ["files.write"]
                return ["files.read"]
            return ["files.write"]
        if m == "GET" and (p.endswith("/new") or p.endswith("/edit")):
            return ["websites.write"]
        if m == "GET":
            return ["websites.read"]
        return ["websites.write"]

    if p == "/" or p.startswith("/nodes"):
        if p == "/nodes/new":
            return ["nodes.write"]
        if m == "GET":
            return ["nodes.read"]
        if p.endswith("/delete"):
            return ["nodes.delete"]
        return ["nodes.write"]

    if p.startswith("/netmon"):
        if m == "GET":
            return ["netmon.read"]
        return ["netmon.write"]

    if p.startswith("/logs"):
        return ["panel.view"]

    if p.startswith("/settings"):
        return ["users.manage"]

    return []


def _deny_not_logged(page: bool) -> None:
    if page:
        raise HTTPException(status_code=302, headers={"Location": "/login"})
    raise HTTPException(status_code=401, detail="Not logged in")


def _deny_forbidden(request: Request, page: bool, detail: str) -> None:
    if page:
        try:
            request.session["flash"] = detail
        except Exception:
            pass
        to = "/" if str(request.url.path or "") != "/" else "/login"
        raise HTTPException(status_code=302, headers={"Location": to})
    raise HTTPException(status_code=403, detail=detail)


def _extract_node_id_from_path(path: str) -> int:
    p = str(path or "").strip()
    if not p:
        return 0
    seg = [x for x in p.split("/") if x]
    if len(seg) >= 3 and seg[0] == "api" and seg[1] == "nodes":
        try:
            return int(seg[2])
        except Exception:
            return 0
    if len(seg) >= 2 and seg[0] == "nodes":
        try:
            return int(seg[1])
        except Exception:
            return 0
    if len(seg) >= 3 and seg[0] == "websites" and seg[1] == "nodes":
        try:
            return int(seg[2])
        except Exception:
            return 0
    return 0


def _extract_site_id_from_path(path: str) -> int:
    p = str(path or "").strip()
    if not p:
        return 0
    seg = [x for x in p.split("/") if x]
    if len(seg) >= 2 and seg[0] == "websites":
        try:
            return int(seg[1])
        except Exception:
            return 0
    return 0


def _check_perms(user: AuthUser, permissions: List[str], any_of: bool = False) -> bool:
    need = [str(p or "").strip() for p in permissions if str(p or "").strip()]
    if not need:
        return True
    if any_of:
        return any(has_permission(user, p) for p in need)
    return all(has_permission(user, p) for p in need)


def _resolve_user(request: Request, page: bool, check_path_perms: bool = True) -> AuthUser:
    user = get_session_user(request.session)
    if user is None:
        try:
            request.session.clear()
        except Exception:
            pass
        _deny_not_logged(page)
    assert user is not None

    request.state.auth_user = user
    request.session["user"] = str(user.username)
    request.session["user_id"] = int(user.id)
    request.session["user_role"] = str(user.role_name)
    request.session["user_permissions"] = sorted(list(user.permissions))
    request.session["user_policy"] = dict(user.policy or {})

    if check_path_perms:
        perms = _path_permissions(str(request.url.path or ""), str(request.method or "GET"))
        if perms and not _check_perms(user, perms, any_of=False):
            _deny_forbidden(request, page, "权限不足")
        nid = _extract_node_id_from_path(str(request.url.path or ""))
        if nid > 0 and not can_access_node(user, nid):
            _deny_forbidden(request, page, "无权访问该机器")
        sid = _extract_site_id_from_path(str(request.url.path or ""))
        if sid > 0:
            try:
                site = get_site(int(sid))
            except Exception:
                site = None
            if isinstance(site, dict):
                try:
                    site_node_id = int(site.get("node_id") or 0)
                except Exception:
                    site_node_id = 0
                if site_node_id > 0 and not can_access_node(user, site_node_id):
                    _deny_forbidden(request, page, "无权访问该机器")
    return user


def get_auth_user(request: Request, page: bool = False) -> AuthUser:
    cached = getattr(request.state, "auth_user", None)
    if isinstance(cached, AuthUser):
        return cached
    return _resolve_user(request, page=page, check_path_perms=False)


def require_role(*permissions: str, any_of: bool = False) -> Callable[[Request], str]:
    need = [str(p or "").strip() for p in permissions if str(p or "").strip()]

    def _dep(request: Request) -> str:
        user = _resolve_user(request, page=False, check_path_perms=True)
        if need and not _check_perms(user, need, any_of=any_of):
            _deny_forbidden(request, False, "权限不足")
        return str(user.username)

    return _dep


def require_role_page(*permissions: str, any_of: bool = False) -> Callable[[Request], str]:
    need = [str(p or "").strip() for p in permissions if str(p or "").strip()]

    def _dep(request: Request) -> str:
        user = _resolve_user(request, page=True, check_path_perms=True)
        if need and not _check_perms(user, need, any_of=any_of):
            _deny_forbidden(request, True, "权限不足")
        return str(user.username)

    return _dep


def require_login(request: Request) -> str:
    user = _resolve_user(request, page=False, check_path_perms=True)
    return str(user.username)


def require_login_page(request: Request) -> str:
    user = _resolve_user(request, page=True, check_path_perms=True)
    return str(user.username)
