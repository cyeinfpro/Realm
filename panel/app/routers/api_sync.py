from __future__ import annotations

import secrets
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, Optional, Tuple

from fastapi import APIRouter, Depends
from fastapi.responses import JSONResponse

from ..clients.agent import agent_get, agent_post
from ..core.deps import require_login
from ..db import get_node, set_desired_pool
from ..services.apply import node_verify_tls
from ..services.pool_ops import (
    choose_receiver_port,
    find_sync_listen_port,
    load_pool_for_node,
    node_host_for_realm,
    port_used_by_other_sync,
    remove_endpoints_by_sync_id,
    upsert_endpoint_by_sync_id,
)
from ..utils.normalize import format_addr, normalize_host_input, split_host_port
from ..utils.validate import PoolValidationError, validate_pool_inplace

router = APIRouter()


def random_wss_params() -> Tuple[str, str, str]:
    """Generate a reasonable random WSS {host, path, sni}."""
    hosts = [
        "cdn.jsdelivr.net",
        "assets.cloudflare.com",
        "edge.microsoft.com",
        "static.cloudflareinsights.com",
        "ajax.googleapis.com",
        "fonts.gstatic.com",
        "images.unsplash.com",
        "cdn.discordapp.com",
    ]
    path_templates = [
        "/ws",
        "/ws/{token}",
        "/socket",
        "/socket/{token}",
        "/connect",
        "/gateway",
        "/api/ws",
        "/v1/ws/{token}",
        "/edge/{token}",
    ]

    host = secrets.choice(hosts)
    token = secrets.token_hex(5)
    tpl = secrets.choice(path_templates)
    path = str(tpl or "/ws").replace("{token}", token)
    if path and not path.startswith("/"):
        path = "/" + path
    sni = host
    return host, path, sni


@router.post("/api/wss_tunnel/save")
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
    balance = str(payload.get("balance") or "roundrobin").strip() or "roundrobin"
    protocol = str(payload.get("protocol") or "tcp+udp").strip() or "tcp+udp"

    wss = payload.get("wss") or {}
    if not isinstance(wss, dict):
        wss = {}
    wss_host = str(wss.get("host") or "").strip()
    wss_path = str(wss.get("path") or "").strip()
    wss_sni = str(wss.get("sni") or "").strip()
    wss_tls = bool(wss.get("tls", True))
    wss_insecure = bool(wss.get("insecure", False))

    if (not wss_host) or (not wss_path) or (not wss_sni):
        rh, rp, rs = random_wss_params()
        if not wss_host:
            wss_host = wss_sni or rh
        if not wss_path:
            wss_path = rp
        if wss_path and not wss_path.startswith("/"):
            wss_path = "/" + wss_path
        if not wss_sni:
            wss_sni = wss_host or rs

    if wss_path and not wss_path.startswith("/"):
        wss_path = "/" + wss_path
    if not wss_sni:
        wss_sni = wss_host

    if not listen:
        return JSONResponse({"ok": False, "error": "listen 不能为空"}, status_code=400)
    if not remotes:
        return JSONResponse({"ok": False, "error": "目标地址不能为空"}, status_code=400)
    if not wss_host or not wss_path:
        return JSONResponse({"ok": False, "error": "WSS Host / Path 不能为空"}, status_code=400)

    sync_id = str(payload.get("sync_id") or "").strip() or uuid.uuid4().hex

    # If editing an existing synced rule and switching receiver node, remove old receiver-side rule.
    sender_pool = await load_pool_for_node(sender)
    old_receiver_id: int = 0
    try:
        for ep in sender_pool.get("endpoints") or []:
            if not isinstance(ep, dict):
                continue
            ex0 = ep.get("extra_config") or {}
            if not isinstance(ex0, dict):
                continue
            if str(ex0.get("sync_id") or "") != str(sync_id):
                continue
            if str(ex0.get("sync_role") or "") != "sender":
                continue
            old_receiver_id = int(ex0.get("sync_peer_node_id") or 0)
            break
    except Exception:
        old_receiver_id = 0

    old_receiver: Optional[Dict[str, Any]] = None
    old_receiver_pool: Optional[Dict[str, Any]] = None
    if old_receiver_id > 0 and old_receiver_id != receiver_id:
        old_receiver = get_node(old_receiver_id)
        if old_receiver:
            try:
                old_receiver_pool = await load_pool_for_node(old_receiver)
                remove_endpoints_by_sync_id(old_receiver_pool, sync_id)
                set_desired_pool(old_receiver_id, old_receiver_pool)
            except Exception:
                old_receiver = None
                old_receiver_pool = None

    # Receiver port policy:
    receiver_pool = await load_pool_for_node(receiver)
    existing_receiver_port = find_sync_listen_port(receiver_pool, sync_id, role="receiver")

    raw_receiver_port = payload.get("receiver_port")
    explicit_receiver_port = raw_receiver_port is not None and raw_receiver_port != ""
    receiver_port: Optional[int] = None
    if explicit_receiver_port:
        try:
            receiver_port = int(raw_receiver_port)
        except Exception:
            return JSONResponse({"ok": False, "error": "receiver_port 必须是数字"}, status_code=400)

    _lh, sender_listen_port = split_host_port(listen)
    if sender_listen_port is None:
        return JSONResponse({"ok": False, "error": "listen 格式不正确，请使用 0.0.0.0:端口"}, status_code=400)

    if receiver_port is None:
        receiver_port = existing_receiver_port
    if receiver_port is None:
        receiver_port = sender_listen_port

    if receiver_port <= 0 or receiver_port > 65535:
        return JSONResponse({"ok": False, "error": "receiver_port 端口范围必须是 1-65535"}, status_code=400)

    port_fixed = explicit_receiver_port or (existing_receiver_port is not None)
    if port_fixed:
        if port_used_by_other_sync(receiver_pool, receiver_port, sync_id):
            return JSONResponse(
                {"ok": False, "error": f"接收机端口 {receiver_port} 已被其他规则占用，请换一个端口"},
                status_code=400,
            )
    else:
        receiver_port = choose_receiver_port(receiver_pool, receiver_port, ignore_sync_id=sync_id)

    receiver_host = node_host_for_realm(receiver)
    if not receiver_host:
        return JSONResponse({"ok": False, "error": "接收机 base_url 无法解析主机名，请检查节点地址"}, status_code=400)
    sender_to_receiver = format_addr(receiver_host, receiver_port)

    now_iso = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")

    # Panel-only meta (remark / favorite)
    has_remark = "remark" in payload
    has_favorite = "favorite" in payload

    def _coerce_bool(v: Any) -> bool:
        if isinstance(v, bool):
            return v
        s = str(v or "").strip().lower()
        return s in ("1", "true", "yes", "y", "on")

    def _find_meta(pool: Dict[str, Any]) -> Tuple[str, Optional[bool]]:
        try:
            for ep in (pool or {}).get("endpoints") or []:
                if not isinstance(ep, dict):
                    continue
                ex0 = ep.get("extra_config") or {}
                if not isinstance(ex0, dict):
                    continue
                if str(ex0.get("sync_id") or "") != str(sync_id):
                    continue
                r = str(ep.get("remark") or "").strip()
                f_raw = ep.get("favorite")
                f_val: Optional[bool] = None
                if f_raw is not None:
                    try:
                        f_val = bool(f_raw)
                    except Exception:
                        f_val = None
                return r, f_val
        except Exception:
            pass
        return "", None

    existing_remark = ""
    existing_fav: Optional[bool] = None
    if (not has_remark) or (not has_favorite):
        r1, f1 = _find_meta(sender_pool)
        r2, f2 = _find_meta(receiver_pool)
        existing_remark = r1 or r2 or ""
        existing_fav = f1 if f1 is not None else f2

    remark = str(payload.get("remark") or "").strip() if has_remark else str(existing_remark or "").strip()
    if len(remark) > 200:
        remark = remark[:200]
    favorite = _coerce_bool(payload.get("favorite")) if has_favorite else bool(existing_fav or False)

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

    if remark:
        sender_ep["remark"] = remark
    if favorite:
        sender_ep["favorite"] = True

    receiver_ep = {
        "listen": format_addr("0.0.0.0", receiver_port),
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

    if remark:
        receiver_ep["remark"] = remark
    if favorite:
        receiver_ep["favorite"] = True

    upsert_endpoint_by_sync_id(sender_pool, sync_id, sender_ep)
    upsert_endpoint_by_sync_id(receiver_pool, sync_id, receiver_ep)

    # Save-time validation (sender+receiver): port conflicts / remote format / weights count
    try:
        validate_pool_inplace(sender_pool)
        validate_pool_inplace(receiver_pool)
    except PoolValidationError as exc:
        return JSONResponse({"ok": False, "error": str(exc), "issues": [i.__dict__ for i in exc.issues]}, status_code=400)

    s_ver, _ = set_desired_pool(sender_id, sender_pool)
    r_ver, _ = set_desired_pool(receiver_id, receiver_pool)

    async def _apply(node: Dict[str, Any], pool: Dict[str, Any]):
        try:
            data = await agent_post(
                node["base_url"],
                node["api_key"],
                "/api/v1/pool",
                {"pool": pool},
                node_verify_tls(node),
            )
            if isinstance(data, dict) and data.get("ok", True):
                await agent_post(node["base_url"], node["api_key"], "/api/v1/apply", {}, node_verify_tls(node))
        except Exception:
            pass

    await _apply(sender, sender_pool)
    await _apply(receiver, receiver_pool)

    if old_receiver and isinstance(old_receiver_pool, dict):
        await _apply(old_receiver, old_receiver_pool)

    return {
        "ok": True,
        "sync_id": sync_id,
        "receiver_port": receiver_port,
        "sender_pool": sender_pool,
        "receiver_pool": receiver_pool,
        "sender_desired_version": s_ver,
        "receiver_desired_version": r_ver,
    }


@router.post("/api/wss_tunnel/delete")
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

    sender_pool = await load_pool_for_node(sender)
    receiver_pool = await load_pool_for_node(receiver)

    remove_endpoints_by_sync_id(sender_pool, sync_id)
    remove_endpoints_by_sync_id(receiver_pool, sync_id)

    s_ver, _ = set_desired_pool(sender_id, sender_pool)
    r_ver, _ = set_desired_pool(receiver_id, receiver_pool)

    async def _apply(node: Dict[str, Any], pool: Dict[str, Any]):
        try:
            data = await agent_post(
                node["base_url"],
                node["api_key"],
                "/api/v1/pool",
                {"pool": pool},
                node_verify_tls(node),
            )
            if isinstance(data, dict) and data.get("ok", True):
                await agent_post(node["base_url"], node["api_key"], "/api/v1/apply", {}, node_verify_tls(node))
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


@router.post("/api/intranet_tunnel/save")
async def api_intranet_tunnel_save(payload: Dict[str, Any], user: str = Depends(require_login)):
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

    if not bool(receiver.get("is_private") or False):
        return JSONResponse(
            {"ok": False, "error": "所选节点未标记为内网机器，请在节点设置中勾选“内网机器”"},
            status_code=400,
        )

    listen = str(payload.get("listen") or "").strip()
    remotes = payload.get("remotes") or []
    if isinstance(remotes, str):
        remotes = [x.strip() for x in remotes.splitlines() if x.strip()]
    if not isinstance(remotes, list):
        remotes = []
    remotes = [str(x).strip() for x in remotes if str(x).strip()]
    disabled = bool(payload.get("disabled", False))
    balance = str(payload.get("balance") or "roundrobin").strip() or "roundrobin"
    protocol = str(payload.get("protocol") or "tcp+udp").strip() or "tcp+udp"

    try:
        server_port = int(payload.get("server_port") or 18443)
    except Exception:
        server_port = 18443
    if server_port <= 0 or server_port > 65535:
        return JSONResponse({"ok": False, "error": "隧道端口无效"}, status_code=400)

    if not listen:
        return JSONResponse({"ok": False, "error": "listen 不能为空"}, status_code=400)
    if not remotes:
        return JSONResponse({"ok": False, "error": "目标地址不能为空"}, status_code=400)

    sync_id = str(payload.get("sync_id") or "").strip() or uuid.uuid4().hex
    token = str(payload.get("token") or "").strip() or uuid.uuid4().hex

    sender_pool = await load_pool_for_node(sender)
    old_receiver_id: int = 0
    try:
        for ep in sender_pool.get("endpoints") or []:
            if not isinstance(ep, dict):
                continue
            ex0 = ep.get("extra_config") or {}
            if not isinstance(ex0, dict):
                continue
            if str(ex0.get("sync_id") or "") != str(sync_id):
                continue
            if str(ex0.get("intranet_role") or "") != "server":
                continue
            old_receiver_id = int(ex0.get("intranet_peer_node_id") or 0)
            break
    except Exception:
        old_receiver_id = 0

    old_receiver: Optional[Dict[str, Any]] = None
    old_receiver_pool: Optional[Dict[str, Any]] = None
    if old_receiver_id > 0 and old_receiver_id != receiver_id:
        old_receiver = get_node(old_receiver_id)
        if old_receiver:
            try:
                old_receiver_pool = await load_pool_for_node(old_receiver)
                remove_endpoints_by_sync_id(old_receiver_pool, sync_id)
                set_desired_pool(old_receiver_id, old_receiver_pool)
            except Exception:
                old_receiver = None
                old_receiver_pool = None

    override_host = normalize_host_input(str(payload.get("server_host") or ""))
    sender_host = override_host or node_host_for_realm(sender)
    if not sender_host:
        return JSONResponse(
            {
                "ok": False,
                "error": "公网入口地址为空。请检查节点 base_url 或在内网穿透中填写“公网入口地址(A)”。",
            },
            status_code=400,
        )

    # Best-effort: fetch A-side tunnel server cert and embed into B config for TLS verification.
    server_cert_pem = ""
    try:
        cert = await agent_get(
            sender.get("base_url", ""),
            sender.get("api_key", ""),
            "/api/v1/intranet/cert",
            node_verify_tls(sender),
        )
        if isinstance(cert, dict) and cert.get("ok") is True:
            server_cert_pem = str(cert.get("cert_pem") or "").strip()
    except Exception:
        server_cert_pem = ""

    receiver_pool = await load_pool_for_node(receiver)

    now_iso = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")

    # Panel-only meta (remark / favorite)
    has_remark = "remark" in payload
    has_favorite = "favorite" in payload

    def _coerce_bool(v: Any) -> bool:
        if isinstance(v, bool):
            return v
        s = str(v or "").strip().lower()
        return s in ("1", "true", "yes", "y", "on")

    def _find_meta(pool: Dict[str, Any]) -> Tuple[str, Optional[bool]]:
        try:
            for ep in (pool or {}).get("endpoints") or []:
                if not isinstance(ep, dict):
                    continue
                ex0 = ep.get("extra_config") or {}
                if not isinstance(ex0, dict):
                    continue
                if str(ex0.get("sync_id") or "") != str(sync_id):
                    continue
                r = str(ep.get("remark") or "").strip()
                f_raw = ep.get("favorite")
                f_val: Optional[bool] = None
                if f_raw is not None:
                    try:
                        f_val = bool(f_raw)
                    except Exception:
                        f_val = None
                return r, f_val
        except Exception:
            pass
        return "", None

    existing_remark = ""
    existing_fav: Optional[bool] = None
    if (not has_remark) or (not has_favorite):
        r1, f1 = _find_meta(sender_pool)
        r2, f2 = _find_meta(receiver_pool)
        existing_remark = r1 or r2 or ""
        existing_fav = f1 if f1 is not None else f2

    remark = str(payload.get("remark") or "").strip() if has_remark else str(existing_remark or "").strip()
    if len(remark) > 200:
        remark = remark[:200]
    favorite = _coerce_bool(payload.get("favorite")) if has_favorite else bool(existing_fav or False)

    sender_ep = {
        "listen": listen,
        "disabled": disabled,
        "balance": balance,
        "protocol": protocol,
        "remotes": remotes,
        "extra_config": {
            "intranet_role": "server",
            "intranet_peer_node_id": receiver_id,
            "intranet_peer_node_name": receiver.get("name"),
            "intranet_public_host": sender_host,
            "intranet_server_port": server_port,
            "intranet_token": token,
            "intranet_original_remotes": remotes,
            "sync_id": sync_id,
            "intranet_updated_at": now_iso,
        },
    }

    if remark:
        sender_ep["remark"] = remark
    if favorite:
        sender_ep["favorite"] = True

    receiver_ep = {
        "listen": format_addr("0.0.0.0", 0),
        "disabled": disabled,
        "balance": balance,
        "protocol": protocol,
        "remotes": remotes,
        "extra_config": {
            "intranet_role": "client",
            "intranet_lock": True,
            "intranet_peer_node_id": sender_id,
            "intranet_peer_node_name": sender.get("name"),
            "intranet_peer_host": sender_host,
            "intranet_server_port": server_port,
            "intranet_token": token,
            "intranet_server_cert_pem": server_cert_pem,
            "intranet_tls_verify": bool(server_cert_pem),
            "intranet_sender_listen": listen,
            "intranet_original_remotes": remotes,
            "sync_id": sync_id,
            "intranet_updated_at": now_iso,
        },
    }

    if remark:
        receiver_ep["remark"] = remark
    if favorite:
        receiver_ep["favorite"] = True

    upsert_endpoint_by_sync_id(sender_pool, sync_id, sender_ep)
    upsert_endpoint_by_sync_id(receiver_pool, sync_id, receiver_ep)

    # Save-time validation (sender+receiver): port conflicts / remote format / weights count
    try:
        validate_pool_inplace(sender_pool)
        validate_pool_inplace(receiver_pool)
    except PoolValidationError as exc:
        return JSONResponse({"ok": False, "error": str(exc), "issues": [i.__dict__ for i in exc.issues]}, status_code=400)

    s_ver, _ = set_desired_pool(sender_id, sender_pool)
    r_ver, _ = set_desired_pool(receiver_id, receiver_pool)

    async def _apply(node: Dict[str, Any], pool: Dict[str, Any]):
        try:
            data = await agent_post(
                node["base_url"],
                node["api_key"],
                "/api/v1/pool",
                {"pool": pool},
                node_verify_tls(node),
            )
            if isinstance(data, dict) and data.get("ok", True):
                await agent_post(node["base_url"], node["api_key"], "/api/v1/apply", {}, node_verify_tls(node))
        except Exception:
            pass

    await _apply(sender, sender_pool)
    await _apply(receiver, receiver_pool)

    if old_receiver and isinstance(old_receiver_pool, dict):
        await _apply(old_receiver, old_receiver_pool)

    return {
        "ok": True,
        "sync_id": sync_id,
        "sender_pool": sender_pool,
        "receiver_pool": receiver_pool,
        "sender_desired_version": s_ver,
        "receiver_desired_version": r_ver,
    }


@router.post("/api/intranet_tunnel/delete")
async def api_intranet_tunnel_delete(payload: Dict[str, Any], user: str = Depends(require_login)):
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

    sender_pool = await load_pool_for_node(sender)
    receiver_pool = await load_pool_for_node(receiver)

    remove_endpoints_by_sync_id(sender_pool, sync_id)
    remove_endpoints_by_sync_id(receiver_pool, sync_id)

    s_ver, _ = set_desired_pool(sender_id, sender_pool)
    r_ver, _ = set_desired_pool(receiver_id, receiver_pool)

    async def _apply(node: Dict[str, Any], pool: Dict[str, Any]):
        try:
            data = await agent_post(
                node["base_url"],
                node["api_key"],
                "/api/v1/pool",
                {"pool": pool},
                node_verify_tls(node),
            )
            if isinstance(data, dict) and data.get("ok", True):
                await agent_post(node["base_url"], node["api_key"], "/api/v1/apply", {}, node_verify_tls(node))
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
