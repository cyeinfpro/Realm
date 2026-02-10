from __future__ import annotations

import asyncio
import base64
import hashlib
import inspect
import io
import json
import os
import random
import threading
import time
import uuid
import zipfile
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlencode, urlparse

from fastapi import APIRouter, Depends, File, Request, UploadFile
from fastapi.responses import JSONResponse, Response

from ..auth import (
    can_access_rule_endpoint,
    filter_nodes_for_user,
    get_user_by_username,
    is_rule_owner_scoped,
    stamp_endpoint_owner,
)
from ..clients.agent import agent_get, agent_get_raw, agent_ping, agent_post
from ..core.deps import require_login
from ..core.settings import DEFAULT_AGENT_PORT
from ..db import (
    add_certificate,
    add_netmon_monitor,
    add_node,
    add_site,
    bump_traffic_reset_version,
    get_desired_pool,
    get_group_orders,
    get_last_report,
    get_node,
    get_node_by_api_key,
    get_node_by_base_url,
    list_certificates,
    list_netmon_monitors,
    list_rule_stats_series,
    list_sites,
    clear_rule_stats_samples,
    list_nodes,
    set_desired_pool,
    upsert_rule_owner_map,
    upsert_group_order,
    update_certificate,
    update_netmon_monitor,
    update_node_basic,
    update_site,
    update_site_health,
)
from ..services.apply import node_verify_tls, schedule_apply_pool
from ..services.backup import get_pool_for_backup
from ..services.assets import panel_public_base_url
from ..services.node_status import is_report_fresh
from ..services.pool_ops import load_pool_for_node, remove_endpoints_by_sync_id
from ..services.stats_history import config as stats_history_config, ingest_stats_snapshot
from ..utils.crypto import generate_api_key
from ..utils.normalize import (
    extract_ip_for_display,
    format_host_for_url,
    safe_filename_part,
    sanitize_pool,
    split_host_and_port,
)
from ..utils.validate import PoolValidationError, PoolValidationIssue, validate_pool_inplace

router = APIRouter()

_FULL_BACKUP_JOBS: Dict[str, Dict[str, Any]] = {}
_FULL_BACKUP_LOCK = threading.Lock()
_FULL_BACKUP_TTL_SEC = 1800

_FULL_RESTORE_JOBS: Dict[str, Dict[str, Any]] = {}
_FULL_RESTORE_LOCK = threading.Lock()
_FULL_RESTORE_TTL_SEC = 1800
_RESTORE_UPLOAD_CHUNK_SIZE = 1024 * 1024


def _parse_restore_upload_max_bytes() -> int:
    raw_b = os.getenv("REALM_FULL_RESTORE_MAX_BYTES")
    raw_mb = os.getenv("REALM_FULL_RESTORE_MAX_MB")
    try:
        if raw_b:
            return max(1, int(float(str(raw_b).strip())))
    except Exception:
        pass
    try:
        if raw_mb:
            return max(1, int(float(str(raw_mb).strip()))) * 1024 * 1024
    except Exception:
        pass
    # default 512MB
    return 512 * 1024 * 1024


def _format_bytes(num: int) -> str:
    n = float(max(0, int(num)))
    if n < 1024:
        return f"{int(n)} B"
    for unit in ("KB", "MB", "GB", "TB"):
        n /= 1024.0
        if n < 1024:
            return f"{n:.1f} {unit}"
    return f"{n:.1f} PB"


_FULL_RESTORE_MAX_BYTES = _parse_restore_upload_max_bytes()


def _env_flag(name: str, default: bool) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return bool(default)
    return str(raw).strip().lower() not in ("0", "false", "off", "no")


def _env_float(name: str, default: float, lo: float, hi: float) -> float:
    try:
        v = float(str(os.getenv(name, str(default))).strip() or default)
    except Exception:
        v = float(default)
    if v < lo:
        v = lo
    if v > hi:
        v = hi
    return float(v)


def _env_int(name: str, default: int, lo: int, hi: int) -> int:
    try:
        v = int(float(str(os.getenv(name, str(default))).strip() or default))
    except Exception:
        v = int(default)
    if v < lo:
        v = lo
    if v > hi:
        v = hi
    return int(v)


_SAVE_PRECHECK_ENABLED = _env_flag("REALM_SAVE_PRECHECK_ENABLED", True)
_SAVE_PRECHECK_HTTP_TIMEOUT = _env_float("REALM_SAVE_PRECHECK_HTTP_TIMEOUT", 4.5, 2.0, 20.0)
_SAVE_PRECHECK_PROBE_TIMEOUT = _env_float("REALM_SAVE_PRECHECK_PROBE_TIMEOUT", 1.2, 0.2, 6.0)
_SAVE_PRECHECK_MAX_ISSUES = _env_int("REALM_SAVE_PRECHECK_MAX_ISSUES", 24, 5, 120)
_POOL_JOB_TTL_SEC = _env_int("REALM_POOL_JOB_TTL_SEC", 1800, 120, 7 * 24 * 3600)
_POOL_JOB_MAX_ATTEMPTS = _env_int("REALM_POOL_JOB_MAX_ATTEMPTS", 3, 1, 10)
_POOL_JOB_RETRY_BASE_SEC = _env_float("REALM_POOL_JOB_RETRY_BASE_SEC", 1.2, 0.2, 30.0)
_POOL_JOB_RETRY_MAX_SEC = _env_float("REALM_POOL_JOB_RETRY_MAX_SEC", 8.0, 1.0, 120.0)
_POOL_JOB_ACK_TIMEOUT_SEC = _env_float("REALM_POOL_JOB_ACK_TIMEOUT_SEC", 45.0, 5.0, 600.0)
_POOL_JOB_ACK_POLL_SEC = _env_float("REALM_POOL_JOB_ACK_POLL_SEC", 1.0, 0.2, 10.0)
_POOL_JOB_REQUIRE_ACK = _env_flag("REALM_POOL_JOB_REQUIRE_ACK", True)

_POOL_JOBS: Dict[str, Dict[str, Any]] = {}
_POOL_JOBS_LOCK = threading.Lock()
_POOL_JOB_EXEC_LOCK = asyncio.Lock()


def _pool_job_now() -> float:
    return float(time.time())


def _prune_pool_jobs_locked(now_ts: Optional[float] = None) -> None:
    now = float(now_ts if now_ts is not None else _pool_job_now())
    stale_ids: List[str] = []
    for jid, job in _POOL_JOBS.items():
        st = str(job.get("status") or "")
        updated = float(job.get("updated_at") or 0.0)
        if st in ("success", "error") and (now - updated) > float(_POOL_JOB_TTL_SEC):
            stale_ids.append(jid)
    for jid in stale_ids:
        _POOL_JOBS.pop(jid, None)


def _pool_job_view(job: Dict[str, Any], include_result: bool = True) -> Dict[str, Any]:
    out: Dict[str, Any] = {
        "job_id": str(job.get("job_id") or ""),
        "node_id": int(job.get("node_id") or 0),
        "kind": str(job.get("kind") or ""),
        "status": str(job.get("status") or ""),
        "created_at": float(job.get("created_at") or 0.0),
        "updated_at": float(job.get("updated_at") or 0.0),
        "attempts": int(job.get("attempts") or 0),
        "max_attempts": int(job.get("max_attempts") or 0),
        "next_retry_at": float(job.get("next_retry_at") or 0.0),
        "status_code": int(job.get("status_code") or 0),
        "error": str(job.get("error") or ""),
        "meta": dict(job.get("meta") or {}),
    }
    if include_result:
        res = job.get("result")
        out["result"] = dict(res) if isinstance(res, dict) else {}
    return out


def _pool_job_parse_json_response(resp: JSONResponse) -> Dict[str, Any]:
    try:
        body = resp.body
        if isinstance(body, (bytes, bytearray)):
            txt = body.decode("utf-8", errors="ignore")
        else:
            txt = str(body or "")
        data = json.loads(txt) if txt else {}
        return data if isinstance(data, dict) else {"ok": False, "error": str(data)}
    except Exception:
        return {"ok": False, "error": "unknown_response"}


def _pool_job_set(job_id: str, **kwargs: Any) -> None:
    now = _pool_job_now()
    with _POOL_JOBS_LOCK:
        job = _POOL_JOBS.get(job_id)
        if not isinstance(job, dict):
            return
        for k, v in kwargs.items():
            job[k] = v
        job["updated_at"] = now


def _pool_job_get(job_id: str) -> Optional[Dict[str, Any]]:
    with _POOL_JOBS_LOCK:
        _prune_pool_jobs_locked()
        job = _POOL_JOBS.get(job_id)
        if not isinstance(job, dict):
            return None
        return dict(job)


def _pool_job_error_text(data: Any, fallback: str = "任务失败") -> str:
    if isinstance(data, dict):
        msg = str(data.get("error") or "").strip()
        if msg:
            return msg
    txt = str(data or "").strip()
    return txt or fallback


def _pool_job_is_retriable(status_code: int, data: Dict[str, Any]) -> bool:
    if status_code <= 0:
        return True
    if status_code >= 500:
        return True
    if status_code == 409:
        if isinstance(data, dict):
            code = str(data.get("code") or "").strip().lower()
            err = str(data.get("error") or "").strip().lower()
            if code == "stale_index" or "索引已过期" in err:
                return False
        return True
    if status_code in (408, 425, 429):
        return True
    if isinstance(data, dict):
        err = str(data.get("error") or "").lower()
        if "超时" in err or "timeout" in err:
            return True
        if "预检失败" in err or "precheck" in err:
            return True
    return False


def _json_deep_clone(value: Any) -> Any:
    try:
        return json.loads(json.dumps(value))
    except Exception:
        if isinstance(value, dict):
            return dict(value)
        if isinstance(value, list):
            return list(value)
        return value


def _normalize_pool_dict(pool: Any) -> Dict[str, Any]:
    out = pool if isinstance(pool, dict) else {}
    if not isinstance(out.get("endpoints"), list):
        out["endpoints"] = []
    return out


def _resolve_rule_user(user_or_name: Any) -> Any:
    if isinstance(user_or_name, str):
        try:
            u = get_user_by_username(user_or_name)
            if u is not None:
                return u
        except Exception:
            return user_or_name
    return user_or_name


def _rule_key_for_endpoint(endpoint: Dict[str, Any]) -> str:
    ex = endpoint.get("extra_config")
    if not isinstance(ex, dict):
        ex = {}
    sid = str(ex.get("sync_id") or "").strip()
    if sid and (ex.get("sync_role") or ex.get("sync_peer_node_id") or ex.get("sync_lock")):
        return f"wss:{sid}"
    if sid and (ex.get("intranet_role") or ex.get("intranet_peer_node_id") or ex.get("intranet_lock")):
        return f"intranet:{sid}"
    listen = str(endpoint.get("listen") or "").strip()
    proto = str(endpoint.get("protocol") or "tcp+udp").strip().lower()
    return f"tcp:{listen}|{proto}"


def _visible_endpoint_tuples(user: str, pool: Dict[str, Any]) -> List[Tuple[int, Dict[str, Any]]]:
    eps = pool.get("endpoints") if isinstance(pool.get("endpoints"), list) else []
    out: List[Tuple[int, Dict[str, Any]]] = []
    user_ref = _resolve_rule_user(user)
    scoped = is_rule_owner_scoped(user_ref)
    for idx, ep in enumerate(eps):
        if not isinstance(ep, dict):
            continue
        if scoped and (not can_access_rule_endpoint(user_ref, ep)):
            continue
        out.append((idx, ep))
    return out


def _filter_pool_for_user(user: str, pool: Any) -> Dict[str, Any]:
    user_ref = _resolve_rule_user(user)
    full = _normalize_pool_dict(_json_deep_clone(pool if isinstance(pool, dict) else {}))
    if not is_rule_owner_scoped(user_ref):
        return full
    full["endpoints"] = [ep for _idx, ep in _visible_endpoint_tuples(user_ref, full)]
    return full


def _merge_submitted_pool_for_user(user: str, existing_pool: Dict[str, Any], submitted_pool: Dict[str, Any]) -> Dict[str, Any]:
    user_ref = _resolve_rule_user(user)
    existing = _normalize_pool_dict(_json_deep_clone(existing_pool if isinstance(existing_pool, dict) else {}))
    submitted = _normalize_pool_dict(_json_deep_clone(submitted_pool if isinstance(submitted_pool, dict) else {}))
    if not is_rule_owner_scoped(user_ref):
        return submitted

    posted_eps_raw = submitted.get("endpoints") if isinstance(submitted.get("endpoints"), list) else []
    posted_eps: List[Dict[str, Any]] = []
    for ep in posted_eps_raw:
        if not isinstance(ep, dict):
            continue
        stamp_endpoint_owner(ep, user_ref)
        posted_eps.append(ep)

    merged_eps: List[Dict[str, Any]] = []
    take = 0
    existing_eps = existing.get("endpoints") if isinstance(existing.get("endpoints"), list) else []
    for old_ep in existing_eps:
        if not isinstance(old_ep, dict):
            continue
        if can_access_rule_endpoint(user_ref, old_ep):
            if take < len(posted_eps):
                merged_eps.append(posted_eps[take])
                take += 1
            continue
        merged_eps.append(old_ep)

    while take < len(posted_eps):
        merged_eps.append(posted_eps[take])
        take += 1

    if not isinstance(submitted, dict):
        submitted = {}
    for k, v in existing.items():
        if k == "endpoints":
            continue
        if k not in submitted:
            submitted[k] = v
    submitted["endpoints"] = merged_eps
    return submitted


def _filter_stats_payload_for_user(user: str, pool: Dict[str, Any], stats_payload: Dict[str, Any]) -> Dict[str, Any]:
    user_ref = _resolve_rule_user(user)
    if not isinstance(stats_payload, dict):
        return {}
    data = dict(stats_payload)
    rules = data.get("rules")
    if not isinstance(rules, list):
        data["rules"] = []
        return data
    if not is_rule_owner_scoped(user_ref):
        return data

    visible = _visible_endpoint_tuples(user_ref, pool)
    idx_map: Dict[int, int] = {int(actual_idx): int(v_idx) for v_idx, (actual_idx, _ep) in enumerate(visible)}
    listen_map: Dict[str, int] = {}
    rule_keys: set[str] = set()
    for v_idx, (_actual_idx, ep) in enumerate(visible):
        listen = str(ep.get("listen") or "").strip()
        if listen and listen not in listen_map:
            listen_map[listen] = int(v_idx)
        try:
            rule_keys.add(_rule_key_for_endpoint(ep))
        except Exception:
            continue

    out_rules: List[Dict[str, Any]] = []
    for r in rules:
        if not isinstance(r, dict):
            continue
        nr = dict(r)
        keep = False
        idx_raw = r.get("idx")
        idx_val: Optional[int] = None
        try:
            idx_val = int(idx_raw)
        except Exception:
            idx_val = None
        if idx_val is not None and idx_val in idx_map:
            nr["idx"] = int(idx_map[idx_val])
            keep = True
        if not keep:
            listen = str(r.get("listen") or "").strip()
            if listen and listen in listen_map:
                nr["idx"] = int(listen_map[listen])
                keep = True
        if not keep:
            rkey = str(r.get("key") or r.get("rule_key") or "").strip()
            if rkey and rkey in rule_keys:
                keep = True
        if keep:
            out_rules.append(nr)
    data["rules"] = out_rules
    return data


def _visible_rule_history_keys(user: str, pool: Dict[str, Any]) -> set[str]:
    user_ref = _resolve_rule_user(user)
    out: set[str] = set()
    for _idx, ep in _visible_endpoint_tuples(user_ref, pool):
        if not isinstance(ep, dict):
            continue
        listen = str(ep.get("listen") or "").strip()
        if listen:
            out.add(listen)
        try:
            out.add(_rule_key_for_endpoint(ep))
        except Exception:
            continue
    return out


def _pool_like_response_with_filter(user: str, payload: Dict[str, Any]) -> Dict[str, Any]:
    if not isinstance(payload, dict):
        return {}
    if not isinstance(payload.get("pool"), dict):
        return dict(payload)
    out = dict(payload)
    out["pool"] = _filter_pool_for_user(user, payload.get("pool"))
    return out


async def _pool_job_wait_ack(node_id: int, desired_ver: int) -> Tuple[bool, str]:
    need = int(desired_ver or 0)
    if need <= 0:
        return True, ""
    if not _POOL_JOB_REQUIRE_ACK:
        return True, ""
    deadline = _pool_job_now() + float(_POOL_JOB_ACK_TIMEOUT_SEC)
    last_ack = 0
    last_seen = ""
    report_fresh = False
    while _pool_job_now() < deadline:
        n = get_node(int(node_id))
        if not n:
            return False, "节点不存在"
        try:
            last_ack = int(n.get("agent_ack_version") or 0)
        except Exception:
            last_ack = 0
        last_seen = str(n.get("last_seen_at") or "")
        try:
            report_fresh = bool(is_report_fresh(n, max_age_sec=max(90, int(_POOL_JOB_ACK_TIMEOUT_SEC) * 2)))
        except Exception:
            report_fresh = False
        if last_ack >= need:
            return True, ""
        await asyncio.sleep(max(0.2, float(_POOL_JOB_ACK_POLL_SEC)))
    if not report_fresh:
        return (
            False,
            f"节点未确认配置版本（ack={last_ack}, desired={need}，last_seen={last_seen or 'never'}）。"
            f"请检查 Agent 上报链路（REALM_PANEL_URL/REALM_AGENT_ID/网络连通）。"
        )
    return False, f"节点未确认配置版本（ack={last_ack}, desired={need}）"


async def _pool_job_invoke(kind: str, node_id: int, payload: Dict[str, Any], user: str) -> Tuple[int, Dict[str, Any]]:
    if kind == "pool_save":
        payload2 = dict(payload or {})
        payload2["_async_job"] = True
        ret = await api_pool_set(None, int(node_id), payload2, user=user)
    elif kind == "rule_delete":
        ret = await api_rule_delete(int(node_id), payload, user=user)
    else:
        return 400, {"ok": False, "error": f"unsupported_job_kind:{kind}"}

    if isinstance(ret, JSONResponse):
        status = int(ret.status_code or 500)
        data = _pool_job_parse_json_response(ret)
        if "ok" not in data:
            data["ok"] = status < 400
        return status, data

    if isinstance(ret, dict):
        ok = bool(ret.get("ok", True))
        return (200 if ok else 500), ret

    return 500, {"ok": False, "error": "unknown_response_type"}


async def _run_pool_job(job_id: str) -> None:
    snap = _pool_job_get(job_id)
    if not isinstance(snap, dict):
        return
    kind = str(snap.get("kind") or "")
    node_id = int(snap.get("node_id") or 0)
    payload = snap.get("_payload") if isinstance(snap.get("_payload"), dict) else {}
    user = str(snap.get("_user") or "").strip() or "system"
    max_attempts = max(1, int(snap.get("max_attempts") or _POOL_JOB_MAX_ATTEMPTS))

    for attempt in range(1, max_attempts + 1):
        _pool_job_set(job_id, status="running", attempts=int(attempt), next_retry_at=0.0, error="", status_code=0)

        status_code = 0
        data: Dict[str, Any] = {}
        try:
            async with _POOL_JOB_EXEC_LOCK:
                status_code, data = await _pool_job_invoke(kind, node_id, payload, user)
        except Exception as exc:
            status_code = 599
            data = {"ok": False, "error": f"任务执行异常：{exc}"}

        ok = bool(isinstance(data, dict) and data.get("ok") is True and status_code < 400)
        if ok:
            desired_ver = 0
            try:
                desired_ver = int(data.get("desired_version") or 0)
            except Exception:
                desired_ver = 0
            if desired_ver > 0:
                ack_ok, ack_err = await _pool_job_wait_ack(node_id, desired_ver)
                if not ack_ok:
                    status_code = 504
                    data = {"ok": False, "error": ack_err, "desired_version": desired_ver}
                    ok = False
            if ok:
                _pool_job_set(
                    job_id,
                    status="success",
                    status_code=int(status_code),
                    result=data,
                    error="",
                    next_retry_at=0.0,
                )
                return

        err = _pool_job_error_text(data, "任务失败")
        retriable = _pool_job_is_retriable(int(status_code), data if isinstance(data, dict) else {})
        if attempt < max_attempts and retriable:
            delay = min(float(_POOL_JOB_RETRY_MAX_SEC), float(_POOL_JOB_RETRY_BASE_SEC) * (2 ** (attempt - 1)))
            _pool_job_set(
                job_id,
                status="retrying",
                status_code=int(status_code),
                result=data if isinstance(data, dict) else {},
                error=err,
                next_retry_at=float(_pool_job_now() + delay),
            )
            await asyncio.sleep(max(0.2, delay))
            continue

        _pool_job_set(
            job_id,
            status="error",
            status_code=int(status_code),
            result=data if isinstance(data, dict) else {},
            error=err,
            next_retry_at=0.0,
        )
        return


def _enqueue_pool_job(node_id: int, kind: str, payload: Dict[str, Any], user: str, meta: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    now = _pool_job_now()
    job_id = uuid.uuid4().hex
    job = {
        "job_id": job_id,
        "node_id": int(node_id),
        "kind": str(kind),
        "status": "queued",
        "created_at": now,
        "updated_at": now,
        "attempts": 0,
        "max_attempts": int(_POOL_JOB_MAX_ATTEMPTS),
        "next_retry_at": 0.0,
        "status_code": 0,
        "error": "",
        "result": {},
        "meta": dict(meta or {}),
        "_payload": dict(payload or {}),
        "_user": str(user or "system"),
    }
    with _POOL_JOBS_LOCK:
        _prune_pool_jobs_locked(now)
        _POOL_JOBS[job_id] = job
    asyncio.create_task(_run_pool_job(job_id))
    return _pool_job_view(job, include_result=False)


async def _read_full_restore_upload(file: UploadFile) -> tuple[Optional[bytes], Optional[str], int]:
    try:
        await file.seek(0)
    except Exception:
        pass

    total = 0
    buf = bytearray()
    try:
        while True:
            chunk = await file.read(_RESTORE_UPLOAD_CHUNK_SIZE)
            if not chunk:
                break
            total += len(chunk)
            if total > _FULL_RESTORE_MAX_BYTES:
                return (
                    None,
                    f"备份包过大（当前限制 {_format_bytes(_FULL_RESTORE_MAX_BYTES)}）",
                    413,
                )
            buf.extend(chunk)
    except asyncio.CancelledError:
        raise
    except Exception as exc:
        return None, f"读取文件失败：{exc}", 400

    raw = bytes(buf)
    if not raw or raw[:2] != b"PK":
        return None, "请上传 nexus-backup-*.zip（兼容旧版备份包）", 400
    return raw, None, 200


def _backup_steps_template() -> List[Dict[str, Any]]:
    return [
        {"key": "scan", "label": "扫描数据", "status": "pending", "detail": ""},
        {"key": "rules", "label": "规则快照", "status": "pending", "detail": ""},
        {"key": "sites", "label": "网站配置", "status": "pending", "detail": ""},
        {"key": "site_files", "label": "网站文件", "status": "pending", "detail": ""},
        {"key": "certs", "label": "证书信息", "status": "pending", "detail": ""},
        {"key": "netmon", "label": "网络波动配置", "status": "pending", "detail": ""},
        {"key": "package", "label": "打包压缩", "status": "pending", "detail": ""},
    ]


def _prune_full_backup_jobs() -> None:
    now = time.time()
    with _FULL_BACKUP_LOCK:
        stale_ids: List[str] = []
        for jid, job in _FULL_BACKUP_JOBS.items():
            st = str(job.get("status") or "")
            updated_at = float(job.get("updated_at") or 0.0)
            if st in ("done", "failed") and (now - updated_at) > _FULL_BACKUP_TTL_SEC:
                stale_ids.append(jid)
        for jid in stale_ids:
            _FULL_BACKUP_JOBS.pop(jid, None)


def _backup_job_snapshot(job_id: str) -> Optional[Dict[str, Any]]:
    with _FULL_BACKUP_LOCK:
        job = _FULL_BACKUP_JOBS.get(job_id)
        if not isinstance(job, dict):
            return None
        return {
            "job_id": str(job_id),
            "status": str(job.get("status") or "unknown"),
            "progress": int(job.get("progress") or 0),
            "stage": str(job.get("stage") or ""),
            "error": str(job.get("error") or ""),
            "created_at": float(job.get("created_at") or 0.0),
            "updated_at": float(job.get("updated_at") or 0.0),
            "size_bytes": int(job.get("size_bytes") or 0),
            "filename": str(job.get("filename") or ""),
            "steps": list(job.get("steps") or []),
            "counts": dict(job.get("counts") or {}),
            "can_download": bool(job.get("status") == "done" and bool(job.get("content"))),
        }


def _touch_backup_job(
    job_id: str,
    *,
    status: Optional[str] = None,
    progress: Optional[int] = None,
    stage: Optional[str] = None,
    error: Optional[str] = None,
    counts: Optional[Dict[str, Any]] = None,
    step_key: Optional[str] = None,
    step_status: Optional[str] = None,
    step_detail: Optional[str] = None,
    filename: Optional[str] = None,
    size_bytes: Optional[int] = None,
    content: Optional[bytes] = None,
) -> None:
    now = time.time()
    with _FULL_BACKUP_LOCK:
        job = _FULL_BACKUP_JOBS.get(job_id)
        if not isinstance(job, dict):
            return
        if status is not None:
            job["status"] = str(status)
        if progress is not None:
            p = max(0, min(100, int(progress)))
            job["progress"] = p
        if stage is not None:
            job["stage"] = str(stage)
        if error is not None:
            job["error"] = str(error)
        if counts is not None:
            job["counts"] = dict(counts)
        if filename is not None:
            job["filename"] = str(filename)
        if size_bytes is not None:
            job["size_bytes"] = int(size_bytes)
        if content is not None:
            job["content"] = bytes(content)
        if step_key:
            for s in (job.get("steps") or []):
                if str(s.get("key") or "") == str(step_key):
                    if step_status is not None:
                        s["status"] = str(step_status)
                    if step_detail is not None:
                        s["detail"] = str(step_detail)
                    break
        job["updated_at"] = now


async def _emit_backup_progress(callback: Any, payload: Dict[str, Any]) -> None:
    if callback is None:
        return
    try:
        ret = callback(payload)
        if inspect.isawaitable(ret):
            await ret
    except Exception:
        pass


def _clean_site_rel_path(raw: Any) -> str:
    txt = str(raw or "").replace("\\", "/").strip().strip("/")
    if not txt:
        return ""
    parts: List[str] = []
    for seg in txt.split("/"):
        s = str(seg or "").strip()
        if not s or s == ".":
            continue
        if s == "..":
            return ""
        parts.append(s)
    return "/".join(parts)


def _site_pkg_dir_name(site: Dict[str, Any]) -> str:
    sid = int(site.get("source_id") or site.get("id") or 0)
    domains = site.get("domains") if isinstance(site.get("domains"), list) else []
    hint = ""
    if domains:
        hint = str(domains[0] or "").strip()
    if not hint:
        hint = str(site.get("name") or f"site-{sid}").strip()
    safe = safe_filename_part(hint)[:64] or "site"
    return f"site-{sid}-{safe}"


async def _collect_site_file_index(site: Dict[str, Any], node: Dict[str, Any]) -> Dict[str, Any]:
    root = str(site.get("root_path") or "").strip()
    out: Dict[str, Any] = {
        "source_site_id": int(site.get("source_id") or site.get("id") or 0),
        "source_node_id": int(site.get("node_source_id") or site.get("node_id") or 0),
        "node_base_url": str(site.get("node_base_url") or node.get("base_url") or ""),
        "root_path": root,
        "package_dir": _site_pkg_dir_name(site),
        "files": [],
        "file_count": 0,
        "total_bytes": 0,
        "errors": [],
    }
    if not root:
        out["errors"].append("站点 root_path 为空，跳过文件备份")
        return out

    root_base = str(node.get("website_root_base") or "").strip()
    queue: List[str] = [""]
    seen_dirs = set([""])
    files: List[Dict[str, Any]] = []

    while queue:
        rel = queue.pop(0)
        q = urlencode({"root": root, "path": rel, "root_base": root_base})
        try:
            data = await agent_get(
                node["base_url"],
                node["api_key"],
                f"/api/v1/website/files/list?{q}",
                node_verify_tls(node),
                timeout=20,
            )
        except Exception as exc:
            out["errors"].append(f"目录读取失败 [{rel or '/'}]：{exc}")
            continue

        if not data.get("ok", True):
            out["errors"].append(f"目录读取失败 [{rel or '/'}]：{data.get('error') or 'unknown'}")
            continue

        for it in (data.get("items") or []):
            if not isinstance(it, dict):
                continue
            p = _clean_site_rel_path(it.get("path"))
            if not p:
                continue
            if bool(it.get("is_dir")):
                if p not in seen_dirs:
                    seen_dirs.add(p)
                    queue.append(p)
                continue
            try:
                size_i = max(0, int(it.get("size") or 0))
            except Exception:
                size_i = 0
            files.append({"path": p, "size": size_i})

    # Deduplicate by path (keep first)
    seen_file_paths = set()
    cleaned: List[Dict[str, Any]] = []
    total_bytes = 0
    for f in sorted(files, key=lambda x: str(x.get("path") or "")):
        p = str(f.get("path") or "")
        if not p or p in seen_file_paths:
            continue
        seen_file_paths.add(p)
        sz = max(0, int(f.get("size") or 0))
        total_bytes += sz
        cleaned.append({"path": p, "size": sz})

    out["files"] = cleaned
    out["file_count"] = len(cleaned)
    out["total_bytes"] = int(total_bytes)
    return out


async def _build_full_backup_bundle(
    request: Request,
    progress_callback: Any = None,
    nodes_override: Optional[List[Dict[str, Any]]] = None,
) -> Dict[str, Any]:
    await _emit_backup_progress(
        progress_callback,
        {"progress": 4, "stage": "扫描数据", "step_key": "scan", "step_status": "running", "step_detail": "读取节点与面板配置"},
    )

    nodes = list(nodes_override) if isinstance(nodes_override, list) else list_nodes()
    group_orders = get_group_orders()
    node_map = {int(n.get("id") or 0): n for n in nodes}
    sites = list_sites()
    certs = list_certificates()
    monitors = list_netmon_monitors()
    ts = datetime.now().strftime("%Y%m%d-%H%M%S")

    fixed_zip_files = 7  # backup_meta + nodes + sites + certs + site_files_manifest + netmon + README
    await _emit_backup_progress(
        progress_callback,
        {
            "progress": 12,
            "stage": "扫描完成",
            "step_key": "scan",
            "step_status": "done",
            "step_detail": f"节点 {len(nodes)} · 站点 {len(sites)} · 证书 {len(certs)} · 监控 {len(monitors)}",
            "counts": {
                "nodes": len(nodes),
                "rules": len(nodes),
                "sites": len(sites),
                "site_files": 0,
                "certificates": len(certs),
                "netmon_monitors": len(monitors),
                "files": fixed_zip_files + len(nodes),
            },
        },
    )

    # Build per-node rules snapshot with progress
    rules_entries: List[tuple[str, Dict[str, Any]]] = []
    total_nodes = len(nodes)
    if total_nodes:
        await _emit_backup_progress(
            progress_callback,
            {
                "progress": 14,
                "stage": "规则快照",
                "step_key": "rules",
                "step_status": "running",
                "step_detail": f"0/{total_nodes}",
            },
        )

        sem = asyncio.Semaphore(12)

        async def build_one(n: Dict[str, Any]) -> tuple[str, Dict[str, Any]]:
            node_id = int(n.get("id") or 0)
            data = await get_pool_for_backup(n)
            data.setdefault("node", {"id": node_id, "name": n.get("name"), "base_url": n.get("base_url")})
            safe = safe_filename_part(n.get("name") or f"node-{node_id}")
            path = f"rules/realm-rules-{safe}-id{node_id}.json"
            return path, data

        async def guarded(n: Dict[str, Any]) -> tuple[str, Dict[str, Any]]:
            async with sem:
                return await build_one(n)

        tasks = [asyncio.create_task(guarded(n)) for n in nodes]
        done = 0
        for fut in asyncio.as_completed(tasks):
            r = await fut
            rules_entries.append(r)
            done += 1
            pct = 14 + int((done / max(1, total_nodes)) * 38)
            await _emit_backup_progress(
                progress_callback,
                {
                    "progress": pct,
                    "stage": "规则快照",
                    "step_key": "rules",
                    "step_status": "running",
                    "step_detail": f"{done}/{total_nodes}",
                },
            )

    await _emit_backup_progress(
        progress_callback,
        {
            "progress": 52,
            "stage": "规则快照完成",
            "step_key": "rules",
            "step_status": "done",
            "step_detail": f"{len(rules_entries)} 个规则文件",
        },
    )

    # Base payloads
    await _emit_backup_progress(
        progress_callback,
        {"progress": 60, "stage": "整理网站配置", "step_key": "sites", "step_status": "running", "step_detail": f"{len(sites)} 个站点"},
    )
    nodes_payload = {
        "kind": "realm_full_backup",
        "created_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "panel_public_url": panel_public_base_url(request),
        "group_orders": [
            {"group_name": k, "sort_order": int(v)}
            for k, v in sorted(group_orders.items(), key=lambda kv: (kv[1], kv[0]))
        ],
        "nodes": [
            {
                "source_id": int(n.get("id") or 0),
                "name": n.get("name"),
                "base_url": n.get("base_url"),
                "api_key": n.get("api_key"),
                "verify_tls": bool(n.get("verify_tls", 0)),
                "group_name": n.get("group_name") or "默认分组",
                "role": n.get("role") or "normal",
                "website_root_base": n.get("website_root_base") or "",
            }
            for n in nodes
        ],
    }
    sites_payload = {
        "kind": "realm_sites_backup",
        "created_at": nodes_payload["created_at"],
        "sites": [
            {
                "source_id": int(s.get("id") or 0),
                "node_source_id": int(s.get("node_id") or 0),
                "node_base_url": str((node_map.get(int(s.get("node_id") or 0)) or {}).get("base_url") or ""),
                "name": str(s.get("name") or ""),
                "domains": [str(x).strip() for x in (s.get("domains") or []) if str(x).strip()],
                "root_path": str(s.get("root_path") or ""),
                "proxy_target": str(s.get("proxy_target") or ""),
                "type": str(s.get("type") or "static"),
                "web_server": str(s.get("web_server") or "nginx"),
                "nginx_tpl": str(s.get("nginx_tpl") or ""),
                "https_redirect": bool(s.get("https_redirect") or False),
                "gzip_enabled": True if s.get("gzip_enabled") is None else bool(s.get("gzip_enabled")),
                "status": str(s.get("status") or "running"),
                "health_status": str(s.get("health_status") or ""),
                "health_code": int(s.get("health_code") or 0),
                "health_latency_ms": int(s.get("health_latency_ms") or 0),
                "health_error": str(s.get("health_error") or ""),
                "health_checked_at": s.get("health_checked_at"),
                "created_at": s.get("created_at"),
                "updated_at": s.get("updated_at"),
            }
            for s in sites
        ],
    }
    await _emit_backup_progress(
        progress_callback,
        {"progress": 66, "stage": "网站配置完成", "step_key": "sites", "step_status": "done", "step_detail": f"{len(sites_payload['sites'])} 条"},
    )

    # Build website file index (list tree first; content will be pulled in package stage)
    site_files_manifest: Dict[str, Any] = {
        "kind": "realm_site_files_backup",
        "created_at": nodes_payload["created_at"],
        "sites": [],
        "summary": {"sites": 0, "files_total": 0, "files_ok": 0, "files_failed": 0, "bytes_total": 0},
    }
    site_file_total = 0
    site_file_bytes = 0
    site_file_failed = 0
    total_sites = len(sites_payload["sites"])
    await _emit_backup_progress(
        progress_callback,
        {"progress": 68, "stage": "扫描网站文件", "step_key": "site_files", "step_status": "running", "step_detail": f"0/{total_sites}"},
    )
    if total_sites:
        for i, s in enumerate(sites_payload["sites"], start=1):
            sid = int(s.get("source_id") or 0)
            nid = int(s.get("node_source_id") or 0)
            node = node_map.get(nid)
            if not node:
                entry = {
                    "source_site_id": sid,
                    "source_node_id": nid,
                    "node_base_url": str(s.get("node_base_url") or ""),
                    "root_path": str(s.get("root_path") or ""),
                    "package_dir": _site_pkg_dir_name(s),
                    "files": [],
                    "file_count": 0,
                    "total_bytes": 0,
                    "errors": ["未找到站点节点，跳过文件备份"],
                }
            else:
                entry = await _collect_site_file_index(s, node)

            pkg_dir = str(entry.get("package_dir") or _site_pkg_dir_name(s))
            files_idx = entry.get("files") if isinstance(entry.get("files"), list) else []
            cleaned_files = []
            for f in files_idx:
                if not isinstance(f, dict):
                    continue
                rel_path = _clean_site_rel_path(f.get("path"))
                if not rel_path:
                    continue
                size_i = max(0, int(f.get("size") or 0))
                cleaned_files.append(
                    {
                        "path": rel_path,
                        "size": size_i,
                        "zip_path": f"websites/files/{pkg_dir}/{rel_path}",
                    }
                )
            entry["files"] = cleaned_files
            entry["file_count"] = len(cleaned_files)
            entry["total_bytes"] = int(sum(int(x.get("size") or 0) for x in cleaned_files))

            site_file_total += int(entry["file_count"])
            site_file_bytes += int(entry["total_bytes"])
            site_file_failed += len(entry.get("errors") or [])
            site_files_manifest["sites"].append(entry)

            p = 68 + int((i / max(1, total_sites)) * 10)
            await _emit_backup_progress(
                progress_callback,
                {
                    "progress": p,
                    "stage": "扫描网站文件",
                    "step_key": "site_files",
                    "step_status": "running",
                    "step_detail": f"{i}/{total_sites} · 已发现 {site_file_total} 个文件",
                    "counts": {
                        "nodes": len(nodes),
                        "rules": len(rules_entries),
                        "sites": len(sites_payload["sites"]),
                        "site_files": site_file_total,
                        "certificates": len(certs),
                        "netmon_monitors": len(monitors),
                        "files": fixed_zip_files + len(rules_entries) + site_file_total,
                    },
                },
            )
    site_files_manifest["summary"] = {
        "sites": len(site_files_manifest["sites"]),
        "files_total": site_file_total,
        "files_ok": 0,
        "files_failed": 0,
        "bytes_total": site_file_bytes,
    }
    await _emit_backup_progress(
        progress_callback,
        {
            "progress": 78,
            "stage": "网站文件扫描完成",
            "step_key": "site_files",
            "step_status": "done",
            "step_detail": f"{site_file_total} 个文件",
            "counts": {
                "nodes": len(nodes),
                "rules": len(rules_entries),
                "sites": len(sites_payload["sites"]),
                "site_files": site_file_total,
                "certificates": len(certs),
                "netmon_monitors": len(monitors),
                "files": fixed_zip_files + len(rules_entries) + site_file_total,
            },
        },
    )

    await _emit_backup_progress(
        progress_callback,
        {"progress": 80, "stage": "整理证书信息", "step_key": "certs", "step_status": "running", "step_detail": f"{len(certs)} 条证书"},
    )
    certs_payload = {
        "kind": "realm_certificates_backup",
        "created_at": nodes_payload["created_at"],
        "certificates": [
            {
                "source_id": int(c.get("id") or 0),
                "node_source_id": int(c.get("node_id") or 0),
                "node_base_url": str((node_map.get(int(c.get("node_id") or 0)) or {}).get("base_url") or ""),
                "site_source_id": int(c.get("site_id") or 0) if c.get("site_id") is not None else None,
                "domains": [str(x).strip() for x in (c.get("domains") or []) if str(x).strip()],
                "issuer": str(c.get("issuer") or "letsencrypt"),
                "challenge": str(c.get("challenge") or "http-01"),
                "status": str(c.get("status") or "pending"),
                "not_before": c.get("not_before"),
                "not_after": c.get("not_after"),
                "renew_at": c.get("renew_at"),
                "last_error": str(c.get("last_error") or ""),
                "created_at": c.get("created_at"),
                "updated_at": c.get("updated_at"),
            }
            for c in certs
        ],
    }
    await _emit_backup_progress(
        progress_callback,
        {"progress": 84, "stage": "证书信息完成", "step_key": "certs", "step_status": "done", "step_detail": f"{len(certs_payload['certificates'])} 条"},
    )

    await _emit_backup_progress(
        progress_callback,
        {"progress": 86, "stage": "整理网络波动配置", "step_key": "netmon", "step_status": "running", "step_detail": f"{len(monitors)} 个监控"},
    )
    monitors_payload = {
        "kind": "realm_netmon_backup",
        "created_at": nodes_payload["created_at"],
        "monitors": [
            {
                "source_id": int(m.get("id") or 0),
                "target": str(m.get("target") or ""),
                "mode": str(m.get("mode") or "ping"),
                "tcp_port": int(m.get("tcp_port") or 443),
                "interval_sec": int(m.get("interval_sec") or 5),
                "warn_ms": int(m.get("warn_ms") or 0),
                "crit_ms": int(m.get("crit_ms") or 0),
                "enabled": bool(m.get("enabled") or 0),
                "node_source_ids": [int(x) for x in (m.get("node_ids") or []) if int(x) > 0],
                "node_base_urls": [
                    str((node_map.get(int(x) or 0) or {}).get("base_url") or "")
                    for x in (m.get("node_ids") or [])
                    if int(x) > 0
                ],
                "last_run_ts_ms": int(m.get("last_run_ts_ms") or 0),
                "last_run_msg": str(m.get("last_run_msg") or ""),
                "created_at": m.get("created_at"),
                "updated_at": m.get("updated_at"),
            }
            for m in monitors
        ],
    }
    await _emit_backup_progress(
        progress_callback,
        {"progress": 90, "stage": "网络波动配置完成", "step_key": "netmon", "step_status": "done", "step_detail": f"{len(monitors_payload['monitors'])} 条"},
    )

    meta_payload = {
        "kind": "realm_backup_meta",
        "created_at": nodes_payload["created_at"],
        "nodes": len(nodes),
        "sites": len(sites_payload["sites"]),
        "site_files": int(site_file_total),
        "site_files_failed": int(site_file_failed),
        "site_file_bytes": int(site_file_bytes),
        "certificates": len(certs_payload["certificates"]),
        "netmon_monitors": len(monitors_payload["monitors"]),
        "rules": len(rules_entries),
        "files": fixed_zip_files + len(rules_entries) + int(site_file_total),
    }

    await _emit_backup_progress(
        progress_callback,
        {"progress": 92, "stage": "打包压缩", "step_key": "package", "step_status": "running", "step_detail": f"{meta_payload['files']} 个文件"},
    )
    buf = io.BytesIO()
    site_files_ok = 0
    site_files_failed_transfer = 0
    site_files_bytes_ok = 0
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as z:
        z.writestr("nodes.json", json.dumps(nodes_payload, ensure_ascii=False, indent=2))
        z.writestr("websites/sites.json", json.dumps(sites_payload, ensure_ascii=False, indent=2))
        z.writestr("websites/certificates.json", json.dumps(certs_payload, ensure_ascii=False, indent=2))
        z.writestr("netmon/monitors.json", json.dumps(monitors_payload, ensure_ascii=False, indent=2))
        for path, data in rules_entries:
            z.writestr(path, json.dumps(data, ensure_ascii=False, indent=2))

        file_jobs: List[tuple[Dict[str, Any], Dict[str, Any]]] = []
        for site_item in (site_files_manifest.get("sites") or []):
            for file_item in (site_item.get("files") or []):
                if isinstance(file_item, dict):
                    file_jobs.append((site_item, file_item))
        total_jobs = len(file_jobs)
        if total_jobs:
            for i, (site_item, file_item) in enumerate(file_jobs, start=1):
                node = node_map.get(int(site_item.get("source_node_id") or 0))
                rel_path = _clean_site_rel_path(file_item.get("path"))
                zip_path = str(file_item.get("zip_path") or "").strip()
                root = str(site_item.get("root_path") or "").strip()
                if not node or not root or not rel_path or not zip_path:
                    file_item["status"] = "failed"
                    file_item["error"] = "元数据不完整，跳过"
                    site_files_failed_transfer += 1
                else:
                    try:
                        r = await agent_get_raw(
                            node.get("base_url", ""),
                            node.get("api_key", ""),
                            "/api/v1/website/files/raw",
                            node_verify_tls(node),
                            params={
                                "root": root,
                                "path": rel_path,
                                "root_base": str(node.get("website_root_base") or ""),
                            },
                            timeout=45,
                        )
                        if r.status_code != 200:
                            raise RuntimeError(f"HTTP {r.status_code}")
                        raw = bytes(r.content or b"")
                        z.writestr(zip_path, raw)
                        file_item["status"] = "ok"
                        file_item["size"] = len(raw)
                        site_files_ok += 1
                        site_files_bytes_ok += len(raw)
                    except Exception as exc:
                        file_item["status"] = "failed"
                        file_item["error"] = str(exc)
                        site_files_failed_transfer += 1
                        errs = site_item.get("errors")
                        if not isinstance(errs, list):
                            site_item["errors"] = []
                        site_item["errors"].append(f"文件拉取失败：{rel_path} · {exc}")

                p = 92 + int((i / max(1, total_jobs)) * 7)
                await _emit_backup_progress(
                    progress_callback,
                    {
                        "progress": p,
                        "stage": "打包压缩",
                        "step_key": "package",
                        "step_status": "running",
                        "step_detail": f"拉取网站文件 {i}/{total_jobs}",
                    },
                )

        # Finalize file manifest/meta with actual transfer result
        site_files_manifest["summary"] = {
            "sites": len(site_files_manifest.get("sites") or []),
            "files_total": total_jobs,
            "files_ok": int(site_files_ok),
            "files_failed": int(site_files_failed_transfer),
            "bytes_total": int(site_files_bytes_ok),
        }
        z.writestr("websites/files_manifest.json", json.dumps(site_files_manifest, ensure_ascii=False, indent=2))

        meta_payload["site_files"] = int(site_files_ok)
        meta_payload["site_files_failed"] = int(site_files_failed_transfer + site_file_failed)
        meta_payload["site_file_bytes"] = int(site_files_bytes_ok)
        meta_payload["files"] = fixed_zip_files + len(rules_entries) + int(site_files_ok)
        z.writestr("backup_meta.json", json.dumps(meta_payload, ensure_ascii=False, indent=2))
        z.writestr(
            "README.txt",
            "Nexus 全量备份说明\n\n"
            "1) 恢复节点列表：登录面板 → 控制台 → 点击『恢复节点列表』，上传本压缩包（或解压后的 nodes.json）。\n"
            "2) 全量恢复：控制台 → 全量恢复，自动恢复 nodes/rules/websites/certificates/netmon。\n"
            "3) 网站文件已打包在 websites/files/ 目录，恢复时会按站点映射自动回传到节点。\n"
            "4) 恢复单节点规则：进入节点页面 → 更多 → 恢复规则，把 rules/ 目录下对应节点的规则文件上传/粘贴即可。\n",
        )

    filename = f"nexus-backup-{ts}.zip"
    content = buf.getvalue()
    await _emit_backup_progress(
        progress_callback,
        {
            "progress": 100,
            "stage": "备份完成",
            "step_key": "package",
            "step_status": "done",
            "step_detail": f"{len(content)} bytes",
            "counts": {
                "nodes": meta_payload["nodes"],
                "rules": meta_payload["rules"],
                "sites": meta_payload["sites"],
                "site_files": int(meta_payload.get("site_files") or 0),
                "certificates": meta_payload["certificates"],
                "netmon_monitors": meta_payload["netmon_monitors"],
                "files": meta_payload["files"],
            },
        },
    )

    return {
        "filename": filename,
        "content": content,
        "meta": meta_payload,
    }


def _restore_steps_template() -> List[Dict[str, Any]]:
    return [
        {"key": "upload", "label": "上传备份包", "status": "pending", "detail": ""},
        {"key": "parse", "label": "解析备份包", "status": "pending", "detail": ""},
        {"key": "rules", "label": "恢复节点与规则", "status": "pending", "detail": ""},
        {"key": "sites_files", "label": "恢复网站与文件", "status": "pending", "detail": ""},
        {"key": "certs_netmon", "label": "恢复证书与网络波动", "status": "pending", "detail": ""},
        {"key": "finalize", "label": "收尾与校验", "status": "pending", "detail": ""},
    ]


def _prune_full_restore_jobs() -> None:
    now = time.time()
    with _FULL_RESTORE_LOCK:
        stale_ids: List[str] = []
        for jid, job in _FULL_RESTORE_JOBS.items():
            st = str(job.get("status") or "")
            updated_at = float(job.get("updated_at") or 0.0)
            if st in ("done", "failed") and (now - updated_at) > _FULL_RESTORE_TTL_SEC:
                stale_ids.append(jid)
        for jid in stale_ids:
            _FULL_RESTORE_JOBS.pop(jid, None)


def _restore_job_snapshot(job_id: str) -> Optional[Dict[str, Any]]:
    with _FULL_RESTORE_LOCK:
        job = _FULL_RESTORE_JOBS.get(job_id)
        if not isinstance(job, dict):
            return None
        return {
            "job_id": str(job_id),
            "status": str(job.get("status") or "unknown"),
            "progress": int(job.get("progress") or 0),
            "stage": str(job.get("stage") or ""),
            "error": str(job.get("error") or ""),
            "created_at": float(job.get("created_at") or 0.0),
            "updated_at": float(job.get("updated_at") or 0.0),
            "steps": list(job.get("steps") or []),
            "result": dict(job.get("result") or {}),
        }


def _touch_restore_job(
    job_id: str,
    *,
    status: Optional[str] = None,
    progress: Optional[int] = None,
    stage: Optional[str] = None,
    error: Optional[str] = None,
    result: Optional[Dict[str, Any]] = None,
    step_key: Optional[str] = None,
    step_status: Optional[str] = None,
    step_detail: Optional[str] = None,
) -> None:
    now = time.time()
    with _FULL_RESTORE_LOCK:
        job = _FULL_RESTORE_JOBS.get(job_id)
        if not isinstance(job, dict):
            return
        if status is not None:
            job["status"] = str(status)
        if progress is not None:
            p = max(0, min(100, int(progress)))
            job["progress"] = p
        if stage is not None:
            job["stage"] = str(stage)
        if error is not None:
            job["error"] = str(error)
        if result is not None:
            job["result"] = dict(result)
        if step_key:
            for s in (job.get("steps") or []):
                if str(s.get("key") or "") == str(step_key):
                    if step_status is not None:
                        s["status"] = str(step_status)
                    if step_detail is not None:
                        s["detail"] = str(step_detail)
                    break
        job["updated_at"] = now


def _restore_stage_by_progress(progress: int) -> Dict[str, str]:
    p = int(progress)
    if p < 15:
        return {"key": "upload", "stage": "上传备份包中…"}
    if p < 30:
        return {"key": "parse", "stage": "解析备份包…"}
    if p < 50:
        return {"key": "rules", "stage": "恢复节点与规则…"}
    if p < 72:
        return {"key": "sites_files", "stage": "恢复网站配置与文件…"}
    if p < 88:
        return {"key": "certs_netmon", "stage": "恢复证书与网络波动…"}
    return {"key": "finalize", "stage": "收尾与校验…"}


async def _restore_progress_ticker(job_id: str) -> None:
    order = ["upload", "parse", "rules", "sites_files", "certs_netmon", "finalize"]
    while True:
        await asyncio.sleep(0.6)
        with _FULL_RESTORE_LOCK:
            job = _FULL_RESTORE_JOBS.get(job_id)
            if not isinstance(job, dict):
                return
            if str(job.get("status") or "") != "running":
                return
            cur = int(job.get("progress") or 6)
        if cur >= 95:
            continue
        bump = random.randint(1, 3) if cur < 60 else random.randint(1, 2)
        nxt = min(95, cur + bump)
        pos = _restore_stage_by_progress(nxt)
        cur_key = str(pos.get("key") or "")
        idx = order.index(cur_key) if cur_key in order else 0
        _touch_restore_job(job_id, progress=nxt, stage=pos.get("stage"), step_key=cur_key, step_status="running")
        for i, k in enumerate(order):
            if i < idx:
                _touch_restore_job(job_id, step_key=k, step_status="done")
            elif i > idx:
                _touch_restore_job(job_id, step_key=k, step_status="pending")


def _parse_json_response_obj(resp: JSONResponse) -> Dict[str, Any]:
    try:
        body = getattr(resp, "body", b"") or b""
        if isinstance(body, bytes):
            return json.loads(body.decode("utf-8"))
        return json.loads(str(body))
    except Exception:
        return {"ok": False, "error": "接口返回异常"}


def _restore_cancel_message(exc: BaseException, fallback: str) -> str:
    cls_name = str(exc.__class__.__name__ or "").strip()
    msg = str(exc or "").strip()
    if isinstance(exc, asyncio.CancelledError):
        return f"{fallback}（请求断开或任务取消）"
    if "disconnect" in cls_name.lower():
        return f"{fallback}（请求连接已断开）"
    if msg:
        return msg
    return fallback


@router.get("/api/nodes/{node_id}/ping")
async def api_ping(request: Request, node_id: int, user: str = Depends(require_login)):
    node = get_node(node_id)
    if not node:
        return JSONResponse({"ok": False, "error": "节点不存在"}, status_code=404)

    # Push-report mode: agent has reported recently -> online (no need panel->agent reachability)
    if is_report_fresh(node):
        rep = get_last_report(node_id)
        info = rep.get("info") if isinstance(rep, dict) else None
        # keep兼容旧前端：ping 只关心 ok + latency_ms
        return {
            "ok": True,
            "source": "report",
            "last_seen_at": node.get("last_seen_at"),
            "info": info,
        }

    info = await agent_ping(node["base_url"], node["api_key"], node_verify_tls(node))
    if not info.get("ok"):
        return {"ok": False, "error": info.get("error", "offline")}
    return info


@router.get("/api/nodes/{node_id}/pool")
async def api_pool_get(request: Request, node_id: int, user: str = Depends(require_login)):
    node = get_node(node_id)
    if not node:
        return JSONResponse({"ok": False, "error": "节点不存在"}, status_code=404)

    # Push-report mode: prefer desired pool stored on panel
    desired_ver, desired_pool = get_desired_pool(node_id)
    if isinstance(desired_pool, dict):
        return {
            "ok": True,
            "pool": _filter_pool_for_user(user, desired_pool),
            "desired_version": desired_ver,
            "source": "panel_desired",
        }

    # If no desired pool, try last report snapshot
    rep = get_last_report(node_id)
    if isinstance(rep, dict) and isinstance(rep.get("pool"), dict):
        return {"ok": True, "pool": _filter_pool_for_user(user, rep.get("pool")), "source": "report_cache"}

    try:
        data = await agent_get(node["base_url"], node["api_key"], "/api/v1/pool", node_verify_tls(node))
        if isinstance(data, dict):
            return _pool_like_response_with_filter(user, data)
        return data
    except Exception as exc:
        return JSONResponse({"ok": False, "error": str(exc)}, status_code=502)


@router.get("/api/nodes/{node_id}/backup")
async def api_backup(request: Request, node_id: int, user: str = Depends(require_login)):
    node = get_node(node_id)
    if not node:
        return JSONResponse({"ok": False, "error": "节点不存在"}, status_code=404)
    data = await get_pool_for_backup(node)
    if isinstance(data, dict):
        data = _pool_like_response_with_filter(user, data)
    # 规则文件名包含节点名，便于区分
    safe = safe_filename_part(node.get("name") or f"node-{node_id}")
    filename = f"realm-rules-{safe}-id{node_id}.json"
    payload = json.dumps(data, ensure_ascii=False, indent=2)
    headers = {"Content-Disposition": f'attachment; filename="{filename}"'}
    return Response(content=payload, media_type="application/json", headers=headers)


@router.get("/api/backup/full")
async def api_backup_full(request: Request, user: str = Depends(require_login)):
    """Direct download full backup zip (legacy one-shot behavior)."""
    visible_nodes = filter_nodes_for_user(user, list_nodes())
    bundle = await _build_full_backup_bundle(request, nodes_override=visible_nodes)
    filename = str(bundle.get("filename") or f"nexus-backup-{datetime.now().strftime('%Y%m%d-%H%M%S')}.zip")
    content = bytes(bundle.get("content") or b"")
    headers = {"Content-Disposition": f'attachment; filename="{filename}"'}
    return Response(content=content, media_type="application/zip", headers=headers)


@router.post("/api/backup/full/start")
async def api_backup_full_start(request: Request, user: str = Depends(require_login)):
    """Start full backup in background and return a job id for progress polling."""
    visible_nodes = filter_nodes_for_user(user, list_nodes())
    _prune_full_backup_jobs()
    job_id = uuid.uuid4().hex
    now = time.time()

    with _FULL_BACKUP_LOCK:
        _FULL_BACKUP_JOBS[job_id] = {
            "status": "running",
            "progress": 1,
            "stage": "准备备份任务",
            "error": "",
            "created_at": now,
            "updated_at": now,
            "size_bytes": 0,
            "filename": "",
            "steps": _backup_steps_template(),
            "counts": {
                "nodes": 0,
                "rules": 0,
                "sites": 0,
                "site_files": 0,
                "certificates": 0,
                "netmon_monitors": 0,
                "files": 0,
            },
            "content": b"",
        }

    async def _progress_cb(payload: Dict[str, Any]) -> None:
        if not isinstance(payload, dict):
            return
        _touch_backup_job(
            job_id,
            progress=payload.get("progress"),
            stage=payload.get("stage"),
            counts=payload.get("counts") if isinstance(payload.get("counts"), dict) else None,
            step_key=payload.get("step_key"),
            step_status=payload.get("step_status"),
            step_detail=payload.get("step_detail"),
        )

    async def _run() -> None:
        try:
            bundle = await _build_full_backup_bundle(request, _progress_cb, nodes_override=visible_nodes)
            meta = bundle.get("meta") if isinstance(bundle.get("meta"), dict) else {}
            counts = {
                "nodes": int(meta.get("nodes") or 0),
                "rules": int(meta.get("rules") or 0),
                "sites": int(meta.get("sites") or 0),
                "site_files": int(meta.get("site_files") or 0),
                "certificates": int(meta.get("certificates") or 0),
                "netmon_monitors": int(meta.get("netmon_monitors") or 0),
                "files": int(meta.get("files") or 0),
            }
            content = bytes(bundle.get("content") or b"")
            _touch_backup_job(
                job_id,
                status="done",
                progress=100,
                stage="备份完成",
                filename=str(bundle.get("filename") or ""),
                size_bytes=len(content),
                counts=counts,
                content=content,
            )
        except Exception as exc:
            _touch_backup_job(
                job_id,
                status="failed",
                progress=100,
                stage="备份失败",
                error=str(exc),
            )

    asyncio.create_task(_run())
    snap = _backup_job_snapshot(job_id)
    if not snap:
        return JSONResponse({"ok": False, "error": "创建备份任务失败"}, status_code=500)
    return {"ok": True, **snap}


@router.get("/api/backup/full/progress")
async def api_backup_full_progress(job_id: str = "", user: str = Depends(require_login)):
    """Get backup job progress."""
    _prune_full_backup_jobs()
    jid = str(job_id or "").strip()
    if not jid:
        return JSONResponse({"ok": False, "error": "缺少 job_id"}, status_code=400)
    snap = _backup_job_snapshot(jid)
    if not snap:
        return JSONResponse({"ok": False, "error": "备份任务不存在或已过期"}, status_code=404)
    return {"ok": True, **snap}


@router.get("/api/backup/full/download")
async def api_backup_full_download(job_id: str = "", user: str = Depends(require_login)):
    """Download finished backup by job id."""
    jid = str(job_id or "").strip()
    if not jid:
        return JSONResponse({"ok": False, "error": "缺少 job_id"}, status_code=400)

    with _FULL_BACKUP_LOCK:
        job = _FULL_BACKUP_JOBS.get(jid)
        if not isinstance(job, dict):
            return JSONResponse({"ok": False, "error": "备份任务不存在或已过期"}, status_code=404)
        status = str(job.get("status") or "")
        filename = str(job.get("filename") or "")
        content = bytes(job.get("content") or b"")

    if status != "done" or not content:
        return JSONResponse({"ok": False, "error": "备份尚未完成，请稍候再试"}, status_code=409)

    if not filename:
        filename = f"nexus-backup-{datetime.now().strftime('%Y%m%d-%H%M%S')}.zip"
    headers = {"Content-Disposition": f'attachment; filename="{filename}"'}
    return Response(content=content, media_type="application/zip", headers=headers)


@router.post("/api/restore/nodes")
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

    # Optional: restore group orders (UI sorting)
    try:
        go = payload.get("group_orders") if isinstance(payload, dict) else None
        items: List[Dict[str, Any]] = []
        if isinstance(go, dict):
            items = [{"group_name": k, "sort_order": v} for k, v in go.items()]
        elif isinstance(go, list):
            items = [x for x in go if isinstance(x, dict)]
        for it in items:
            gname = str(it.get("group_name") or it.get("name") or "").strip() or "默认分组"
            try:
                s = int(it.get("sort_order", it.get("order", 1000)))
            except Exception:
                continue
            upsert_group_order(gname, s)
    except Exception:
        pass

    added = 0
    updated = 0
    skipped = 0
    mapping: Dict[str, int] = {}

    for item in nodes_list:
        if not isinstance(item, dict):
            skipped += 1
            continue
        name = (item.get("name") or "").strip()
        base_url = (item.get("base_url") or "").strip().rstrip("/")
        api_key = (item.get("api_key") or "").strip()
        verify_tls = bool(item.get("verify_tls", False))
        is_private = bool(item.get("is_private", False))
        role = str(item.get("role") or "normal").strip().lower() or "normal"
        if role not in ("normal", "website"):
            role = "normal"
        website_root_base = str(item.get("website_root_base") or "").strip()
        group_name = (
            (item.get("group_name") or "默认分组").strip()
            if isinstance(item.get("group_name"), str)
            else (
                "默认分组" if not item.get("group_name") else str(item.get("group_name"))
            )
        )
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
                name or existing.get("name") or extract_ip_for_display(base_url),
                base_url,
                api_key,
                verify_tls=verify_tls,
                is_private=is_private,
                group_name=group_name,
                role=role,
                website_root_base=website_root_base,
            )
            updated += 1
            if source_id_i is not None:
                mapping[str(source_id_i)] = int(existing["id"])
        else:
            new_id = add_node(
                name or extract_ip_for_display(base_url),
                base_url,
                api_key,
                verify_tls=verify_tls,
                is_private=is_private,
                group_name=group_name,
                role=role,
                website_root_base=website_root_base,
            )
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


@router.post("/api/restore/full/start")
async def api_restore_full_start(
    file: UploadFile = File(...),
    user: str = Depends(require_login),
):
    """Start full restore in background and return a job id for polling."""
    _prune_full_restore_jobs()
    try:
        raw, read_err, read_status = await _read_full_restore_upload(file)
    except asyncio.CancelledError as exc:
        msg = _restore_cancel_message(exc, "读取上传文件失败")
        return JSONResponse({"ok": False, "error": msg}, status_code=499)
    if raw is None:
        return JSONResponse({"ok": False, "error": str(read_err or "上传文件无效")}, status_code=int(read_status or 400))

    job_id = uuid.uuid4().hex
    now = time.time()
    with _FULL_RESTORE_LOCK:
        _FULL_RESTORE_JOBS[job_id] = {
            "status": "running",
            "progress": 8,
            "stage": "上传完成，准备恢复",
            "error": "",
            "created_at": now,
            "updated_at": now,
            "steps": _restore_steps_template(),
            "result": {},
        }
    _touch_restore_job(job_id, step_key="upload", step_status="done", step_detail="上传完成")
    _touch_restore_job(job_id, step_key="parse", step_status="running", step_detail="准备解析")

    async def _run() -> None:
        ticker: Optional[asyncio.Task] = None
        upf: Optional[UploadFile] = None
        try:
            ticker = asyncio.create_task(_restore_progress_ticker(job_id))
            upf = UploadFile(filename=str(file.filename or "restore.zip"), file=io.BytesIO(raw))
            restore_resp = await api_restore_full(file=upf, user=user)
            if isinstance(restore_resp, JSONResponse):
                payload = _parse_json_response_obj(restore_resp)
            elif isinstance(restore_resp, dict):
                payload = dict(restore_resp)
            else:
                payload = {"ok": False, "error": "恢复返回异常"}

            if not bool(payload.get("ok")):
                msg = str(payload.get("error") or "恢复失败")
                pos = _restore_stage_by_progress(int((_restore_job_snapshot(job_id) or {}).get("progress") or 0))
                _touch_restore_job(
                    job_id,
                    status="failed",
                    progress=min(99, int((_restore_job_snapshot(job_id) or {}).get("progress") or 90)),
                    stage=msg,
                    error=msg,
                    result=payload,
                    step_key=pos.get("key"),
                    step_status="failed",
                    step_detail="执行失败",
                )
                return

            for k in ("upload", "parse", "rules", "sites_files", "certs_netmon", "finalize"):
                _touch_restore_job(job_id, step_key=k, step_status="done")
            _touch_restore_job(
                job_id,
                status="done",
                progress=100,
                stage="恢复完成",
                result=payload,
                step_key="finalize",
                step_status="done",
                step_detail="恢复完成",
            )
        except asyncio.CancelledError as exc:
            pos = _restore_stage_by_progress(int((_restore_job_snapshot(job_id) or {}).get("progress") or 0))
            _touch_restore_job(
                job_id,
                status="failed",
                progress=min(99, int((_restore_job_snapshot(job_id) or {}).get("progress") or 90)),
                stage="恢复已取消",
                error=_restore_cancel_message(exc, "恢复任务被取消"),
                step_key=pos.get("key"),
                step_status="failed",
                step_detail="任务取消",
            )
        except Exception as exc:
            pos = _restore_stage_by_progress(int((_restore_job_snapshot(job_id) or {}).get("progress") or 0))
            _touch_restore_job(
                job_id,
                status="failed",
                progress=min(99, int((_restore_job_snapshot(job_id) or {}).get("progress") or 90)),
                stage="恢复失败",
                error=str(exc),
                step_key=pos.get("key"),
                step_status="failed",
                step_detail="执行异常",
            )
        finally:
            if ticker:
                ticker.cancel()
                try:
                    await ticker
                except BaseException:
                    pass
            if upf:
                try:
                    await upf.close()
                except Exception:
                    pass

    asyncio.create_task(_run())
    snap = _restore_job_snapshot(job_id)
    if not snap:
        return JSONResponse({"ok": False, "error": "创建恢复任务失败"}, status_code=500)
    return {"ok": True, **snap}


@router.get("/api/restore/full/progress")
async def api_restore_full_progress(job_id: str = "", user: str = Depends(require_login)):
    _prune_full_restore_jobs()
    jid = str(job_id or "").strip()
    if not jid:
        return JSONResponse({"ok": False, "error": "缺少 job_id"}, status_code=400)
    snap = _restore_job_snapshot(jid)
    if not snap:
        return JSONResponse({"ok": False, "error": "恢复任务不存在或已过期"}, status_code=404)
    return {"ok": True, **snap}


@router.post("/api/restore/full")
async def api_restore_full(
    file: UploadFile = File(...),
    user: str = Depends(require_login),
):
    """Restore nodes list + per-node rules from full backup zip."""
    try:
        raw, read_err, read_status = await _read_full_restore_upload(file)
    except asyncio.CancelledError as exc:
        msg = _restore_cancel_message(exc, "读取上传文件失败")
        return JSONResponse({"ok": False, "error": msg}, status_code=499)
    if raw is None:
        return JSONResponse({"ok": False, "error": str(read_err or "上传文件无效")}, status_code=int(read_status or 400))

    try:
        z = zipfile.ZipFile(io.BytesIO(raw))
    except Exception as exc:
        return JSONResponse({"ok": False, "error": f"压缩包解析失败：{exc}"}, status_code=400)
    zip_names = z.namelist()
    zip_table = {str(n).lower(): n for n in zip_names}

    def _find_zip_path(*candidates: str) -> Optional[str]:
        for c in candidates:
            hit = zip_table.get(str(c).lower())
            if hit:
                return hit
        return None

    # ---- read nodes.json ----
    nodes_payload = None
    nodes_name = _find_zip_path("nodes.json")
    if not nodes_name:
        return JSONResponse({"ok": False, "error": "压缩包中未找到 nodes.json"}, status_code=400)

    try:
        nodes_payload = json.loads(z.read(nodes_name).decode("utf-8"))
    except Exception as exc:
        return JSONResponse({"ok": False, "error": f"nodes.json 解析失败：{exc}"}, status_code=400)

    # Accept: {nodes:[...]} or plain list
    nodes_list = None
    if isinstance(nodes_payload, dict) and isinstance(nodes_payload.get("nodes"), list):
        nodes_list = nodes_payload.get("nodes")
    elif isinstance(nodes_payload, list):
        nodes_list = nodes_payload

    if not isinstance(nodes_list, list):
        return JSONResponse({"ok": False, "error": "备份内容缺少 nodes 列表"}, status_code=400)

    # Optional: restore group orders (UI sorting)
    try:
        go = nodes_payload.get("group_orders") if isinstance(nodes_payload, dict) else None
        items: List[Dict[str, Any]] = []
        if isinstance(go, dict):
            items = [{"group_name": k, "sort_order": v} for k, v in go.items()]
        elif isinstance(go, list):
            items = [x for x in go if isinstance(x, dict)]
        for it in items:
            gname = str(it.get("group_name") or it.get("name") or "").strip() or "默认分组"
            try:
                s = int(it.get("sort_order", it.get("order", 1000)))
            except Exception:
                continue
            upsert_group_order(gname, s)
    except Exception:
        pass

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
        name = (item.get("name") or "").strip()
        base_url = (item.get("base_url") or "").strip().rstrip("/")
        api_key = (item.get("api_key") or "").strip()
        verify_tls = bool(item.get("verify_tls", False))
        is_private = bool(item.get("is_private", False))
        role = str(item.get("role") or "normal").strip().lower() or "normal"
        if role not in ("normal", "website"):
            role = "normal"
        website_root_base = str(item.get("website_root_base") or "").strip()
        group_name = item.get("group_name") or "默认分组"
        group_name = str(group_name).strip() or "默认分组"
        source_id = item.get("source_id")
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
                existing["id"],
                name or existing.get("name") or extract_ip_for_display(base_url),
                base_url,
                api_key,
                verify_tls=verify_tls,
                is_private=is_private,
                group_name=group_name,
                role=role,
                website_root_base=website_root_base,
            )
            updated += 1
            node_id = int(existing["id"])
        else:
            node_id = int(
                add_node(
                    name or extract_ip_for_display(base_url),
                    base_url,
                    api_key,
                    verify_tls=verify_tls,
                    is_private=is_private,
                    group_name=group_name,
                    role=role,
                    website_root_base=website_root_base,
                )
            )
            added += 1

        baseurl_to_nodeid[base_url] = node_id
        if source_id_i is not None:
            mapping[str(source_id_i)] = node_id

    # ---- restore rules (batch) ----
    rule_paths = [n for n in zip_names if n.lower().startswith("rules/") and n.lower().endswith(".json")]

    import re as _re

    async def apply_pool_to_node(target_id: int, pool: Dict[str, Any]) -> Dict[str, Any]:
        node = get_node(int(target_id))
        if not node:
            raise RuntimeError("节点不存在")

        # store desired on panel
        desired_ver, _ = set_desired_pool(int(target_id), pool)

        # best-effort immediate apply
        applied = False
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
    rule_failed: List[Dict[str, Any]] = []
    rule_unmatched: List[Dict[str, Any]] = []

    tasks = []
    task_meta = []

    for p in rule_paths:
        try:
            payload = json.loads(z.read(p).decode("utf-8"))
        except Exception as exc:
            failed_rules += 1
            rule_failed.append({"path": p, "error": f"JSON 解析失败：{exc}"})
            continue

        pool = payload.get("pool") if isinstance(payload, dict) else None
        if pool is None:
            pool = payload
        if not isinstance(pool, dict):
            failed_rules += 1
            rule_failed.append({"path": p, "error": "备份内容缺少 pool 数据"})
            continue

        sanitize_pool(pool)

        # resolve source_id / base_url
        node_meta = payload.get("node") if isinstance(payload, dict) else None
        source_id = None
        base_url = None
        if isinstance(node_meta, dict):
            try:
                if node_meta.get("id") is not None:
                    source_id = int(node_meta.get("id"))
            except Exception:
                source_id = None
            base_url = (node_meta.get("base_url") or "").strip().rstrip("/") or None

        if source_id is None:
            m = _re.search(r"id(\d+)\.json$", p)
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
                target_id = int(ex.get("id"))

        if target_id is None:
            unmatched_rules += 1
            rule_unmatched.append(
                {"path": p, "source_id": source_id, "base_url": base_url, "error": "未找到对应节点"}
            )
            continue

        tasks.append(guarded_apply(int(target_id), pool))
        task_meta.append({"path": p, "target_id": int(target_id), "source_id": source_id, "base_url": base_url})

    if tasks:
        results = await asyncio.gather(*tasks, return_exceptions=True)
        for meta, res in zip(task_meta, results):
            if isinstance(res, Exception):
                failed_rules += 1
                rule_failed.append({"path": meta.get("path"), "target_id": meta.get("target_id"), "error": str(res)})
            else:
                restored_rules += 1

    def _as_int(v: Any, default: int = 0) -> int:
        try:
            return int(v)
        except Exception:
            return int(default)

    def _as_bool(v: Any, default: bool = False) -> bool:
        if v is None:
            return bool(default)
        if isinstance(v, bool):
            return v
        s = str(v).strip().lower()
        if s in ("1", "true", "yes", "y", "on"):
            return True
        if s in ("0", "false", "no", "n", "off"):
            return False
        return bool(v)

    def _norm_domains(val: Any) -> List[str]:
        if not isinstance(val, list):
            return []
        out: List[str] = []
        seen = set()
        for x in val:
            d = str(x or "").strip().lower().strip(".")
            if not d or d in seen:
                continue
            seen.add(d)
            out.append(d)
        return out

    def _primary_domain(domains: List[str]) -> str:
        for d in domains or []:
            dd = str(d or "").strip().lower()
            if dd:
                return dd
        return ""

    def _resolve_node_id(source_id: Optional[int], base_url: Optional[str]) -> Optional[int]:
        if source_id is not None:
            hit = mapping.get(str(source_id))
            if hit:
                return int(hit)
        bu = str(base_url or "").strip().rstrip("/")
        if bu:
            hit2 = baseurl_to_nodeid.get(bu)
            if hit2:
                return int(hit2)
            ex = get_node_by_base_url(bu)
            if ex:
                return int(ex.get("id") or 0)
        if source_id is not None:
            b2 = srcid_to_baseurl.get(str(source_id))
            if b2:
                hit3 = baseurl_to_nodeid.get(str(b2).rstrip("/"))
                if hit3:
                    return int(hit3)
        return None

    # ---- restore websites (site config) ----
    site_added = 0
    site_updated = 0
    site_skipped = 0
    site_mapping: Dict[str, int] = {}
    site_unmatched: List[Dict[str, Any]] = []

    site_primary_index: Dict[tuple[int, str], int] = {}
    try:
        for s in list_sites():
            nid = _as_int(s.get("node_id"), 0)
            sid = _as_int(s.get("id"), 0)
            pd = _primary_domain(_norm_domains(s.get("domains") or []))
            if nid > 0 and sid > 0 and pd:
                site_primary_index[(nid, pd)] = sid
    except Exception:
        site_primary_index = {}

    sites_path = _find_zip_path("websites/sites.json")
    if sites_path:
        try:
            sites_payload = json.loads(z.read(sites_path).decode("utf-8"))
            site_items = (
                sites_payload.get("sites")
                if isinstance(sites_payload, dict) and isinstance(sites_payload.get("sites"), list)
                else (sites_payload if isinstance(sites_payload, list) else [])
            )
        except Exception as exc:
            site_items = []
            site_unmatched.append({"path": sites_path, "error": f"sites.json 解析失败：{exc}"})

        for item in site_items:
            if not isinstance(item, dict):
                site_skipped += 1
                continue

            source_site_id_raw = item.get("source_id")
            source_site_id = _as_int(source_site_id_raw, 0) if source_site_id_raw is not None else None

            source_node_id_raw = item.get("node_source_id")
            source_node_id = _as_int(source_node_id_raw, 0) if source_node_id_raw is not None else None
            node_base_url = str(item.get("node_base_url") or "").strip().rstrip("/")
            target_node_id = _resolve_node_id(source_node_id, node_base_url)
            if not target_node_id:
                site_skipped += 1
                site_unmatched.append(
                    {
                        "source_site_id": source_site_id,
                        "source_node_id": source_node_id,
                        "node_base_url": node_base_url,
                        "error": "站点未匹配到节点",
                    }
                )
                continue

            domains = _norm_domains(item.get("domains"))
            primary = _primary_domain(domains)
            key = (int(target_node_id), primary) if primary else None

            site_name = str(item.get("name") or "").strip() or (domains[0] if domains else f"site-{int(target_node_id)}")
            site_type = str(item.get("type") or "static").strip().lower() or "static"
            if site_type not in ("static", "php", "reverse_proxy"):
                site_type = "static"
            web_server = str(item.get("web_server") or "nginx").strip() or "nginx"
            root_path = str(item.get("root_path") or "").strip()
            proxy_target = str(item.get("proxy_target") or "").strip()
            nginx_tpl = str(item.get("nginx_tpl") or "")
            https_redirect = _as_bool(item.get("https_redirect"), False)
            gzip_enabled = _as_bool(item.get("gzip_enabled"), True)
            status = str(item.get("status") or "running").strip() or "running"

            site_id = 0
            if key and key in site_primary_index:
                site_id = int(site_primary_index[key] or 0)

            if site_id > 0:
                update_site(
                    site_id,
                    name=site_name,
                    domains=domains,
                    root_path=root_path,
                    proxy_target=proxy_target,
                    site_type=site_type,
                    web_server=web_server,
                    nginx_tpl=nginx_tpl,
                    https_redirect=https_redirect,
                    gzip_enabled=gzip_enabled,
                    status=status,
                )
                site_updated += 1
            else:
                site_id = int(
                    add_site(
                        node_id=int(target_node_id),
                        name=site_name,
                        domains=domains,
                        root_path=root_path,
                        proxy_target=proxy_target,
                        site_type=site_type,
                        web_server=web_server,
                        nginx_tpl=nginx_tpl,
                        https_redirect=https_redirect,
                        gzip_enabled=gzip_enabled,
                        status=status,
                    )
                )
                site_added += 1

            update_site_health(
                site_id,
                str(item.get("health_status") or "").strip(),
                health_code=_as_int(item.get("health_code"), 0),
                health_latency_ms=_as_int(item.get("health_latency_ms"), 0),
                health_error=str(item.get("health_error") or "").strip(),
                health_checked_at=item.get("health_checked_at"),
            )

            if key:
                site_primary_index[key] = int(site_id)
            if source_site_id is not None:
                site_mapping[str(source_site_id)] = int(site_id)

    # ---- restore website files ----
    site_file_restored = 0
    site_file_failed = 0
    site_file_skipped = 0
    site_file_unmatched = 0
    site_file_bytes = 0
    site_file_failed_items: List[Dict[str, Any]] = []

    files_manifest_path = _find_zip_path("websites/files_manifest.json")
    if files_manifest_path:
        try:
            files_manifest = json.loads(z.read(files_manifest_path).decode("utf-8"))
            site_file_items = (
                files_manifest.get("sites")
                if isinstance(files_manifest, dict) and isinstance(files_manifest.get("sites"), list)
                else (files_manifest if isinstance(files_manifest, list) else [])
            )
        except Exception as exc:
            site_file_items = []
            site_file_failed_items.append({"path": files_manifest_path, "error": f"files_manifest 解析失败：{exc}"})

        current_sites: Dict[int, Dict[str, Any]] = {}
        try:
            for s in list_sites():
                sid = _as_int(s.get("id"), 0)
                if sid > 0:
                    current_sites[sid] = s
        except Exception:
            current_sites = {}

        async def _upload_site_file_bytes(
            node: Dict[str, Any],
            root_path: str,
            rel_path: str,
            raw: bytes,
        ) -> None:
            clean_rel = _clean_site_rel_path(rel_path)
            if not clean_rel:
                raise RuntimeError("非法文件路径")
            if "/" in clean_rel:
                dir_path, filename = clean_rel.rsplit("/", 1)
            else:
                dir_path, filename = "", clean_rel
            filename = filename.strip()
            if not filename:
                raise RuntimeError("文件名为空")
            root_base = str(node.get("website_root_base") or "").strip()
            upload_id = uuid.uuid4().hex
            if not raw:
                payload_empty = {
                    "root": root_path,
                    "path": dir_path,
                    "filename": filename,
                    "upload_id": upload_id,
                    "offset": 0,
                    "done": True,
                    "allow_empty": True,
                    "root_base": root_base,
                }
                resp_empty = await agent_post(
                    node["base_url"],
                    node["api_key"],
                    "/api/v1/website/files/upload_chunk",
                    payload_empty,
                    node_verify_tls(node),
                    timeout=20,
                )
                if not resp_empty.get("ok", True):
                    raise RuntimeError(str(resp_empty.get("error") or "空文件上传失败"))
                return

            chunk_size = 512 * 1024
            offset = 0
            total = len(raw)
            while offset < total:
                chunk = raw[offset : offset + chunk_size]
                done = (offset + len(chunk)) >= total
                payload_chunk = {
                    "root": root_path,
                    "path": dir_path,
                    "filename": filename,
                    "upload_id": upload_id,
                    "offset": offset,
                    "done": done,
                    "content_b64": base64.b64encode(chunk).decode("ascii"),
                    "chunk_sha256": hashlib.sha256(chunk).hexdigest(),
                    "root_base": root_base,
                }
                resp_chunk = await agent_post(
                    node["base_url"],
                    node["api_key"],
                    "/api/v1/website/files/upload_chunk",
                    payload_chunk,
                    node_verify_tls(node),
                    timeout=45,
                )
                if not resp_chunk.get("ok", True):
                    raise RuntimeError(str(resp_chunk.get("error") or "文件上传失败"))
                offset += len(chunk)

        for sitem in site_file_items:
            if not isinstance(sitem, dict):
                continue
            source_site_id_raw = sitem.get("source_site_id")
            source_site_id = _as_int(source_site_id_raw, 0) if source_site_id_raw is not None else None
            target_site_id = None
            if source_site_id is not None and str(source_site_id) in site_mapping:
                target_site_id = _as_int(site_mapping.get(str(source_site_id)), 0) or None
            if not target_site_id:
                # fallback: if source id happens to exist after restore
                if source_site_id is not None and source_site_id in current_sites:
                    target_site_id = int(source_site_id)

            files_arr = sitem.get("files")
            file_items = files_arr if isinstance(files_arr, list) else []
            if not target_site_id:
                site_file_unmatched += len(file_items)
                continue

            site_obj = current_sites.get(int(target_site_id))
            if not site_obj:
                site_obj = next((x for x in list_sites() if _as_int(x.get("id"), 0) == int(target_site_id)), None)
                if site_obj:
                    current_sites[int(target_site_id)] = site_obj
            if not isinstance(site_obj, dict):
                site_file_unmatched += len(file_items)
                continue

            target_node = get_node(_as_int(site_obj.get("node_id"), 0))
            root_path = str(site_obj.get("root_path") or "").strip()
            if not target_node or not root_path:
                site_file_skipped += len(file_items)
                continue

            pkg_dir = str(sitem.get("package_dir") or "")
            for fitem in file_items:
                if not isinstance(fitem, dict):
                    site_file_skipped += 1
                    continue
                rel_path = _clean_site_rel_path(fitem.get("path"))
                if not rel_path:
                    site_file_skipped += 1
                    continue
                zip_hint = str(fitem.get("zip_path") or "").strip()
                if not zip_hint:
                    zip_hint = f"websites/files/{pkg_dir}/{rel_path}" if pkg_dir else ""
                if not zip_hint:
                    site_file_failed += 1
                    site_file_failed_items.append(
                        {"site_id": target_site_id, "path": rel_path, "error": "缺少 zip_path"}
                    )
                    continue
                zpath = _find_zip_path(zip_hint)
                if not zpath:
                    site_file_failed += 1
                    site_file_failed_items.append(
                        {"site_id": target_site_id, "path": rel_path, "error": "备份包缺少对应文件"}
                    )
                    continue
                try:
                    raw_bytes = bytes(z.read(zpath))
                    await _upload_site_file_bytes(target_node, root_path, rel_path, raw_bytes)
                    site_file_restored += 1
                    site_file_bytes += len(raw_bytes)
                except Exception as exc:
                    site_file_failed += 1
                    site_file_failed_items.append(
                        {"site_id": target_site_id, "path": rel_path, "error": str(exc)}
                    )

    # ---- restore website certificates ----
    cert_added = 0
    cert_updated = 0
    cert_skipped = 0
    cert_unmatched: List[Dict[str, Any]] = []

    cert_index: Dict[tuple[int, int, str], int] = {}
    try:
        for c in list_certificates():
            nid = _as_int(c.get("node_id"), 0)
            sid = _as_int(c.get("site_id"), 0) if c.get("site_id") is not None else 0
            pd = _primary_domain(_norm_domains(c.get("domains") or []))
            cid = _as_int(c.get("id"), 0)
            if nid > 0 and cid > 0 and pd:
                cert_index[(nid, sid, pd)] = cid
    except Exception:
        cert_index = {}

    certs_path = _find_zip_path("websites/certificates.json")
    if certs_path:
        try:
            certs_payload = json.loads(z.read(certs_path).decode("utf-8"))
            cert_items = (
                certs_payload.get("certificates")
                if isinstance(certs_payload, dict) and isinstance(certs_payload.get("certificates"), list)
                else (certs_payload if isinstance(certs_payload, list) else [])
            )
        except Exception as exc:
            cert_items = []
            cert_unmatched.append({"path": certs_path, "error": f"certificates.json 解析失败：{exc}"})

        for item in cert_items:
            if not isinstance(item, dict):
                cert_skipped += 1
                continue

            source_node_id_raw = item.get("node_source_id")
            source_node_id = _as_int(source_node_id_raw, 0) if source_node_id_raw is not None else None
            node_base_url = str(item.get("node_base_url") or "").strip().rstrip("/")
            target_node_id = _resolve_node_id(source_node_id, node_base_url)
            if not target_node_id:
                cert_skipped += 1
                cert_unmatched.append(
                    {
                        "source_id": item.get("source_id"),
                        "source_node_id": source_node_id,
                        "node_base_url": node_base_url,
                        "error": "证书未匹配到节点",
                    }
                )
                continue

            source_site_id_raw = item.get("site_source_id")
            source_site_id = _as_int(source_site_id_raw, 0) if source_site_id_raw is not None else None
            target_site_id: Optional[int] = None
            if source_site_id is not None and str(source_site_id) in site_mapping:
                target_site_id = _as_int(site_mapping.get(str(source_site_id)), 0) or None

            domains = _norm_domains(item.get("domains"))
            pd = _primary_domain(domains)
            if target_site_id is None and pd:
                sid2 = site_primary_index.get((int(target_node_id), pd))
                if sid2:
                    target_site_id = int(sid2)

            key = (int(target_node_id), int(target_site_id or 0), pd)
            cert_id = cert_index.get(key) if pd else None

            status = str(item.get("status") or "pending").strip() or "pending"
            not_before = item.get("not_before")
            not_after = item.get("not_after")
            renew_at = item.get("renew_at")
            last_error = str(item.get("last_error") or "").strip()

            if cert_id:
                update_certificate(
                    int(cert_id),
                    domains=domains,
                    status=status,
                    not_before=not_before,
                    not_after=not_after,
                    renew_at=renew_at,
                    last_error=last_error,
                )
                cert_updated += 1
            else:
                cert_id = int(
                    add_certificate(
                        node_id=int(target_node_id),
                        site_id=int(target_site_id) if target_site_id is not None else None,
                        domains=domains,
                        issuer=str(item.get("issuer") or "letsencrypt"),
                        challenge=str(item.get("challenge") or "http-01"),
                        status=status,
                        not_before=not_before,
                        not_after=not_after,
                        renew_at=renew_at,
                        last_error=last_error,
                    )
                )
                cert_added += 1

            if pd:
                cert_index[key] = int(cert_id)

    # ---- restore netmon monitor configs ----
    mon_added = 0
    mon_updated = 0
    mon_skipped = 0

    def _monitor_key(target: str, mode: str, tcp_port: int, node_ids: List[int]) -> tuple[str, str, int, tuple[int, ...]]:
        cleaned = sorted(set([int(x) for x in (node_ids or []) if int(x) > 0]))
        return ((target or "").strip().lower(), (mode or "ping").strip().lower(), int(tcp_port or 443), tuple(cleaned))

    monitor_index: Dict[tuple[str, str, int, tuple[int, ...]], int] = {}
    try:
        for m in list_netmon_monitors():
            mid = _as_int(m.get("id"), 0)
            if mid <= 0:
                continue
            mk = _monitor_key(
                str(m.get("target") or ""),
                str(m.get("mode") or "ping"),
                _as_int(m.get("tcp_port"), 443),
                [int(x) for x in (m.get("node_ids") or []) if _as_int(x, 0) > 0],
            )
            monitor_index[mk] = mid
    except Exception:
        monitor_index = {}

    monitors_path = _find_zip_path("netmon/monitors.json")
    if monitors_path:
        try:
            monitors_payload = json.loads(z.read(monitors_path).decode("utf-8"))
            monitor_items = (
                monitors_payload.get("monitors")
                if isinstance(monitors_payload, dict) and isinstance(monitors_payload.get("monitors"), list)
                else (monitors_payload if isinstance(monitors_payload, list) else [])
            )
        except Exception:
            monitor_items = []

        for item in monitor_items:
            if not isinstance(item, dict):
                mon_skipped += 1
                continue

            target = str(item.get("target") or "").strip()
            if not target:
                mon_skipped += 1
                continue
            mode = str(item.get("mode") or "ping").strip().lower() or "ping"
            if mode not in ("ping", "tcping"):
                mode = "ping"
            tcp_port = _as_int(item.get("tcp_port"), 443)
            interval_sec = _as_int(item.get("interval_sec"), 5)
            warn_ms = _as_int(item.get("warn_ms"), 0)
            crit_ms = _as_int(item.get("crit_ms"), 0)
            enabled = _as_bool(item.get("enabled"), True)

            src_node_ids_raw = item.get("node_source_ids")
            src_node_ids = src_node_ids_raw if isinstance(src_node_ids_raw, list) else []
            base_urls_raw = item.get("node_base_urls")
            base_urls = base_urls_raw if isinstance(base_urls_raw, list) else []

            resolved_ids: List[int] = []
            for sid in src_node_ids:
                nid = _resolve_node_id(_as_int(sid, 0), None)
                if nid and nid > 0 and nid not in resolved_ids:
                    resolved_ids.append(int(nid))
            for bu in base_urls:
                nid = _resolve_node_id(None, str(bu or "").strip().rstrip("/"))
                if nid and nid > 0 and nid not in resolved_ids:
                    resolved_ids.append(int(nid))

            if not resolved_ids:
                mon_skipped += 1
                continue

            mk = _monitor_key(target, mode, tcp_port, resolved_ids)
            mid = monitor_index.get(mk)
            if mid:
                update_netmon_monitor(
                    int(mid),
                    target=target,
                    mode=mode,
                    tcp_port=tcp_port,
                    interval_sec=interval_sec,
                    node_ids=resolved_ids,
                    warn_ms=warn_ms,
                    crit_ms=crit_ms,
                    enabled=enabled,
                    last_run_ts_ms=_as_int(item.get("last_run_ts_ms"), 0),
                    last_run_msg=str(item.get("last_run_msg") or ""),
                )
                mon_updated += 1
            else:
                new_mid = int(
                    add_netmon_monitor(
                        target=target,
                        mode=mode,
                        tcp_port=tcp_port,
                        interval_sec=interval_sec,
                        node_ids=resolved_ids,
                        warn_ms=warn_ms,
                        crit_ms=crit_ms,
                        enabled=enabled,
                    )
                )
                monitor_index[mk] = new_mid
                mon_added += 1

    return {
        "ok": True,
        "nodes": {"added": added, "updated": updated, "skipped": skipped, "mapping": mapping},
        "rules": {
            "total": total_rules,
            "restored": restored_rules,
            "unmatched": unmatched_rules,
            "failed": failed_rules,
        },
        "sites": {
            "added": site_added,
            "updated": site_updated,
            "skipped": site_skipped,
            "mapped": len(site_mapping),
        },
        "site_files": {
            "restored": site_file_restored,
            "failed": site_file_failed,
            "skipped": site_file_skipped,
            "unmatched": site_file_unmatched,
            "bytes": site_file_bytes,
        },
        "certificates": {
            "added": cert_added,
            "updated": cert_updated,
            "skipped": cert_skipped,
        },
        "netmon": {
            "added": mon_added,
            "updated": mon_updated,
            "skipped": mon_skipped,
        },
        "site_unmatched": site_unmatched[:50],
        "site_file_failed": site_file_failed_items[:50],
        "cert_unmatched": cert_unmatched[:50],
        "rule_unmatched": rule_unmatched[:50],
        "rule_failed": rule_failed[:50],
    }


@router.post("/api/nodes/{node_id}/restore")
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

    sanitize_pool(pool)

    # Store on panel; apply will be done asynchronously (avoid blocking / proxy timeouts).
    desired_ver, _ = set_desired_pool(node_id, pool)
    schedule_apply_pool(node, pool)
    return {"ok": True, "desired_version": desired_ver, "queued": True}


def _append_precheck_issue(
    issues: List[PoolValidationIssue],
    seen: set[str],
    issue: PoolValidationIssue,
    limit: int,
) -> None:
    key = f"{issue.path}|{issue.code}|{issue.severity}|{issue.message}"
    if key in seen:
        return
    if len(issues) >= limit:
        return
    seen.add(key)
    issues.append(issue)


def _safe_error_text(data: Any, default: str = "unknown") -> str:
    if isinstance(data, dict):
        msg = str(data.get("error") or "").strip()
        return msg or default
    msg = str(data or "").strip()
    return msg or default


async def _run_pool_save_precheck(node: Dict[str, Any], pool: Dict[str, Any]) -> Dict[str, Any]:
    """Save-time runtime precheck via agent /api/v1/netprobe (mode=rules)."""
    out_issues: List[PoolValidationIssue] = []
    seen: set[str] = set()

    eps = pool.get("endpoints") if isinstance(pool.get("endpoints"), list) else []
    if not isinstance(eps, list) or not eps:
        return {
            "ok": True,
            "issues": out_issues,
            "summary": {"enabled": _SAVE_PRECHECK_ENABLED, "rules_total": 0, "issues": 0, "source": "save_precheck"},
        }

    if not _SAVE_PRECHECK_ENABLED:
        return {
            "ok": True,
            "issues": out_issues,
            "summary": {"enabled": False, "rules_total": len(eps), "issues": 0, "source": "save_precheck"},
        }

    rules_payload: List[Dict[str, Any]] = []
    for ep in eps[:160]:
        if not isinstance(ep, dict):
            continue
        item: Dict[str, Any] = {
            "id": str(ep.get("id") or ""),
            "listen": str(ep.get("listen") or ""),
            "protocol": str(ep.get("protocol") or ""),
            "disabled": bool(ep.get("disabled")),
            "remote": ep.get("remote"),
            "remotes": ep.get("remotes") if isinstance(ep.get("remotes"), list) else [],
            "extra_remotes": ep.get("extra_remotes") if isinstance(ep.get("extra_remotes"), list) else [],
        }
        if ep.get("listen_transport") is not None:
            item["listen_transport"] = ep.get("listen_transport")
        if ep.get("remote_transport") is not None:
            item["remote_transport"] = ep.get("remote_transport")
        ex = ep.get("extra_config")
        if isinstance(ex, dict):
            item["extra_config"] = ex
        rules_payload.append(item)

    body = {"mode": "rules", "rules": rules_payload, "timeout": _SAVE_PRECHECK_PROBE_TIMEOUT}
    try:
        data = await agent_post(
            node.get("base_url", ""),
            node.get("api_key", ""),
            "/api/v1/netprobe",
            body,
            node_verify_tls(node),
            timeout=_SAVE_PRECHECK_HTTP_TIMEOUT,
        )
    except Exception as exc:
        _append_precheck_issue(
            out_issues,
            seen,
            PoolValidationIssue(
                path="endpoints",
                message=f"预检失败：无法连接 Agent 执行规则探测（{exc}）",
                severity="warning",
                code="precheck_unreachable",
            ),
            _SAVE_PRECHECK_MAX_ISSUES,
        )
        return {
            "ok": False,
            "issues": out_issues,
            "summary": {
                "enabled": True,
                "rules_total": len(rules_payload),
                "issues": len(out_issues),
                "source": "agent_netprobe_rules",
                "error": "agent_unreachable",
            },
        }

    if not isinstance(data, dict) or data.get("ok") is not True:
        _append_precheck_issue(
            out_issues,
            seen,
            PoolValidationIssue(
                path="endpoints",
                message=f"预检失败：Agent rules 探测返回异常（{_safe_error_text(data)}）",
                severity="warning",
                code="precheck_failed",
            ),
            _SAVE_PRECHECK_MAX_ISSUES,
        )
        return {
            "ok": False,
            "issues": out_issues,
            "summary": {
                "enabled": True,
                "rules_total": len(rules_payload),
                "issues": len(out_issues),
                "source": "agent_netprobe_rules",
                "error": "probe_failed",
            },
        }

    # deps
    deps = data.get("deps") if isinstance(data.get("deps"), dict) else {}
    if isinstance(deps, dict):
        if deps.get("sysctl") is False:
            _append_precheck_issue(
                out_issues,
                seen,
                PoolValidationIssue(
                    path="endpoints",
                    message="依赖提示：节点缺少 sysctl 命令，性能优化提示可能不完整",
                    severity="warning",
                    code="dependency_missing",
                ),
                _SAVE_PRECHECK_MAX_ISSUES,
            )
        if deps.get("ss") is False:
            _append_precheck_issue(
                out_issues,
                seen,
                PoolValidationIssue(
                    path="endpoints",
                    message="依赖提示：节点缺少 ss 命令，端口占用检查可能不完整",
                    severity="warning",
                    code="dependency_missing",
                ),
                _SAVE_PRECHECK_MAX_ISSUES,
            )

    # perf hints
    perf_hints = data.get("perf_hints") if isinstance(data.get("perf_hints"), list) else []
    for hint in perf_hints[:8]:
        msg = str(hint or "").strip()
        if not msg:
            continue
        _append_precheck_issue(
            out_issues,
            seen,
            PoolValidationIssue(path="endpoints", message=f"性能风险提示：{msg}", severity="warning", code="sysctl_tuning_recommended"),
            _SAVE_PRECHECK_MAX_ISSUES,
        )

    # per-rule warnings / unreachable
    rules = data.get("rules") if isinstance(data.get("rules"), list) else []
    for r in rules[:200]:
        if not isinstance(r, dict):
            continue
        try:
            idx = int(r.get("idx"))
        except Exception:
            idx = -1
        nth = idx + 1 if idx >= 0 else 0
        path = f"endpoints[{idx}]" if idx >= 0 else "endpoints"

        unreach = r.get("unreachable") if isinstance(r.get("unreachable"), list) else []
        if unreach:
            targets = [str(x).strip() for x in unreach if str(x).strip()]
            if targets:
                show = ", ".join(targets[:3])
                if len(targets) > 3:
                    show += f" 等 {len(targets)} 个"
                prefix = f"第 {nth} 条规则" if nth > 0 else "规则"
                _append_precheck_issue(
                    out_issues,
                    seen,
                    PoolValidationIssue(
                        path=path,
                        message=f"{prefix}目标不可达：{show}",
                        severity="warning",
                        code="target_unreachable",
                    ),
                    _SAVE_PRECHECK_MAX_ISSUES,
                )

        warns = r.get("warnings") if isinstance(r.get("warnings"), list) else []
        for w in warns[:6]:
            msg = str(w or "").strip()
            if not msg:
                continue
            prefix = f"第 {nth} 条规则预检提示：" if nth > 0 else "规则预检提示："
            _append_precheck_issue(
                out_issues,
                seen,
                PoolValidationIssue(path=path, message=f"{prefix}{msg}", severity="warning", code="runtime_warning"),
                _SAVE_PRECHECK_MAX_ISSUES,
            )

    summary = data.get("summary") if isinstance(data.get("summary"), dict) else {}
    return {
        "ok": True,
        "issues": out_issues,
        "summary": {
            "enabled": True,
            "source": "agent_netprobe_rules",
            "rules_total": int(summary.get("rules_total") or len(rules_payload)),
            "targets_total": int(summary.get("targets_total") or 0),
            "rules_unreachable": int(summary.get("rules_unreachable") or 0),
            "targets_unreachable": int(summary.get("targets_unreachable") or 0),
            "issues": len(out_issues),
        },
    }


@router.post("/api/nodes/{node_id}/pool")
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
    is_async_job = bool(isinstance(payload, dict) and payload.get("_async_job") is True)

    unlock_sync_ids: set[str] = set()
    if isinstance(payload, dict):
        raw_unlock = payload.get("unlock_sync_ids")
        if isinstance(raw_unlock, list):
            for x in raw_unlock[:256]:
                sid = str(x or "").strip()
                if sid:
                    unlock_sync_ids.add(sid)

    sanitize_pool(pool)
    existing_pool: Dict[str, Any]
    try:
        existing_pool = await load_pool_for_node(node)
    except Exception:
        existing_pool = {}
    existing_pool = _normalize_pool_dict(existing_pool)
    pool = _merge_submitted_pool_for_user(user, existing_pool, pool)
    sanitize_pool(pool)

    # Prevent editing/deleting synced receiver rules from UI
    try:
        locked: Dict[str, Any] = {}
        for ep in existing_pool.get("endpoints") or []:
            if not isinstance(ep, dict):
                continue
            ex0 = ep.get("extra_config") or {}
            if not isinstance(ex0, dict):
                ex0 = {}
            sid = ex0.get("sync_id")
            if sid and (
                ex0.get("sync_lock") is True
                or ex0.get("sync_role") == "receiver"
                or ex0.get("intranet_lock") is True
                or ex0.get("intranet_role") == "client"
            ):
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
                ex.pop("intranet_updated_at", None)
                return {
                    "listen": e.get("listen"),
                    "remotes": e.get("remotes") or [],
                    "disabled": bool(e.get("disabled", False)),
                    "balance": e.get("balance"),
                    "protocol": e.get("protocol"),
                    "extra_config": ex,
                }

            for sid, old_ep in locked.items():
                if str(sid) in unlock_sync_ids:
                    # 临时解锁：允许本次请求修改/删除该同步规则
                    continue
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

    # Save-time validation: format/conflict errors + static warnings
    static_warnings: List[PoolValidationIssue] = []
    try:
        static_warnings = validate_pool_inplace(pool)
    except PoolValidationError as exc:
        return JSONResponse({"ok": False, "error": str(exc), "issues": [i.__dict__ for i in exc.issues]}, status_code=400)
    except Exception as exc:
        return JSONResponse({"ok": False, "error": f"保存失败：规则校验异常（{exc}）"}, status_code=500)

    runtime_precheck: Dict[str, Any]
    # Async jobs should return quickly; runtime netprobe is kept for sync path only.
    skip_runtime_precheck = bool(is_async_job)
    if _SAVE_PRECHECK_ENABLED and (not skip_runtime_precheck):
        try:
            runtime_precheck = await _run_pool_save_precheck(node, pool)
        except Exception as exc:
            runtime_precheck = {
                "issues": [
                    PoolValidationIssue(
                        path="endpoints",
                        message=f"预检失败：保存前探测发生异常（{exc}）",
                        severity="warning",
                        code="precheck_exception",
                    )
                ],
                "summary": {"enabled": True, "source": "save_precheck", "error": "exception"},
            }
    elif skip_runtime_precheck:
        runtime_precheck = {
            "issues": [],
            "summary": {"enabled": False, "source": "save_precheck_skipped_async", "skipped": True},
        }
    else:
        runtime_precheck = {
            "issues": [],
            "summary": {"enabled": False, "source": "save_precheck_disabled"},
        }
    precheck_issues: List[PoolValidationIssue] = []
    precheck_seen: set[str] = set()
    for i in static_warnings:
        _append_precheck_issue(precheck_issues, precheck_seen, i, _SAVE_PRECHECK_MAX_ISSUES)
    for i in (runtime_precheck.get("issues") or []):
        if isinstance(i, PoolValidationIssue):
            _append_precheck_issue(precheck_issues, precheck_seen, i, _SAVE_PRECHECK_MAX_ISSUES)

    try:
        upsert_rule_owner_map(node_id=node_id, pool=pool)
    except Exception:
        # Ownership map is best-effort; do not block save path.
        pass

    # Store desired pool on panel. Agent will pull it on next report.
    try:
        desired_ver, _ = set_desired_pool(node_id, pool)
    except Exception as exc:
        return JSONResponse({"ok": False, "error": f"保存失败：写入面板配置时异常（{exc}）"}, status_code=500)

    # Apply in background: do not block HTTP response
    try:
        schedule_apply_pool(node, pool)
    except Exception as exc:
        return JSONResponse({"ok": False, "error": f"保存失败：下发任务创建失败（{exc}）"}, status_code=500)

    return {
        "ok": True,
        "pool": _filter_pool_for_user(user, pool),
        "desired_version": desired_ver,
        "queued": True,
        "note": "waiting agent report",
        "precheck": {
            "issues": [i.__dict__ for i in precheck_issues],
            "summary": runtime_precheck.get("summary") if isinstance(runtime_precheck.get("summary"), dict) else {},
        },
    }


@router.post("/api/nodes/{node_id}/pool_async")
async def api_pool_set_async(node_id: int, payload: Dict[str, Any], user: str = Depends(require_login)):
    node = get_node(node_id)
    if not node:
        return JSONResponse({"ok": False, "error": "节点不存在"}, status_code=404)
    if not isinstance(payload, dict):
        return JSONResponse({"ok": False, "error": "payload 无效"}, status_code=400)

    pool = payload.get("pool")
    if pool is None:
        pool = payload
    if not isinstance(pool, dict):
        return JSONResponse({"ok": False, "error": "请求缺少 pool 字段"}, status_code=400)

    unlock_ids: List[str] = []
    raw_unlock = payload.get("unlock_sync_ids")
    if isinstance(raw_unlock, list):
        for x in raw_unlock[:256]:
            sid = str(x or "").strip()
            if sid:
                unlock_ids.append(sid)

    job_payload: Dict[str, Any] = {"pool": pool}
    if unlock_ids:
        job_payload["unlock_sync_ids"] = unlock_ids

    job = _enqueue_pool_job(
        node_id=int(node_id),
        kind="pool_save",
        payload=job_payload,
        user=user,
        meta={"action": "pool_save"},
    )
    return {"ok": True, "job": job}


@router.post("/api/nodes/{node_id}/rule_delete")
async def api_rule_delete(node_id: int, payload: Dict[str, Any], user: str = Depends(require_login)):
    """Delete one endpoint by index (best-effort immediate queue).

    This endpoint is intentionally lightweight and does not run full save-time precheck,
    so UI single-rule delete won't be blocked by unrelated validation/precheck noise.
    """
    node = get_node(node_id)
    if not node:
        return JSONResponse({"ok": False, "error": "节点不存在"}, status_code=404)

    try:
        idx = int((payload or {}).get("idx"))
    except Exception:
        idx = -1
    if idx < 0:
        return JSONResponse({"ok": False, "error": "idx 无效"}, status_code=400)

    unlock_sync_ids: set[str] = set()
    raw_unlock = (payload or {}).get("unlock_sync_ids")
    if isinstance(raw_unlock, list):
        for x in raw_unlock[:256]:
            sid = str(x or "").strip()
            if sid:
                unlock_sync_ids.add(sid)

    user_ref = _resolve_rule_user(user)
    scoped = is_rule_owner_scoped(user_ref)
    pool = _normalize_pool_dict(await load_pool_for_node(node))
    eps = pool.get("endpoints")
    if not isinstance(eps, list):
        eps = []
    if scoped:
        visible = _visible_endpoint_tuples(user_ref, pool)
        if idx >= len(visible):
            return JSONResponse({"ok": False, "error": "规则不存在或已删除"}, status_code=404)
        idx = int(visible[idx][0])
    if idx >= len(eps):
        return JSONResponse({"ok": False, "error": "规则不存在或已删除"}, status_code=404)

    ep = eps[idx] if isinstance(eps[idx], dict) else {}
    if scoped and not can_access_rule_endpoint(user_ref, ep):
        return JSONResponse({"ok": False, "error": "规则不存在或已删除"}, status_code=404)
    ex = ep.get("extra_config") if isinstance(ep.get("extra_config"), dict) else {}

    expected_key = str((payload or {}).get("expected_key") or "").strip()
    if expected_key:
        actual_key = _rule_key_for_endpoint(ep)
        if actual_key != expected_key:
            return JSONResponse(
                {
                    "ok": False,
                    "error": "规则索引已过期，请刷新后重试",
                    "code": "stale_index",
                    "actual_key": actual_key,
                },
                status_code=409,
            )

    sid = str(ex.get("sync_id") or "").strip() if isinstance(ex, dict) else ""
    allow_unlock = bool(sid and sid in unlock_sync_ids)
    if isinstance(ex, dict):
        if (ex.get("sync_lock") is True or ex.get("sync_role") == "receiver") and not allow_unlock:
            return JSONResponse(
                {"ok": False, "error": "该规则由发送机同步生成，已锁定不可删除，请在发送机节点操作。"},
                status_code=403,
            )
        if ex.get("intranet_lock") is True or ex.get("intranet_role") == "client":
            return JSONResponse(
                {"ok": False, "error": "该规则由公网入口同步生成，已锁定不可删除，请在公网入口节点操作。"},
                status_code=403,
            )

    del eps[idx]
    pool["endpoints"] = eps

    try:
        desired_ver, _ = set_desired_pool(node_id, pool)
    except Exception as exc:
        return JSONResponse({"ok": False, "error": f"删除失败：写入面板配置时异常（{exc}）"}, status_code=500)
    try:
        schedule_apply_pool(node, pool)
    except Exception as exc:
        return JSONResponse({"ok": False, "error": f"删除失败：下发任务创建失败（{exc}）"}, status_code=500)
    return {
        "ok": True,
        "pool": _filter_pool_for_user(user, pool),
        "desired_version": desired_ver,
        "queued": True,
        "note": "waiting agent report",
    }


@router.post("/api/nodes/{node_id}/rule_delete_async")
async def api_rule_delete_async(node_id: int, payload: Dict[str, Any], user: str = Depends(require_login)):
    node = get_node(node_id)
    if not node:
        return JSONResponse({"ok": False, "error": "节点不存在"}, status_code=404)
    if not isinstance(payload, dict):
        return JSONResponse({"ok": False, "error": "payload 无效"}, status_code=400)

    idx_meta = -1
    try:
        idx_meta = int((payload or {}).get("idx"))
    except Exception:
        idx_meta = -1

    job = _enqueue_pool_job(
        node_id=int(node_id),
        kind="rule_delete",
        payload=dict(payload),
        user=user,
        meta={
            "action": "rule_delete",
            "idx": int(idx_meta),
        },
    )
    return {"ok": True, "job": job}


@router.get("/api/nodes/{node_id}/pool_jobs/{job_id}")
async def api_pool_job_get(node_id: int, job_id: str, user: str = Depends(require_login)):
    jid = str(job_id or "").strip()
    if not jid:
        return JSONResponse({"ok": False, "error": "job_id 不能为空"}, status_code=400)
    with _POOL_JOBS_LOCK:
        _prune_pool_jobs_locked()
        job = _POOL_JOBS.get(jid)
        if not isinstance(job, dict) or int(job.get("node_id") or 0) != int(node_id):
            return JSONResponse({"ok": False, "error": "任务不存在或已过期"}, status_code=404)
        return {"ok": True, "job": _pool_job_view(job, include_result=True)}


@router.post("/api/nodes/{node_id}/pool_jobs/{job_id}/retry")
async def api_pool_job_retry(node_id: int, job_id: str, user: str = Depends(require_login)):
    jid = str(job_id or "").strip()
    if not jid:
        return JSONResponse({"ok": False, "error": "job_id 不能为空"}, status_code=400)

    kind = ""
    payload: Dict[str, Any] = {}
    meta: Dict[str, Any] = {}
    with _POOL_JOBS_LOCK:
        _prune_pool_jobs_locked()
        job = _POOL_JOBS.get(jid)
        if not isinstance(job, dict) or int(job.get("node_id") or 0) != int(node_id):
            return JSONResponse({"ok": False, "error": "任务不存在或已过期"}, status_code=404)
        st = str(job.get("status") or "")
        if st not in ("error", "success"):
            return JSONResponse({"ok": False, "error": "任务仍在执行中，请稍后再试"}, status_code=409)
        kind = str(job.get("kind") or "")
        if kind not in ("pool_save", "rule_delete"):
            return JSONResponse({"ok": False, "error": "不支持该任务类型重试"}, status_code=400)
        payload0 = job.get("_payload")
        if not isinstance(payload0, dict):
            return JSONResponse({"ok": False, "error": "原任务缺少可重试参数"}, status_code=400)
        payload = dict(payload0)
        meta0 = job.get("meta")
        if isinstance(meta0, dict):
            meta = dict(meta0)

    nj = _enqueue_pool_job(node_id=int(node_id), kind=kind, payload=payload, user=user, meta=meta)
    return {"ok": True, "job": nj}


@router.post("/api/nodes/{node_id}/purge")
async def api_node_purge(
    request: Request,
    node_id: int,
    payload: Dict[str, Any],
    user: str = Depends(require_login),
):
    """Dangerous: clear all endpoints on a node (including locked/synced rules)."""

    confirm_text = str((payload or {}).get("confirm_text") or "").strip()
    if confirm_text != "确认删除":
        return JSONResponse({"ok": False, "error": "确认文本不匹配（需要完整输入：确认删除）"}, status_code=400)

    node = get_node(node_id)
    if not node:
        return JSONResponse({"ok": False, "error": "节点不存在"}, status_code=404)

    # Load current pool snapshot (desired > report > agent)
    cur_pool = await load_pool_for_node(node)

    # Collect sync pairs so we can remove peer rules too (avoid leaving orphaned locked rules)
    peer_tasks: List[tuple[int, str]] = []  # (peer_node_id, sync_id)
    seen_pairs: set[tuple[int, str]] = set()

    for ep in (cur_pool.get("endpoints") or []):
        if not isinstance(ep, dict):
            continue
        ex = ep.get("extra_config") or {}
        if not isinstance(ex, dict):
            continue
        sid = str(ex.get("sync_id") or "").strip()
        if not sid:
            continue

        peer_id = 0

        # WSS node-to-node sync
        role = str(ex.get("sync_role") or "").strip()
        if role == "sender":
            try:
                peer_id = int(ex.get("sync_peer_node_id") or 0)
            except Exception:
                peer_id = 0
        elif role == "receiver":
            try:
                peer_id = int(ex.get("sync_from_node_id") or 0)
            except Exception:
                peer_id = 0

        # Intranet tunnel sync (server/client)
        if peer_id <= 0:
            irole = str(ex.get("intranet_role") or "").strip()
            if irole in ("server", "client"):
                try:
                    peer_id = int(ex.get("intranet_peer_node_id") or 0)
                except Exception:
                    peer_id = 0

        if peer_id > 0 and peer_id != int(node_id):
            key = (peer_id, sid)
            if key not in seen_pairs:
                seen_pairs.add(key)
                peer_tasks.append((peer_id, sid))

    # Remove peers first (best effort). We do not block purge if peers fail.
    peers_cleared: List[int] = []
    for peer_id, sid in peer_tasks:
        peer = get_node(int(peer_id))
        if not peer:
            continue
        try:
            peer_pool = await load_pool_for_node(peer)
            remove_endpoints_by_sync_id(peer_pool, sid)
            set_desired_pool(int(peer_id), peer_pool)
            schedule_apply_pool(peer, peer_pool)
            peers_cleared.append(int(peer_id))
        except Exception:
            continue

    # Clear local endpoints (keep other pool keys as-is)
    new_pool = dict(cur_pool)
    new_pool["endpoints"] = []

    desired_ver, _ = set_desired_pool(node_id, new_pool)
    schedule_apply_pool(node, new_pool)

    return {
        "ok": True,
        "node_id": int(node_id),
        "cleared": True,
        "peer_nodes_touched": sorted(set(peers_cleared)),
        "desired_version": desired_ver,
        "queued": True,
    }


@router.post("/api/nodes/create")
async def api_nodes_create(request: Request, user: str = Depends(require_login)):
    """Dashboard 快速接入节点（弹窗模式）。返回 JSON，前端可直接跳转节点详情页。"""
    try:
        data = await request.json()
    except Exception:
        data = {}

    name = str(data.get("name") or "").strip()
    ip_address = str(data.get("ip_address") or "").strip()
    scheme = str(data.get("scheme") or "http").strip().lower()
    verify_tls = bool(data.get("verify_tls")) if "verify_tls" in data else None
    is_private = bool(data.get("is_private") or False)
    is_website = data.get("is_website")
    website_root_base = str(data.get("website_root_base") or "").strip()
    group_name = str(data.get("group_name") or "").strip() or "默认分组"

    if scheme not in ("http", "https"):
        return JSONResponse({"ok": False, "error": "协议仅支持 http 或 https"}, status_code=400)
    if not ip_address:
        return JSONResponse({"ok": False, "error": "节点地址不能为空"}, status_code=400)

    # 端口在 UI 中隐藏：默认 18700；如用户自带 :port 则兼容解析（仍不展示）
    if "://" not in ip_address:
        ip_address = f"{scheme}://{ip_address}"

    port_value = DEFAULT_AGENT_PORT
    host, parsed_port, has_port, scheme = split_host_and_port(ip_address, port_value)
    if verify_tls is None:
        verify_tls = scheme == "https"
    if not host:
        return JSONResponse({"ok": False, "error": "节点地址不能为空"}, status_code=400)
    if has_port:
        port_value = parsed_port

    base_url = f"{scheme}://{format_host_for_url(host)}:{port_value}"
    api_key = generate_api_key()

    display_name = name or extract_ip_for_display(base_url)
    role = "website" if bool(is_website) else "normal"
    root_base = website_root_base.strip()
    if role == "website" and not root_base:
        root_base = "/www"
    if role != "website":
        root_base = ""
    node_id = add_node(
        display_name,
        base_url,
        api_key,
        verify_tls=bool(verify_tls),
        is_private=is_private,
        group_name=group_name,
        role=role,
        website_root_base=root_base,
    )

    # 创建完成后，进入节点详情页时自动弹出“接入命令”窗口
    try:
        request.session["show_install_cmd"] = True
    except Exception:
        pass

    return JSONResponse({"ok": True, "node_id": node_id, "redirect_url": f"/nodes/{node_id}"})


@router.post("/api/nodes/{node_id}/update")
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

    # is_private: only update when provided
    if "is_private" in data:
        is_private = bool(data.get("is_private") or False)
    else:
        is_private = bool(node.get("is_private", 0))

    # verify_tls: only update when provided
    if "verify_tls" in data:
        verify_tls = bool(data.get("verify_tls")) if "verify_tls" in data else None
    else:
        verify_tls = bool(node.get("verify_tls", 0))

    # role: only update when provided
    if "is_website" in data:
        role = "website" if bool(data.get("is_website")) else "normal"
    else:
        role = str(node.get("role") or "normal").strip().lower() or "normal"
        if role not in ("normal", "website"):
            role = "normal"

    # website root base
    if "website_root_base" in data:
        website_root_base = str(data.get("website_root_base") or "").strip()
    else:
        website_root_base = str(node.get("website_root_base") or "").strip()

    if role == "website" and not website_root_base:
        website_root_base = "/www"
    if role != "website":
        website_root_base = ""

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
        h, p, has_p, parsed_scheme = split_host_and_port(ip_full, fallback_port)
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

    base_url = f"{scheme}://{format_host_for_url(host)}"
    if has_port and port_value:
        base_url += f":{int(port_value)}"

    # prevent duplicates
    other = get_node_by_base_url(base_url)
    if other and int(other.get("id") or 0) != int(node_id):
        return JSONResponse({"ok": False, "error": "该节点地址已被其他节点使用"}, status_code=400)

    # name
    if name_in is None:
        name = str(node.get("name") or "").strip() or extract_ip_for_display(base_url)
    else:
        name = str(name_in or "").strip() or extract_ip_for_display(base_url)

    update_node_basic(
        int(node_id),
        name,
        base_url,
        str(node.get("api_key") or ""),
        verify_tls=bool(verify_tls),
        is_private=is_private,
        group_name=group_name,
        role=role,
        website_root_base=website_root_base,
    )

    # Return updated fields for client-side UI refresh
    updated = get_node(int(node_id)) or {}
    display_ip = extract_ip_for_display(str(updated.get("base_url") or base_url))

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
                "is_private": bool(updated.get("is_private") or is_private),
                "role": str(updated.get("role") or role),
                "website_root_base": str(updated.get("website_root_base") or website_root_base),
            },
        }
    )


@router.get("/api/nodes")
async def api_nodes_list(user: str = Depends(require_login)):
    out = []
    for n in filter_nodes_for_user(user, list_nodes()):
        out.append(
            {
                "id": int(n["id"]),
                "name": n["name"],
                "base_url": n["base_url"],
                "group_name": n.get("group_name"),
                "is_private": bool(n.get("is_private") or 0),
                "role": n.get("role") or "normal",
                "website_root_base": n.get("website_root_base") or "",
            }
        )
    return {"ok": True, "nodes": out}


@router.post("/api/nodes/{node_id}/apply")
async def api_apply(request: Request, node_id: int, user: str = Depends(require_login)):
    node = get_node(node_id)
    if not node:
        return JSONResponse({"ok": False, "error": "节点不存在"}, status_code=404)
    try:
        data = await agent_post(node["base_url"], node["api_key"], "/api/v1/apply", {}, node_verify_tls(node))
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



@router.post("/api/nodes/{node_id}/traffic/reset")
async def api_reset_traffic(request: Request, node_id: int, user: str = Depends(require_login)):
    """Reset rule traffic counters on a node."""
    node = get_node(node_id)
    if not node:
        return JSONResponse({"ok": False, "error": "节点不存在"}, status_code=404)
    try:
        data = await agent_post(
            node["base_url"],
            node["api_key"],
            "/api/v1/traffic/reset",
            {},
            node_verify_tls(node),
            timeout=10.0,
        )
        return data
    except Exception as exc:
        # Fallback: queue via agent push-report (works for private/unreachable nodes)
        try:
            new_ver = bump_traffic_reset_version(int(node_id))
            return {
                "ok": True,
                "queued": True,
                "desired_reset_version": new_ver,
                "direct_error": str(exc),
                "message": "Agent 直连失败，已改为排队等待节点上报后自动执行",
            }
        except Exception as exc2:
            return JSONResponse(
                {"ok": False, "error": f"{exc}; 同时排队失败：{exc2}"},
                status_code=502,
            )


@router.get("/api/nodes/{node_id}/stats")
async def api_stats(request: Request, node_id: int, force: int = 0, user: str = Depends(require_login)):
    node = get_node(node_id)
    if not node:
        return JSONResponse({"ok": False, "error": "节点不存在"}, status_code=404)

    pool_for_scope: Optional[Dict[str, Any]] = None
    scoped_rule_view = is_rule_owner_scoped(user)
    # Push-report cache (unless forced)
    if not force and is_report_fresh(node):
        rep = get_last_report(node_id)
        if isinstance(rep, dict) and isinstance(rep.get("stats"), dict):
            out = dict(rep["stats"])
            out["source"] = "report"
            # Use report receive time as series timestamp.
            # If we always use "now" here, repeated reads of an unchanged cached report
            # will create artificial zero/peak alternation in rate charts.
            try:
                ts_ms = int(out.get("ts_ms") or 0)
            except Exception:
                ts_ms = 0
            if ts_ms <= 0:
                try:
                    seen = str(node.get("last_seen_at") or "").strip()
                    dt = datetime.strptime(seen, "%Y-%m-%d %H:%M:%S")
                    ts_ms = int(dt.timestamp() * 1000)
                except Exception:
                    ts_ms = 0
            if ts_ms <= 0:
                try:
                    ts_ms = int(time.time() * 1000)
                except Exception:
                    ts_ms = 0
            if ts_ms > 0:
                out["ts_ms"] = ts_ms
            if scoped_rule_view:
                try:
                    pool_for_scope = await load_pool_for_node(node)
                except Exception:
                    pool_for_scope = {}
                out = _filter_stats_payload_for_user(user, _normalize_pool_dict(pool_for_scope), out)
            return out

    try:
        data = await agent_get(node["base_url"], node["api_key"], "/api/v1/stats", node_verify_tls(node))

        # Provide a stable server-side timestamp for frontend history alignment.
        try:
            if isinstance(data, dict):
                data["ts_ms"] = int(time.time() * 1000)
                data.setdefault("source", "agent")
        except Exception:
            pass

        # Fallback sampling: if push-report is not used, persist history from direct stats.
        # Best-effort: never fail the request.
        try:
            if isinstance(data, dict) and data.get("ok") is True:
                ingest_stats_snapshot(node_id=node_id, stats=data)
        except Exception:
            pass

        if scoped_rule_view and isinstance(data, dict):
            if pool_for_scope is None:
                try:
                    pool_for_scope = await load_pool_for_node(node)
                except Exception:
                    pool_for_scope = {}
            data = _filter_stats_payload_for_user(user, _normalize_pool_dict(pool_for_scope), data)

        return data
    except Exception as exc:
        # Return 200 with ok=false to keep frontend error message stable.
        return {"ok": False, "error": str(exc), "rules": []}


@router.get("/api/nodes/{node_id}/stats_history")
async def api_stats_history(
    request: Request,
    node_id: int,
    key: str = "__all__",
    window_ms: int = 10 * 60 * 1000,
    limit: int = 0,
    user: str = Depends(require_login),
):
    """Return persistent traffic/connection history series for a node.

    Notes:
      - The series is stored on the panel (SQLite) and will survive browser refresh/close.
      - One extra point before the window is included (when available) so the UI can compute rate.
    """
    node = get_node(node_id)
    if not node:
        return JSONResponse({"ok": False, "error": "节点不存在"}, status_code=404)

    cfg = stats_history_config() if callable(stats_history_config) else {}
    try:
        retention_days = int((cfg or {}).get("retention_days") or 7)
    except Exception:
        retention_days = 7
    if retention_days < 1:
        retention_days = 1
    if retention_days > 90:
        retention_days = 90
    max_win_ms = retention_days * 24 * 3600 * 1000

    # Clamp window to protect DB and payload size (bounded by retention days).
    try:
        win = int(window_ms)
    except Exception:
        win = 10 * 60 * 1000
    if win < 60 * 1000:
        win = 60 * 1000
    if win > max_win_ms:
        win = max_win_ms

    # Auto-select a sensible point limit when client does not provide one.
    try:
        lim = int(limit)
    except Exception:
        lim = 0
    if lim <= 0:
        try:
            sample_interval_sec = float((cfg or {}).get("sample_interval_sec") or 10.0)
        except Exception:
            sample_interval_sec = 10.0
        if sample_interval_sec < 1.0:
            sample_interval_sec = 1.0
        # +32 to keep a small buffer and include previous-boundary sample.
        lim = int((float(win) / 1000.0) / sample_interval_sec) + 32
    if lim < 200:
        lim = 200
    if lim > 200000:
        lim = 200000

    now_ms = int(time.time() * 1000)
    from_ms = now_ms - win
    if from_ms < 0:
        from_ms = 0

    k = (key or "__all__").strip() or "__all__"
    if is_rule_owner_scoped(user):
        try:
            scoped_pool = _normalize_pool_dict(await load_pool_for_node(node))
        except Exception:
            scoped_pool = {"endpoints": []}
        allowed_keys = _visible_rule_history_keys(user, scoped_pool)
        if k == "__all__":
            # Scoped users cannot read aggregated series that may include hidden rules.
            return {
                "ok": True,
                "node_id": int(node_id),
                "key": k,
                "from_ts_ms": int(from_ms),
                "to_ts_ms": int(now_ms),
                "window_ms": int(win),
                "limit": int(lim),
                "t": [],
                "rx": [],
                "tx": [],
                "conn": [],
                "source": "db_scoped",
                "config": stats_history_config(),
            }
        if k not in allowed_keys:
            return JSONResponse({"ok": False, "error": "规则不存在或无权限"}, status_code=403)

    try:
        rows = list_rule_stats_series(
            node_id=int(node_id),
            rule_key=k,
            from_ts_ms=int(from_ms),
            to_ts_ms=int(now_ms),
            limit=int(lim),
            include_prev=True,
        )
    except Exception:
        rows = []

    t: List[int] = []
    rx: List[int] = []
    tx: List[int] = []
    conn: List[int] = []
    for r in rows:
        if not isinstance(r, dict):
            continue
        try:
            ts = int(r.get("ts_ms") or 0)
        except Exception:
            ts = 0
        if ts <= 0:
            continue
        try:
            rrx = int(r.get("rx_bytes") or 0)
        except Exception:
            rrx = 0
        try:
            rtx = int(r.get("tx_bytes") or 0)
        except Exception:
            rtx = 0
        try:
            rc = int(r.get("connections_active") or 0)
        except Exception:
            rc = 0
        t.append(ts)
        rx.append(max(0, rrx))
        tx.append(max(0, rtx))
        conn.append(max(0, rc))

    return {
        "ok": True,
        "node_id": int(node_id),
        "key": k,
        "from_ts_ms": int(from_ms),
        "to_ts_ms": int(now_ms),
        "window_ms": int(win),
        "limit": int(lim),
        "t": t,
        "rx": rx,
        "tx": tx,
        "conn": conn,
        "source": "db",
        "config": stats_history_config(),
    }


@router.post("/api/nodes/{node_id}/stats_history/clear")
async def api_stats_history_clear(
    request: Request,
    node_id: int,
    user: str = Depends(require_login),
):
    """Clear persistent history for a node."""
    node = get_node(node_id)
    if not node:
        return JSONResponse({"ok": False, "error": "节点不存在"}, status_code=404)

    try:
        deleted = clear_rule_stats_samples(int(node_id))
    except Exception as exc:
        return JSONResponse({"ok": False, "error": str(exc)}, status_code=500)

    return {
        "ok": True,
        "node_id": int(node_id),
        "deleted": int(deleted or 0),
    }


@router.get("/api/nodes/{node_id}/sys")
async def api_sys(request: Request, node_id: int, cached: int = 0, user: str = Depends(require_login)):
    """节点系统信息：CPU/内存/硬盘/交换/在线时长/流量/实时速率。"""
    node = get_node(node_id)
    if not node:
        return JSONResponse({"ok": False, "error": "节点不存在"}, status_code=404)

    sys_data = None
    source = None

    # 1) Push-report cache（更快、更稳定）
    if cached:
        rep = get_last_report(node_id)
        if isinstance(rep, dict) and isinstance(rep.get("sys"), dict):
            sys_data = dict(rep["sys"])  # copy
            sys_data["stale"] = not is_report_fresh(node)
            source = "report"
    else:
        if is_report_fresh(node):
            rep = get_last_report(node_id)
            if isinstance(rep, dict) and isinstance(rep.get("sys"), dict):
                sys_data = dict(rep["sys"])  # copy
                source = "report"

    # 2) Fallback：直连 Agent
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
            data = await agent_get(node["base_url"], node["api_key"], "/api/v1/sys", node_verify_tls(node))
            if isinstance(data, dict) and data.get("ok") is True:
                sys_data = dict(data)  # copy
                source = "agent"
            else:
                return {"ok": False, "error": (data.get("error") if isinstance(data, dict) else "响应格式异常")}
        except Exception as exc:
            return {"ok": False, "error": str(exc)}

    sys_data["source"] = source or "unknown"
    return {"ok": True, "sys": sys_data}


@router.get("/api/nodes/{node_id}/graph")
async def api_graph(request: Request, node_id: int, user: str = Depends(require_login)):
    node = get_node(node_id)
    if not node:
        return JSONResponse({"ok": False, "error": "节点不存在"}, status_code=404)
    desired_ver, desired_pool = get_desired_pool(node_id)
    pool = desired_pool if isinstance(desired_pool, dict) else None

    if pool is None and is_report_fresh(node):
        rep = get_last_report(node_id)
        if isinstance(rep, dict) and isinstance(rep.get("pool"), dict):
            pool = rep["pool"]

    if pool is None:
        try:
            data = await agent_get(node["base_url"], node["api_key"], "/api/v1/pool", node_verify_tls(node))
            pool = data.get("pool") if isinstance(data, dict) else None
        except Exception as exc:
            return JSONResponse({"ok": False, "error": str(exc)}, status_code=502)

    if not isinstance(pool, dict):
        pool = {}
    pool = _filter_pool_for_user(user, pool)
    endpoints = pool.get("endpoints", []) if isinstance(pool, dict) else []
    elements: List[Dict[str, Any]] = []

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


@router.post("/api/traffic/reset_all")
async def api_reset_all_traffic(request: Request, user: str = Depends(require_login)):
    """Reset rule traffic counters for all nodes.

    Strategy:
    - Try direct panel -> agent call first (retry once).
    - If direct call fails, queue a signed push-report command (agent -> panel),
      so private/unreachable nodes will reset next time they report.
    """
    nodes = filter_nodes_for_user(user, list_nodes())

    if not nodes:
        return {"ok": True, "total": 0, "ok_count": 0, "queued_count": 0, "fail_count": 0, "results": []}

    sem = asyncio.Semaphore(10)

    async def _direct(n: Dict[str, Any]) -> Dict[str, Any]:
        nid = int(n.get("id") or 0)
        name = n.get("name") or f"Node-{nid}"
        base_url = n.get("base_url", "")
        api_key = n.get("api_key", "")
        verify_tls = node_verify_tls(n)

        # 1) Try direct reset (retry once)
        last_err: str = ""
        async with sem:
            for attempt in range(2):
                try:
                    data = await agent_post(
                        base_url,
                        api_key,
                        "/api/v1/traffic/reset",
                        {},
                        verify_tls,
                        timeout=10.0,
                    )
                    ok = bool((data or {}).get("ok", True)) if isinstance(data, dict) else True
                    return {
                        "node_id": nid,
                        "name": name,
                        "ok": ok,
                        "queued": False,
                        "detail": data if isinstance(data, dict) else {},
                    }
                except Exception as exc:
                    last_err = str(exc)
                    if attempt == 0:
                        await asyncio.sleep(0.2)

        # direct failed (exception)
        return {"node_id": nid, "name": name, "ok": False, "queued": False, "direct_error": last_err}

    direct_results = await asyncio.gather(*[_direct(n) for n in nodes])

    # 2) Queue fallback sequentially to avoid DB-lock contention
    results: List[Dict[str, Any]] = []
    for r in direct_results:
        if r.get("ok") or not r.get("direct_error"):
            results.append(r)
            continue

        nid = int(r.get("node_id") or 0)
        name = r.get("name") or f"Node-{nid}"
        last_err = str(r.get("direct_error") or "")
        try:
            new_ver = bump_traffic_reset_version(nid)
            results.append(
                {
                    "node_id": nid,
                    "name": name,
                    "ok": True,
                    "queued": True,
                    "desired_reset_version": new_ver,
                    "direct_error": last_err,
                }
            )
        except Exception as exc2:
            results.append(
                {"node_id": nid, "name": name, "ok": False, "queued": False, "error": f"{last_err}; queue failed: {exc2}"}
            )

    ok_count = sum(1 for r in results if r.get("ok") and not r.get("queued"))
    queued_count = sum(1 for r in results if r.get("ok") and r.get("queued"))
    fail_count = sum(1 for r in results if not r.get("ok"))

    return {
        "ok": True,
        "total": len(results),
        "ok_count": ok_count,
        "queued_count": queued_count,
        "fail_count": fail_count,
        "results": results,
    }
