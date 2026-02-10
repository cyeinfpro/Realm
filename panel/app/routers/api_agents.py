from __future__ import annotations

import gzip
import json
import os
import time
import uuid
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse

from ..core.deps import require_login
from ..core.paths import STATIC_DIR
from ..db import (
    add_certificate,
    add_site_event,
    delete_certificates_by_node,
    delete_sites_by_node,
    get_task,
    get_site,
    get_desired_pool,
    get_group_orders,
    get_node,
    list_sites,
    list_tasks,
    list_nodes,
    set_agent_rollout_all,
    set_desired_pool,
    set_desired_pool_exact,
    set_desired_pool_version_exact,
    update_certificate,
    update_node_basic,
    update_agent_status,
    update_node_report,
    update_task,
)
from ..services.agent_commands import sign_cmd, single_rule_ops
from ..services.adaptive_lb import suggest_adaptive_pool_patch
from ..services.assets import agent_asset_urls, file_sha256, panel_public_base_url, parse_agent_version_from_ua, read_latest_agent_version
from ..services.node_status import is_report_fresh
from ..services.stats_history import ingest_stats_snapshot

router = APIRouter()


def _parse_int_env(name: str, default: int) -> int:
    raw = (os.getenv(name) or "").strip()
    if not raw:
        return int(default)
    try:
        return int(float(raw))
    except Exception:
        return int(default)


def _parse_float_env(name: str, default: float) -> float:
    raw = (os.getenv(name) or "").strip()
    if not raw:
        return float(default)
    try:
        return float(raw)
    except Exception:
        return float(default)


_SITE_TASK_TYPES = {"website_env_ensure", "website_env_uninstall", "website_ssl_issue", "website_ssl_renew"}
_SITE_TASK_MAX_ATTEMPTS = max(1, min(30, _parse_int_env("REALM_WEBSITE_OP_MAX_ATTEMPTS", 10)))
_SITE_TASK_RETRY_BASE_SEC = max(1.0, min(120.0, _parse_float_env("REALM_WEBSITE_OP_RETRY_BASE_SEC", 3.0)))
_SITE_TASK_RETRY_MAX_SEC = max(
    _SITE_TASK_RETRY_BASE_SEC,
    min(600.0, _parse_float_env("REALM_WEBSITE_OP_RETRY_MAX_SEC", 60.0)),
)
_SITE_TASK_RUNNING_REDISPATCH_SEC = max(30.0, min(600.0, _parse_float_env("REALM_WEBSITE_RUNNING_REDISPATCH_SEC", 180.0)))

_ENV_CAP_ALIAS = {
    "nginx": "nginx",
    "php": "php-fpm",
    "php-fpm": "php-fpm",
    "phpfpm": "php-fpm",
    "acme": "acme.sh",
    "acme.sh": "acme.sh",
}


def _site_task_backoff_sec(attempt_no: int) -> float:
    n = max(1, int(attempt_no or 1))
    return float(min(_SITE_TASK_RETRY_MAX_SEC, _SITE_TASK_RETRY_BASE_SEC * (2 ** (n - 1))))


def _site_task_progress_for_attempt(attempt_no: int, max_attempts: int) -> int:
    total = max(1, int(max_attempts or 1))
    cur = max(1, min(total, int(attempt_no or 1)))
    if total <= 1:
        return 10
    ratio = float(cur - 1) / float(total - 1)
    return max(8, min(90, int(8 + ratio * 72)))


def _site_task_max_attempts(task: Dict[str, Any]) -> int:
    payload = task.get("payload") if isinstance(task, dict) else None
    raw = None
    if isinstance(payload, dict):
        raw = payload.get("max_attempts")
    try:
        val = int(raw) if raw is not None else int(_SITE_TASK_MAX_ATTEMPTS)
    except Exception:
        val = int(_SITE_TASK_MAX_ATTEMPTS)
    return max(1, min(30, val))


def _site_task_current_attempt(task: Dict[str, Any]) -> int:
    result = task.get("result") if isinstance(task, dict) else None
    if not isinstance(result, dict):
        return 0
    raw = result.get("attempt")
    if raw is None:
        raw = result.get("attempts")
    try:
        val = int(raw or 0)
    except Exception:
        val = 0
    return max(0, val)


def _site_task_retry_ready(task: Dict[str, Any], now_ts: float) -> bool:
    result = task.get("result") if isinstance(task, dict) else None
    if not isinstance(result, dict):
        return True
    try:
        next_retry_ts = float(result.get("next_retry_ts") or 0.0)
    except Exception:
        next_retry_ts = 0.0
    return next_retry_ts <= 0.0 or now_ts >= next_retry_ts


def _site_task_last_dispatched_ts(task: Dict[str, Any]) -> float:
    result = task.get("result") if isinstance(task, dict) else None
    if not isinstance(result, dict):
        return 0.0
    try:
        return float(result.get("last_dispatched_ts") or 0.0)
    except Exception:
        return 0.0


def _normalize_proxy_target(target: str) -> str:
    t = (target or "").strip()
    if not t:
        return ""
    if t.startswith("unix:"):
        return t
    if "://" in t:
        return t
    return f"http://{t}"


def _node_root_base(node: Dict[str, Any]) -> str:
    return str((node or {}).get("website_root_base") or "").strip()


def _normalize_env_cap_name(raw: Any) -> str:
    k = str(raw or "").strip().lower()
    if not k:
        return ""
    return _ENV_CAP_ALIAS.get(k, k)


def _merge_node_env_caps(node: Dict[str, Any], env_data: Any) -> None:
    if not isinstance(node, dict) or not isinstance(env_data, dict):
        return
    caps = node.get("capabilities")
    merged: Dict[str, Any] = dict(caps) if isinstance(caps, dict) else {}
    changed = False
    for key in ("installed", "already"):
        rows = env_data.get(key)
        if not isinstance(rows, list):
            continue
        for item in rows:
            cap = _normalize_env_cap_name(item)
            if not cap:
                continue
            if not bool(merged.get(cap)):
                merged[cap] = True
                changed = True
    if not changed:
        return
    try:
        update_node_basic(
            int(node.get("id") or 0),
            str(node.get("name") or ""),
            str(node.get("base_url") or ""),
            str(node.get("api_key") or ""),
            verify_tls=bool(node.get("verify_tls")),
            is_private=bool(node.get("is_private")),
            group_name=str(node.get("group_name") or "默认分组"),
            capabilities=merged,
            website_root_base=str(node.get("website_root_base") or "").strip(),
        )
    except Exception:
        pass


def _site_event_action(task_type: str) -> str:
    if task_type == "website_ssl_issue":
        return "ssl_issue"
    if task_type == "website_ssl_renew":
        return "ssl_renew"
    return task_type


def _site_task_final_fail(node: Dict[str, Any], task: Dict[str, Any], err_text: str, attempt: int) -> None:
    task_id = int(task.get("id") or 0)
    t = str(task.get("type") or "").strip().lower()
    payload = task.get("payload") if isinstance(task.get("payload"), dict) else {}
    max_attempts = _site_task_max_attempts(task)
    result_payload = {
        "op": t,
        "attempt": int(attempt),
        "attempts": int(attempt),
        "max_attempts": int(max_attempts),
        "reported_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    }
    update_task(task_id, status="failed", progress=100, error=str(err_text or ""), result=result_payload)

    if t in ("website_ssl_issue", "website_ssl_renew"):
        site_id = int(payload.get("site_id") or 0) if isinstance(payload, dict) else 0
        cert_id = int(payload.get("cert_id") or 0) if isinstance(payload, dict) else 0
        if cert_id > 0:
            update_certificate(int(cert_id), status="failed", last_error=str(err_text or ""))
        else:
            site = get_site(int(site_id)) if site_id > 0 else None
            domains = list(site.get("domains") or []) if isinstance(site, dict) else []
            node_id = int((site or {}).get("node_id") or int(node.get("id") or 0))
            if node_id > 0 and domains:
                add_certificate(
                    node_id=node_id,
                    site_id=int(site_id) if site_id > 0 else None,
                    domains=domains,
                    status="failed",
                    last_error=str(err_text or ""),
                )
        if site_id > 0:
            add_site_event(
                int(site_id),
                _site_event_action(t),
                status="failed",
                actor="agent",
                error=str(err_text or ""),
                payload={"task_id": int(task_id), "attempt": int(attempt)},
            )


def _site_task_retry(node: Dict[str, Any], task: Dict[str, Any], err_text: str, attempt: int) -> None:
    task_id = int(task.get("id") or 0)
    t = str(task.get("type") or "").strip().lower()
    max_attempts = _site_task_max_attempts(task)
    backoff = _site_task_backoff_sec(int(attempt))
    next_retry_ts = float(time.time() + backoff)
    result_payload = {
        "op": t,
        "attempt": int(attempt),
        "max_attempts": int(max_attempts),
        "retry_in_sec": float(backoff),
        "next_retry_ts": float(next_retry_ts),
        "reported_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    }
    update_task(
        task_id,
        status="queued",
        progress=_site_task_progress_for_attempt(int(attempt), int(max_attempts)),
        error=str(err_text or ""),
        result=result_payload,
    )
    payload = task.get("payload") if isinstance(task.get("payload"), dict) else {}
    if t in ("website_ssl_issue", "website_ssl_renew"):
        cert_id = int(payload.get("cert_id") or 0)
        if cert_id > 0:
            update_certificate(int(cert_id), status="pending", last_error=str(err_text or ""))


def _site_task_mark_success(node: Dict[str, Any], task: Dict[str, Any], result_data: Dict[str, Any], attempt: int) -> None:
    task_id = int(task.get("id") or 0)
    t = str(task.get("type") or "").strip().lower()
    payload = task.get("payload") if isinstance(task.get("payload"), dict) else {}
    max_attempts = _site_task_max_attempts(task)
    result_payload = dict(result_data or {})
    result_payload["attempt"] = int(attempt)
    result_payload["attempts"] = int(attempt)
    result_payload["max_attempts"] = int(max_attempts)
    result_payload["reported_at"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    update_task(task_id, status="success", progress=100, error="", result=result_payload)

    node_id = int(node.get("id") or 0)
    if t == "website_env_ensure":
        _merge_node_env_caps(node, result_payload)
        return
    if t == "website_env_uninstall":
        if bool(payload.get("purge_data")) and node_id > 0:
            delete_certificates_by_node(node_id)
            delete_sites_by_node(node_id)
        return
    if t not in ("website_ssl_issue", "website_ssl_renew"):
        return

    site_id = int(payload.get("site_id") or 0)
    cert_id = int(payload.get("cert_id") or 0)
    site = get_site(int(site_id)) if site_id > 0 else None
    domains = result_payload.get("domains")
    if not isinstance(domains, list):
        domains = list(site.get("domains") or []) if isinstance(site, dict) else []
    if cert_id > 0:
        update_certificate(
            int(cert_id),
            status="valid",
            domains=list(domains or []),
            not_before=result_payload.get("not_before"),
            not_after=result_payload.get("not_after"),
            renew_at=result_payload.get("renew_at"),
            last_error="",
        )
    elif node_id > 0 and domains:
        add_certificate(
            node_id=node_id,
            site_id=int(site_id) if site_id > 0 else None,
            domains=list(domains),
            status="valid",
            not_before=result_payload.get("not_before"),
            not_after=result_payload.get("not_after"),
            renew_at=result_payload.get("renew_at"),
            last_error="",
        )

    if site_id > 0:
        add_site_event(
            int(site_id),
            _site_event_action(t),
            status="success",
            actor="agent",
            result=result_payload,
            payload={"task_id": int(task_id), "attempt": int(attempt)},
        )


def _apply_site_task_result(node: Dict[str, Any], row: Dict[str, Any]) -> None:
    task_id = int(row.get("task_id") or 0)
    if task_id <= 0:
        return
    task = get_task(task_id)
    if not isinstance(task, dict):
        return
    node_id = int(node.get("id") or 0)
    if int(task.get("node_id") or 0) != node_id:
        return

    t = str(task.get("type") or "").strip().lower()
    if t not in _SITE_TASK_TYPES:
        return

    current_status = str(task.get("status") or "").strip().lower()
    if current_status in ("success", "failed"):
        return

    result_data = row.get("result")
    if not isinstance(result_data, dict):
        result_data = {}
    err_text = str(row.get("error") or result_data.get("error") or "").strip()
    ok = bool(row.get("ok"))
    if ok and result_data.get("ok") is False:
        ok = False
        if not err_text:
            err_text = str(result_data.get("error") or "").strip()

    try:
        attempt = int(row.get("attempt") or 0)
    except Exception:
        attempt = 0
    if attempt <= 0:
        attempt = max(1, _site_task_current_attempt(task))

    max_attempts = _site_task_max_attempts(task)
    if ok:
        _site_task_mark_success(node, task, result_data, attempt)
        return
    if attempt >= max_attempts:
        _site_task_final_fail(node, task, err_text or "任务执行失败", attempt)
        return
    _site_task_retry(node, task, err_text or "任务执行失败", attempt)


def _ingest_site_task_results(node: Dict[str, Any], rows: Any) -> None:
    if not isinstance(rows, list) or not rows:
        return
    for row in rows:
        if not isinstance(row, dict):
            continue
        try:
            _apply_site_task_result(node, row)
        except Exception:
            continue


def _build_website_cmd(task: Dict[str, Any], node: Dict[str, Any], attempt: int) -> Tuple[Optional[Dict[str, Any]], str]:
    t = str(task.get("type") or "").strip().lower()
    task_id = int(task.get("id") or 0)
    payload = task.get("payload") if isinstance(task.get("payload"), dict) else {}
    node_id = int(node.get("id") or 0)
    if t == "website_env_ensure":
        include_php = bool(payload.get("include_php"))
        return {
            "type": t,
            "task_id": int(task_id),
            "attempt": int(attempt),
            "need_nginx": True,
            "need_php": bool(include_php),
            "need_acme": True,
        }, ""

    if t == "website_env_uninstall":
        purge_data = bool(payload.get("purge_data"))
        deep_uninstall = bool(payload.get("deep_uninstall"))
        sites_payload: List[Dict[str, Any]] = []
        if purge_data and node_id > 0:
            for s in list_sites(node_id=node_id):
                if not isinstance(s, dict):
                    continue
                sites_payload.append(
                    {
                        "domains": list(s.get("domains") or []),
                        "root_path": str(s.get("root_path") or ""),
                        "root_base": _node_root_base(node),
                    }
                )
        return {
            "type": t,
            "task_id": int(task_id),
            "attempt": int(attempt),
            "purge_data": bool(purge_data),
            "deep_uninstall": bool(deep_uninstall),
            "sites": sites_payload,
        }, ""

    if t in ("website_ssl_issue", "website_ssl_renew"):
        site_id = int(payload.get("site_id") or 0)
        cert_id = int(payload.get("cert_id") or 0)
        if site_id <= 0:
            return None, "site_id 无效"
        site = get_site(int(site_id))
        if not isinstance(site, dict):
            return None, "站点不存在"
        if int(site.get("node_id") or 0) != node_id:
            return None, "站点与节点不匹配"
        domains = list(site.get("domains") or [])
        if not domains:
            return None, "站点域名为空"
        req_payload = {
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
        }
        return {
            "type": t,
            "task_id": int(task_id),
            "site_id": int(site_id),
            "cert_id": int(cert_id),
            "attempt": int(attempt),
            "request": req_payload,
        }, ""

    return None, "不支持的任务类型"


def _next_site_task_command(node: Dict[str, Any], api_key: str) -> Optional[Dict[str, Any]]:
    node_id = int(node.get("id") or 0)
    if node_id <= 0:
        return None
    try:
        rows = list_tasks(node_id=node_id, limit=200)
    except Exception:
        rows = []
    if not rows:
        return None

    pending: List[Dict[str, Any]] = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        t = str(row.get("type") or "").strip().lower()
        if t not in _SITE_TASK_TYPES:
            continue
        st = str(row.get("status") or "").strip().lower()
        if st not in ("queued", "running"):
            continue
        pending.append(row)
    if not pending:
        return None

    pending.sort(key=lambda x: int(x.get("id") or 0))
    now_ts = float(time.time())

    for task in pending:
        task_id = int(task.get("id") or 0)
        task_type = str(task.get("type") or "").strip().lower()
        if task_id <= 0:
            continue

        status = str(task.get("status") or "").strip().lower()
        if status == "queued" and not _site_task_retry_ready(task, now_ts):
            continue
        if status == "running":
            last_dispatched_ts = _site_task_last_dispatched_ts(task)
            if last_dispatched_ts > 0 and (now_ts - last_dispatched_ts) < _SITE_TASK_RUNNING_REDISPATCH_SEC:
                continue

        cur_attempt = _site_task_current_attempt(task)
        max_attempts = _site_task_max_attempts(task)
        attempt = max(1, cur_attempt + 1)
        if attempt > max_attempts:
            _site_task_final_fail(node, task, "任务重试次数超限", max_attempts)
            continue

        cmd, err = _build_website_cmd(task, node, attempt)
        if not isinstance(cmd, dict):
            _site_task_final_fail(node, task, err or "任务参数无效", attempt)
            continue

        result_payload = task.get("result") if isinstance(task.get("result"), dict) else {}
        result_payload = dict(result_payload)
        result_payload.update(
            {
                "op": task_type,
                "attempt": int(attempt),
                "max_attempts": int(max_attempts),
                "last_dispatched_ts": float(now_ts),
                "next_retry_ts": 0.0,
                "dispatched_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            }
        )
        update_task(
            task_id,
            status="running",
            progress=_site_task_progress_for_attempt(attempt, max_attempts),
            error="",
            result=result_payload,
        )

        if task_type in ("website_ssl_issue", "website_ssl_renew") and int(attempt) == 1:
            payload = task.get("payload") if isinstance(task.get("payload"), dict) else {}
            site_id = int(payload.get("site_id") or 0)
            if site_id > 0:
                add_site_event(
                    int(site_id),
                    _site_event_action(task_type),
                    status="running",
                    actor="agent",
                    payload={"task_id": int(task_id), "attempt": int(attempt)},
                )

        return sign_cmd(str(api_key or ""), cmd)

    return None


# ------------------------ Agent push-report API (no login) ------------------------


@router.post("/api/agent/report")
async def api_agent_report(request: Request):
    """Agent 主动上报接口。

    认证：HTTP Header `X-API-Key: <node.api_key>`。
    载荷：至少包含 node_id 字段。

    返回：commands（例如同步规则池 / 自更新）。
    """

    # Agent may gzip-compress report payload to reduce panel ingress traffic.
    try:
        content_encoding = str(request.headers.get("content-encoding") or "").strip().lower()
        if "gzip" in content_encoding:
            raw = await request.body()
            raw = gzip.decompress(raw or b"")
            parsed = json.loads(raw.decode("utf-8"))
        else:
            parsed = await request.json()
    except Exception:
        return JSONResponse({"ok": False, "error": "请求体解析失败"}, status_code=400)

    if not isinstance(parsed, dict):
        return JSONResponse({"ok": False, "error": "请求体必须是 JSON 对象"}, status_code=400)

    payload: Dict[str, Any] = parsed

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

    # Agent software/update meta (optional)
    agent_version = str(payload.get("agent_version") or "").strip()
    if not agent_version:
        agent_version = parse_agent_version_from_ua(
            (request.headers.get("User-Agent") or request.headers.get("user-agent") or "").strip()
        )

    agent_update = payload.get("agent_update")
    if not isinstance(agent_update, dict):
        agent_update = {}

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

    traffic_ack_version = payload.get("traffic_ack_version")
    try:
        traffic_ack = int(traffic_ack_version) if traffic_ack_version is not None else None
    except Exception:
        traffic_ack = None

    try:
        update_node_report(
            node_id=node_id,
            report_json=json.dumps(report, ensure_ascii=False),
            last_seen_at=now,
            agent_ack_version=int(ack_version) if ack_version is not None else None,
            traffic_ack_version=traffic_ack,
        )
    except Exception:
        # 不要让写库失败影响 agent
        pass

    # Persist rule traffic/connection history (best-effort, never block agent report)
    try:
        if isinstance(report, dict) and isinstance(report.get("stats"), dict):
            ingest_stats_snapshot(node_id=node_id, stats=report.get("stats"))
    except Exception:
        pass

    # Website async task results from agent execution (best-effort).
    try:
        _ingest_site_task_results(node, payload.get("task_results"))
    except Exception:
        pass

    # Persist agent version + update status (best-effort)
    # ⚠️ 关键：面板触发新一轮更新（desired_agent_update_id 改变）时，
    # Agent 可能还在上报「上一轮」的状态（甚至旧版本 Agent 的状态里没有 update_id）。
    # 如果直接用 agent_update.state 覆盖 DB，就会把面板刚设置的 queued/sent 覆盖成 done。
    # 解决：
    #   - 若面板当前存在 desired_update_id：只接受 update_id == desired_update_id 的状态回报。
    #   - 若面板未在滚动更新：允许无 update_id 的旧状态回报（仅用于展示历史状态）。
    try:
        desired_update_id_now = str(node.get("desired_agent_update_id") or "").strip()
        rep_update_id = str(agent_update.get("update_id") or "").strip() if isinstance(agent_update, dict) else ""
        st = str(agent_update.get("state") or "").strip() if isinstance(agent_update, dict) else ""
        msg = (
            str(agent_update.get("error") or agent_update.get("msg") or "").strip()
            if isinstance(agent_update, dict)
            else ""
        )

        if desired_update_id_now:
            # 正在更新：必须强制对齐 update_id，否则视为“旧状态/噪声”不覆盖
            if rep_update_id and rep_update_id == desired_update_id_now:
                update_agent_status(
                    node_id=node_id,
                    agent_reported_version=agent_version or None,
                    state=st or None,
                    msg=msg or None,
                )
            else:
                # 仅更新版本号，不覆盖面板当前批次的状态
                update_agent_status(node_id=node_id, agent_reported_version=agent_version or None)
        else:
            # 未处于滚动更新中：允许旧版 agent（无 update_id）也能回报“上次更新状态”
            update_agent_status(
                node_id=node_id,
                agent_reported_version=agent_version or None,
                state=st or None,
                msg=msg or None,
            )
    except Exception:
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
            rep_pool = None
            if isinstance(report, dict):
                rep_pool = report.get("pool")
            if isinstance(rep_pool, dict):
                # Trust agent as source of truth when panel version went backwards (e.g. DB restore).
                desired_ver, desired_pool = set_desired_pool_exact(node_id, rep_pool, agent_ack)
            else:
                desired_ver = set_desired_pool_version_exact(node_id, agent_ack)

    # 自适应负载均衡：基于实时探测结果自动调权（单次仅调整一条规则，优先走 pool_patch）
    try:
        if isinstance(desired_pool, dict) and isinstance(report, dict):
            adaptive = suggest_adaptive_pool_patch(
                node_id=int(node_id),
                desired_ver=int(desired_ver),
                agent_ack=int(agent_ack),
                desired_pool=desired_pool,
                report=report,
            )
            if isinstance(adaptive, dict) and isinstance(adaptive.get("pool"), dict):
                desired_ver, desired_pool = set_desired_pool(node_id, adaptive["pool"])
    except Exception:
        # Never break agent heartbeat because of auto-LB logic.
        pass

    # 下发命令：规则池同步
    cmds: List[Dict[str, Any]] = []
    if isinstance(desired_pool, dict) and desired_ver > agent_ack:
        # ✅ 单条规则增量下发：仅当 agent 落后 1 个版本，且报告中存在当前 pool 时才尝试 patch
        base_pool = None
        if isinstance(report, dict):
            base_pool = report.get("pool") if isinstance(report.get("pool"), dict) else None

        cmd: Dict[str, Any]
        ops = None
        if desired_ver == agent_ack + 1 and isinstance(base_pool, dict):
            ops = single_rule_ops(base_pool, desired_pool)

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

        cmds.append(sign_cmd(str(node.get("api_key") or ""), cmd))

    # 下发命令：Agent 自更新（可选）
    try:
        desired_agent_ver = str(node.get("desired_agent_version") or "").strip()
        desired_update_id = str(node.get("desired_agent_update_id") or "").strip()
        cur_agent_ver = (agent_version or str(node.get("agent_reported_version") or "")).strip()

        rep_update_id = str(agent_update.get("update_id") or "").strip() if isinstance(agent_update, dict) else ""
        rep_state = (
            str(agent_update.get("state") or "").strip().lower() if isinstance(agent_update, dict) else ""
        )

        if desired_agent_ver and desired_update_id:
            # ✅ “一键更新”=强制按面板/GitHub 文件重装：不再用版本号短路。
            # 只有当 agent 明确回报「本批次 update_id 已 done」时才停止下发。
            already_done = rep_update_id == desired_update_id and rep_state == "done"

            if already_done:
                if str(node.get("agent_update_state") or "").strip() != "done":
                    try:
                        update_agent_status(node_id=node_id, state="done", msg="")
                    except Exception:
                        pass
            else:
                # ✅ 不对旧版本做“硬阻断”。
                # 有些环境里节点上跑的 Agent 版本可能很旧/无法准确上报版本号。
                # 这里仍然尝试下发 update_agent，让节点“尽最大可能”自更新。

                panel_base = panel_public_base_url(request)
                sh_url, zip_url, github_only = agent_asset_urls(panel_base)
                zip_sha256 = "" if github_only else file_sha256(STATIC_DIR / "realm-agent.zip")

                # ✅ 强制更新关键：
                # 旧版 Agent 的 update_agent 实现里存在“版本号短路”逻辑：
                #   - 当 current_version >= desired_version 时，直接标记 done 并返回
                # 为了做到“无论当前版本如何，点更新就必须重装”，我们给 desired_version
                # 加一个批次后缀，让旧版 Agent 的 int() 解析失败，从而不会短路。
                desired_ver_for_cmd = desired_agent_ver
                try:
                    suf = (desired_update_id or "")[:8] or str(int(time.time()))
                    if desired_ver_for_cmd:
                        desired_ver_for_cmd = f"{desired_ver_for_cmd}-force-{suf}"
                except Exception:
                    pass

                ucmd: Dict[str, Any] = {
                    "type": "update_agent",
                    "update_id": desired_update_id,
                    "desired_version": desired_ver_for_cmd,
                    "panel_url": panel_base,
                    "sh_url": sh_url,
                    "zip_url": zip_url,
                    "zip_sha256": zip_sha256,
                    "github_only": bool(github_only),
                    "force": True,
                }

                cmds.append(sign_cmd(str(node.get("api_key") or ""), ucmd))

                # mark queued->sent (best-effort)
                if str(node.get("agent_update_state") or "").strip() in ("", "queued"):
                    try:
                        update_agent_status(node_id=node_id, state="sent")
                    except Exception:
                        pass

    except Exception:
        pass


    # 下发命令：一键重置规则流量（可选）
    try:
        desired_reset_ver = int(node.get("desired_traffic_reset_version") or 0)
    except Exception:
        desired_reset_ver = 0

    try:
        ack_reset_ver = int(traffic_ack) if traffic_ack is not None else int(node.get("agent_traffic_reset_ack_version") or 0)
    except Exception:
        ack_reset_ver = 0

    try:
        if desired_reset_ver > 0 and desired_reset_ver > ack_reset_ver:
            rcmd = {
                "type": "reset_traffic",
                "version": desired_reset_ver,
                "reset_iptables": True,
                "reset_baseline": True,
                "reset_ss_cache": True,
                "reset_conn_history": True,
            }
            cmds.append(sign_cmd(str(node.get("api_key") or ""), rcmd))
    except Exception:
        pass

    # 下发命令：网站任务（环境安装/卸载、SSL 申请/续签）
    try:
        site_cmd = _next_site_task_command(node, str(node.get("api_key") or ""))
        if isinstance(site_cmd, dict):
            cmds.append(site_cmd)
    except Exception:
        pass

    return {"ok": True, "server_time": now, "desired_version": desired_ver, "commands": cmds}


# ------------------------ API (needs login) ------------------------


@router.get("/api/agents/latest")
async def api_agents_latest(_: Request, user: str = Depends(require_login)):
    """Return the latest agent version bundled with this panel."""
    latest = read_latest_agent_version()
    zip_sha256 = file_sha256(STATIC_DIR / "realm-agent.zip")
    return {
        "ok": True,
        "latest_version": latest,
        "zip_sha256": zip_sha256,
    }


@router.post("/api/agents/update_all")
async def api_agents_update_all(request: Request, user: str = Depends(require_login)):
    """Trigger an agent rollout to all nodes."""
    target = (read_latest_agent_version() or "").strip()
    if not target:
        return JSONResponse(
            {
                "ok": False,
                "error": "无法确定当前面板内置的 Agent 版本（realm-agent.zip 缺失或不可解析）",
            },
            status_code=500,
        )

    update_id = uuid.uuid4().hex
    affected = 0
    try:
        affected = set_agent_rollout_all(desired_version=target, update_id=update_id, state="queued", msg="")
    except Exception:
        affected = 0

    return {
        "ok": True,
        "update_id": update_id,
        "target_version": target,
        "affected": affected,
        "server_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    }


@router.get("/api/agents/update_progress")
async def api_agents_update_progress(update_id: str = "", user: str = Depends(require_login)):
    """Return rollout progress."""
    uid = (update_id or "").strip()
    nodes = list_nodes()
    orders = get_group_orders()

    items: List[Dict[str, Any]] = []
    summary = {
        "total": 0,
        "done": 0,
        "failed": 0,
        "installing": 0,
        "sent": 0,
        "queued": 0,
        "offline": 0,
        "other": 0,
    }

    for n in nodes:
        nuid = str(n.get("desired_agent_update_id") or "").strip()
        if uid and nuid != uid:
            continue

        summary["total"] += 1
        online = is_report_fresh(n)
        desired = str(n.get("desired_agent_version") or "").strip()
        cur = str(n.get("agent_reported_version") or "").strip()
        st = str(n.get("agent_update_state") or "").strip() or "queued"

        # ✅ 一键更新进度：以 agent_update_state 为准。
        # 不再用“当前版本 >= 目标版本”来直接判定 done。
        if not online:
            st2 = "offline"
        else:
            st2 = st

        if st2 in summary:
            summary[st2] += 1
        else:
            summary["other"] += 1

        group_name = str(n.get("group_name") or "").strip() or "默认分组"
        group_order = int(orders.get(group_name, 9999) or 9999)

        items.append(
            {
                "id": n.get("id"),
                "name": n.get("name"),
                "group_name": group_name,
                "group_order": group_order,
                "online": bool(online),
                "agent_version": cur,
                "desired_version": desired,
                "state": st2,
                "msg": str(n.get("agent_update_msg") or "").strip(),
                "last_seen_at": n.get("last_seen_at"),
            }
        )

    # Deterministic ordering (group order -> group -> name -> id)
    try:
        items.sort(
            key=lambda x: (
                int(x.get("group_order") or 9999),
                str(x.get("group_name") or ""),
                str(x.get("name") or ""),
                int(x.get("id") or 0),
            )
        )
    except Exception:
        pass

    return {"ok": True, "update_id": uid, "summary": summary, "nodes": items}
