from __future__ import annotations

import calendar
import gzip
import io
import json
import os
import time
import uuid
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlsplit

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
    get_node_runtime,
    list_sites,
    list_tasks,
    list_nodes,
    node_auto_restart_policy_from_row,
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
from ..services.assets import (
    agent_asset_urls,
    agent_fallback_asset_urls,
    file_sha256,
    panel_public_base_url,
    parse_agent_version_from_ua,
    read_latest_agent_version,
)
try:
    from ..services.panel_config import setting_int
except Exception:
    def _cfg_env(names: Optional[list[str]]) -> str:
        for n in (names or []):
            name = str(n or "").strip()
            if not name:
                continue
            v = str(os.getenv(name) or "").strip()
            if v:
                return v
        return ""

    def setting_int(
        key: str,
        default: int,
        lo: int,
        hi: int,
        env_names: Optional[list[str]] = None,
    ) -> int:
        raw = _cfg_env(env_names)
        try:
            v = int(float(raw if raw else default))
        except Exception:
            v = int(default)
        if v < int(lo):
            v = int(lo)
        if v > int(hi):
            v = int(hi)
        return int(v)
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


def _explicit_url_port(raw: Any) -> int:
    s = str(raw or "").strip()
    if not s:
        return 0
    if "://" not in s:
        s = "http://" + s
    try:
        u = urlsplit(s)
        p = int(u.port or 0)
        if p > 0 and p <= 65535:
            return p
    except Exception:
        return 0
    return 0


_SITE_TASK_TYPES = {"website_env_ensure", "website_env_uninstall", "website_ssl_issue", "website_ssl_renew"}
_SITE_TASK_MAX_ATTEMPTS = max(1, min(30, _parse_int_env("REALM_WEBSITE_OP_MAX_ATTEMPTS", 10)))
_SITE_TASK_RETRY_BASE_SEC = max(1.0, min(120.0, _parse_float_env("REALM_WEBSITE_OP_RETRY_BASE_SEC", 3.0)))
_SITE_TASK_RETRY_MAX_SEC = max(
    _SITE_TASK_RETRY_BASE_SEC,
    min(600.0, _parse_float_env("REALM_WEBSITE_OP_RETRY_MAX_SEC", 60.0)),
)
_SITE_TASK_RUNNING_REDISPATCH_SEC = max(30.0, min(600.0, _parse_float_env("REALM_WEBSITE_RUNNING_REDISPATCH_SEC", 180.0)))

_AGENT_UPDATE_MAX_RETRIES = max(1, min(20, _parse_int_env("REALM_AGENT_UPDATE_MAX_RETRIES", 4)))
_AGENT_UPDATE_ACK_TIMEOUT_SEC = max(120.0, min(7200.0, _parse_float_env("REALM_AGENT_UPDATE_ACK_TIMEOUT_SEC", 300.0)))
_AGENT_UPDATE_RUNNING_TIMEOUT_SEC = max(
    600.0, min(172800.0, _parse_float_env("REALM_AGENT_UPDATE_RUNNING_TIMEOUT_SEC", 7200.0))
)
# Legacy/compat delivered 阶段（无 accepted/running 回执）不应沿用完整 running 超时，
# 否则“下一次重试”会被拉到 2 小时以上，用户观感像卡死。
_AGENT_UPDATE_LEGACY_DELIVERED_TIMEOUT_SEC = max(
    120.0, min(7200.0, _parse_float_env("REALM_AGENT_UPDATE_LEGACY_DELIVERED_TIMEOUT_SEC", 600.0))
)
_AGENT_UPDATE_RETRY_BASE_SEC = max(20.0, min(1800.0, _parse_float_env("REALM_AGENT_UPDATE_RETRY_BASE_SEC", 60.0)))
_AGENT_UPDATE_RETRY_MAX_SEC = max(
    _AGENT_UPDATE_RETRY_BASE_SEC, min(21600.0, _parse_float_env("REALM_AGENT_UPDATE_RETRY_MAX_SEC", 3600.0))
)
_AGENT_UPDATE_EARLY_COMPAT_SEC = max(
    20.0, min(3600.0, _parse_float_env("REALM_AGENT_UPDATE_EARLY_COMPAT_SEC", 90.0))
)
_AGENT_UPDATE_REDISPATCH_SEC = max(
    10.0, min(600.0, _parse_float_env("REALM_AGENT_UPDATE_REDISPATCH_SEC", 30.0))
)
_AGENT_UPDATE_OFFLINE_EXPIRE_SEC = max(
    3600.0, min(604800.0, _parse_float_env("REALM_AGENT_UPDATE_OFFLINE_EXPIRE_SEC", 43200.0))
)
_AGENT_REPORT_MAX_COMPRESSED_BYTES = max(
    128 * 1024,
    min(32 * 1024 * 1024, _parse_int_env("REALM_AGENT_REPORT_MAX_COMPRESSED_BYTES", 2 * 1024 * 1024)),
)
_AGENT_REPORT_MAX_DECOMPRESSED_BYTES = max(
    _AGENT_REPORT_MAX_COMPRESSED_BYTES,
    min(64 * 1024 * 1024, _parse_int_env("REALM_AGENT_REPORT_MAX_DECOMPRESSED_BYTES", 12 * 1024 * 1024)),
)


class _RequestBodyTooLargeError(RuntimeError):
    pass


def _gunzip_limited(raw: bytes, max_decompressed: int) -> bytes:
    """Decompress gzip payload with an output cap to avoid memory spikes."""
    limit = max(1, int(max_decompressed or 1))
    out = bytearray()
    with gzip.GzipFile(fileobj=io.BytesIO(raw or b"")) as gz:
        while True:
            remain = limit - len(out)
            if remain <= 0:
                raise _RequestBodyTooLargeError("decompressed body too large")
            # Read at most remain+1 bytes so overflow can be detected deterministically.
            chunk = gz.read(min(64 * 1024, remain + 1))
            if not chunk:
                break
            out.extend(chunk)
            if len(out) > limit:
                raise _RequestBodyTooLargeError("decompressed body too large")
    return bytes(out)


_AGENT_REASON_TEXT = {
    "unsupported_agent_protocol": "节点 Agent 不支持更新协议 v2（缺少 command_id/accepted 回执）。",
    "ack_timeout": "等待节点确认超时，已进入退避重试。",
    "ack_timeout_exhausted": "等待节点确认超时，且重试次数已耗尽。",
    "running_timeout": "安装执行超时，已进入退避重试。",
    "running_timeout_exhausted": "安装执行超时，且重试次数已耗尽。",
    "download_error": "下载更新文件失败（主备地址均不可用）。",
    "installer_error": "安装脚本执行失败。",
    "update_cmd_exception": "更新命令处理异常。",
    "invalid_command": "更新命令参数不合法。",
    "missing_systemd_run": "节点缺少 systemd-run，无法安全执行自更新。",
    "signature_rejected": "更新命令签名校验失败（可能是节点时间偏移或密钥不一致）。",
    "offline_timeout": "节点长期离线，更新任务已过期。",
    "agent_failed": "节点执行更新失败。",
    "retry_exhausted": "节点多次执行失败，已达到最大重试次数。",
}

_AGENT_TERMINAL_FAIL_REASONS = {
    "invalid_command",
    "missing_systemd_run",
    "unsupported_agent_protocol",
}


def _fmt_dt(ts: float) -> str:
    return datetime.fromtimestamp(float(ts)).strftime("%Y-%m-%d %H:%M:%S")


def _parse_dt(v: Any) -> float:
    s = str(v or "").strip()
    if not s:
        return 0.0
    try:
        return datetime.strptime(s, "%Y-%m-%d %H:%M:%S").timestamp()
    except Exception:
        return 0.0


def _valid_dt_str(v: Any, fallback: str) -> str:
    s = str(v or "").strip()
    if not s:
        return fallback
    try:
        datetime.strptime(s, "%Y-%m-%d %H:%M:%S")
        return s
    except Exception:
        return fallback


def _canon_agent_update_state(raw: Any) -> str:
    s = str(raw or "").strip().lower()
    if s in ("queued", "pending"):
        return "queued"
    if s in ("sent", "delivered"):
        return "delivered"
    if s == "accepted":
        return "accepted"
    if s in ("installing", "running"):
        return "running"
    if s == "retrying":
        return "retrying"
    if s in ("done", "success"):
        return "done"
    if s in ("failed", "error"):
        return "failed"
    if s in ("expired", "timeout"):
        return "expired"
    return s or "queued"


def _agent_retry_backoff_sec(next_attempt_no: int) -> float:
    n = max(1, int(next_attempt_no or 1))
    return float(min(_AGENT_UPDATE_RETRY_MAX_SEC, _AGENT_UPDATE_RETRY_BASE_SEC * (2 ** (n - 1))))


def _to_bool(v: Any) -> bool:
    if isinstance(v, bool):
        return v
    if v is None:
        return False
    if isinstance(v, (int, float)):
        return bool(int(v))
    s = str(v).strip().lower()
    if s in ("1", "true", "yes", "on", "y"):
        return True
    if s in ("0", "false", "no", "off", "n", ""):
        return False
    return False


def _infer_agent_cmd_ts_candidates(report: Any, fallback_ts: float) -> List[int]:
    """Infer candidate command timestamps from agent-reported wall clock.

    Returns a candidate list sorted by proximity to panel-now. This allows
    robust retries for legacy agents with unknown timezone + clock drift.
    """
    fb = int(fallback_ts or time.time())
    if not isinstance(report, dict):
        return [fb]
    raw = ""
    try:
        raw = str(
            report.get("time")
            or ((report.get("info") or {}).get("time") if isinstance(report.get("info"), dict) else "")
            or ""
        ).strip()
    except Exception:
        raw = ""
    if not raw:
        return [fb]
    try:
        dt = datetime.strptime(raw, "%Y-%m-%d %H:%M:%S")
        base_utc = int(calendar.timegm(dt.timetuple()))
        now_i = int(fallback_ts or time.time())
        arr: List[Tuple[int, int]] = []
        for off_min in range(-14 * 60, 14 * 60 + 1, 30):
            cand = int(base_utc - off_min * 60)
            arr.append((abs(cand - now_i), cand))
        arr.sort(key=lambda x: x[0])
        out: List[int] = []
        seen: set[int] = set()
        for _, cand in arr:
            if cand in seen:
                continue
            seen.add(cand)
            out.append(int(cand))
        if not out:
            out = [fb]
        return out
    except Exception:
        return [fb]


def _normalize_agent_caps(raw: Any) -> Dict[str, Any]:
    if not isinstance(raw, dict):
        return {}
    out: Dict[str, Any] = {}
    proto_raw = raw.get("update_protocol_version", raw.get("update_protocol"))
    try:
        proto = int(proto_raw)
    except Exception:
        proto = 0
    supports_cmd_id = _to_bool(raw.get("supports_update_command_id"))
    supports_ack = _to_bool(raw.get("supports_update_accept_ack"))
    supports_reason = _to_bool(raw.get("supports_update_reason_code"))
    if proto >= 2:
        supports_cmd_id = True
        supports_ack = True
        supports_reason = True
    out["update_protocol_version"] = int(proto)
    out["supports_update_command_id"] = bool(supports_cmd_id)
    out["supports_update_accept_ack"] = bool(supports_ack)
    out["supports_update_reason_code"] = bool(supports_reason)
    return out


def _supports_update_v2(caps: Dict[str, Any]) -> bool:
    if not isinstance(caps, dict):
        return False
    proto = 0
    try:
        proto = int(caps.get("update_protocol_version") or 0)
    except Exception:
        proto = 0
    if proto >= 2:
        return True
    return _to_bool(caps.get("supports_update_command_id")) and _to_bool(caps.get("supports_update_accept_ack"))


def _reason_text(code: Any) -> str:
    k = str(code or "").strip().lower()
    if not k:
        return ""
    return str(_AGENT_REASON_TEXT.get(k) or "")


def _is_terminal_fail_reason(code: Any) -> bool:
    k = str(code or "").strip().lower()
    if not k:
        return False
    return k in _AGENT_TERMINAL_FAIL_REASONS


def _infer_agent_fail_reason(rep_reason: Any, rep_msg: Any) -> str:
    reason = str(rep_reason or "").strip().lower()
    if reason:
        return reason
    msg = str(rep_msg or "").strip().lower()
    if not msg:
        return "agent_failed"
    if "systemd-run" in msg or "missing_systemd_run" in msg:
        return "missing_systemd_run"
    if "签名校验失败" in msg or "signature" in msg:
        return "signature_rejected"
    if "invalid command" in msg or "缺少必要参数" in msg or "invalid_command" in msg:
        return "invalid_command"
    if "download" in msg or "下载" in msg:
        return "download_error"
    if "curl" in msg or "sha256" in msg or "zip" in msg:
        return "installer_error"
    if "timeout" in msg:
        return "running_timeout"
    return "agent_failed"

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


def _is_ssl_renew_skip_error(err: Any) -> bool:
    msg = str(err or "").strip().lower()
    if not msg:
        return False
    signs = (
        "domains not changed",
        "next renewal time is",
        "force renewal",
        "--force",
        "not yet time to renew",
        "skip, next renewal time is",
        "skipping. next renewal time is",
    )
    return any(s in msg for s in signs)


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
    if (not ok) and t == "website_ssl_renew" and _is_ssl_renew_skip_error(err_text):
        # Compatibility for older agents: treat acme "renew skipped (not due yet)" as success.
        ok = True
        err_text = ""
        if not isinstance(result_data, dict):
            result_data = {}
        result_data["ok"] = True
        result_data["renew_skipped"] = True
        if not str(result_data.get("message") or "").strip():
            result_data["message"] = "证书未到续期时间，已保持当前证书"
        result_data.pop("error", None)

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
        gzip_encoded = "gzip" in content_encoding
        req_limit = (
            int(_AGENT_REPORT_MAX_COMPRESSED_BYTES)
            if gzip_encoded
            else int(_AGENT_REPORT_MAX_DECOMPRESSED_BYTES)
        )
        try:
            content_len = int(request.headers.get("content-length") or "0")
        except Exception:
            content_len = 0
        if content_len > 0 and content_len > req_limit:
            return JSONResponse({"ok": False, "error": "请求体过大"}, status_code=413)

        chunks = bytearray()
        total = 0
        async for chunk in request.stream():
            if not chunk:
                continue
            total += len(chunk)
            if total > req_limit:
                return JSONResponse({"ok": False, "error": "请求体过大"}, status_code=413)
            chunks.extend(chunk)
        raw = bytes(chunks)

        if gzip_encoded:
            try:
                raw = _gunzip_limited(raw, int(_AGENT_REPORT_MAX_DECOMPRESSED_BYTES))
            except _RequestBodyTooLargeError:
                return JSONResponse({"ok": False, "error": "请求体解压后过大"}, status_code=413)
        if len(raw) > int(_AGENT_REPORT_MAX_DECOMPRESSED_BYTES):
            return JSONResponse({"ok": False, "error": "请求体解压后过大"}, status_code=413)

        parsed = json.loads((raw or b"{}").decode("utf-8"))
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

    node = get_node_runtime(node_id)
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
    raw_caps = payload.get("capabilities")
    # 一些旧/异常节点可能暂时不带 capabilities；
    # 这种情况下不要把库里已知能力覆盖成 {}，避免误判为旧协议。
    agent_caps: Optional[Dict[str, Any]]
    if isinstance(raw_caps, dict):
        agent_caps = _normalize_agent_caps(raw_caps)
    else:
        agent_caps = None
    now_ts = float(time.time())
    now = _fmt_dt(now_ts)

    # report_json：尽量只保存 report 字段（更干净），但也兼容直接上报全量
    report = payload.get("report") if isinstance(payload, dict) else None
    if report is None:
        report = payload
    agent_cmd_ts_candidates = _infer_agent_cmd_ts_candidates(report, now_ts)

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
    auto_restart_ack_version = payload.get("auto_restart_ack_version")
    try:
        auto_restart_ack = int(auto_restart_ack_version) if auto_restart_ack_version is not None else None
    except Exception:
        auto_restart_ack = None

    report_for_store: Any = report
    if isinstance(report, dict) and bool(node.get("desired_pool_present")) and "pool" in report:
        # Desired pool already exists on panel; avoid rewriting large pool blob every heartbeat.
        report_for_store = dict(report)
        report_for_store.pop("pool", None)

    try:
        update_node_report(
            node_id=node_id,
            report_json=json.dumps(report_for_store, ensure_ascii=False, separators=(",", ":")),
            last_seen_at=now,
            agent_ack_version=int(ack_version) if ack_version is not None else None,
            traffic_ack_version=traffic_ack,
            auto_restart_ack_version=auto_restart_ack,
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

    # Persist agent version/capabilities (best-effort).
    # 仅当本次 payload 明确携带 capabilities 时才覆盖库中能力字段；
    # 否则保留历史值，避免短暂缺失导致“立即降级兼容旧协议”。
    try:
        extra_updates: Dict[str, Any] = {}
        if isinstance(agent_caps, dict):
            extra_updates["agent_capabilities_json"] = json.dumps(agent_caps, ensure_ascii=False)
        update_agent_status(
            node_id=node_id,
            agent_reported_version=agent_version or None,
            extra_updates=extra_updates if extra_updates else None,
            touch_update_at=False,
        )
    except Exception:
        pass

    # Persist update lifecycle status.
    # v2 agents: require update_id + command_id match.
    # legacy agents: fallback to update_id match only.
    try:
        desired_update_id_now = str(node.get("desired_agent_update_id") or "").strip()
        desired_cmd_id_now = str(node.get("desired_agent_command_id") or "").strip()
        rep_update_id = str(agent_update.get("update_id") or "").strip() if isinstance(agent_update, dict) else ""
        rep_cmd_id = str(agent_update.get("command_id") or "").strip() if isinstance(agent_update, dict) else ""
        rep_state = _canon_agent_update_state(agent_update.get("state")) if isinstance(agent_update, dict) else ""
        rep_reason = (
            str(agent_update.get("reason_code") or "").strip().lower() if isinstance(agent_update, dict) else ""
        )
        rep_msg = (
            str(agent_update.get("error") or agent_update.get("msg") or "").strip()
            if isinstance(agent_update, dict)
            else ""
        )
        rep_accepted_at = _valid_dt_str(agent_update.get("accepted_at"), now) if isinstance(agent_update, dict) else now
        rep_started_at = _valid_dt_str(agent_update.get("started_at"), now) if isinstance(agent_update, dict) else now
        rep_finished_at = _valid_dt_str(agent_update.get("finished_at"), now) if isinstance(agent_update, dict) else now
        # Use *current report* capabilities for lifecycle matching.
        # Missing capabilities should be treated as legacy/unknown (conservative),
        # instead of inheriting possibly stale v2 flags from database.
        caps_now = agent_caps if isinstance(agent_caps, dict) else node.get("agent_capabilities")
        if not isinstance(caps_now, dict):
            caps_now = {}
        supports_v2_now = _supports_update_v2(caps_now)

        if desired_update_id_now:
            same_update = bool(rep_update_id and rep_update_id == desired_update_id_now)
            matched = bool(same_update)
            if matched and supports_v2_now and desired_cmd_id_now and rep_cmd_id and (rep_cmd_id != desired_cmd_id_now):
                # Out-of-order or legacy-compat execution may report a previous command_id.
                # For progressed states, prefer update_id continuity to avoid delivered-stall.
                matched = rep_state in ("accepted", "running", "done", "failed")

            if matched:
                if rep_state == "delivered":
                    update_agent_status(
                        node_id=node_id,
                        state="delivered",
                        msg=(rep_msg or "节点已收到更新命令"),
                        reason_code="",
                        extra_updates={
                            "agent_update_next_retry_at": None,
                        },
                        touch_update_at=True,
                    )
                elif rep_state == "queued":
                    update_agent_status(
                        node_id=node_id,
                        state="queued",
                        msg=(rep_msg or "更新任务排队中"),
                        reason_code="",
                        extra_updates={
                            "agent_update_next_retry_at": None,
                        },
                        touch_update_at=True,
                    )
                if rep_state == "accepted":
                    update_agent_status(
                        node_id=node_id,
                        state="accepted",
                        msg=(rep_msg or "节点已确认更新命令"),
                        reason_code="",
                        extra_updates={
                            "agent_update_accepted_at": rep_accepted_at,
                            "agent_update_started_at": None,
                            "agent_update_finished_at": None,
                            "agent_update_next_retry_at": None,
                        },
                        touch_update_at=True,
                    )
                elif rep_state == "running":
                    update_agent_status(
                        node_id=node_id,
                        state="running",
                        msg=(rep_msg or "节点正在执行安装"),
                        reason_code="",
                        extra_updates={
                            "agent_update_accepted_at": rep_accepted_at,
                            "agent_update_started_at": rep_started_at,
                            "agent_update_finished_at": None,
                            "agent_update_next_retry_at": None,
                        },
                        touch_update_at=True,
                    )
                elif rep_state == "done":
                    update_agent_status(
                        node_id=node_id,
                        state="done",
                        msg=(rep_msg or ""),
                        reason_code="",
                        extra_updates={
                            "agent_update_finished_at": rep_finished_at,
                            "agent_update_next_retry_at": None,
                        },
                        touch_update_at=True,
                    )
                elif rep_state == "failed":
                    reason = _infer_agent_fail_reason(rep_reason, rep_msg)
                    try:
                        retry_count_now = int(node.get("agent_update_retry_count") or 0)
                    except Exception:
                        retry_count_now = 0
                    try:
                        max_retries_now = int(node.get("agent_update_max_retries") or 0)
                    except Exception:
                        max_retries_now = 0
                    if max_retries_now <= 0:
                        max_retries_now = int(_AGENT_UPDATE_MAX_RETRIES)
                    retry_count_now = max(0, int(retry_count_now))
                    retryable = not _is_terminal_fail_reason(reason)

                    if retryable and retry_count_now < max_retries_now:
                        wait_s = _agent_retry_backoff_sec(retry_count_now + 1)
                        next_retry_at = _fmt_dt(now_ts + wait_s)
                        update_agent_status(
                            node_id=node_id,
                            state="retrying",
                            msg=(
                                rep_msg
                                or _reason_text(reason)
                                or f"节点执行失败，已安排重试（{retry_count_now}/{max_retries_now}）"
                            ),
                            reason_code=reason,
                            extra_updates={
                                "agent_update_next_retry_at": next_retry_at,
                                "agent_update_finished_at": None,
                            },
                            touch_update_at=True,
                        )
                    else:
                        final_reason = reason
                        if retryable and retry_count_now >= max_retries_now:
                            final_reason = "retry_exhausted"
                        update_agent_status(
                            node_id=node_id,
                            state="failed",
                            msg=(rep_msg or _reason_text(final_reason) or "节点执行更新失败"),
                            reason_code=final_reason,
                            extra_updates={
                                "agent_update_finished_at": rep_finished_at,
                                "agent_update_next_retry_at": None,
                            },
                            touch_update_at=True,
                        )
        else:
            if rep_state:
                update_agent_status(
                    node_id=node_id,
                    state=rep_state,
                    msg=(rep_msg or None),
                    reason_code=(rep_reason or None),
                    touch_update_at=True,
                )
    except Exception:
        pass

    # Refresh node snapshot after potential status updates.
    try:
        node = get_node_runtime(node_id) or node
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

    def _sign_for_node(cmd_obj: Dict[str, Any], ts_override: Optional[int] = None) -> Dict[str, Any]:
        out_cmd = dict(cmd_obj or {})
        ts_i = int(ts_override) if ts_override is not None else int(now_ts or 0)
        if ts_i > 0:
            out_cmd["ts"] = ts_i
        return sign_cmd(str(node.get("api_key") or ""), out_cmd)

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

        cmds.append(_sign_for_node(cmd))

    # 下发命令：Agent 自更新（可选）
    try:
        desired_agent_ver = str(node.get("desired_agent_version") or "").strip()
        desired_update_id = str(node.get("desired_agent_update_id") or "").strip()
        if desired_agent_ver and desired_update_id:
            rollout_state = _canon_agent_update_state(node.get("agent_update_state") or "queued")
            cmd_id = str(node.get("desired_agent_command_id") or "").strip()
            reason_code_now = str(node.get("agent_update_reason_code") or "").strip().lower()

            try:
                retry_count = int(node.get("agent_update_retry_count") or 0)
            except Exception:
                retry_count = 0
            try:
                max_retries = int(node.get("agent_update_max_retries") or 0)
            except Exception:
                max_retries = 0
            if max_retries <= 0:
                max_retries = int(_AGENT_UPDATE_MAX_RETRIES)
            retry_count = max(0, int(retry_count))

            delivered_ts = _parse_dt(node.get("agent_update_delivered_at"))
            accepted_ts = _parse_dt(node.get("agent_update_accepted_at"))
            started_ts = _parse_dt(node.get("agent_update_started_at"))
            next_retry_ts = _parse_dt(node.get("agent_update_next_retry_at"))

            caps = node.get("agent_capabilities")
            if not isinstance(caps, dict):
                caps = {}
            supports_v2 = _supports_update_v2(caps)

            if rollout_state not in ("done", "failed", "expired"):
                # Legacy agents do not report "accepted". keep state machine compatible.
                if rollout_state == "accepted" and not supports_v2:
                    rollout_state = "delivered"

                # 1) Timeout -> retrying / expired
                if rollout_state == "delivered":
                    ack_required = bool(supports_v2 and cmd_id)
                    delivered_timeout = float(
                        _AGENT_UPDATE_ACK_TIMEOUT_SEC if ack_required else _AGENT_UPDATE_LEGACY_DELIVERED_TIMEOUT_SEC
                    )
                    deadline_ts = next_retry_ts if next_retry_ts > 0 else (
                        delivered_ts + delivered_timeout if delivered_ts > 0 else 0.0
                    )
                    if deadline_ts > 0 and now_ts >= deadline_ts:
                        if retry_count >= max_retries:
                            reason = "ack_timeout_exhausted" if ack_required else "running_timeout_exhausted"
                            update_agent_status(
                                node_id=node_id,
                                state="expired",
                                msg=_reason_text(reason) or "等待节点状态确认超时，已结束本次更新批次。",
                                reason_code=reason,
                                extra_updates={
                                    "agent_update_next_retry_at": None,
                                    "agent_update_finished_at": now,
                                },
                                touch_update_at=True,
                            )
                            rollout_state = "expired"
                        else:
                            wait_s = _agent_retry_backoff_sec(retry_count + 1)
                            next_retry_at = _fmt_dt(now_ts + wait_s)
                            reason = "ack_timeout" if ack_required else "running_timeout"
                            update_agent_status(
                                node_id=node_id,
                                state="retrying",
                                msg=_reason_text(reason) or "等待节点状态确认超时，已安排重试。",
                                reason_code=reason,
                                extra_updates={"agent_update_next_retry_at": next_retry_at},
                                touch_update_at=True,
                            )
                            rollout_state = "retrying"
                            next_retry_ts = _parse_dt(next_retry_at)
                elif rollout_state in ("accepted", "running"):
                    running_from = started_ts if started_ts > 0 else (accepted_ts if accepted_ts > 0 else delivered_ts)
                    if running_from > 0 and now_ts >= (running_from + float(_AGENT_UPDATE_RUNNING_TIMEOUT_SEC)):
                        if retry_count >= max_retries:
                            reason = "running_timeout_exhausted"
                            update_agent_status(
                                node_id=node_id,
                                state="expired",
                                msg=_reason_text(reason) or "节点执行更新超时，已结束本次更新批次。",
                                reason_code=reason,
                                extra_updates={
                                    "agent_update_next_retry_at": None,
                                    "agent_update_finished_at": now,
                                },
                                touch_update_at=True,
                            )
                            rollout_state = "expired"
                        else:
                            wait_s = _agent_retry_backoff_sec(retry_count + 1)
                            next_retry_at = _fmt_dt(now_ts + wait_s)
                            reason = "running_timeout"
                            update_agent_status(
                                node_id=node_id,
                                state="retrying",
                                msg=_reason_text(reason) or "节点执行更新超时，已安排重试。",
                                reason_code=reason,
                                extra_updates={"agent_update_next_retry_at": next_retry_at},
                                touch_update_at=True,
                            )
                            rollout_state = "retrying"
                            next_retry_ts = _parse_dt(next_retry_at)

                # 2) Dispatch command when queued/retrying/delivered.
                # Split to:
                #   - new: start a new attempt (increments retry_count).
                #   - redeliver: same attempt periodic resend (no retry_count jump).
                early_compat = bool(
                    rollout_state == "delivered"
                    and supports_v2
                    and bool(cmd_id)
                    and accepted_ts <= 0
                    and started_ts <= 0
                    and delivered_ts > 0
                    and now_ts >= (delivered_ts + float(_AGENT_UPDATE_EARLY_COMPAT_SEC))
                )
                redeliver_due = bool(
                    rollout_state == "delivered"
                    and accepted_ts <= 0
                    and started_ts <= 0
                    and delivered_ts > 0
                    and now_ts >= (delivered_ts + float(_AGENT_UPDATE_REDISPATCH_SEC))
                )
                should_dispatch = False
                dispatch_kind = ""
                if rollout_state == "queued":
                    should_dispatch = True
                    dispatch_kind = "new"
                elif rollout_state == "retrying":
                    if next_retry_ts <= 0 or now_ts >= next_retry_ts:
                        should_dispatch = True
                        dispatch_kind = "new"
                elif rollout_state == "delivered" and supports_v2 and not cmd_id:
                    # migrated rows may have delivered state but no command id.
                    should_dispatch = True
                    dispatch_kind = "new"
                elif rollout_state == "delivered" and (not supports_v2) and cmd_id:
                    # node no longer reports v2 capabilities, but row still carries
                    # historical command_id: keep same attempt and compat-resend.
                    should_dispatch = True
                    dispatch_kind = "redeliver"
                elif early_compat:
                    # v2 node keeps heartbeat but does not send accepted/running.
                    should_dispatch = True
                    dispatch_kind = "redeliver"
                elif redeliver_due:
                    # periodic resend to survive transient response loss/timeouts.
                    should_dispatch = True
                    dispatch_kind = "redeliver"

                if should_dispatch:
                    is_new_attempt = bool(dispatch_kind == "new")
                    attempt_no = max(1, (retry_count + 1) if is_new_attempt else (retry_count if retry_count > 0 else 1))

                    panel_base = panel_public_base_url(request)
                    report_base = str(request.base_url).rstrip("/")
                    sh_url, zip_url, github_only = agent_asset_urls(panel_base)
                    fallback_sh_url, fallback_zip_url = agent_fallback_asset_urls(panel_base)
                    # 自更新下载采用“双地址候选”：
                    # - 主：面板公开地址（兼容大多数节点）
                    # - 备：该节点本次上报实际入口（常见为 IP:6080）
                    # 这样避免全局切换导致“修了一批、坏了一批”。
                    if report_base and report_base != panel_base:
                        fallback_sh_url = f"{report_base}/static/realm_agent.sh"
                        fallback_zip_url = f"{report_base}/static/realm-agent.zip"
                    panel_zip_sha256 = file_sha256(STATIC_DIR / "realm-agent.zip")
                    zip_sha256 = "" if github_only else panel_zip_sha256
                    fallback_zip_sha256 = ""
                    try:
                        fallback_zip_url_s = str(fallback_zip_url or "").strip()
                        panel_zip_url = f"{panel_base}/static/realm-agent.zip"
                        if (
                            fallback_zip_url_s.endswith("/static/realm-agent.zip")
                            and (fallback_zip_url_s.startswith("http://") or fallback_zip_url_s.startswith("https://"))
                            and panel_zip_sha256
                        ):
                            fallback_zip_sha256 = panel_zip_sha256
                        if str(fallback_zip_url or "").strip() == panel_zip_url and panel_zip_sha256:
                            fallback_zip_sha256 = panel_zip_sha256
                    except Exception:
                        fallback_zip_sha256 = ""

                    base_ucmd: Dict[str, Any] = {
                        "type": "update_agent",
                        "update_id": desired_update_id,
                        "desired_version": desired_agent_ver,
                        "panel_url": panel_base,
                        "panel_ip_fallback_port": (
                            _explicit_url_port(report_base)
                            or _explicit_url_port(panel_base)
                            or setting_int(
                                "agent_panel_ip_fallback_port",
                                default=6080,
                                lo=1,
                                hi=65535,
                                env_names=["REALM_PANEL_IP_FALLBACK_PORT"],
                            )
                        ),
                        "sh_url": sh_url,
                        "zip_url": zip_url,
                        "zip_sha256": zip_sha256,
                        "fallback_sh_url": fallback_sh_url,
                        "fallback_zip_url": fallback_zip_url,
                        "fallback_zip_sha256": fallback_zip_sha256,
                        "github_only": bool(github_only),
                        "force": True,
                    }

                    force_compat = bool(
                        (not supports_v2)
                        or early_compat
                        or (supports_v2 and retry_count >= 1 and reason_code_now in ("ack_timeout",))
                    )
                    use_v2_dispatch = bool(supports_v2 and (not force_compat))
                    command_id = ""
                    dispatch_variants: List[Dict[str, Any]] = []
                    if use_v2_dispatch:
                        if (not is_new_attempt) and cmd_id:
                            command_id = str(cmd_id)
                        else:
                            command_id = uuid.uuid4().hex
                        v2_cmd = dict(base_ucmd)
                        v2_cmd["command_id"] = command_id
                        v2_cmd["update_protocol_version"] = 2
                        dispatch_variants.append(v2_cmd)
                        if dispatch_kind == "redeliver":
                            # Shadow legacy command helps old/hybrid agents converge.
                            dispatch_variants.append(dict(base_ucmd))
                    else:
                        dispatch_variants.append(dict(base_ucmd))

                    if use_v2_dispatch:
                        if dispatch_kind == "redeliver":
                            dispatch_msg = f"命令重投（尝试 {attempt_no}/{max_retries}），等待节点确认"
                        else:
                            dispatch_msg = f"命令已投递（尝试 {attempt_no}/{max_retries}），等待节点确认"
                    else:
                        if supports_v2:
                            if dispatch_kind == "redeliver":
                                dispatch_msg = f"命令重投（兼容模式降级，尝试 {attempt_no}/{max_retries}）"
                            else:
                                dispatch_msg = f"命令已投递（兼容模式降级，尝试 {attempt_no}/{max_retries}）"
                        else:
                            if dispatch_kind == "redeliver":
                                dispatch_msg = f"命令重投（兼容旧版协议，尝试 {attempt_no}/{max_retries}）"
                            else:
                                dispatch_msg = f"命令已投递（兼容旧版协议，尝试 {attempt_no}/{max_retries}）"

                    if reason_code_now == "signature_rejected":
                        ts_candidates = [int(now_ts)]
                        for tsv in list(agent_cmd_ts_candidates or []):
                            try:
                                ts_i = int(tsv)
                            except Exception:
                                continue
                            if ts_i not in ts_candidates:
                                ts_candidates.append(ts_i)
                        # full timezone sweep (<=57 variants) to pass legacy skew checks
                        for tsv in ts_candidates[:57]:
                            for out_cmd in dispatch_variants:
                                cmds.append(_sign_for_node(out_cmd, ts_override=int(tsv)))
                    else:
                        for out_cmd in dispatch_variants:
                            cmds.append(_sign_for_node(out_cmd))

                    timeout_window = float(
                        _AGENT_UPDATE_ACK_TIMEOUT_SEC
                        if use_v2_dispatch
                        else _AGENT_UPDATE_LEGACY_DELIVERED_TIMEOUT_SEC
                    )
                    extra_updates: Dict[str, Any] = {
                        "desired_agent_command_id": (command_id if use_v2_dispatch else ""),
                        "agent_update_retry_count": int(attempt_no),
                        "agent_update_max_retries": int(max_retries),
                        "agent_update_delivered_at": now,
                    }
                    if is_new_attempt:
                        extra_updates["agent_update_next_retry_at"] = _fmt_dt(now_ts + timeout_window)
                        extra_updates["agent_update_accepted_at"] = None
                        extra_updates["agent_update_started_at"] = None
                        extra_updates["agent_update_finished_at"] = None
                    elif next_retry_ts <= 0 or (
                        (not use_v2_dispatch) and next_retry_ts > (now_ts + timeout_window + 1.0)
                    ):
                        # 历史兼容：老记录可能带着过长 deadline（如 2h）。
                        # 对旧协议分支收敛到当前超时窗口，避免界面长期“卡住”。
                        extra_updates["agent_update_next_retry_at"] = _fmt_dt(now_ts + timeout_window)

                    update_agent_status(
                        node_id=node_id,
                        state="delivered",
                        msg=dispatch_msg,
                        reason_code="",
                        extra_updates=extra_updates,
                        touch_update_at=True,
                    )

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
            cmds.append(_sign_for_node(rcmd))
    except Exception:
        pass

    # 下发命令：节点自动重启策略（可选）
    try:
        desired_restart_ver = int(node.get("desired_auto_restart_policy_version") or 0)
    except Exception:
        desired_restart_ver = 0
    try:
        ack_restart_ver = (
            int(auto_restart_ack) if auto_restart_ack is not None else int(node.get("agent_auto_restart_policy_ack_version") or 0)
        )
    except Exception:
        ack_restart_ver = 0

    try:
        if desired_restart_ver > 0 and desired_restart_ver > ack_restart_ver:
            pol = node_auto_restart_policy_from_row(node if isinstance(node, dict) else {})
            pcmd = {
                "type": "auto_restart_policy",
                "version": int(desired_restart_ver),
                "policy": {
                    "enabled": bool(pol.get("enabled", True)),
                    "schedule_type": str(pol.get("schedule_type") or "daily"),
                    "interval": int(pol.get("interval") or 1),
                    "hour": int(pol.get("hour")) if pol.get("hour") is not None else 4,
                    "minute": int(pol.get("minute")) if pol.get("minute") is not None else 8,
                    "weekdays": list(pol.get("weekdays") or [1, 2, 3, 4, 5, 6, 7]),
                    "monthdays": list(pol.get("monthdays") or [1]),
                },
            }
            cmds.append(_sign_for_node(pcmd))
    except Exception:
        pass

    # 下发命令：网站任务（环境安装/卸载、SSL 申请/续签）
    try:
        site_cmd = _next_site_task_command(node, str(node.get("api_key") or ""))
        if isinstance(site_cmd, dict):
            cmds.append(site_cmd)
    except Exception:
        pass

    return {
        "ok": True,
        "server_time": now,
        "server_ts": int(now_ts),
        "desired_version": desired_ver,
        "commands": cmds,
    }


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
        affected = set_agent_rollout_all(
            desired_version=target,
            update_id=update_id,
            state="queued",
            msg="",
            max_retries=int(_AGENT_UPDATE_MAX_RETRIES),
        )
    except Exception:
        affected = 0

    return {
        "ok": True,
        "update_id": update_id,
        "target_version": target,
        "max_retries": int(_AGENT_UPDATE_MAX_RETRIES),
        "affected": affected,
        "server_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    }


@router.get("/api/agents/update_progress")
async def api_agents_update_progress(update_id: str = "", user: str = Depends(require_login)):
    """Return rollout progress."""
    uid = (update_id or "").strip()
    nodes = list_nodes()
    orders = get_group_orders()
    now_ts = float(time.time())
    now_str = _fmt_dt(now_ts)

    items: List[Dict[str, Any]] = []
    summary = {
        "total": 0,
        "done": 0,
        "failed": 0,
        "expired": 0,
        "running": 0,
        "accepted": 0,
        "delivered": 0,
        "retrying": 0,
        "queued": 0,
        "offline": 0,
        "other": 0,
    }
    active_states = {"queued", "delivered", "accepted", "running", "retrying"}

    for n in nodes:
        nuid = str(n.get("desired_agent_update_id") or "").strip()
        if uid and nuid != uid:
            continue

        summary["total"] += 1
        online = is_report_fresh(n)
        if not online:
            summary["offline"] += 1

        desired = str(n.get("desired_agent_version") or "").strip()
        cur = str(n.get("agent_reported_version") or "").strip()
        st = _canon_agent_update_state(n.get("agent_update_state") or "queued")
        reason = str(n.get("agent_update_reason_code") or "").strip().lower()
        msg = str(n.get("agent_update_msg") or "").strip()

        # Offline sweep: avoid infinite "delivered/running" when node disappeared.
        if (not online) and st in active_states:
            ref_ts = _parse_dt(n.get("agent_update_delivered_at")) or _parse_dt(n.get("agent_update_at"))
            if ref_ts > 0 and (now_ts - ref_ts) >= float(_AGENT_UPDATE_OFFLINE_EXPIRE_SEC):
                st = "expired"
                reason = "offline_timeout"
                msg = _reason_text(reason) or "节点长期离线，更新任务已过期。"
                try:
                    update_agent_status(
                        node_id=int(n.get("id") or 0),
                        state="expired",
                        msg=msg,
                        reason_code=reason,
                        extra_updates={
                            "agent_update_next_retry_at": None,
                            "agent_update_finished_at": now_str,
                        },
                        touch_update_at=True,
                    )
                except Exception:
                    pass

        if not msg and reason:
            msg = _reason_text(reason) or ""

        if st in summary:
            summary[st] += 1
        else:
            summary["other"] += 1

        group_name = str(n.get("group_name") or "").strip() or "默认分组"
        group_order = int(orders.get(group_name, 9999) or 9999)
        try:
            retry_count_val = int(n.get("agent_update_retry_count") or 0)
        except Exception:
            retry_count_val = 0
        try:
            max_retries_val = int(n.get("agent_update_max_retries") or 0)
        except Exception:
            max_retries_val = 0

        items.append(
            {
                "id": n.get("id"),
                "name": n.get("name"),
                "group_name": group_name,
                "group_order": group_order,
                "online": bool(online),
                "agent_version": cur,
                "desired_version": desired,
                "state": st,
                "msg": msg,
                "reason_code": reason,
                "command_id": str(n.get("desired_agent_command_id") or "").strip(),
                "retry_count": int(retry_count_val),
                "max_retries": int(max_retries_val),
                "next_retry_at": n.get("agent_update_next_retry_at"),
                "last_seen_at": n.get("last_seen_at"),
            }
        )

    # Backward-compatible summary aliases for old UI readers.
    summary["installing"] = int(summary.get("running") or 0)
    summary["sent"] = int(summary.get("delivered") or 0)

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
