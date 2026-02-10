from __future__ import annotations

import asyncio
import base64
import datetime
import hashlib
import json
import os
import re
import tempfile
import threading
import time
import uuid
import zipfile
from typing import Any, Awaitable, Callable, Dict, List, Optional, Tuple
from urllib.parse import parse_qs, quote, urlencode, urlparse

from fastapi import APIRouter, Depends, File, Form, Request, UploadFile
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, RedirectResponse, Response, StreamingResponse
from ..auth import can_access_node, filter_nodes_for_user
from ..clients.agent import AgentError, agent_get, agent_get_raw_stream, agent_post
from ..core.deps import require_login_page
from ..core.flash import flash, set_flash
from ..core.share import make_share_token, verify_share_token, verify_share_token_allow_expired
from ..core.templates import templates
from ..db import (
    add_certificate,
    add_site,
    add_site_check,
    add_site_event,
    add_task,
    create_site_file_share_short_link,
    delete_site_file_share_short_links,
    delete_certificates_by_node,
    delete_certificates_by_site,
    delete_site,
    delete_site_checks,
    delete_site_events,
    delete_sites_by_node,
    get_node,
    get_site,
    list_certificates,
    list_site_checks,
    list_site_events,
    list_site_file_share_short_links,
    list_tasks,
    list_nodes,
    list_sites,
    get_site_file_share_short_link,
    is_site_file_share_token_revoked,
    revoke_site_file_share_token,
    update_node_basic,
    update_certificate,
    update_site,
    update_site_health,
    update_task,
)
from ..services.apply import node_verify_tls
from ..services.assets import panel_public_base_url

router = APIRouter()
UPLOAD_CHUNK_SIZE = 1024 * 512


def _parse_upload_max_bytes() -> int:
    raw_b = os.getenv("REALM_WEBSITE_UPLOAD_MAX_BYTES")
    raw_mb = os.getenv("REALM_WEBSITE_UPLOAD_MAX_MB")
    try:
        if raw_b:
            v = int(float(str(raw_b).strip()))
            return max(1, v)
    except Exception:
        pass
    try:
        if raw_mb:
            v = int(float(str(raw_mb).strip()))
            return max(1, v) * 1024 * 1024
    except Exception:
        pass
    # default 2GB
    return 1024 * 1024 * 2048


UPLOAD_MAX_BYTES = _parse_upload_max_bytes()


def _parse_upload_compat_concurrency() -> int:
    raw = os.getenv("REALM_WEBSITE_UPLOAD_COMPAT_CONCURRENCY")
    try:
        if raw:
            v = int(float(str(raw).strip()))
            return max(1, min(8, v))
    except Exception:
        pass
    return 3


UPLOAD_COMPAT_CONCURRENCY = _parse_upload_compat_concurrency()


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


FILE_SHARE_MIN_TTL_SEC = max(300, _parse_int_env("REALM_WEBSITE_FILE_SHARE_MIN_TTL_SEC", 300))
FILE_SHARE_MAX_TTL_SEC = max(FILE_SHARE_MIN_TTL_SEC, _parse_int_env("REALM_WEBSITE_FILE_SHARE_MAX_TTL_SEC", 30 * 86400))
FILE_SHARE_DEFAULT_TTL_SEC = _parse_int_env("REALM_WEBSITE_FILE_SHARE_DEFAULT_TTL_SEC", 86400)
if FILE_SHARE_DEFAULT_TTL_SEC < FILE_SHARE_MIN_TTL_SEC:
    FILE_SHARE_DEFAULT_TTL_SEC = FILE_SHARE_MIN_TTL_SEC
if FILE_SHARE_DEFAULT_TTL_SEC > FILE_SHARE_MAX_TTL_SEC:
    FILE_SHARE_DEFAULT_TTL_SEC = FILE_SHARE_MAX_TTL_SEC
FILE_SHARE_MAX_ITEMS = max(1, _parse_int_env("REALM_WEBSITE_FILE_SHARE_MAX_ITEMS", 200))
_SHORT_SHARE_CODE_RE = re.compile(r"^[A-Za-z0-9]{6,24}$")
_SHARE_ZIP_JOB_TTL_SEC = max(300, _parse_int_env("REALM_WEBSITE_SHARE_ZIP_JOB_TTL_SEC", 3600))
_SHARE_ZIP_MAX_JOBS = max(20, _parse_int_env("REALM_WEBSITE_SHARE_ZIP_MAX_JOBS", 200))
_SHARE_ZIP_JOBS: Dict[str, Dict[str, Any]] = {}
_SHARE_ZIP_JOBS_LOCK = threading.Lock()

_SITE_OP_MAX_ATTEMPTS = max(1, min(30, _parse_int_env("REALM_WEBSITE_OP_MAX_ATTEMPTS", 10)))
_SITE_OP_RETRY_BASE_SEC = max(1.0, min(120.0, _parse_float_env("REALM_WEBSITE_OP_RETRY_BASE_SEC", 3.0)))
_SITE_OP_RETRY_MAX_SEC = max(_SITE_OP_RETRY_BASE_SEC, min(600.0, _parse_float_env("REALM_WEBSITE_OP_RETRY_MAX_SEC", 60.0)))
_SITE_OP_MAX_CONCURRENT = max(1, min(8, _parse_int_env("REALM_WEBSITE_OP_MAX_CONCURRENT", 2)))
_SITE_OP_SEM: Optional[asyncio.Semaphore] = None
_SITE_OP_SEM_LOCK = threading.Lock()
_SITE_BG_TASKS: set[asyncio.Task[Any]] = set()
_SITE_BG_TASKS_LOCK = threading.Lock()


class _WebsiteTaskFatalError(RuntimeError):
    """Unrecoverable website background task error (do not retry)."""


def _site_op_semaphore() -> asyncio.Semaphore:
    global _SITE_OP_SEM
    sem = _SITE_OP_SEM
    if sem is not None:
        return sem
    with _SITE_OP_SEM_LOCK:
        sem = _SITE_OP_SEM
        if sem is None:
            sem = asyncio.Semaphore(_SITE_OP_MAX_CONCURRENT)
            _SITE_OP_SEM = sem
        return sem


def _site_task_backoff_sec(attempt_no: int) -> float:
    n = max(1, int(attempt_no or 1))
    return float(min(_SITE_OP_RETRY_MAX_SEC, _SITE_OP_RETRY_BASE_SEC * (2 ** (n - 1))))


def _site_task_progress_for_attempt(attempt_no: int, max_attempts: int) -> int:
    total = max(1, int(max_attempts or 1))
    cur = max(1, min(total, int(attempt_no or 1)))
    if total <= 1:
        return 10
    ratio = float(cur - 1) / float(total - 1)
    return max(8, min(90, int(8 + ratio * 72)))


def _track_site_bg_task(task: asyncio.Task[Any]) -> None:
    with _SITE_BG_TASKS_LOCK:
        _SITE_BG_TASKS.add(task)

    def _done(t: asyncio.Task[Any]) -> None:
        with _SITE_BG_TASKS_LOCK:
            _SITE_BG_TASKS.discard(t)
        try:
            _ = t.exception()
        except Exception:
            pass

    task.add_done_callback(_done)


def _launch_site_bg_job(coro: Awaitable[Any]) -> bool:
    try:
        t = asyncio.create_task(coro)
    except Exception:
        return False
    _track_site_bg_task(t)
    return True


def _to_flag(value: Any) -> bool:
    s = str(value or "").strip().lower()
    return s in ("1", "true", "yes", "on", "y")


async def _run_site_task_with_retry(
    task_id: int,
    op_name: str,
    runner: Callable[[], Awaitable[Any]],
) -> Tuple[Any, int]:
    last_exc: Optional[Exception] = None
    for attempt in range(1, _SITE_OP_MAX_ATTEMPTS + 1):
        update_task(
            int(task_id),
            status="running",
            progress=_site_task_progress_for_attempt(attempt, _SITE_OP_MAX_ATTEMPTS),
            error="",
            result={"op": str(op_name or ""), "attempt": int(attempt), "max_attempts": int(_SITE_OP_MAX_ATTEMPTS)},
        )
        try:
            async with _site_op_semaphore():
                data = await runner()
            return data, int(attempt)
        except _WebsiteTaskFatalError as exc:
            last_exc = exc
            break
        except Exception as exc:
            last_exc = exc
            if attempt >= _SITE_OP_MAX_ATTEMPTS:
                break
            wait_s = _site_task_backoff_sec(attempt)
            update_task(
                int(task_id),
                status="queued",
                progress=_site_task_progress_for_attempt(attempt, _SITE_OP_MAX_ATTEMPTS),
                error=str(exc),
                result={
                    "op": str(op_name or ""),
                    "attempt": int(attempt),
                    "max_attempts": int(_SITE_OP_MAX_ATTEMPTS),
                    "retry_in_sec": float(wait_s),
                },
            )
            await asyncio.sleep(wait_s)
    if last_exc is None:
        raise RuntimeError("任务执行失败")
    raise last_exc


def _parse_share_ttl_sec(raw: Any) -> int:
    try:
        ttl = int(float(raw))
    except Exception:
        ttl = int(FILE_SHARE_DEFAULT_TTL_SEC)
    if ttl < FILE_SHARE_MIN_TTL_SEC:
        ttl = FILE_SHARE_MIN_TTL_SEC
    if ttl > FILE_SHARE_MAX_TTL_SEC:
        ttl = FILE_SHARE_MAX_TTL_SEC
    return ttl


def _normalize_rel_path(raw: Any) -> str:
    text = str(raw or "").replace("\\", "/").strip().lstrip("/")
    if not text:
        return ""
    segs: List[str] = []
    for seg in text.split("/"):
        if not seg or seg == ".":
            continue
        if seg == "..":
            raise ValueError("非法路径")
        segs.append(seg)
    return "/".join(segs)


def _parse_share_items(raw: Any) -> List[Dict[str, Any]]:
    rows = raw
    if isinstance(rows, dict):
        rows = [rows]
    elif isinstance(rows, str):
        rows = [x for x in rows.split(",") if x.strip()]
    if not isinstance(rows, list):
        return []

    out: List[Dict[str, Any]] = []
    seen: Dict[str, int] = {}
    for row in rows:
        path_raw: Any = row
        is_dir = False
        if isinstance(row, dict):
            path_raw = row.get("path") or row.get("value") or ""
            is_dir = bool(row.get("is_dir"))
        path = _normalize_rel_path(path_raw)
        if not path:
            continue
        idx = seen.get(path)
        if idx is None:
            seen[path] = len(out)
            out.append({"path": path, "is_dir": is_dir})
        elif is_dir:
            out[idx]["is_dir"] = True
    return out


def _sanitize_download_name(raw: Any, fallback: str) -> str:
    text = str(raw or "").strip().lower()
    if not text:
        text = fallback
    parts: List[str] = []
    for ch in text:
        if ("a" <= ch <= "z") or ("0" <= ch <= "9") or ch in ("-", "_", "."):
            parts.append(ch)
        else:
            parts.append("-")
    name = "".join(parts).strip("-.")
    if not name:
        name = fallback
    return name[:96]


def _zip_arcname(raw: Any) -> str:
    text = str(raw or "").replace("\\", "/").strip().lstrip("/")
    if not text:
        return ""
    segs: List[str] = []
    for seg in text.split("/"):
        if not seg or seg == ".":
            continue
        if seg == "..":
            continue
        segs.append(seg)
    return "/".join(segs)


def _remove_file_quiet(path: str) -> None:
    try:
        if path and os.path.exists(path):
            os.remove(path)
    except Exception:
        pass


def _share_items_signature(share_items: List[Dict[str, Any]]) -> str:
    rows: List[str] = []
    for item in share_items:
        try:
            rel = _normalize_rel_path(item.get("path"))
        except Exception:
            rel = ""
        if not rel:
            continue
        rows.append(f"{rel}|{1 if bool(item.get('is_dir')) else 0}")
    rows.sort()
    if not rows:
        return ""
    return hashlib.sha256("\n".join(rows).encode("utf-8")).hexdigest()


def _cleanup_share_zip_jobs() -> None:
    now_ts = time.time()
    to_remove: List[str] = []
    with _SHARE_ZIP_JOBS_LOCK:
        for jid, job in list(_SHARE_ZIP_JOBS.items()):
            expire_at = float(job.get("expire_at") or 0)
            if expire_at > 0 and now_ts >= expire_at:
                to_remove.append(jid)

        if len(_SHARE_ZIP_JOBS) - len(to_remove) > _SHARE_ZIP_MAX_JOBS:
            kept = [j for j in _SHARE_ZIP_JOBS.items() if j[0] not in to_remove]
            removable = []
            for kv in kept:
                status = str(((kv[1] or {}).get("status") or "")).strip().lower()
                if status in ("done", "error"):
                    removable.append(kv)
            removable.sort(key=lambda kv: float((kv[1] or {}).get("updated_at") or 0))
            overflow = (len(_SHARE_ZIP_JOBS) - len(to_remove)) - _SHARE_ZIP_MAX_JOBS
            for idx in range(max(0, overflow)):
                if idx >= len(removable):
                    break
                to_remove.append(str(removable[idx][0]))

        to_remove = list(dict.fromkeys(to_remove))
        remove_paths = []
        for jid in to_remove:
            job = _SHARE_ZIP_JOBS.pop(jid, None)
            if isinstance(job, dict):
                remove_paths.append(str(job.get("zip_path") or ""))

    for path in remove_paths:
        _remove_file_quiet(path)


def _get_share_zip_job(job_id: str) -> Optional[Dict[str, Any]]:
    _cleanup_share_zip_jobs()
    jid = str(job_id or "").strip()
    if not jid:
        return None
    with _SHARE_ZIP_JOBS_LOCK:
        row = _SHARE_ZIP_JOBS.get(jid)
        if not isinstance(row, dict):
            return None
        return dict(row)


def _upsert_share_zip_job(job: Dict[str, Any]) -> None:
    if not isinstance(job, dict):
        return
    jid = str(job.get("id") or "").strip()
    if not jid:
        return
    with _SHARE_ZIP_JOBS_LOCK:
        _SHARE_ZIP_JOBS[jid] = dict(job)


def _new_share_zip_job(site_id: int, token_sha256: str, items_sig: str, filename: str) -> Dict[str, Any]:
    now_ts = time.time()
    return {
        "id": uuid.uuid4().hex,
        "site_id": int(site_id),
        "token_sha256": str(token_sha256 or ""),
        "items_sig": str(items_sig or ""),
        "filename": str(filename or "download.zip"),
        "status": "queued",  # queued -> running -> done|error
        "error": "",
        "zip_path": "",
        "file_count": 0,
        "created_at": now_ts,
        "updated_at": now_ts,
        "expire_at": now_ts + float(_SHARE_ZIP_JOB_TTL_SEC),
    }


def _find_share_zip_job(site_id: int, token_sha256: str, items_sig: str) -> Optional[Dict[str, Any]]:
    _cleanup_share_zip_jobs()
    with _SHARE_ZIP_JOBS_LOCK:
        for row in _SHARE_ZIP_JOBS.values():
            if not isinstance(row, dict):
                continue
            if int(row.get("site_id") or 0) != int(site_id):
                continue
            if str(row.get("token_sha256") or "") != str(token_sha256 or ""):
                continue
            if str(row.get("items_sig") or "") != str(items_sig or ""):
                continue
            status = str(row.get("status") or "")
            if status in ("queued", "running", "done"):
                return dict(row)
    return None


def _share_zip_wait_page_html(job_id: str, token: str) -> str:
    job_js = json.dumps(str(job_id or ""))
    tok_js = json.dumps(str(token or ""))
    return (
        "<!doctype html><html lang='zh'><head><meta charset='utf-8'>"
        "<meta name='viewport' content='width=device-width, initial-scale=1'>"
        "<title>准备下载中</title>"
        "<style>body{font-family:-apple-system,BlinkMacSystemFont,Segoe UI,Roboto,PingFang SC,Microsoft YaHei,sans-serif;"
        "background:#0b1220;color:#e5e7eb;padding:32px} .box{max-width:760px;margin:0 auto;padding:20px;border:1px solid #334155;"
        "border-radius:12px;background:#0f172a} .muted{color:#93a4bf} .mono{font-family:ui-monospace,Menlo,Consolas,monospace}"
        " .bar{height:8px;border-radius:999px;background:#1e293b;overflow:hidden;margin:14px 0} .fill{height:100%;width:14%;"
        "background:linear-gradient(90deg,#38bdf8,#22c55e);animation:slide 1.2s ease-in-out infinite} @keyframes slide{0%{margin-left:-35%}"
        "50%{margin-left:40%}100%{margin-left:100%}}</style></head><body><div class='box'>"
        "<h2 style='margin:0 0 8px;'>正在打包文件，请稍候…</h2>"
        "<div class='muted' id='status'>任务已创建，准备开始</div>"
        "<div class='bar'><div class='fill'></div></div>"
        "<div class='muted mono' id='hint'></div></div><script>"
        f"const JOB_ID={job_js}; const TOKEN={tok_js};"
        "const statusEl=document.getElementById('status'); const hintEl=document.getElementById('hint');"
        "function dlUrl(){return '/share/site-files/job/download?j='+encodeURIComponent(JOB_ID)+'&t='+encodeURIComponent(TOKEN)}"
        "async function poll(){"
        "try{const r=await fetch('/share/site-files/job/status?j='+encodeURIComponent(JOB_ID)+'&t='+encodeURIComponent(TOKEN),{cache:'no-store'});"
        "const d=await r.json();"
        "if(!d||!d.ok){statusEl.textContent=String((d&&d.error)||'打包状态获取失败');return;}"
        "const st=String(d.status||'queued');"
        "if(st==='done'){statusEl.textContent='打包完成，开始下载…';window.location.href=dlUrl();return;}"
        "if(st==='error'){statusEl.textContent=String(d.error||'打包失败');return;}"
        "statusEl.textContent=st==='running'?'正在打包中…':'排队中…';"
        "const files=parseInt(d.file_count||0,10)||0;"
        "if(files>0){hintEl.textContent='已处理文件数：'+files;}"
        "setTimeout(poll,1500);}catch(e){statusEl.textContent='网络波动，正在重试状态查询…';setTimeout(poll,2000);}}"
        "poll();</script></body></html>"
    )


def _validate_site_files_share_token(t: str) -> Tuple[Optional[Dict[str, Any]], Optional[Response]]:
    payload = verify_share_token(t)
    if not isinstance(payload, dict) or str(payload.get("page") or "") != "site_files_download":
        return None, Response(content="分享链接无效或已过期", media_type="text/plain", status_code=403)

    try:
        site_id = int(payload.get("site_id") or 0)
    except Exception:
        site_id = 0
    if site_id <= 0:
        return None, Response(content="分享链接无效", media_type="text/plain", status_code=400)
    digest = _share_token_sha256(t)
    if digest and is_site_file_share_token_revoked(site_id, digest):
        return None, Response(content="分享链接已取消", media_type="text/plain", status_code=403)
    return {"payload": payload, "site_id": site_id, "token_sha256": digest, "token": str(t or "")}, None


async def _run_share_zip_job(
    job_id: str,
    node: Dict[str, Any],
    root: str,
    share_items: List[Dict[str, Any]],
) -> None:
    row = _get_share_zip_job(job_id) or {}
    if not row:
        return
    row["status"] = "running"
    row["updated_at"] = time.time()
    _upsert_share_zip_job(row)
    try:
        zip_path, file_count = await _build_share_zip(node, root, share_items)
        if file_count <= 0:
            _remove_file_quiet(zip_path)
            raise RuntimeError("没有可下载的文件")
        row = _get_share_zip_job(job_id) or {}
        if not row:
            _remove_file_quiet(zip_path)
            return
        row["status"] = "done"
        row["zip_path"] = zip_path
        row["file_count"] = int(file_count)
        row["error"] = ""
        row["updated_at"] = time.time()
        row["expire_at"] = max(float(row.get("expire_at") or 0), time.time() + float(_SHARE_ZIP_JOB_TTL_SEC))
        _upsert_share_zip_job(row)
    except Exception as exc:
        row = _get_share_zip_job(job_id) or {}
        if not row:
            return
        row["status"] = "error"
        row["error"] = str(exc)
        row["updated_at"] = time.time()
        _upsert_share_zip_job(row)


def _build_stream_zip_filename(site_id: int, site_name: Any) -> str:
    stamp = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
    base = _sanitize_download_name(site_name, f"site-{site_id}")
    return f"{base}-share-{stamp}.zip"


def _build_path_zip_filename(site_id: int, site_name: Any, rel_path: str) -> str:
    stamp = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
    leaf = str(rel_path or "").replace("\\", "/").rstrip("/").split("/")[-1]
    fallback = _sanitize_download_name(site_name, f"site-{site_id}")
    base = _sanitize_download_name(leaf, fallback)
    return f"{base}-{stamp}.zip"


async def _iter_share_zip_stream(
    node: Dict[str, Any],
    root: str,
    share_items: List[Dict[str, Any]],
):
    queue: "asyncio.Queue[Optional[bytes]]" = asyncio.Queue()
    state: Dict[str, Any] = {"error": None, "started": False}

    class _QueueWriter:
        def __init__(self, out_queue: "asyncio.Queue[Optional[bytes]]") -> None:
            self._queue = out_queue

        def write(self, data: Any) -> int:
            if not data:
                return 0
            chunk = bytes(data)
            if not chunk:
                return 0
            self._queue.put_nowait(chunk)
            return len(chunk)

        def flush(self) -> None:
            return None

    async def _producer() -> None:
        errors: List[str] = []

        async def _add_entry(zf: zipfile.ZipFile, rel_path: str, arc_path: str, is_dir: bool) -> None:
            arc = _zip_arcname(arc_path)
            if not arc:
                return
            if is_dir:
                try:
                    rows = await _agent_list_files(node, root, rel_path)
                except Exception as exc:
                    errors.append(f"{rel_path}: {exc}")
                    return
                if not rows:
                    zf.writestr(f"{arc.rstrip('/')}/", b"")
                    return
                for row in rows:
                    child_arc = _zip_arcname(f"{arc}/{row.get('name') or ''}")
                    await _add_entry(zf, str(row.get("path") or ""), child_arc, bool(row.get("is_dir")))
                return

            upstream, status_code, _detail = await _open_agent_file_stream(node, root, rel_path, timeout=600)
            if upstream is None:
                errors.append(f"{rel_path}: HTTP {status_code}")
                return
            try:
                with zf.open(arc, mode="w", force_zip64=True) as dst:
                    async for chunk in upstream.aiter_bytes():
                        if chunk:
                            dst.write(chunk)
            finally:
                try:
                    await upstream.aclose()
                except Exception:
                    pass

        try:
            writer = _QueueWriter(queue)
            with zipfile.ZipFile(writer, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=6, allowZip64=True) as zf:
                # Emit first bytes immediately to avoid proxy first-byte timeout.
                zf.writestr(".nexus-share.keep", b"")
                state["started"] = True
                for item in share_items:
                    rel = str(item.get("path") or "")
                    await _add_entry(zf, rel, rel, bool(item.get("is_dir")))
                if errors:
                    zf.writestr(".nexus-share-errors.txt", "\n".join(errors).encode("utf-8"))
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            state["error"] = exc
        finally:
            await queue.put(None)

    producer_task = asyncio.create_task(_producer())
    try:
        while True:
            chunk = await queue.get()
            if chunk is None:
                break
            if chunk:
                yield chunk
        err = state.get("error")
        if err is not None and not bool(state.get("started")):
            raise err
    finally:
        if not producer_task.done():
            producer_task.cancel()
        try:
            await producer_task
        except asyncio.CancelledError:
            pass
        except Exception:
            pass


def _download_content_disposition(filename: str) -> str:
    raw = str(filename or "download.bin").replace("\r", "").replace("\n", "").replace('"', "")
    if not raw:
        raw = "download.bin"
    ascii_name = "".join(
        ch if (("0" <= ch <= "9") or ("a" <= ch <= "z") or ("A" <= ch <= "Z") or ch in ("-", "_", "."))
        else "_"
        for ch in raw
    ).strip("._")
    if not ascii_name:
        ascii_name = "download.bin"
    return f"attachment; filename=\"{ascii_name}\"; filename*=UTF-8''{quote(raw)}"


async def _open_agent_file_stream(
    node: Dict[str, Any],
    root: str,
    rel_path: str,
    timeout: float,
) -> Tuple[Optional[Any], int, str]:
    resp = await agent_get_raw_stream(
        node.get("base_url", ""),
        node.get("api_key", ""),
        "/api/v1/website/files/raw",
        node_verify_tls(node),
        params={"root": root, "path": rel_path, "root_base": _node_root_base(node)},
        timeout=timeout,
    )
    if resp.status_code == 200:
        return resp, 200, ""
    body_text = ""
    try:
        body = await resp.aread()
        body_text = (body or b"").decode(errors="ignore").strip()
    except Exception:
        body_text = ""
    try:
        await resp.aclose()
    except Exception:
        pass
    return None, int(resp.status_code or 500), body_text


def _stream_file_download_response(upstream: Any, filename: str) -> StreamingResponse:
    headers = {"Content-Disposition": _download_content_disposition(filename)}
    content_len = str(upstream.headers.get("content-length") or "").strip()
    if content_len.isdigit():
        headers["Content-Length"] = content_len
    media_type = str(upstream.headers.get("content-type") or "application/octet-stream")

    async def _iter_bytes():
        try:
            async for chunk in upstream.aiter_bytes():
                if chunk:
                    yield chunk
        finally:
            try:
                await upstream.aclose()
            except Exception:
                pass

    return StreamingResponse(_iter_bytes(), media_type=media_type, headers=headers)


def _share_token_sha256(token: str) -> str:
    tok = str(token or "").strip()
    if not tok:
        return ""
    return hashlib.sha256(tok.encode("utf-8")).hexdigest()


def _extract_share_token(raw: Any) -> str:
    text = str(raw or "").strip()
    if not text:
        return ""
    if "://" not in text and "?" not in text:
        return text
    try:
        parsed = urlparse(text)
        q = parse_qs(parsed.query or "")
        token = ""
        vals = q.get("t") or []
        if vals:
            token = str(vals[0] or "").strip()
        return token
    except Exception:
        return ""


def _extract_share_short_code(raw: Any) -> str:
    text = str(raw or "").strip()
    if not text:
        return ""
    if _SHORT_SHARE_CODE_RE.fullmatch(text):
        return text

    path = ""
    try:
        if "://" in text:
            path = str(urlparse(text).path or "")
        elif text.startswith("/"):
            path = text
    except Exception:
        path = ""

    marker = "/share/site-files/s/"
    if marker and marker in path:
        tail = path.split(marker, 1)[1]
        code = tail.split("/", 1)[0].strip()
        if _SHORT_SHARE_CODE_RE.fullmatch(code):
            return code
    return ""


def _resolve_share_token_input(raw: Any) -> str:
    tok = _extract_share_token(raw)
    if tok and verify_share_token(tok):
        return tok
    code = _extract_share_short_code(raw)
    if not code:
        return tok
    row = get_site_file_share_short_link(code)
    if not row:
        return tok
    tok2 = str(row.get("token") or "").strip()
    return tok2 or tok


async def _agent_list_files(node: Dict[str, Any], root: str, path: str) -> List[Dict[str, Any]]:
    q = urlencode({"root": root, "path": path, "root_base": _node_root_base(node)})
    data = await agent_get(
        node["base_url"],
        node["api_key"],
        f"/api/v1/website/files/list?{q}",
        node_verify_tls(node),
        timeout=20,
    )
    if not data.get("ok", True):
        raise AgentError(str(data.get("error") or "读取目录失败"))
    rows = data.get("items") or []
    out: List[Dict[str, Any]] = []
    for row in rows:
        try:
            rel = _normalize_rel_path(row.get("path"))
        except Exception:
            continue
        if not rel:
            continue
        out.append(
            {
                "path": rel,
                "name": str(row.get("name") or rel.split("/")[-1] or rel),
                "is_dir": bool(row.get("is_dir")),
            }
        )
    return out


async def _build_share_zip(
    node: Dict[str, Any],
    root: str,
    share_items: List[Dict[str, Any]],
) -> Tuple[str, int]:
    fd, zip_path = tempfile.mkstemp(prefix="nexus-share-", suffix=".zip")
    os.close(fd)
    file_count = 0

    async def _add_entry(zf: zipfile.ZipFile, rel_path: str, arc_path: str, is_dir: bool) -> None:
        nonlocal file_count
        arc = _zip_arcname(arc_path)
        if not arc:
            return
        if is_dir:
            rows = await _agent_list_files(node, root, rel_path)
            if not rows:
                zf.writestr(f"{arc.rstrip('/')}/", b"")
                return
            for row in rows:
                child_arc = _zip_arcname(f"{arc}/{row.get('name') or ''}")
                await _add_entry(zf, str(row.get("path") or ""), child_arc, bool(row.get("is_dir")))
            return

        upstream, status_code, _detail = await _open_agent_file_stream(node, root, rel_path, timeout=600)
        if upstream is None:
            raise AgentError(f"打包失败：{rel_path}（HTTP {status_code}）")
        try:
            with zf.open(arc, mode="w", force_zip64=True) as dst:
                async for chunk in upstream.aiter_bytes():
                    if chunk:
                        dst.write(chunk)
        finally:
            try:
                await upstream.aclose()
            except Exception:
                pass
        file_count += 1

    try:
        with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=6) as zf:
            for item in share_items:
                rel = str(item.get("path") or "")
                arc = rel
                await _add_entry(zf, rel, arc, bool(item.get("is_dir")))
    except Exception:
        _remove_file_quiet(zip_path)
        raise
    return zip_path, file_count


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


def _is_agent_unreachable_error(err: Any) -> bool:
    msg = str(err or "").strip().lower()
    if not msg:
        return False
    tokens = (
        "all connection attempts failed",
        "connection refused",
        "connect timeout",
        "read timeout",
        "timed out",
        "name or service not known",
        "temporary failure in name resolution",
        "network is unreachable",
        "no route to host",
        "cannot assign requested address",
        "tls handshake",
        "ssl:",
    )
    return any(t in msg for t in tokens)


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


_ENV_CAP_ALIAS = {
    "nginx": "nginx",
    "php": "php-fpm",
    "php-fpm": "php-fpm",
    "phpfpm": "php-fpm",
    "acme": "acme.sh",
    "acme.sh": "acme.sh",
}


def _normalize_env_cap_name(raw: Any) -> str:
    k = str(raw or "").strip().lower()
    if not k:
        return ""
    return _ENV_CAP_ALIAS.get(k, k)


def _persist_node_capabilities(node: Dict[str, Any], caps: Dict[str, Any]) -> None:
    try:
        update_node_basic(
            int(node.get("id") or 0),
            str(node.get("name") or ""),
            str(node.get("base_url") or ""),
            str(node.get("api_key") or ""),
            verify_tls=bool(node.get("verify_tls")),
            is_private=bool(node.get("is_private")),
            group_name=str(node.get("group_name") or "默认分组"),
            capabilities=dict(caps or {}),
            website_root_base=str(node.get("website_root_base") or "").strip(),
        )
        node["capabilities"] = dict(caps or {})
    except Exception:
        # Best-effort UI metadata; never block main website operations.
        pass


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

    if changed:
        _persist_node_capabilities(node, merged)


_ENV_TASK_TYPES = {"website_env_ensure", "website_env_uninstall"}


def _attach_latest_env_tasks(nodes: List[Dict[str, Any]]) -> None:
    if not isinstance(nodes, list) or not nodes:
        return
    node_ids: set[int] = set()
    for n in nodes:
        try:
            nid = int((n or {}).get("id") or 0)
        except Exception:
            nid = 0
        if nid > 0:
            node_ids.add(nid)
    if not node_ids:
        return
    latest: Dict[int, Dict[str, Any]] = {}
    try:
        rows = list_tasks(limit=max(80, len(node_ids) * 10))
    except Exception:
        rows = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        tname = str(row.get("type") or "").strip().lower()
        if tname not in _ENV_TASK_TYPES:
            continue
        try:
            nid = int(row.get("node_id") or 0)
        except Exception:
            nid = 0
        if nid <= 0 or nid not in node_ids or nid in latest:
            continue
        latest[nid] = row
    for n in nodes:
        try:
            nid = int((n or {}).get("id") or 0)
        except Exception:
            nid = 0
        if nid > 0:
            n["latest_env_task"] = latest.get(nid)


def _ensure_certificate_pending(site_id: int, node_id: int, domains: List[str]) -> int:
    existing = list_certificates(site_id=int(site_id))
    cert_id = int(existing[0].get("id") or 0) if existing else 0
    if cert_id > 0:
        update_certificate(
            cert_id,
            domains=list(domains or []),
            status="pending",
            last_error="",
        )
        return cert_id
    return int(
        add_certificate(
            node_id=int(node_id),
            site_id=int(site_id),
            domains=list(domains or []),
            status="pending",
            last_error="",
        )
    )


async def _bg_website_env_ensure(task_id: int, node_id: int, include_php: bool) -> None:
    try:
        async def _runner() -> Dict[str, Any]:
            node = get_node(int(node_id))
            if not node or str(node.get("role") or "") != "website":
                raise _WebsiteTaskFatalError("节点不存在或不是网站机")
            payload = {
                "need_nginx": True,
                "need_php": bool(include_php),
                "need_acme": True,
            }
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
            _merge_node_env_caps(node, data)
            return data

        data, attempts = await _run_site_task_with_retry(int(task_id), "website_env_ensure", _runner)
        result = dict(data) if isinstance(data, dict) else {}
        result["attempts"] = int(attempts)
        update_task(int(task_id), status="success", progress=100, error="", result=result)
    except Exception as exc:
        update_task(
            int(task_id),
            status="failed",
            progress=100,
            error=str(exc),
            result={"op": "website_env_ensure"},
        )


async def _bg_website_env_uninstall(task_id: int, node_id: int, purge_data: bool, deep_uninstall: bool) -> None:
    try:
        async def _runner() -> Dict[str, Any]:
            node = get_node(int(node_id))
            if not node or str(node.get("role") or "") != "website":
                raise _WebsiteTaskFatalError("节点不存在或不是网站机")
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
            return data

        data, attempts = await _run_site_task_with_retry(int(task_id), "website_env_uninstall", _runner)
        result = dict(data) if isinstance(data, dict) else {}
        result["attempts"] = int(attempts)
        update_task(int(task_id), status="success", progress=100, error="", result=result)
    except Exception as exc:
        update_task(
            int(task_id),
            status="failed",
            progress=100,
            error=str(exc),
            result={"op": "website_env_uninstall"},
        )


async def _bg_website_ssl_task(task_id: int, site_id: int, cert_id: int, actor: str, action: str) -> None:
    act = str(action or "").strip().lower()
    if act not in ("issue", "renew"):
        update_task(
            int(task_id),
            status="failed",
            progress=100,
            error="不支持的 SSL 任务类型",
            result={"op": f"website_ssl_{act or 'unknown'}"},
        )
        return

    event_action = f"ssl_{act}"
    site_payload: Dict[str, Any] = {}
    site_obj = get_site(int(site_id))
    if isinstance(site_obj, dict):
        site_payload = {"domains": list(site_obj.get("domains") or []), "task_id": int(task_id)}
    add_site_event(int(site_id), event_action, status="running", actor=str(actor or ""), payload=site_payload)

    path = "/api/v1/website/ssl/issue" if act == "issue" else "/api/v1/website/ssl/renew"
    task_op = f"website_ssl_{act}"

    try:
        async def _runner() -> Dict[str, Any]:
            site = get_site(int(site_id))
            if not site:
                raise _WebsiteTaskFatalError("站点不存在")
            node_id = int(site.get("node_id") or 0)
            node = get_node(node_id)
            if not node:
                raise _WebsiteTaskFatalError("节点不存在")
            domains = site.get("domains") or []
            if not domains:
                raise _WebsiteTaskFatalError("站点域名为空")

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

            data = await agent_post(
                node["base_url"],
                node["api_key"],
                path,
                req_payload,
                node_verify_tls(node),
                timeout=240,
            )
            if not data.get("ok", True):
                err = str(data.get("error") or ("证书申请失败" if act == "issue" else "证书续期失败"))
                if "未安装" in err and "acme.sh" in err:
                    env_payload = {
                        "need_nginx": True,
                        "need_php": bool((site.get("type") or "") == "php"),
                        "need_acme": True,
                    }
                    env_data = await agent_post(
                        node["base_url"],
                        node["api_key"],
                        "/api/v1/website/env/ensure",
                        env_payload,
                        node_verify_tls(node),
                        timeout=300,
                    )
                    if not env_data.get("ok", True):
                        raise AgentError(f"{err}；自动安装环境失败：{env_data.get('error')}")
                    _merge_node_env_caps(node, env_data)
                    data = await agent_post(
                        node["base_url"],
                        node["api_key"],
                        path,
                        req_payload,
                        node_verify_tls(node),
                        timeout=240,
                    )
                    if not data.get("ok", True):
                        raise AgentError(str(data.get("error") or err))
                else:
                    raise AgentError(err)
            return {"site": site, "domains": domains, "data": data}

        ret, attempts = await _run_site_task_with_retry(int(task_id), task_op, _runner)
        site = ret.get("site") if isinstance(ret, dict) else {}
        domains = (ret.get("domains") if isinstance(ret, dict) else []) or []
        data = (ret.get("data") if isinstance(ret, dict) else {}) or {}
        node_id = int((site or {}).get("node_id") or 0)

        if int(cert_id) > 0:
            update_certificate(
                int(cert_id),
                status="valid",
                domains=list(domains),
                not_before=data.get("not_before"),
                not_after=data.get("not_after"),
                renew_at=data.get("renew_at"),
                last_error="",
            )
        elif node_id > 0:
            add_certificate(
                node_id=node_id,
                site_id=int(site_id),
                domains=list(domains),
                status="valid",
                not_before=data.get("not_before"),
                not_after=data.get("not_after"),
                renew_at=data.get("renew_at"),
                last_error="",
            )

        result = dict(data) if isinstance(data, dict) else {}
        result["attempts"] = int(attempts)
        update_task(int(task_id), status="success", progress=100, error="", result=result)
        add_site_event(int(site_id), event_action, status="success", actor=str(actor or ""), result=data)
    except Exception as exc:
        err_text = str(exc)
        if int(cert_id) > 0:
            update_certificate(int(cert_id), status="failed", last_error=err_text)
        else:
            site = get_site(int(site_id))
            if isinstance(site, dict):
                node_id = int(site.get("node_id") or 0)
                domains = site.get("domains") or []
                if node_id > 0 and domains:
                    add_certificate(
                        node_id=node_id,
                        site_id=int(site_id),
                        domains=domains,
                        status="failed",
                        last_error=err_text,
                    )
        update_task(int(task_id), status="failed", progress=100, error=err_text, result={"op": task_op})
        add_site_event(int(site_id), event_action, status="failed", actor=str(actor or ""), error=err_text)


def _default_nginx_template(site_type: str) -> str:
    st = str(site_type or "static").strip().lower()
    if st == "reverse_proxy":
        return """server {
  listen 80;
  server_name {{SERVER_NAME}};
  {{GZIP_CONF}}

  location ^~ /.well-known/acme-challenge/ {
    root {{ACME_ROOT}};
    default_type "text/plain";
    try_files $uri =404;
  }

  location / {
    proxy_pass {{PROXY_TARGET}};
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto $scheme;
  }
}

# Optional: enable 443 block after certificate is ready.
# server {
#   listen 443 ssl http2;
#   server_name {{SERVER_NAME}};
#   ssl_certificate {{SSL_CERT}};
#   ssl_certificate_key {{SSL_KEY}};
#   {{GZIP_CONF}}
#   location ^~ /.well-known/acme-challenge/ {
#     root {{ACME_ROOT}};
#     default_type "text/plain";
#     try_files $uri =404;
#   }
#   location / {
#     proxy_pass {{PROXY_TARGET}};
#     proxy_set_header Host $host;
#     proxy_set_header X-Real-IP $remote_addr;
#     proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
#     proxy_set_header X-Forwarded-Proto $scheme;
#   }
# }
"""
    if st == "php":
        return """server {
  listen 80;
  server_name {{SERVER_NAME}};
  root {{ROOT_PATH}};
  index index.php index.html index.htm;
  {{GZIP_CONF}}

  location ^~ /.well-known/acme-challenge/ {
    root {{ACME_ROOT}};
    default_type "text/plain";
    try_files $uri =404;
  }

  location / {
    try_files $uri $uri/ /index.php?$args;
  }

  location ~ \\.php$ {
    include fastcgi_params;
    fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
    fastcgi_pass unix:/run/php/php-fpm.sock;
  }
}

# Optional: enable 443 block after certificate is ready.
# server {
#   listen 443 ssl http2;
#   server_name {{SERVER_NAME}};
#   root {{ROOT_PATH}};
#   ssl_certificate {{SSL_CERT}};
#   ssl_certificate_key {{SSL_KEY}};
#   index index.php index.html index.htm;
#   {{GZIP_CONF}}
#   location ^~ /.well-known/acme-challenge/ {
#     root {{ACME_ROOT}};
#     default_type "text/plain";
#     try_files $uri =404;
#   }
#   location / {
#     try_files $uri $uri/ /index.php?$args;
#   }
#   location ~ \\.php$ {
#     include fastcgi_params;
#     fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
#     fastcgi_pass unix:/run/php/php-fpm.sock;
#   }
# }
"""
    return """server {
  listen 80;
  server_name {{SERVER_NAME}};
  root {{ROOT_PATH}};
  index index.html index.htm;
  {{GZIP_CONF}}

  location ^~ /.well-known/acme-challenge/ {
    root {{ACME_ROOT}};
    default_type "text/plain";
    try_files $uri =404;
  }

  location / {
    try_files $uri $uri/ =404;
  }
}

# Optional: enable 443 block after certificate is ready.
# server {
#   listen 443 ssl http2;
#   server_name {{SERVER_NAME}};
#   root {{ROOT_PATH}};
#   ssl_certificate {{SSL_CERT}};
#   ssl_certificate_key {{SSL_KEY}};
#   index index.html index.htm;
#   {{GZIP_CONF}}
#   location ^~ /.well-known/acme-challenge/ {
#     root {{ACME_ROOT}};
#     default_type "text/plain";
#     try_files $uri =404;
#   }
#   location / {
#     try_files $uri $uri/ =404;
#   }
# }
"""


def _diag_base_payload(site: Dict[str, Any]) -> Dict[str, Any]:
    hs = str(site.get("health_status") or "").strip().lower()
    ok: Optional[bool] = None
    if hs == "ok":
        ok = True
    elif hs == "fail":
        ok = False

    return {
        "ok": ok,
        "status_code": int(site.get("health_code") or 0),
        "latency_ms": int(site.get("health_latency_ms") or 0),
        "error": str(site.get("health_error") or "").strip(),
        "checks": {
            "nginx_test_ok": None,
            "nginx_active": None,
            "conf_exists": None,
            "conf_included": None,
            "root_exists": None,
            "php_ok": None,
            "http_ok": None,
            "http_status": 0,
            "vhost_match": None,
            "conf_path": "",
            "nginx_test_output": "",
        },
    }


def _diag_merge(base: Dict[str, Any], live: Any) -> Dict[str, Any]:
    out = dict(base or {})
    if not isinstance(live, dict):
        return out
    out.update(live)
    checks = dict((base or {}).get("checks") or {})
    if isinstance(live.get("checks"), dict):
        checks.update(live.get("checks") or {})
    out["checks"] = checks
    return out


@router.get("/websites", response_class=HTMLResponse)
async def websites_index(request: Request, user: str = Depends(require_login_page)):
    nodes = [n for n in filter_nodes_for_user(user, list_nodes()) if str(n.get("role") or "") == "website"]
    _attach_latest_env_tasks(nodes)
    sites = list_sites()
    node_map = {int(n["id"]): n for n in nodes}
    open_create = str(request.query_params.get("create") or request.query_params.get("new") or "").strip().lower() in (
        "1",
        "true",
        "yes",
        "on",
    )

    visible_sites: List[Dict[str, Any]] = []
    for s in sites:
        nid = int(s.get("node_id") or 0)
        node = node_map.get(nid)
        if not node:
            continue
        # If health failed only because panel cannot reach agent, show as unknown instead of fail.
        hs = str(s.get("health_status") or "").strip().lower()
        herr = str(s.get("health_error") or "").strip()
        if hs == "fail" and _is_agent_unreachable_error(herr):
            try:
                update_site_health(
                    int(s.get("id") or 0),
                    "unknown",
                    health_code=int(s.get("health_code") or 0),
                    health_latency_ms=int(s.get("health_latency_ms") or 0),
                    health_error=herr,
                )
            except Exception:
                pass
            s["health_status"] = "unknown"
        s["node"] = node
        s["domains_text"] = ", ".join(s.get("domains") or [])
        visible_sites.append(s)

    return templates.TemplateResponse(
        "websites.html",
        {
            "request": request,
            "user": user,
            "flash": flash(request),
            "title": "网站管理",
            "nodes": nodes,
            "sites": visible_sites,
            "open_create": open_create,
        },
    )


@router.get("/websites/new", response_class=HTMLResponse)
async def websites_new(request: Request, user: str = Depends(require_login_page)):
    return RedirectResponse(url="/websites?create=1", status_code=303)


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
    if not can_access_node(user, int(node_id)):
        set_flash(request, "无权访问该机器")
        return RedirectResponse(url="/websites?create=1", status_code=303)
    node = get_node(int(node_id))
    if not node or str(node.get("role") or "") != "website":
        set_flash(request, "请选择网站机节点")
        return RedirectResponse(url="/websites?create=1", status_code=303)

    domains_list = _parse_domains(domains)
    if not domains_list:
        set_flash(request, "域名不能为空")
        return RedirectResponse(url="/websites?create=1", status_code=303)

    site_type = (site_type or "static").strip()
    if site_type not in ("static", "php", "reverse_proxy"):
        site_type = "static"

    web_server = (web_server or "nginx").strip() or "nginx"
    if web_server != "nginx":
        set_flash(request, "当前仅支持 nginx")
        return RedirectResponse(url="/websites?create=1", status_code=303)

    # prevent duplicate domains on same node
    existing = list_sites(node_id=int(node_id))
    for s in existing:
        if str(s.get("status") or "").strip().lower() == "error":
            continue
        s_domains = set([str(x).lower() for x in (s.get("domains") or [])])
        if s_domains.intersection(set(domains_list)):
            set_flash(request, "该节点已有重复域名的站点")
            return RedirectResponse(url="/websites?create=1", status_code=303)

    root_base = str(node.get("website_root_base") or "").strip() or "/www"
    root_path = (root_path or "").strip()
    if not root_path and site_type != "reverse_proxy":
        root_path = f"{root_base.rstrip('/')}/wwwroot/{domains_list[0]}"
    proxy_target = _normalize_proxy_target(proxy_target or "")
    if site_type == "reverse_proxy" and not proxy_target.strip():
        set_flash(request, "反向代理必须填写目标地址")
        return RedirectResponse(url="/websites?create=1", status_code=303)

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
        _merge_node_env_caps(node, data)
    except Exception as exc:
        set_flash(request, f"环境安装失败：{exc}")
        return RedirectResponse(url="/websites?create=1", status_code=303)

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
        # post-create health check
        health_status = "unknown"
        health_error = ""
        try:
            health = await agent_post(
                node["base_url"],
                node["api_key"],
                "/api/v1/website/health",
                {
                    "domains": domains_list,
                    "type": site_type,
                    "root_path": root_path,
                    "proxy_target": proxy_target,
                    "root_base": _node_root_base(node),
                },
                node_verify_tls(node),
                timeout=10,
            )
            if isinstance(health, dict):
                if health.get("ok"):
                    health_status = "ok"
                else:
                    health_status = "fail"
                    health_error = str(health.get("error") or "")
        except Exception as exc:
            health_error = str(exc)
            health_status = "unknown" if _is_agent_unreachable_error(health_error) else "fail"

        update_site(site_id, status="running" if health_status != "fail" else "error")
        try:
            if health_status in ("ok", "fail", "unknown"):
                update_site_health(
                    site_id,
                    health_status,
                    health_code=int(health.get("status_code") or 0) if isinstance(health, dict) else 0,
                    health_latency_ms=int(health.get("latency_ms") or 0) if isinstance(health, dict) else 0,
                    health_error=str(health.get("error") or "") if isinstance(health, dict) else health_error,
                )
        except Exception:
            pass
        update_task(task_id, status="success", progress=100, result=data)
        add_site_event(site_id, "site_create", status="success", actor=str(user or ""), result=data)
        if health_status == "fail":
            set_flash(request, f"站点创建成功，但健康检查失败：{health_error or 'HTTP 探测失败'}")
        elif health_status == "unknown":
            set_flash(request, f"站点创建成功，但暂时无法连到节点执行健康检查：{health_error or '等待节点连通'}")
        else:
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
        },
    )


@router.get("/websites/{site_id}/edit", response_class=HTMLResponse)
async def website_edit(request: Request, site_id: int, user: str = Depends(require_login_page)):
    """Edit site configuration without having to delete & recreate."""
    site = get_site(int(site_id))
    if not site:
        set_flash(request, "站点不存在")
        return RedirectResponse(url="/websites", status_code=303)
    node = get_node(int(site.get("node_id") or 0))
    if not node:
        set_flash(request, "节点不存在")
        return RedirectResponse(url=f"/websites/{site_id}", status_code=303)

    # UI helper: comma-separated domains
    site_view = dict(site)
    site_view["domains_text"] = ", ".join(site.get("domains") or [])

    return templates.TemplateResponse(
        "site_edit.html",
        {
            "request": request,
            "user": user,
            "flash": flash(request),
            "title": f"编辑 · {site.get('name') or (site.get('domains') or ['站点'])[0]}",
            "site": site_view,
            "node": node,
            "default_nginx_tpl": _default_nginx_template(site.get("type") or "static"),
        },
    )


@router.post("/websites/{site_id}/edit")
async def website_edit_post(
    request: Request,
    site_id: int,
    name: str = Form(""),
    domains: str = Form(""),
    site_type: str = Form("static"),
    root_path: str = Form(""),
    proxy_target: str = Form(""),
    https_redirect: Optional[str] = Form(None),
    gzip_enabled: Optional[str] = Form(None),
    nginx_tpl: str = Form(""),
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

    # -------- Parse & validate --------
    raw = (domains or "").strip()
    parts = []
    for token in raw.replace("\n", ",").replace("\t", ",").split(","):
        t = (token or "").strip()
        if not t:
            continue
        parts.append(t)
    # de-dup, keep order
    seen = set()
    domains_list: List[str] = []
    for d in parts:
        dl = d.strip()
        if not dl or dl in seen:
            continue
        seen.add(dl)
        domains_list.append(dl)

    if not domains_list:
        set_flash(request, "域名不能为空")
        return RedirectResponse(url=f"/websites/{site_id}/edit", status_code=303)

    if site_type not in ("static", "php", "reverse_proxy"):
        set_flash(request, "站点类型无效")
        return RedirectResponse(url=f"/websites/{site_id}/edit", status_code=303)

    root_path = (root_path or "").strip()
    proxy_target = _normalize_proxy_target(proxy_target or "")
    https_flag = bool(https_redirect)
    gzip_flag = bool(gzip_enabled)
    tpl = (nginx_tpl or "").strip()

    if site_type != "reverse_proxy":
        if not root_path:
            # keep consistent with create default: <root_base>/wwwroot/<primary_domain>
            rb = _node_root_base(node)
            root_path = os.path.join(rb, "wwwroot", domains_list[0])
    else:
        if not proxy_target:
            set_flash(request, "反向代理站点必须填写代理目标")
            return RedirectResponse(url=f"/websites/{site_id}/edit", status_code=303)

    # Domain collision on the same node (exclude self)
    try:
        other_sites = list_sites(node_id=int(site.get("node_id") or 0))
        other_domains = set()
        for s in other_sites:
            if int(s.get("id") or 0) == int(site_id):
                continue
            if s.get("status") == "error":
                continue
            for d in (s.get("domains") or []):
                other_domains.add(str(d).strip())
        dup = [d for d in domains_list if d in other_domains]
        if dup:
            set_flash(request, f"域名冲突：{', '.join(dup)}")
            return RedirectResponse(url=f"/websites/{site_id}/edit", status_code=303)
    except Exception:
        # don't hard-fail on domain collision checks
        pass

    # -------- Apply on node --------
    old_domains = site.get("domains") or []
    old_primary = str(old_domains[0]) if old_domains else ""
    new_primary = str(domains_list[0])

    task_id = add_task(
        node_id=int(site.get("node_id") or 0),
        task_type="site_update",
        payload={"site_id": site_id, "old_domains": old_domains, "new_domains": domains_list},
        status="running",
        progress=5,
    )
    add_site_event(
        int(site_id),
        "site_update",
        status="running",
        actor=str(user or ""),
        payload={"old_domains": old_domains, "new_domains": domains_list, "type": site_type},
    )

    try:
        # Ensure required runtime (idempotent)
        ensure = await agent_post(
            node["base_url"],
            node["api_key"],
            "/api/v1/website/env/ensure",
            {
                "need_nginx": True,
                "need_php": bool(site_type == "php"),
                "need_acme": True,
            },
            node_verify_tls(node),
            timeout=300,
        )
        if not ensure.get("ok", True):
            raise AgentError(str(ensure.get("error") or "环境检查失败"))
        _merge_node_env_caps(node, ensure)
        update_task(task_id, progress=15)

        # If primary domain changed, remove old nginx conf first (keep data/cert)
        if old_primary and old_primary != new_primary:
            await agent_post(
                node["base_url"],
                node["api_key"],
                "/api/v1/website/site/delete",
                {
                    "domains": old_domains,
                    "root_path": site.get("root_path") or "",
                    "root_base": _node_root_base(node),
                    "delete_root": False,
                    "delete_cert": False,
                },
                node_verify_tls(node),
                timeout=30,
            )
        update_task(task_id, progress=35)

        payload = {
            "domains": domains_list,
            "type": site_type,
            "web_server": "nginx",
            "proxy_target": proxy_target,
            "https_redirect": https_flag,
            "gzip_enabled": gzip_flag,
            "nginx_tpl": tpl,
            "root_path": root_path,
            "root_base": _node_root_base(node),
        }
        data = await agent_post(
            node["base_url"],
            node["api_key"],
            "/api/v1/website/site/create",
            payload,
            node_verify_tls(node),
            timeout=45,
        )
        if not data.get("ok", True):
            raise AgentError(str(data.get("error") or "站点更新失败"))

        update_task(task_id, progress=60)

        # post-update health check
        health_status = "unknown"
        health_error = ""
        health = {}
        try:
            health = await agent_post(
                node["base_url"],
                node["api_key"],
                "/api/v1/website/health",
                {
                    "domains": domains_list,
                    "type": site_type,
                    "root_path": root_path,
                    "proxy_target": proxy_target,
                    "root_base": _node_root_base(node),
                },
                node_verify_tls(node),
                timeout=10,
            )
            if isinstance(health, dict):
                if health.get("ok"):
                    health_status = "ok"
                else:
                    health_status = "fail"
                    health_error = str(health.get("error") or "")
        except Exception as exc:
            health_error = str(exc)
            health_status = "unknown" if _is_agent_unreachable_error(health_error) else "fail"

        # Update DB
        update_site(
            int(site_id),
            name=(name or site.get("name") or domains_list[0]).strip(),
            domains=domains_list,
            type=site_type,
            root_path=root_path if site_type != "reverse_proxy" else (root_path or ""),
            proxy_target=proxy_target,
            https_redirect=1 if https_flag else 0,
            gzip_enabled=1 if gzip_flag else 0,
            nginx_tpl=tpl,
            status="running" if health_status != "fail" else "error",
        )
        try:
            if health_status in ("ok", "fail", "unknown"):
                update_site_health(
                    int(site_id),
                    health_status,
                    health_code=int(health.get("status_code") or 0) if isinstance(health, dict) else 0,
                    health_latency_ms=int(health.get("latency_ms") or 0) if isinstance(health, dict) else 0,
                    health_error=str(health.get("error") or "") if isinstance(health, dict) else health_error,
                )
        except Exception:
            pass

        # If domains changed, mark cert record as pending to nudge re-issue
        try:
            if set(map(str, old_domains)) != set(map(str, domains_list)):
                certs = list_certificates(site_id=int(site_id))
                if certs:
                    update_certificate(
                        int(certs[0].get("id") or 0),
                        domains=domains_list,
                        status="pending",
                        last_error="站点域名已变更，建议重新申请/续期 SSL 证书",
                    )
        except Exception:
            pass

        update_task(task_id, status="success", progress=100, result=data)
        add_site_event(int(site_id), "site_update", status="success", actor=str(user or ""), result=data)
        if health_status == "fail":
            set_flash(request, f"站点更新成功，但健康检查失败：{health_error or 'HTTP 探测失败'}")
        elif health_status == "unknown":
            set_flash(request, f"站点更新成功，但暂时无法连到节点执行健康检查：{health_error or '等待节点连通'}")
        else:
            set_flash(request, "站点更新成功")
        return RedirectResponse(url=f"/websites/{site_id}", status_code=303)
    except Exception as exc:
        update_task(task_id, status="failed", progress=100, error=str(exc))
        add_site_event(int(site_id), "site_update", status="failed", actor=str(user or ""), error=str(exc))
        set_flash(request, f"站点更新失败：{exc}")
        return RedirectResponse(url=f"/websites/{site_id}/edit", status_code=303)


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

    refresh = str(request.query_params.get("refresh") or "").strip().lower() in (
        "1",
        "true",
        "yes",
        "on",
    )
    diag: Dict[str, Any] = _diag_base_payload(site)
    err_msg = ""
    diag_source = "cache"
    live_diag_ready = False

    if refresh:
        payload = {
            "domains": site.get("domains") or [],
            "type": site.get("type") or "static",
            "root_path": site.get("root_path") or "",
            "proxy_target": site.get("proxy_target") or "",
            "root_base": _node_root_base(node),
        }
        try:
            data = await agent_post(
                node["base_url"],
                node["api_key"],
                "/api/v1/website/diagnose",
                payload,
                node_verify_tls(node),
                timeout=10,
            )
            diag = _diag_merge(diag, data)
            diag_source = "live"
            live_diag_ready = True
            if not diag.get("ok", True):
                err_msg = str(diag.get("error") or "诊断失败")
        except Exception as exc:
            err_msg = str(exc)

        try:
            if live_diag_ready and isinstance(diag.get("ok"), bool):
                ok = bool(diag.get("ok"))
                status_code = int(diag.get("status_code") or (diag.get("checks") or {}).get("http_status") or 0)
                latency_ms = int(diag.get("latency_ms") or 0)
                err = str(diag.get("error") or "").strip()
                update_site_health(
                    int(site_id),
                    "ok" if ok else "fail",
                    health_code=status_code,
                    health_latency_ms=latency_ms,
                    health_error=err,
                )
                add_site_check(int(site_id), ok=ok, status_code=status_code, latency_ms=latency_ms, error=err)
        except Exception:
            pass

    events = list_site_events(int(site_id), limit=24)
    checks = list_site_checks(int(site_id), limit=20)

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
            "diag_source": diag_source,
            "diag_refreshed": bool(refresh and diag_source == "live"),
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
    cert_id = _ensure_certificate_pending(int(site_id), int(site.get("node_id") or 0), domains)
    task_id = add_task(
        node_id=int(site.get("node_id") or 0),
        task_type="website_ssl_issue",
        payload={
            "site_id": int(site_id),
            "cert_id": int(cert_id),
            "domains": domains,
            "actor": str(user or ""),
            "max_attempts": int(_SITE_OP_MAX_ATTEMPTS),
        },
        status="queued",
        progress=0,
        result={"queued": True, "op": "website_ssl_issue", "max_attempts": int(_SITE_OP_MAX_ATTEMPTS), "attempt": 0},
    )
    add_site_event(
        int(site_id),
        "ssl_issue",
        status="queued",
        actor=str(user or ""),
        payload={"domains": domains, "task_id": int(task_id)},
    )
    set_flash(request, f"已创建 SSL 申请任务 #{task_id}，等待节点上报后自动执行（支持内网节点）。")
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
    cert_id = _ensure_certificate_pending(int(site_id), int(site.get("node_id") or 0), domains)
    task_id = add_task(
        node_id=int(site.get("node_id") or 0),
        task_type="website_ssl_renew",
        payload={
            "site_id": int(site_id),
            "cert_id": int(cert_id),
            "domains": domains,
            "actor": str(user or ""),
            "max_attempts": int(_SITE_OP_MAX_ATTEMPTS),
        },
        status="queued",
        progress=0,
        result={"queued": True, "op": "website_ssl_renew", "max_attempts": int(_SITE_OP_MAX_ATTEMPTS), "attempt": 0},
    )
    add_site_event(
        int(site_id),
        "ssl_renew",
        status="queued",
        actor=str(user or ""),
        payload={"domains": domains, "task_id": int(task_id)},
    )
    set_flash(request, f"已创建 SSL 续期任务 #{task_id}，等待节点上报后自动执行（支持内网节点）。")
    return RedirectResponse(url=f"/websites/{site_id}", status_code=303)


@router.post("/websites/{site_id}/https_redirect")
async def website_https_redirect_set(
    request: Request,
    site_id: int,
    enabled: Optional[str] = Form(None),
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
        set_flash(request, "站点域名为空，无法更新 HTTPS 跳转")
        return RedirectResponse(url=f"/websites/{site_id}", status_code=303)

    raw_flag = str(enabled or "").strip().lower()
    https_flag = raw_flag in ("1", "true", "yes", "y", "on")

    task_id = add_task(
        node_id=int(site.get("node_id") or 0),
        task_type="site_https_redirect",
        payload={"site_id": site_id, "domains": domains, "https_redirect": https_flag},
        status="running",
        progress=10,
    )
    add_site_event(
        int(site_id),
        "site_https_redirect",
        status="running",
        actor=str(user or ""),
        payload={"domains": domains, "https_redirect": https_flag},
    )

    try:
        payload = {
            "domains": domains,
            "type": site.get("type") or "static",
            "web_server": site.get("web_server") or "nginx",
            "proxy_target": _normalize_proxy_target(site.get("proxy_target") or ""),
            "https_redirect": https_flag,
            "gzip_enabled": True if site.get("gzip_enabled") is None else bool(site.get("gzip_enabled")),
            "nginx_tpl": site.get("nginx_tpl") or "",
            "root_path": site.get("root_path") or "",
            "root_base": _node_root_base(node),
        }

        update_task(task_id, progress=45)
        data = await agent_post(
            node["base_url"],
            node["api_key"],
            "/api/v1/website/site/create",
            payload,
            node_verify_tls(node),
            timeout=45,
        )
        if not data.get("ok", True):
            raise AgentError(str(data.get("error") or "更新 HTTPS 跳转失败"))

        update_site(int(site_id), https_redirect=https_flag)
        update_task(task_id, status="success", progress=100, result=data)
        add_site_event(int(site_id), "site_https_redirect", status="success", actor=str(user or ""), result=data)
        set_flash(request, "已开启强制 HTTPS" if https_flag else "已关闭强制 HTTPS")
    except Exception as exc:
        update_task(task_id, status="failed", progress=100, error=str(exc))
        add_site_event(int(site_id), "site_https_redirect", status="failed", actor=str(user or ""), error=str(exc))
        set_flash(request, f"更新强制 HTTPS 失败：{exc}")

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
        delete_site_events(int(site_id))
        delete_site_checks(int(site_id))
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
    purge_flag = _to_flag(purge_data)
    deep_flag = _to_flag(deep_uninstall)
    task_id = add_task(
        node_id=int(node_id),
        task_type="website_env_uninstall",
        payload={
            "node_id": int(node_id),
            "purge_data": bool(purge_flag),
            "deep_uninstall": bool(deep_flag),
            "actor": str(user or ""),
            "max_attempts": int(_SITE_OP_MAX_ATTEMPTS),
        },
        status="queued",
        progress=0,
        result={
            "queued": True,
            "op": "website_env_uninstall",
            "max_attempts": int(_SITE_OP_MAX_ATTEMPTS),
            "attempt": 0,
        },
    )
    set_flash(request, f"已创建环境卸载任务 #{task_id}，等待节点上报后自动执行（支持内网节点）。")
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
    php_flag = _to_flag(include_php)
    task_id = add_task(
        node_id=int(node_id),
        task_type="website_env_ensure",
        payload={
            "node_id": int(node_id),
            "include_php": bool(php_flag),
            "actor": str(user or ""),
            "max_attempts": int(_SITE_OP_MAX_ATTEMPTS),
        },
        status="queued",
        progress=0,
        result={
            "queued": True,
            "op": "website_env_ensure",
            "max_attempts": int(_SITE_OP_MAX_ATTEMPTS),
            "attempt": 0,
        },
    )
    set_flash(request, f"已创建环境安装任务 #{task_id}，等待节点上报后自动执行（支持内网节点）。")
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
            "upload_max_bytes": UPLOAD_MAX_BYTES,
            "upload_max_h": _format_bytes(UPLOAD_MAX_BYTES),
            "file_share_default_ttl_sec": FILE_SHARE_DEFAULT_TTL_SEC,
            "file_share_min_ttl_sec": FILE_SHARE_MIN_TTL_SEC,
            "file_share_max_ttl_sec": FILE_SHARE_MAX_TTL_SEC,
            "file_share_max_items": FILE_SHARE_MAX_ITEMS,
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

    # offset 参数校验：避免 int(...) 转换异常导致 500
    try:
        offset = int(data.get("offset") or 0)
    except Exception:
        return {"ok": False, "error": "offset 参数无效（必须是整数）"}
    if offset < 0:
        return {"ok": False, "error": "offset 参数无效（不能为负数）"}

    payload = {
        "root": root,
        "path": str(data.get("path") or ""),
        "filename": str(data.get("filename") or "upload.bin"),
        "upload_id": str(data.get("upload_id") or ""),
        "offset": offset,
        "done": bool(data.get("done")),
        "content_b64": str(data.get("content_b64") or ""),
        "chunk_sha256": str(data.get("chunk_sha256") or ""),
        "allow_empty": bool(data.get("allow_empty")),
        "root_base": _node_root_base(node),
    }
    try:
        resp = await agent_post(
            node["base_url"],
            node["api_key"],
            "/api/v1/website/files/upload_chunk",
            payload,
            node_verify_tls(node),
            timeout=90,
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
    files: Optional[List[UploadFile]] = File(None),
    folder: Optional[List[UploadFile]] = File(None),
    file: Optional[UploadFile] = File(None),
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

    def _split_upload_name(raw: str) -> Tuple[str, str]:
        clean = (raw or "").replace("\\", "/").lstrip("/")
        if not clean:
            return "", ""
        parts = [p for p in clean.split("/") if p and p != "."]
        if any(p == ".." for p in parts):
            raise ValueError("非法路径")
        if not parts:
            return "", ""
        return "/".join(parts[:-1]), parts[-1]

    def _join_rel(a: str, b: str) -> str:
        aa = (a or "").strip().strip("/")
        bb = (b or "").strip().strip("/")
        if not aa:
            return bb
        if not bb:
            return aa
        return f"{aa}/{bb}"

    async def _upload_one(upload: UploadFile, target_path: str, filename: str) -> None:
        upload_id = uuid.uuid4().hex
        offset = 0
        total = 0
        chunk = await upload.read(UPLOAD_CHUNK_SIZE)
        if not chunk:
            payload = {
                "root": root,
                "path": target_path,
                "filename": filename,
                "upload_id": upload_id,
                "offset": 0,
                "done": True,
                "allow_empty": True,
                "root_base": _node_root_base(node),
            }
            resp = await agent_post(
                node["base_url"],
                node["api_key"],
                "/api/v1/website/files/upload_chunk",
                payload,
                node_verify_tls(node),
                timeout=10,
            )
            if not resp.get("ok", True):
                raise AgentError(str(resp.get("error") or "上传失败"))
            return
        while True:
            next_chunk = await upload.read(UPLOAD_CHUNK_SIZE)
            done = not next_chunk
            total += len(chunk)
            if total > UPLOAD_MAX_BYTES:
                raise RuntimeError(f"文件过大（当前限制 {_format_bytes(UPLOAD_MAX_BYTES)}）")
            payload = {
                "root": root,
                "path": target_path,
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
                timeout=90,
            )
            if not resp.get("ok", True):
                raise AgentError(str(resp.get("error") or "上传失败"))
            offset += len(chunk)
            if done:
                break
            chunk = next_chunk

    uploads: List[UploadFile] = []
    if files:
        uploads.extend(files)
    if folder:
        uploads.extend(folder)
    if file:
        uploads.append(file)

    if not uploads:
        set_flash(request, "请选择文件或文件夹")
        return RedirectResponse(url=f"/websites/{site_id}/files?path={path}", status_code=303)

    ok_count = 0
    try:
        prepared: List[Tuple[UploadFile, str, str]] = []
        for upload in uploads:
            name_raw = str(upload.filename or "").strip()
            if not name_raw:
                raise RuntimeError("文件名为空")
            rel_dir, base = _split_upload_name(name_raw)
            if not base:
                raise RuntimeError("文件名为空")
            target_path = _join_rel(path, rel_dir)
            prepared.append((upload, target_path, os.path.basename(base)))

        if not prepared:
            raise RuntimeError("请选择文件或文件夹")

        first_error: Optional[Exception] = None
        cursor = 0
        state_lock = asyncio.Lock()

        async def _worker() -> None:
            nonlocal ok_count, first_error, cursor
            while True:
                async with state_lock:
                    if first_error is not None or cursor >= len(prepared):
                        return
                    upload, target_path, base_name = prepared[cursor]
                    cursor += 1
                try:
                    await _upload_one(upload, target_path, base_name)
                    async with state_lock:
                        ok_count += 1
                except Exception as exc:
                    async with state_lock:
                        if first_error is None:
                            first_error = exc
                    return

        worker_count = min(max(1, UPLOAD_COMPAT_CONCURRENCY), len(prepared))
        await asyncio.gather(*[_worker() for _ in range(worker_count)])
        if first_error is not None:
            raise first_error

        set_flash(request, f"上传成功（{ok_count} 个文件）")
    except Exception as exc:
        msg = f"上传失败：{exc}"
        if ok_count:
            msg = f"部分上传成功（{ok_count} 个），{msg}"
        set_flash(request, msg)
    finally:
        for upload in uploads:
            try:
                await upload.close()
            except Exception:
                pass

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


@router.post("/websites/{site_id}/files/unzip")
async def website_files_unzip(
    request: Request,
    site_id: int,
    path: str = Form(""),
    dest: str = Form(""),
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
            "/api/v1/website/files/unzip",
            {"root": root, "path": path, "dest": dest, "root_base": _node_root_base(node)},
            node_verify_tls(node),
            timeout=60,
        )
        set_flash(request, "解压成功")
    except Exception as exc:
        set_flash(request, f"解压失败：{exc}")
    return RedirectResponse(url=f"/websites/{site_id}/files?path={dest}", status_code=303)


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

    rel_path = str(path or "").replace("\\", "/").strip().lstrip("/")
    parent_path = "/".join(rel_path.split("/")[:-1]) if rel_path else ""
    if not rel_path:
        set_flash(request, "请选择要下载的文件或目录")
        return RedirectResponse(url=f"/websites/{site_id}/files?path={parent_path}", status_code=303)

    # Directory download: stream as zip.
    try:
        await _agent_list_files(node, root, rel_path)
        zip_name = _build_path_zip_filename(site_id, site.get("name"), rel_path)
        headers = {"Content-Disposition": _download_content_disposition(zip_name)}
        return StreamingResponse(
            _iter_share_zip_stream(node, root, [{"path": rel_path, "is_dir": True}]),
            media_type="application/zip",
            headers=headers,
        )
    except Exception:
        pass

    filename = rel_path.split("/")[-1] or "download.bin"
    try:
        upstream, status_code, _detail = await _open_agent_file_stream(node, root, rel_path, timeout=600)
    except Exception as exc:
        set_flash(request, f"下载失败：{exc}")
        return RedirectResponse(url=f"/websites/{site_id}/files?path={parent_path}", status_code=303)
    if upstream is None:
        set_flash(request, f"下载失败（HTTP {status_code}）")
        return RedirectResponse(url=f"/websites/{site_id}/files?path={parent_path}", status_code=303)
    return _stream_file_download_response(upstream, filename)

@router.post("/websites/{site_id}/files/share")
async def website_files_share_link(
    request: Request,
    site_id: int,
    user: str = Depends(require_login_page),
):
    _ = user
    site = get_site(int(site_id))
    node = get_node(int(site.get("node_id") or 0)) if site else None
    if not site or not node:
        return {"ok": False, "error": "站点不存在"}

    root = _agent_payload_root(site, node)
    if not root:
        return {"ok": False, "error": "该站点没有可管理的根目录"}

    try:
        data = await request.json()
    except Exception:
        data = {}

    try:
        share_items = _parse_share_items((data or {}).get("items") or (data or {}).get("paths") or [])
    except Exception:
        return {"ok": False, "error": "分享路径不合法"}
    if not share_items:
        return {"ok": False, "error": "请先选择要分享的文件或目录"}
    if len(share_items) > FILE_SHARE_MAX_ITEMS:
        return {"ok": False, "error": f"最多可分享 {FILE_SHARE_MAX_ITEMS} 项"}

    ttl_sec = _parse_share_ttl_sec((data or {}).get("ttl_sec"))
    token_payload = {
        "page": "site_files_download",
        "site_id": int(site_id),
        "items": share_items,
    }
    token = make_share_token(token_payload, ttl_sec=ttl_sec)
    base = panel_public_base_url(request)
    long_url = f"{base}/share/site-files?t={token}"
    try:
        short_code = create_site_file_share_short_link(int(site_id), token, created_by=str(user or ""))
    except Exception as exc:
        return {"ok": False, "error": f"生成短链失败：{exc}"}
    short_url = f"{base}/share/site-files/s/{short_code}"
    expire_at = datetime.datetime.now() + datetime.timedelta(seconds=ttl_sec)
    return {
        "ok": True,
        "url": short_url,
        "short_url": short_url,
        "long_url": long_url,
        "short_code": short_code,
        "ttl_sec": ttl_sec,
        "expire_at": expire_at.strftime("%Y-%m-%d %H:%M:%S"),
        "items": share_items,
    }


@router.get("/websites/{site_id}/files/share/list")
async def website_files_share_list(
    request: Request,
    site_id: int,
    limit: int = 50,
    user: str = Depends(require_login_page),
):
    _ = user
    site = get_site(int(site_id))
    if not site:
        return {"ok": False, "error": "站点不存在"}

    # Auto-clean short links that have already been revoked.
    try:
        delete_site_file_share_short_links(int(site_id), token_sha256="")
    except Exception:
        pass

    rows = list_site_file_share_short_links(int(site_id), limit=max(1, min(int(limit or 50), 200)))
    base = panel_public_base_url(request)
    now_ts = int(time.time())
    out: List[Dict[str, Any]] = []

    for row in rows:
        code = str(row.get("code") or "").strip()
        token = str(row.get("token") or "").strip()
        payload = verify_share_token_allow_expired(token)
        try:
            token_site_id = int((payload or {}).get("site_id") or 0) if isinstance(payload, dict) else 0
        except Exception:
            token_site_id = 0
        valid = bool(
            isinstance(payload, dict)
            and str(payload.get("page") or "") == "site_files_download"
            and token_site_id == int(site_id)
        )
        exp = 0
        if isinstance(payload, dict):
            try:
                exp = int(payload.get("exp") or 0)
            except Exception:
                exp = 0
        expired = bool(exp and now_ts > exp)
        revoked = bool(str(row.get("revoked_at") or "").strip())
        if revoked:
            continue

        status = "invalid"
        if valid and expired:
            status = "expired"
        elif valid:
            status = "active"

        share_items: List[Dict[str, Any]] = []
        if isinstance(payload, dict):
            try:
                share_items = _parse_share_items(payload.get("items") or payload.get("paths") or [])
            except Exception:
                share_items = []
        item_count = len(share_items)
        first_path = str(share_items[0].get("path") or "") if share_items else ""
        if item_count > 1 and first_path:
            first_label = f"{first_path} (+{item_count - 1})"
        else:
            first_label = first_path

        expire_at = ""
        if exp > 0:
            try:
                expire_at = datetime.datetime.fromtimestamp(exp).strftime("%Y-%m-%d %H:%M:%S")
            except Exception:
                expire_at = ""

        out.append(
            {
                "code": code,
                "url": f"{base}/share/site-files/s/{code}" if code else "",
                "status": status,
                "can_revoke": status == "active",
                "is_expired": expired,
                "is_revoked": revoked,
                "created_at": str(row.get("created_at") or ""),
                "expire_at": expire_at,
                "revoked_at": str(row.get("revoked_at") or ""),
                "revoked_by": str(row.get("revoked_by") or ""),
                "item_count": item_count,
                "first_item": first_label,
                "items": share_items,
            }
        )

    return {"ok": True, "items": out}


@router.post("/websites/{site_id}/files/share/revoke")
async def website_files_share_revoke(
    request: Request,
    site_id: int,
    user: str = Depends(require_login_page),
):
    site = get_site(int(site_id))
    if not site:
        return {"ok": False, "error": "站点不存在"}

    try:
        data = await request.json()
    except Exception:
        data = {}

    token = _resolve_share_token_input((data or {}).get("token") or (data or {}).get("url") or "")
    if not token:
        return {"ok": False, "error": "缺少分享链接"}

    payload = verify_share_token(token)
    if not isinstance(payload, dict):
        return {"ok": False, "error": "分享链接无效或已过期"}
    if str(payload.get("page") or "") != "site_files_download":
        return {"ok": False, "error": "分享链接类型不匹配"}
    try:
        token_site_id = int(payload.get("site_id") or 0)
    except Exception:
        token_site_id = 0
    if token_site_id != int(site_id):
        return {"ok": False, "error": "分享链接不属于当前站点"}

    digest = _share_token_sha256(token)
    if not digest:
        return {"ok": False, "error": "分享链接无效"}
    created = revoke_site_file_share_token(
        int(site_id),
        digest,
        revoked_by=str(user or ""),
        reason=str((data or {}).get("reason") or ""),
    )
    deleted = 0
    try:
        deleted = delete_site_file_share_short_links(int(site_id), digest)
    except Exception:
        deleted = 0
    return {"ok": True, "revoked": True, "newly_revoked": bool(created), "deleted_short_links": int(deleted)}


@router.get("/share/site-files/s/{code}")
async def website_files_share_download_short(request: Request, code: str):
    key = str(code or "").strip()
    if not _SHORT_SHARE_CODE_RE.fullmatch(key):
        return Response(content="分享链接无效或已过期", media_type="text/plain", status_code=404)
    row = get_site_file_share_short_link(key)
    if not row:
        return Response(content="分享链接无效或已过期", media_type="text/plain", status_code=404)
    token = str(row.get("token") or "").strip()
    if not token:
        return Response(content="分享链接无效或已过期", media_type="text/plain", status_code=404)
    return await website_files_share_download(request, t=token)


@router.get("/share/site-files")
async def website_files_share_download(request: Request, t: str = ""):
    _ = request
    ctx, bad = _validate_site_files_share_token(t)
    if bad is not None:
        return bad
    payload = dict((ctx or {}).get("payload") or {})
    site_id = int((ctx or {}).get("site_id") or 0)
    digest = str((ctx or {}).get("token_sha256") or "")

    try:
        share_items = _parse_share_items(payload.get("items") or payload.get("paths") or [])
    except Exception:
        share_items = []
    if not share_items:
        return Response(content="分享内容为空", media_type="text/plain", status_code=400)
    if len(share_items) > FILE_SHARE_MAX_ITEMS:
        share_items = share_items[:FILE_SHARE_MAX_ITEMS]

    site = get_site(int(site_id))
    node = get_node(int(site.get("node_id") or 0)) if site else None
    if not site or not node:
        return Response(content="站点不存在或已删除", media_type="text/plain", status_code=404)
    root = _agent_payload_root(site, node)
    if not root:
        return Response(content="该站点没有可分享目录", media_type="text/plain", status_code=404)

    single = share_items[0] if len(share_items) == 1 else None
    if single and not bool(single.get("is_dir")):
        rel_path = str(single.get("path") or "")
        try:
            upstream, status_code, _detail = await _open_agent_file_stream(node, root, rel_path, timeout=600)
        except Exception:
            return Response(content="文件不存在或无法下载", media_type="text/plain", status_code=404)
        if upstream is None:
            code = 404 if status_code == 404 else 502
            return Response(content="文件不存在或无法下载", media_type="text/plain", status_code=code)
        filename = rel_path.split("/")[-1] or "download.bin"
        return _stream_file_download_response(upstream, filename)

    stream_raw = str(request.query_params.get("stream") or "1").strip().lower()
    stream_enabled = stream_raw not in ("0", "false", "no", "off")
    if stream_enabled:
        filename = _build_stream_zip_filename(site_id, site.get("name"))
        headers = {"Content-Disposition": _download_content_disposition(filename)}
        return StreamingResponse(
            _iter_share_zip_stream(node, root, share_items),
            media_type="application/zip",
            headers=headers,
        )

    items_sig = _share_items_signature(share_items)
    if not items_sig:
        return Response(content="分享内容为空", media_type="text/plain", status_code=400)
    filename = _build_stream_zip_filename(site_id, site.get("name"))

    job = _find_share_zip_job(site_id, digest, items_sig)
    if job and str(job.get("status") or "") == "done":
        zip_path = str(job.get("zip_path") or "")
        if zip_path and os.path.exists(zip_path):
            return FileResponse(path=zip_path, filename=str(job.get("filename") or filename), media_type="application/zip")

    if not job:
        job = _new_share_zip_job(site_id, digest, items_sig, filename=filename)
        _upsert_share_zip_job(job)
        asyncio.create_task(_run_share_zip_job(str(job.get("id") or ""), node, root, list(share_items)))

    return HTMLResponse(content=_share_zip_wait_page_html(str(job.get("id") or ""), t), media_type="text/html")


@router.get("/share/site-files/job/status")
async def website_files_share_download_job_status(request: Request, j: str = "", t: str = ""):
    _ = request
    ctx, bad = _validate_site_files_share_token(t)
    if bad is not None:
        return JSONResponse({"ok": False, "status": "error", "error": "分享链接无效或已过期"}, status_code=403)

    site_id = int((ctx or {}).get("site_id") or 0)
    digest = str((ctx or {}).get("token_sha256") or "")
    job_id = str(j or "").strip()
    if not job_id:
        return {"ok": False, "status": "error", "error": "缺少任务编号"}

    row = _get_share_zip_job(job_id)
    if not isinstance(row, dict):
        return {"ok": False, "status": "error", "error": "任务不存在或已过期"}
    if int(row.get("site_id") or 0) != int(site_id) or str(row.get("token_sha256") or "") != digest:
        return {"ok": False, "status": "error", "error": "任务不存在或已过期"}

    status = str(row.get("status") or "queued")
    zip_path = str(row.get("zip_path") or "")
    if status == "done" and (not zip_path or not os.path.exists(zip_path)):
        row["status"] = "error"
        row["error"] = "打包结果已过期，请刷新链接重试"
        row["updated_at"] = time.time()
        _upsert_share_zip_job(row)
        status = "error"

    out = {
        "ok": True,
        "job_id": job_id,
        "status": status,
        "file_count": int(row.get("file_count") or 0),
        "error": str(row.get("error") or ""),
    }
    return out


@router.get("/share/site-files/job/download")
async def website_files_share_download_job_download(request: Request, j: str = "", t: str = ""):
    _ = request
    ctx, bad = _validate_site_files_share_token(t)
    if bad is not None:
        return bad

    site_id = int((ctx or {}).get("site_id") or 0)
    digest = str((ctx or {}).get("token_sha256") or "")
    job_id = str(j or "").strip()
    if not job_id:
        return Response(content="缺少任务编号", media_type="text/plain", status_code=400)

    row = _get_share_zip_job(job_id)
    if not isinstance(row, dict):
        return Response(content="任务不存在或已过期", media_type="text/plain", status_code=404)
    if int(row.get("site_id") or 0) != int(site_id) or str(row.get("token_sha256") or "") != digest:
        return Response(content="任务不存在或已过期", media_type="text/plain", status_code=404)

    status = str(row.get("status") or "")
    if status in ("queued", "running"):
        return Response(content="仍在打包中，请稍后重试", media_type="text/plain", status_code=409)
    if status != "done":
        return Response(content=str(row.get("error") or "打包失败"), media_type="text/plain", status_code=500)

    zip_path = str(row.get("zip_path") or "")
    if not zip_path or not os.path.exists(zip_path):
        return Response(content="打包结果已过期，请刷新链接重试", media_type="text/plain", status_code=404)

    filename = str(row.get("filename") or "download.zip")
    return FileResponse(path=zip_path, filename=filename, media_type="application/zip")
