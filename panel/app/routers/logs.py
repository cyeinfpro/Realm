from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, Tuple

from fastapi import APIRouter, Depends, Query, Request
from fastapi.responses import HTMLResponse, JSONResponse

from ..core.deps import require_role, require_role_page
from ..core.flash import flash
from ..core.logging_setup import get_runtime_log_paths
from ..core.templates import templates

router = APIRouter()


def _log_sources() -> Dict[str, Dict[str, str]]:
    paths = get_runtime_log_paths()
    sources = {
        "panel": {
            "key": "panel",
            "title": "Panel 运行日志",
            "path": str(paths.get("panel") or ""),
        },
        "crash": {
            "key": "crash",
            "title": "Panel 崩溃日志",
            "path": str(paths.get("crash") or ""),
        },
    }
    fault_path = str(paths.get("fault") or "").strip()
    if fault_path:
        sources["fault"] = {
            "key": "fault",
            "title": "Panel 崩溃堆栈",
            "path": fault_path,
        }
    return sources


def _tail_text(path: str, lines: int, max_bytes: int = 2 * 1024 * 1024) -> Tuple[str, bool, int, float, str]:
    p = Path(str(path or "").strip())
    if not str(p):
        return "", False, 0, 0.0, "invalid_path"

    try:
        st = p.stat()
        size = int(st.st_size or 0)
        mtime = float(st.st_mtime or 0.0)
    except FileNotFoundError:
        return "", False, 0, 0.0, "not_found"
    except Exception as exc:
        return "", False, 0, 0.0, str(exc)

    if size <= 0:
        return "", False, size, mtime, ""

    read_bytes = min(int(max_bytes), int(size))
    if read_bytes <= 0:
        read_bytes = int(size)

    truncated = bool(size > read_bytes)
    try:
        with p.open("rb") as f:
            if size > read_bytes:
                f.seek(size - read_bytes)
            data = f.read(read_bytes)
    except Exception as exc:
        return "", truncated, size, mtime, str(exc)

    rows = data.splitlines()
    if len(rows) > int(lines):
        rows = rows[-int(lines):]
        truncated = True

    text = b"\n".join(rows).decode("utf-8", errors="replace")
    return text, truncated, size, mtime, ""


@router.get("/logs", response_class=HTMLResponse)
async def logs_page(request: Request, user: str = Depends(require_role_page("panel.view"))):
    _ = user
    src = _log_sources()
    return templates.TemplateResponse(
        "logs.html",
        {
            "request": request,
            "user": user,
            "flash": flash(request),
            "title": "系统日志",
            "log_sources": list(src.values()),
            "default_source": "panel",
            "default_lines": 300,
        },
    )


@router.get("/api/logs/tail")
async def api_logs_tail(
    request: Request,
    source: str = Query("panel"),
    lines: int = Query(300, ge=20, le=2000),
    user: str = Depends(require_role("panel.view")),
):
    _ = request
    _ = user
    sources = _log_sources()
    key = str(source or "panel").strip().lower()
    conf = sources.get(key)
    if not conf:
        return JSONResponse({"ok": False, "error": "未知日志源"}, status_code=400)

    text, truncated, size, mtime, read_error = _tail_text(conf.get("path") or "", int(lines))
    return {
        "ok": True,
        "source": key,
        "title": conf.get("title") or key,
        "path": conf.get("path") or "",
        "lines": int(lines),
        "exists": (read_error != "not_found"),
        "truncated": bool(truncated),
        "size_bytes": int(size),
        "mtime": float(mtime or 0.0),
        "read_error": str(read_error or ""),
        "text": text,
    }
