from __future__ import annotations

import logging

from fastapi import FastAPI, Request
from fastapi.staticfiles import StaticFiles
from starlette.middleware.gzip import GZipMiddleware
from starlette.middleware.sessions import SessionMiddleware

from .clients.agent import close_agent_clients
from .core.logging_setup import configure_runtime_logging, install_asyncio_exception_logging
from .core.paths import STATIC_DIR
from .core.session import SECRET_KEY, SESSION_COOKIE_NAME
from .core.settings import APP_TITLE, APP_VERSION
from .db import ensure_db
from .utils.redact import redact_log_text
from .routers import (
    api_agents,
    api_groups,
    api_netmon,
    api_nodes,
    api_sync,
    auth,
    logs,
    pages,
    scripts,
    websites,
)
from .services.netmon import start_background as start_netmon_background
from .services.site_monitor import start_background as start_site_monitor_background

configure_runtime_logging()
logger = logging.getLogger(__name__)
crash_logger = logging.getLogger("realm.panel.crash")

# Ensure DB exists before serving.
try:
    ensure_db()
except Exception:
    logger.exception("database init failed")
    raise

app = FastAPI(title=APP_TITLE, version=APP_VERSION)

# Session cookie for browser auth (panel UI)
app.add_middleware(
    SessionMiddleware,
    secret_key=SECRET_KEY,
    session_cookie=SESSION_COOKIE_NAME,
)
# Compress HTML/CSS/JS/JSON payloads to speed up page/API delivery over WAN.
app.add_middleware(GZipMiddleware, minimum_size=1024, compresslevel=5)

# Static assets (CSS/JS + realm-agent.zip + install scripts)
app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")


@app.middleware("http")
async def _static_app_js_no_cache(request: Request, call_next):
    """Prevent stale app.js / html from browser/proxy cache after hotfix releases."""
    try:
        resp = await call_next(request)
    except Exception:
        crash_logger.exception(
            "unhandled request exception method=%s path=%s",
            request.method,
            redact_log_text(str(request.url.path or "")),
        )
        raise
    path = str(request.url.path or "")
    ct = str(resp.headers.get("content-type") or "").lower()
    if path == "/static/app.js" or "text/html" in ct:
        resp.headers["Cache-Control"] = "no-store, max-age=0"
        resp.headers["Pragma"] = "no-cache"
        resp.headers["Expires"] = "0"
    return resp

# Routers
app.include_router(auth.router)
app.include_router(pages.router)
app.include_router(scripts.router)

app.include_router(api_agents.router)
app.include_router(api_nodes.router)
app.include_router(api_groups.router)
app.include_router(api_sync.router)
app.include_router(api_netmon.router)
app.include_router(websites.router)
app.include_router(logs.router)


@app.on_event("startup")
async def _startup() -> None:
    try:
        install_asyncio_exception_logging()
    except Exception:
        logger.exception("failed to install asyncio exception handler")
    # Background NetMon collector (configurable via env).
    try:
        await start_netmon_background(app)
    except Exception:
        logger.exception("netmon background startup failed")
    # Background site monitor
    try:
        await start_site_monitor_background(app)
    except Exception:
        logger.exception("site monitor background startup failed")


@app.on_event("shutdown")
async def _shutdown() -> None:
    try:
        await close_agent_clients()
    except Exception:
        logger.exception("failed to close shared agent clients")
