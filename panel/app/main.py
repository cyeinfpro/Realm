from __future__ import annotations

from fastapi import FastAPI, Request
from fastapi.staticfiles import StaticFiles
from starlette.middleware.gzip import GZipMiddleware
from starlette.middleware.sessions import SessionMiddleware

from .clients.agent import close_agent_clients
from .core.paths import STATIC_DIR
from .core.session import SECRET_KEY, SESSION_COOKIE_NAME
from .core.settings import APP_TITLE, APP_VERSION
from .db import ensure_db
from .routers import (
    api_agents,
    api_groups,
    api_netmon,
    api_nodes,
    api_sync,
    auth,
    pages,
    scripts,
    websites,
)
from .services.netmon import start_background as start_netmon_background
from .services.site_monitor import start_background as start_site_monitor_background


# Ensure DB exists before serving.
ensure_db()

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
    resp = await call_next(request)
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


@app.on_event("startup")
async def _startup() -> None:
    # Background NetMon collector (configurable via env).
    try:
        await start_netmon_background(app)
    except Exception:
        # Never fail panel startup due to bg worker.
        pass
    # Background site monitor
    try:
        await start_site_monitor_background(app)
    except Exception:
        pass


@app.on_event("shutdown")
async def _shutdown() -> None:
    try:
        await close_agent_clients()
    except Exception:
        pass
