from __future__ import annotations

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from starlette.middleware.sessions import SessionMiddleware

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


# Ensure DB exists before serving.
ensure_db()

app = FastAPI(title=APP_TITLE, version=APP_VERSION)

# Session cookie for browser auth (panel UI)
app.add_middleware(
    SessionMiddleware,
    secret_key=SECRET_KEY,
    session_cookie=SESSION_COOKIE_NAME,
)

# Static assets (CSS/JS + realm-agent.zip + install scripts)
app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

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
