from __future__ import annotations

from ..auth import ensure_secret_key

SESSION_COOKIE_NAME = "realm_panel_sess"

# Used for SessionMiddleware and also for signed share tokens.
SECRET_KEY: str = ensure_secret_key()
