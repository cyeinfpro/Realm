from __future__ import annotations

from fastapi.templating import Jinja2Templates

from .paths import TEMPLATES_DIR

# Shared Jinja2 templates environment.
# Routers can import this without creating circular imports with app.main.
templates = Jinja2Templates(directory=str(TEMPLATES_DIR))
