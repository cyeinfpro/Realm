from __future__ import annotations

from fastapi.templating import Jinja2Templates

from .paths import TEMPLATES_DIR
from ..utils.redact import mask_host, mask_secret, mask_url

# Shared Jinja2 templates environment.
# Routers can import this without creating circular imports with app.main.
templates = Jinja2Templates(directory=str(TEMPLATES_DIR))
templates.env.filters.setdefault("mask_url", mask_url)
templates.env.filters.setdefault("mask_secret", mask_secret)
templates.env.filters.setdefault("mask_host", mask_host)
