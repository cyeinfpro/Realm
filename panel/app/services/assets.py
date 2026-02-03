from __future__ import annotations

import hashlib
import os
import zipfile
from pathlib import Path
from typing import Tuple

from fastapi import Request

from ..core.paths import STATIC_DIR


def read_latest_agent_version() -> str:
    """Return latest agent version shipped with this panel.

    We read it from panel/static/realm-agent.zip -> agent/app/main.py -> FastAPI(..., version='XX').

    Important: do NOT cache at import-time; panel static assets may be replaced without restarting.
    """
    zpath = STATIC_DIR / "realm-agent.zip"
    try:
        with zipfile.ZipFile(str(zpath), "r") as z:
            raw = z.read("agent/app/main.py").decode("utf-8", errors="ignore")
        # FastAPI(title='Realm Agent', version='31')
        import re

        m = re.search(r"FastAPI\([^\)]*version\s*=\s*['\"]([^'\"]+)['\"]", raw)
        if m:
            return str(m.group(1)).strip()
    except Exception:
        pass
    return ""


def parse_agent_version_from_ua(ua: str) -> str:
    try:
        import re

        m = re.search(r"realm-agent\/([0-9A-Za-z._-]+)", ua or "", re.I)
        return (m.group(1) if m else "")
    except Exception:
        return ""


def file_sha256(path: Path) -> str:
    try:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(1024 * 1024), b""):
                if not chunk:
                    break
                h.update(chunk)
        return h.hexdigest()
    except Exception:
        return ""


def panel_asset_source() -> str:
    """Return where nodes should fetch installer assets.

    Values:
      - "panel"  : fetch from panel /static (default)
      - "github" : fetch from GitHub (for private panel without public reachability)
    """
    return (os.getenv("REALM_PANEL_ASSET_SOURCE") or "panel").strip().lower() or "panel"


def agent_asset_urls(base_url: str) -> Tuple[str, str, bool]:
    """Return (agent_sh_url, agent_zip_url, github_only)."""
    src = panel_asset_source()
    if src == "github":
        sh_url = (os.getenv("REALM_PANEL_AGENT_SH_URL") or "").strip() or (
            "https://raw.githubusercontent.com/cyeinfpro/Realm/main/realm_agent.sh"
        )
        zip_url = (os.getenv("REALM_PANEL_AGENT_ZIP_URL") or "").strip() or (
            "https://github.com/cyeinfpro/Realm/archive/refs/heads/main.zip"
        )
        return sh_url, zip_url, True

    return f"{base_url}/static/realm_agent.sh", f"{base_url}/static/realm-agent.zip", False


def panel_public_base_url(request: Request) -> str:
    """Return panel public base URL for generating scripts/links.

    If REALM_PANEL_PUBLIC_URL or REALM_PANEL_URL is set, it takes precedence.
    """
    cfg = (os.getenv("REALM_PANEL_PUBLIC_URL") or os.getenv("REALM_PANEL_URL") or "").strip()
    if cfg:
        cfg = cfg.rstrip("/")
        if "://" not in cfg:
            # When user only provides domain/host, default to https (typical reverse-proxy setup).
            cfg = "https://" + cfg
        return cfg
    return str(request.base_url).rstrip("/")
