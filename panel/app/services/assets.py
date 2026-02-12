from __future__ import annotations

import hashlib
import os
import zipfile
from pathlib import Path
from typing import Any, Optional, Tuple
from urllib.parse import urlparse

from fastapi import Request

from ..core.paths import STATIC_DIR
from ..db import get_panel_setting
from ..utils.normalize import format_host_for_url, split_host_and_port

try:
    from .panel_config import setting_bool, setting_int, setting_str
except Exception:
    _TRUE_SET = {"1", "true", "yes", "on", "y"}
    _FALSE_SET = {"0", "false", "no", "off", "n"}

    def _first_env(names: Optional[list[str]]) -> str:
        for n in (names or []):
            name = str(n or "").strip()
            if not name:
                continue
            v = str(os.getenv(name) or "").strip()
            if v:
                return v
        return ""

    def setting_str(key: str, default: str = "", env_names: Optional[list[str]] = None) -> str:
        raw = get_panel_setting(str(key or "").strip())
        if raw is not None:
            s = str(raw).strip()
            if s:
                return s
        env_v = _first_env(env_names)
        if env_v:
            return env_v
        return str(default or "")

    def setting_bool(key: str, default: bool = False, env_names: Optional[list[str]] = None) -> bool:
        raw = get_panel_setting(str(key or "").strip())
        if raw is not None and str(raw).strip() != "":
            s = str(raw).strip().lower()
            if s in _TRUE_SET:
                return True
            if s in _FALSE_SET:
                return False
            return bool(default)
        env_v = _first_env(env_names).lower()
        if env_v in _TRUE_SET:
            return True
        if env_v in _FALSE_SET:
            return False
        return bool(default)

    def setting_int(
        key: str,
        default: int,
        lo: int,
        hi: int,
        env_names: Optional[list[str]] = None,
    ) -> int:
        raw = get_panel_setting(str(key or "").strip())
        v_raw: Any = raw
        if raw is None or str(raw).strip() == "":
            env_v = _first_env(env_names)
            v_raw = env_v if env_v else default
        try:
            v = int(float(str(v_raw).strip() or default))
        except Exception:
            v = int(default)
        if v < int(lo):
            v = int(lo)
        if v > int(hi):
            v = int(hi)
        return int(v)


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
    src = setting_str("panel_asset_source", default="panel", env_names=["REALM_PANEL_ASSET_SOURCE"]).strip().lower()
    if src not in ("panel", "github"):
        src = "panel"
    return src


def _parse_bool(raw: Optional[str], default: bool) -> bool:
    if raw is None:
        return bool(default)
    s = str(raw).strip().lower()
    if not s:
        return bool(default)
    if s in ("1", "true", "yes", "on", "y"):
        return True
    if s in ("0", "false", "no", "off", "n"):
        return False
    return bool(default)


def _request_scheme_and_port(request: Request) -> Tuple[str, int]:
    scheme = "http"
    port = 80
    try:
        parsed = urlparse(str(request.base_url or ""))
        if str(parsed.scheme or "").strip().lower() == "https":
            scheme = "https"
            port = 443
        req_port = parsed.port
        if req_port and int(req_port) > 0:
            port = int(req_port)
    except Exception:
        pass
    return scheme, int(port)


def _normalize_base_url(raw: str, default_scheme: str, default_port: int) -> str:
    val = str(raw or "").strip()
    if not val:
        return ""
    if "://" in val:
        try:
            p = urlparse(val)
            host = str(p.hostname or "").strip()
            scheme = str(p.scheme or "").strip().lower() or str(default_scheme or "https")
            if scheme not in ("http", "https"):
                scheme = str(default_scheme or "https")
            if not host:
                return ""
            if p.port:
                port = int(p.port)
            else:
                port = 443 if scheme == "https" else 80
            return f"{scheme}://{format_host_for_url(host)}:{int(port)}"
        except Exception:
            return ""

    host, port, has_port, _ = split_host_and_port(val, int(default_port))
    host = str(host or "").strip()
    if not host:
        return ""
    if (not has_port) or int(port or 0) <= 0:
        port = int(default_port)
    scheme = str(default_scheme or "https").strip().lower() or "https"
    if scheme not in ("http", "https"):
        scheme = "https"
    return f"{scheme}://{format_host_for_url(host)}:{int(port)}"


def agent_asset_urls(base_url: str) -> Tuple[str, str, bool]:
    """Return (agent_sh_url, agent_zip_url, github_only)."""
    src = panel_asset_source()
    if src == "github":
        sh_url = setting_str("panel_agent_sh_url", default="", env_names=["REALM_PANEL_AGENT_SH_URL"]) or (
            "https://raw.githubusercontent.com/cyeinfpro/NexusControlPlane/main/realm_agent.sh"
        )
        zip_url = setting_str("panel_agent_zip_url", default="", env_names=["REALM_PANEL_AGENT_ZIP_URL"]) or (
            "https://github.com/cyeinfpro/NexusControlPlane/archive/refs/heads/main.zip"
        )
        return sh_url, zip_url, True

    return f"{base_url}/static/realm_agent.sh", f"{base_url}/static/realm-agent.zip", False


def agent_fallback_asset_urls(base_url: str) -> Tuple[str, str]:
    """Return fallback (agent_sh_url, agent_zip_url) opposite to primary source."""
    src = panel_asset_source()
    github_sh = setting_str("panel_agent_sh_url", default="", env_names=["REALM_PANEL_AGENT_SH_URL"]) or (
        "https://raw.githubusercontent.com/cyeinfpro/NexusControlPlane/main/realm_agent.sh"
    )
    github_zip = setting_str("panel_agent_zip_url", default="", env_names=["REALM_PANEL_AGENT_ZIP_URL"]) or (
        "https://github.com/cyeinfpro/NexusControlPlane/archive/refs/heads/main.zip"
    )
    panel_sh = f"{base_url}/static/realm_agent.sh"
    panel_zip = f"{base_url}/static/realm-agent.zip"
    if src == "github":
        return panel_sh, panel_zip
    return github_sh, github_zip


def panel_public_base_url(request: Request) -> str:
    """Return panel public base URL for generating scripts/links.

    If REALM_PANEL_PUBLIC_URL or REALM_PANEL_URL is set, it takes precedence.
    """
    cfg = setting_str(
        "panel_public_url",
        default="",
        env_names=["REALM_PANEL_PUBLIC_URL", "REALM_PANEL_URL"],
    ).strip()
    if cfg:
        cfg = cfg.rstrip("/")
        if "://" not in cfg:
            # When user only provides domain/host, default to https (typical reverse-proxy setup).
            default_scheme = setting_str("agent_bootstrap_default_scheme", default="https").strip().lower() or "https"
            if default_scheme not in ("http", "https"):
                default_scheme = "https"
            cfg = f"{default_scheme}://" + cfg
        return cfg
    return str(request.base_url).rstrip("/")


def panel_bootstrap_base_url(request: Request) -> str:
    """Return base URL for join/uninstall bootstrap script download."""
    scheme, port = _request_scheme_and_port(request)
    req_explicit_port = False
    try:
        parsed_req = urlparse(str(request.base_url or ""))
        req_explicit_port = parsed_req.port is not None
    except Exception:
        req_explicit_port = False
    scheme_cfg = setting_str("agent_bootstrap_default_scheme", default="", env_names=[]).strip().lower()
    if scheme_cfg in ("http", "https"):
        scheme = scheme_cfg
        if req_explicit_port:
            if int(port or 0) <= 0:
                port = 443 if scheme_cfg == "https" else 80
        else:
            port = 443 if scheme_cfg == "https" else 80
    fallback_port = setting_int(
        "agent_panel_ip_fallback_port",
        default=int(port),
        lo=1,
        hi=65535,
        env_names=["REALM_PANEL_IP_FALLBACK_PORT"],
    )
    if int(port or 0) <= 0:
        port = int(fallback_port)
    configured = get_panel_setting("agent_bootstrap_url")
    if configured:
        normalized = _normalize_base_url(configured, default_scheme=scheme, default_port=port)
        if normalized:
            return normalized

    env_cfg = (os.getenv("REALM_PANEL_BOOTSTRAP_URL") or "").strip()
    if env_cfg:
        normalized = _normalize_base_url(env_cfg, default_scheme=scheme, default_port=port)
        if normalized:
            return normalized

    return panel_public_base_url(request)


def panel_bootstrap_insecure_tls(default: bool = True) -> bool:
    """Whether curl bootstrap/install should skip HTTPS certificate verification."""
    cfg = get_panel_setting("agent_bootstrap_insecure_tls")
    if cfg is not None and str(cfg).strip() != "":
        return _parse_bool(cfg, default=default)
    return setting_bool(
        "agent_bootstrap_insecure_tls",
        default=default,
        env_names=["REALM_PANEL_BOOTSTRAP_INSECURE_TLS"],
    )
