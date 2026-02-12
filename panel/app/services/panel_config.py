from __future__ import annotations

import os
from typing import Any, Iterable, Optional

from ..db import get_panel_setting


_TRUE_SET = {"1", "true", "yes", "on", "y"}
_FALSE_SET = {"0", "false", "no", "off", "n"}


def _first_env(names: Optional[Iterable[str]]) -> str:
    if not names:
        return ""
    for n in names:
        name = str(n or "").strip()
        if not name:
            continue
        v = str(os.getenv(name) or "").strip()
        if v:
            return v
    return ""


def setting_str(key: str, default: str = "", env_names: Optional[Iterable[str]] = None) -> str:
    """Read panel setting first, then env fallback, then default."""
    raw = get_panel_setting(str(key or "").strip())
    if raw is not None:
        s = str(raw).strip()
        if s:
            return s
    env_v = _first_env(env_names)
    if env_v:
        return env_v
    return str(default or "")


def setting_bool(
    key: str,
    default: bool = False,
    env_names: Optional[Iterable[str]] = None,
) -> bool:
    raw = get_panel_setting(str(key or "").strip())
    if raw is not None and str(raw).strip() != "":
        s = str(raw).strip().lower()
        if s in _TRUE_SET:
            return True
        if s in _FALSE_SET:
            return False
        return bool(default)

    env_v = _first_env(env_names)
    if env_v:
        s2 = str(env_v).strip().lower()
        if s2 in _TRUE_SET:
            return True
        if s2 in _FALSE_SET:
            return False
    return bool(default)


def setting_int(
    key: str,
    default: int,
    lo: int,
    hi: int,
    env_names: Optional[Iterable[str]] = None,
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


def setting_float(
    key: str,
    default: float,
    lo: float,
    hi: float,
    env_names: Optional[Iterable[str]] = None,
) -> float:
    raw = get_panel_setting(str(key or "").strip())
    v_raw: Any = raw
    if raw is None or str(raw).strip() == "":
        env_v = _first_env(env_names)
        v_raw = env_v if env_v else default
    try:
        v = float(str(v_raw).strip() or default)
    except Exception:
        v = float(default)
    if v < float(lo):
        v = float(lo)
    if v > float(hi):
        v = float(hi)
    return float(v)


def parse_bool_loose(raw: Any, default: bool = False) -> bool:
    if raw is None:
        return bool(default)
    s = str(raw).strip().lower()
    if not s:
        return bool(default)
    if s in _TRUE_SET:
        return True
    if s in _FALSE_SET:
        return False
    return bool(default)
