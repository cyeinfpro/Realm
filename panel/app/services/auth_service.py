from __future__ import annotations

from ..auth import load_credentials


def has_credentials() -> bool:
    return load_credentials() is not None
