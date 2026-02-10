from __future__ import annotations

from ..auth import has_accounts


def has_credentials() -> bool:
    # Keep old function name for compatibility with existing login/setup routes.
    return has_accounts()
