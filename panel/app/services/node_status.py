from __future__ import annotations

from datetime import datetime
from typing import Any, Dict


def is_report_fresh(node: Dict[str, Any], max_age_sec: int = 90) -> bool:
    ts = node.get("last_seen_at")
    if not ts:
        return False
    try:
        dt = datetime.strptime(str(ts), "%Y-%m-%d %H:%M:%S")
        return (datetime.now() - dt).total_seconds() <= max_age_sec
    except Exception:
        return False
