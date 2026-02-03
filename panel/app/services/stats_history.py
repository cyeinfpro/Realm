from __future__ import annotations

import os
import time
from typing import Any, Dict, List, Optional, Tuple

from ..db import insert_rule_stats_samples, prune_rule_stats_samples


# ---------------- Persistent rule traffic/connection history ----------------
#
# Goal:
#   Keep rule traffic/active-connections history even when browser window closes.
#
# Source of samples:
#   - Agent push-report (/api/agent/report) contains report.stats (recommended)
#   - Fallback: panel direct /api/v1/stats call (when push-report is not used)
#
# Storage:
#   SQLite table rule_stats_samples
#
# Retention:
#   Controlled via env REALM_STATS_HISTORY_RETENTION_DAYS (default 7).
#   Pruning is performed opportunistically during ingestion.


def _env_flag(name: str, default: str = "1") -> bool:
    v = (os.getenv(name) or default).strip().lower()
    return v not in ("0", "false", "no", "off")


STATS_HISTORY_ENABLED = _env_flag("REALM_STATS_HISTORY_ENABLED", "1")

try:
    _SAMPLE_INTERVAL_SEC = float((os.getenv("REALM_STATS_HISTORY_INTERVAL_SEC") or "10").strip() or 10)
except Exception:
    _SAMPLE_INTERVAL_SEC = 10.0
if _SAMPLE_INTERVAL_SEC < 2.0:
    _SAMPLE_INTERVAL_SEC = 2.0
if _SAMPLE_INTERVAL_SEC > 300.0:
    _SAMPLE_INTERVAL_SEC = 300.0

try:
    _RETENTION_DAYS = int((os.getenv("REALM_STATS_HISTORY_RETENTION_DAYS") or "7").strip() or 7)
except Exception:
    _RETENTION_DAYS = 7
if _RETENTION_DAYS < 1:
    _RETENTION_DAYS = 1
if _RETENTION_DAYS > 90:
    _RETENTION_DAYS = 90

# How often to run prune (seconds)
try:
    _PRUNE_EVERY_SEC = float((os.getenv("REALM_STATS_HISTORY_PRUNE_EVERY_SEC") or "900").strip() or 900)
except Exception:
    _PRUNE_EVERY_SEC = 900.0
if _PRUNE_EVERY_SEC < 60.0:
    _PRUNE_EVERY_SEC = 60.0
if _PRUNE_EVERY_SEC > 6 * 3600:
    _PRUNE_EVERY_SEC = 6 * 3600


# In-memory last sampling timestamps: node_id -> ts_ms
_LAST_SAMPLE_MS: Dict[int, int] = {}

# In-memory last prune timestamp (epoch seconds)
_LAST_PRUNE_AT: float = 0.0


def config() -> Dict[str, Any]:
    """Return effective config for UI/debug."""
    return {
        "enabled": bool(STATS_HISTORY_ENABLED),
        "sample_interval_sec": float(_SAMPLE_INTERVAL_SEC),
        "retention_days": int(_RETENTION_DAYS),
        "prune_every_sec": float(_PRUNE_EVERY_SEC),
    }


def _now_ms() -> int:
    return int(time.time() * 1000)


def _should_sample(node_id: int, ts_ms: int) -> bool:
    if not STATS_HISTORY_ENABLED:
        return False
    if node_id <= 0 or ts_ms <= 0:
        return False
    last = int(_LAST_SAMPLE_MS.get(int(node_id)) or 0)
    if last and (ts_ms - last) < int(_SAMPLE_INTERVAL_SEC * 1000):
        return False
    return True


def _dedup_rules(rules: List[Dict[str, Any]]) -> Dict[str, Tuple[int, int, int, int]]:
    """Return mapping: rule_key -> (rx, tx, conn_active, conn_total).

    Stats payload is per-endpoint; in rare cases the same listen key may appear multiple times.
    To avoid double-counting, we keep the max value per field.
    """
    out: Dict[str, Tuple[int, int, int, int]] = {}
    for r in rules:
        if not isinstance(r, dict):
            continue
        key = str(r.get("listen") or "").strip()
        if not key:
            continue

        try:
            rx = int(r.get("rx_bytes") or 0)
        except Exception:
            rx = 0
        try:
            tx = int(r.get("tx_bytes") or 0)
        except Exception:
            tx = 0
        # Prefer explicit connections_active, fallback to connections
        try:
            ca = int(r.get("connections_active") if r.get("connections_active") is not None else r.get("connections") or 0)
        except Exception:
            ca = 0
        try:
            ct = int(r.get("connections_total") or 0)
        except Exception:
            ct = 0

        prev = out.get(key)
        if prev is None:
            out[key] = (max(0, rx), max(0, tx), max(0, ca), max(0, ct))
        else:
            out[key] = (
                max(int(prev[0]), rx),
                max(int(prev[1]), tx),
                max(int(prev[2]), ca),
                max(int(prev[3]), ct),
            )

    return out


def ingest_stats_snapshot(node_id: int, stats: Dict[str, Any], ts_ms: Optional[int] = None) -> int:
    """Ingest a single stats snapshot into persistent history.

    This function is safe to call frequently.
    - It enforces a sampling interval per-node.
    - It deduplicates rule keys to avoid double counting.
    - It is best-effort: call sites should wrap in try/except and never fail request handling.
    """
    try:
        nid = int(node_id)
    except Exception:
        nid = 0
    if nid <= 0:
        return 0

    if not isinstance(stats, dict) or stats.get("ok") is not True:
        return 0

    now_ms = int(ts_ms) if ts_ms is not None else _now_ms()
    if not _should_sample(nid, now_ms):
        return 0

    rules_raw = stats.get("rules")
    rules = rules_raw if isinstance(rules_raw, list) else []

    by_key = _dedup_rules(rules)
    if not by_key:
        # Still store an "__all__" point so charts can show emptiness over time.
        rows = [(nid, "__all__", now_ms, 0, 0, 0, 0)]
        inserted = insert_rule_stats_samples(rows)
        _LAST_SAMPLE_MS[nid] = now_ms
        _maybe_prune(now_ms)
        return inserted

    sum_rx = 0
    sum_tx = 0
    sum_ca = 0
    sum_ct = 0

    rows: List[Tuple[int, str, int, int, int, int, int]] = []
    for key, (rx, tx, ca, ct) in by_key.items():
        sum_rx += int(rx)
        sum_tx += int(tx)
        sum_ca += int(ca)
        sum_ct += int(ct)
        rows.append((nid, key, now_ms, int(rx), int(tx), int(ca), int(ct)))

    # Aggregated "all rules" series
    rows.append((nid, "__all__", now_ms, int(sum_rx), int(sum_tx), int(sum_ca), int(sum_ct)))

    inserted = insert_rule_stats_samples(rows)
    _LAST_SAMPLE_MS[nid] = now_ms
    _maybe_prune(now_ms)
    return inserted


def _maybe_prune(now_ms: int) -> None:
    global _LAST_PRUNE_AT
    if not STATS_HISTORY_ENABLED:
        return

    now_s = float(now_ms) / 1000.0
    if _LAST_PRUNE_AT and (now_s - float(_LAST_PRUNE_AT)) < float(_PRUNE_EVERY_SEC):
        return

    _LAST_PRUNE_AT = now_s
    cutoff = int(now_ms - int(_RETENTION_DAYS) * 86400 * 1000)
    if cutoff <= 0:
        return
    try:
        prune_rule_stats_samples(cutoff)
    except Exception:
        # Best-effort: ignore pruning errors.
        pass
