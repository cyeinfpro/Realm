from __future__ import annotations

import copy
import os
import threading
import time
from typing import Any, Dict, List, Optional, Set, Tuple


def _env_flag(name: str, default: str = "1") -> bool:
    raw = (os.getenv(name) or default).strip().lower()
    return raw not in ("0", "false", "off", "no")


def _env_int(name: str, default: int, lo: int, hi: int) -> int:
    try:
        v = int(float((os.getenv(name) or str(default)).strip() or default))
    except Exception:
        v = int(default)
    if v < lo:
        v = lo
    if v > hi:
        v = hi
    return int(v)


def _env_float(name: str, default: float, lo: float, hi: float) -> float:
    try:
        v = float((os.getenv(name) or str(default)).strip() or default)
    except Exception:
        v = float(default)
    if v < lo:
        v = lo
    if v > hi:
        v = hi
    return float(v)


_AUTO_LB_ENABLED = _env_flag("REALM_ADAPTIVE_LB_ENABLED", "1")
_AUTO_LB_COOLDOWN_SEC = _env_float("REALM_ADAPTIVE_LB_COOLDOWN_SEC", 18.0, 1.0, 600.0)
_AUTO_LB_MIN_DIFF_PCT = _env_float("REALM_ADAPTIVE_LB_MIN_DIFF_PCT", 8.0, 0.5, 80.0)
_AUTO_LB_MIN_SAMPLES = _env_int("REALM_ADAPTIVE_LB_MIN_SAMPLES", 3, 1, 120)
_AUTO_LB_DOWN_CONSEC_FAIL = _env_int("REALM_ADAPTIVE_LB_DOWN_CONSEC_FAIL", 3, 1, 30)
_AUTO_LB_DOWN_AVAIL_PCT = _env_float("REALM_ADAPTIVE_LB_DOWN_AVAIL_PCT", 35.0, 0.0, 95.0)
_AUTO_LB_LATENCY_REF_MS = _env_float("REALM_ADAPTIVE_LB_LATENCY_REF_MS", 120.0, 10.0, 5000.0)
_AUTO_LB_WEIGHT_SCALE = _env_int("REALM_ADAPTIVE_LB_WEIGHT_SCALE", 100, 20, 10000)
_AUTO_LB_MAX_WEIGHT = _env_int("REALM_ADAPTIVE_LB_MAX_WEIGHT", 1000, 10, 100000)
_AUTO_LB_MIN_WEIGHT = _env_int("REALM_ADAPTIVE_LB_MIN_WEIGHT", 2, 1, 1000)
_AUTO_LB_MIN_DOWN_WEIGHT = _env_int("REALM_ADAPTIVE_LB_MIN_DOWN_WEIGHT", 1, 1, 1000)
_AUTO_LB_RULE_TTL_SEC = max(180.0, float(_AUTO_LB_COOLDOWN_SEC) * 12.0)


_RULE_STATE_LOCK = threading.Lock()
_RULE_STATE: Dict[str, Dict[str, Any]] = {}
_RULE_STATE_PRUNE_TS = 0.0


def enabled() -> bool:
    return bool(_AUTO_LB_ENABLED)


def _clamp(v: float, lo: float, hi: float) -> float:
    if v < lo:
        return lo
    if v > hi:
        return hi
    return v


def _to_float(v: Any) -> Optional[float]:
    try:
        return float(v)
    except Exception:
        return None


def _to_int(v: Any, default: int = 0) -> int:
    try:
        return int(v)
    except Exception:
        return int(default)


def _norm_algo(raw: Any) -> str:
    s = str(raw or "").strip().lower()
    for ch in ("_", "-", " "):
        s = s.replace(ch, "")
    return "iphash" if s == "iphash" else "roundrobin"


def _parse_balance(balance: Any, remote_count: int) -> Tuple[str, List[int]]:
    n = max(0, int(remote_count))
    if n <= 0:
        return "roundrobin", []
    b = str(balance or "roundrobin").strip()
    if not b:
        return "roundrobin", [1] * n
    if ":" not in b:
        return _norm_algo(b), [1] * n
    left, right = b.split(":", 1)
    algo = _norm_algo(left)
    ws: List[int] = []
    for part in right.replace("，", ",").split(","):
        x = part.strip()
        if not x:
            continue
        try:
            v = int(x)
        except Exception:
            continue
        if v > 0:
            ws.append(v)
    if len(ws) != n:
        ws = [1] * n
    return algo, ws


def _format_balance(weights: List[int]) -> str:
    ws = [max(1, int(x)) for x in weights]
    return "roundrobin: " + ", ".join(str(x) for x in ws)


def _collect_remotes(ep: Dict[str, Any]) -> List[str]:
    out: List[str] = []
    if isinstance(ep.get("remote"), str):
        s = str(ep.get("remote") or "").strip()
        if s:
            out.append(s)
    if isinstance(ep.get("remotes"), list):
        for x in ep.get("remotes") or []:
            s = str(x or "").strip()
            if s:
                out.append(s)
    if isinstance(ep.get("extra_remotes"), list):
        for x in ep.get("extra_remotes") or []:
            s = str(x or "").strip()
            if s:
                out.append(s)
    dedup: List[str] = []
    seen: Set[str] = set()
    for r in out:
        if r in seen:
            continue
        seen.add(r)
        dedup.append(r)
    return dedup


def _weights_to_pct(weights: List[int]) -> List[float]:
    ws = [max(1, int(x)) for x in weights]
    total = float(sum(ws) or 1.0)
    return [(float(w) * 100.0) / total for w in ws]


def _weights_diff_pct(old_weights: List[int], new_weights: List[int]) -> float:
    if len(old_weights) != len(new_weights):
        return 100.0
    if not old_weights:
        return 0.0
    a = _weights_to_pct(old_weights)
    b = _weights_to_pct(new_weights)
    return max(abs(float(a[i]) - float(b[i])) for i in range(len(a)))


def _lookup_remote_metric(remote: str, rule_stats: Optional[Dict[str, Any]], probe_remotes: Dict[str, Any]) -> Dict[str, Any]:
    if isinstance(probe_remotes, dict):
        x = probe_remotes.get(remote)
        if isinstance(x, dict):
            return x
    if not isinstance(rule_stats, dict):
        return {}
    health = rule_stats.get("health")
    if not isinstance(health, list):
        return {}
    for item in health:
        if not isinstance(item, dict):
            continue
        t = str(item.get("target") or "").strip()
        if not t:
            continue
        if t == remote:
            return item
        # Agent may label extra WSS check as "WSS host:port".
        if t.startswith("WSS ") and t[4:].strip() == remote:
            return item
    return {}


def _derive_remote(remote: str, metric: Dict[str, Any]) -> Dict[str, Any]:
    ok_raw = metric.get("ok")
    ok: Optional[bool]
    if ok_raw is True:
        ok = True
    elif ok_raw is False:
        ok = False
    else:
        ok = None

    availability_pct = _to_float(metric.get("availability"))
    error_rate_pct = _to_float(metric.get("error_rate"))
    latency_ms = _to_float(metric.get("latency_ema_ms"))
    if latency_ms is None:
        latency_ms = _to_float(metric.get("latency_ms"))
    samples = max(0, _to_int(metric.get("samples"), 0))
    consec_fail = max(0, _to_int(metric.get("consecutive_failures"), 0))

    has_signal = (
        ok is not None
        or availability_pct is not None
        or error_rate_pct is not None
        or latency_ms is not None
        or samples > 0
    )

    if availability_pct is None:
        if ok is True:
            availability_pct = 100.0
        elif ok is False:
            availability_pct = 0.0
        else:
            availability_pct = 50.0
    availability_pct = _clamp(float(availability_pct), 0.0, 100.0)

    if error_rate_pct is None:
        error_rate_pct = 100.0 - availability_pct
    error_rate_pct = _clamp(float(error_rate_pct), 0.0, 100.0)

    availability = availability_pct / 100.0
    err_ratio = error_rate_pct / 100.0

    if latency_ms is None:
        if ok is True:
            lat_factor = 0.72
        elif ok is False:
            lat_factor = 0.18
        else:
            lat_factor = 0.45
    else:
        lat_factor = float(_AUTO_LB_LATENCY_REF_MS) / max(float(_AUTO_LB_LATENCY_REF_MS), float(latency_ms))
        lat_factor = _clamp(lat_factor, 0.05, 1.0)

    stability = 1.0 - min(1.0, float(consec_fail) / float(max(1, _AUTO_LB_DOWN_CONSEC_FAIL * 2)))
    score = (availability * 0.62) + ((1.0 - err_ratio) * 0.18) + (lat_factor * 0.15) + (stability * 0.05)
    score = _clamp(score, 0.01, 1.0)
    if ok is False and samples < _AUTO_LB_MIN_SAMPLES:
        score = _clamp(score * 0.7, 0.01, 1.0)

    down = False
    if samples >= _AUTO_LB_MIN_SAMPLES:
        if consec_fail >= _AUTO_LB_DOWN_CONSEC_FAIL:
            down = True
        if availability_pct <= float(_AUTO_LB_DOWN_AVAIL_PCT):
            down = True
    if metric.get("down") is True and samples >= _AUTO_LB_MIN_SAMPLES:
        down = True

    if down:
        score = _clamp(score * 0.05, 0.01, 1.0)

    return {
        "remote": remote,
        "score": score,
        "down": bool(down),
        "ok": ok,
        "samples": samples,
        "availability": round(availability_pct, 2),
        "error_rate": round(error_rate_pct, 2),
        "latency_ms": (round(latency_ms, 2) if latency_ms is not None else None),
        "consecutive_failures": consec_fail,
        "has_signal": bool(has_signal),
    }


def _derive_weights(rows: List[Dict[str, Any]]) -> List[int]:
    if not rows:
        return []
    any_healthy = any(not bool(r.get("down")) for r in rows)
    raw: List[float] = []
    for r in rows:
        s = _clamp(float(r.get("score") or 0.01), 0.01, 1.0)
        if any_healthy and bool(r.get("down")):
            s = min(s, 0.02)
        raw.append(s)
    total = float(sum(raw) or 1.0)

    out: List[int] = []
    for i, r in enumerate(rows):
        w = int(round((float(raw[i]) / total) * float(_AUTO_LB_WEIGHT_SCALE)))
        floor = _AUTO_LB_MIN_DOWN_WEIGHT if (any_healthy and bool(r.get("down"))) else _AUTO_LB_MIN_WEIGHT
        if w < int(floor):
            w = int(floor)
        if w > int(_AUTO_LB_MAX_WEIGHT):
            w = int(_AUTO_LB_MAX_WEIGHT)
        out.append(int(w))

    if any_healthy:
        healthy_idx = [i for i, r in enumerate(rows) if not bool(r.get("down"))]
        down_idx = [i for i, r in enumerate(rows) if bool(r.get("down"))]
        if healthy_idx and down_idx:
            max_healthy = max(int(out[i]) for i in healthy_idx)
            for i in down_idx:
                if int(out[i]) >= int(max_healthy):
                    out[i] = int(_AUTO_LB_MIN_DOWN_WEIGHT)
    return out


def _rule_state_key(node_id: int, listen: str) -> str:
    return f"{int(node_id)}|{listen}"


def _rule_state_prune_locked(now: float) -> None:
    global _RULE_STATE_PRUNE_TS
    if (now - float(_RULE_STATE_PRUNE_TS)) < 60.0:
        return
    for k, item in list(_RULE_STATE.items()):
        try:
            ts = float(item.get("applied_at") or 0.0)
        except Exception:
            ts = 0.0
        if ts <= 0.0 or (now - ts) > float(_AUTO_LB_RULE_TTL_SEC):
            _RULE_STATE.pop(k, None)
    _RULE_STATE_PRUNE_TS = now


def _rule_state_get(node_id: int, listen: str) -> Dict[str, Any]:
    k = _rule_state_key(node_id, listen)
    now = time.monotonic()
    with _RULE_STATE_LOCK:
        _rule_state_prune_locked(now)
        item = _RULE_STATE.get(k)
        if not isinstance(item, dict):
            return {}
        out = dict(item)
    return out


def _rule_state_set(node_id: int, listen: str, *, weights: List[int], down_set: Set[str], applied_at: float) -> None:
    k = _rule_state_key(node_id, listen)
    with _RULE_STATE_LOCK:
        _RULE_STATE[k] = {
            "applied_at": float(applied_at),
            "weights": [int(max(1, x)) for x in weights],
            "down_set": sorted(str(x) for x in down_set if str(x).strip()),
        }


def suggest_adaptive_pool_patch(
    *,
    node_id: int,
    desired_ver: int,
    agent_ack: int,
    desired_pool: Dict[str, Any],
    report: Dict[str, Any],
) -> Optional[Dict[str, Any]]:
    """Suggest one adaptive balance change based on latest stats.

    Returns:
      {
        "pool": <new_pool>,
        "idx": int,
        "listen": str,
        "old_balance": str,
        "new_balance": str,
        "weights": [int, ...],
        "diff_pct": float,
        "down": [remote...],
        "newly_down": [remote...],
        "recovered": [remote...],
      }
    """
    if not _AUTO_LB_ENABLED:
        return None
    if int(node_id) <= 0:
        return None
    if int(desired_ver) > int(agent_ack):
        # Node is still applying previous changes; avoid piling up versions.
        return None
    if not isinstance(desired_pool, dict) or not isinstance(report, dict):
        return None

    stats = report.get("stats")
    if not isinstance(stats, dict) or stats.get("ok") is False:
        return None

    endpoints = desired_pool.get("endpoints")
    if not isinstance(endpoints, list) or not endpoints:
        return None

    rules_raw = stats.get("rules")
    rules = rules_raw if isinstance(rules_raw, list) else []
    if not rules:
        return None
    probe_remotes = stats.get("probe_remotes") if isinstance(stats.get("probe_remotes"), dict) else {}

    rules_by_listen: Dict[str, Dict[str, Any]] = {}
    rules_by_idx: Dict[int, Dict[str, Any]] = {}
    for r in rules:
        if not isinstance(r, dict):
            continue
        listen = str(r.get("listen") or "").strip()
        if listen and listen not in rules_by_listen:
            rules_by_listen[listen] = r
        try:
            idx = int(r.get("idx"))
        except Exception:
            idx = -1
        if idx >= 0 and idx not in rules_by_idx:
            rules_by_idx[idx] = r

    now = time.monotonic()
    candidates: List[Dict[str, Any]] = []

    for idx, ep in enumerate(endpoints):
        if not isinstance(ep, dict):
            continue
        if bool(ep.get("disabled")):
            continue
        listen = str(ep.get("listen") or "").strip()
        if not listen:
            continue
        protocol = str(ep.get("protocol") or "tcp+udp").strip().lower()
        if "tcp" not in protocol:
            continue

        ex = ep.get("extra_config") if isinstance(ep.get("extra_config"), dict) else {}
        if isinstance(ex, dict) and (ex.get("intranet_role") or ex.get("intranet_token")):
            continue

        remotes = _collect_remotes(ep)
        if len(remotes) < 2:
            continue

        algo, old_weights = _parse_balance(ep.get("balance"), len(remotes))
        if algo != "roundrobin":
            continue
        if len(old_weights) != len(remotes):
            old_weights = [1] * len(remotes)

        rule_stats = rules_by_listen.get(listen) or rules_by_idx.get(idx)
        if not isinstance(rule_stats, dict):
            continue

        rows: List[Dict[str, Any]] = []
        signal_count = 0
        for r in remotes:
            m = _lookup_remote_metric(r, rule_stats, probe_remotes)
            row = _derive_remote(r, m if isinstance(m, dict) else {})
            if row.get("has_signal"):
                signal_count += 1
            rows.append(row)
        if signal_count <= 0:
            continue

        new_weights = _derive_weights(rows)
        if len(new_weights) != len(remotes):
            continue

        diff_pct = _weights_diff_pct(old_weights, new_weights)
        down_set = {str(x.get("remote") or "").strip() for x in rows if bool(x.get("down"))}
        down_set.discard("")

        st = _rule_state_get(int(node_id), listen)
        prev_down_set = {str(x).strip() for x in (st.get("down_set") or []) if str(x).strip()}
        newly_down = sorted(down_set - prev_down_set)
        recovered = sorted(prev_down_set - down_set)

        try:
            last_applied = float(st.get("applied_at") or 0.0)
        except Exception:
            last_applied = 0.0
        in_cooldown = (now - last_applied) < float(_AUTO_LB_COOLDOWN_SEC)
        if in_cooldown and not newly_down:
            continue
        if diff_pct < float(_AUTO_LB_MIN_DIFF_PCT) and not newly_down and not recovered:
            continue

        old_balance = str(ep.get("balance") or "roundrobin").strip() or "roundrobin"
        new_balance = _format_balance(new_weights)
        if old_balance == new_balance:
            continue

        urgency = float(diff_pct) + (35.0 * len(newly_down)) + (10.0 * len(recovered))
        candidates.append(
            {
                "idx": int(idx),
                "listen": listen,
                "old_balance": old_balance,
                "new_balance": new_balance,
                "weights": new_weights,
                "diff_pct": float(diff_pct),
                "down": sorted(down_set),
                "newly_down": newly_down,
                "recovered": recovered,
                "urgency": urgency,
            }
        )

    if not candidates:
        return None

    candidates.sort(key=lambda x: (float(x.get("urgency") or 0.0), float(x.get("diff_pct") or 0.0)), reverse=True)
    best = candidates[0]

    try:
        idx_best = int(best.get("idx"))
    except Exception:
        return None
    if idx_best < 0 or idx_best >= len(endpoints):
        return None

    new_pool = copy.deepcopy(desired_pool)
    new_eps = new_pool.get("endpoints")
    if not isinstance(new_eps, list) or idx_best >= len(new_eps):
        return None
    ep2 = new_eps[idx_best]
    if not isinstance(ep2, dict):
        return None
    ep2["balance"] = str(best.get("new_balance") or "roundrobin")

    _rule_state_set(
        int(node_id),
        str(best.get("listen") or ""),
        weights=[int(x) for x in (best.get("weights") or [])],
        down_set={str(x) for x in (best.get("down") or [])},
        applied_at=now,
    )

    out = dict(best)
    out["pool"] = new_pool
    return out

