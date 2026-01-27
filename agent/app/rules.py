import time
import uuid
from typing import Any, Dict, List, Optional, Tuple

from .storage import Paths, ensure_pool_full, load_json, save_json_atomic


def _now() -> int:
    return int(time.time())


def ensure_rule_ids(paths: Paths) -> Dict[str, Any]:
    full = ensure_pool_full(paths)
    changed = False
    for ep in full.get("endpoints", []):
        if not isinstance(ep, dict):
            continue
        if not ep.get("id"):
            ep["id"] = uuid.uuid4().hex[:12]
            changed = True
        if "disabled" not in ep:
            ep["disabled"] = False
            changed = True
        if "created_at" not in ep:
            ep["created_at"] = _now()
            changed = True
        if "updated_at" not in ep:
            ep["updated_at"] = _now()
            changed = True
    if changed:
        save_json_atomic(paths.pool_full, full)
    return full


def list_rules(paths: Paths) -> List[Dict[str, Any]]:
    full = ensure_rule_ids(paths)
    eps = [ep for ep in full.get("endpoints", []) if isinstance(ep, dict)]
    # stable sort by listen port
    def port_key(ep: Dict[str, Any]) -> Tuple[int, str]:
        listen = ep.get("listen", "")
        try:
            p = int(listen.rsplit(":", 1)[1])
        except Exception:
            p = 0
        return (p, ep.get("id", ""))

    return sorted(eps, key=port_key)


def get_rule(paths: Paths, rule_id: str) -> Optional[Dict[str, Any]]:
    for ep in list_rules(paths):
        if ep.get("id") == rule_id:
            return ep
    return None


def _normalize_rule_payload(payload: Dict[str, Any]) -> Dict[str, Any]:
    ep = dict(payload)
    # basic fields
    if not ep.get("listen") or not isinstance(ep.get("listen"), str):
        raise ValueError("listen required")

    # allow remote string or remotes list
    remote = ep.get("remote")
    remotes = ep.get("remotes")
    if remote and isinstance(remote, str):
        pass
    elif isinstance(remotes, list) and remotes:
        # convert to remote + extra_remotes
        rems = [r for r in remotes if isinstance(r, str) and r.strip()]
        if not rems:
            raise ValueError("remote/remotes required")
        ep["remote"] = rems[0]
        if len(rems) > 1:
            ep["extra_remotes"] = rems[1:]
        ep.pop("remotes", None)
    else:
        raise ValueError("remote/remotes required")

    # clean timestamps
    ep["updated_at"] = _now()
    if "created_at" not in ep:
        ep["created_at"] = _now()

    # ensure booleans
    ep["disabled"] = bool(ep.get("disabled", False))

    # ensure extra_config dict
    if "extra_config" in ep and not isinstance(ep["extra_config"], dict):
        ep["extra_config"] = {}

    return ep


def add_rule(paths: Paths, payload: Dict[str, Any]) -> Dict[str, Any]:
    full = ensure_rule_ids(paths)
    ep = _normalize_rule_payload(payload)
    if not ep.get("id"):
        ep["id"] = uuid.uuid4().hex[:12]
    full["endpoints"].append(ep)
    save_json_atomic(paths.pool_full, full)
    return ep


def update_rule(paths: Paths, rule_id: str, payload: Dict[str, Any]) -> Dict[str, Any]:
    full = ensure_rule_ids(paths)
    found = False
    new_ep = _normalize_rule_payload(payload)
    new_ep["id"] = rule_id
    # keep created_at if exists
    for ep in full.get("endpoints", []):
        if isinstance(ep, dict) and ep.get("id") == rule_id:
            new_ep["created_at"] = ep.get("created_at", new_ep.get("created_at"))
            found = True
            break
    if not found:
        raise KeyError("rule not found")

    eps = []
    for ep in full.get("endpoints", []):
        if not isinstance(ep, dict):
            continue
        if ep.get("id") == rule_id:
            eps.append(new_ep)
        else:
            eps.append(ep)
    full["endpoints"] = eps
    save_json_atomic(paths.pool_full, full)
    return new_ep


def delete_rule(paths: Paths, rule_id: str) -> None:
    full = ensure_rule_ids(paths)
    full["endpoints"] = [
        ep for ep in full.get("endpoints", []) if not (isinstance(ep, dict) and ep.get("id") == rule_id)
    ]
    save_json_atomic(paths.pool_full, full)


def toggle_rule(paths: Paths, rule_id: str, disabled: bool) -> Dict[str, Any]:
    full = ensure_rule_ids(paths)
    changed = False
    for ep in full.get("endpoints", []):
        if isinstance(ep, dict) and ep.get("id") == rule_id:
            ep["disabled"] = bool(disabled)
            ep["updated_at"] = _now()
            changed = True
            break
    if not changed:
        raise KeyError("rule not found")
    save_json_atomic(paths.pool_full, full)
    # return updated
    ep = get_rule(paths, rule_id)
    assert ep is not None
    return ep
