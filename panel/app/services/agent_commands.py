from __future__ import annotations

import hashlib
import hmac
import json
import secrets
import time
from typing import Any, Dict, Optional, List


def canonical_json(obj: Any) -> str:
    return json.dumps(obj, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def cmd_signature(secret: str, cmd: Dict[str, Any]) -> str:
    """Return hex HMAC-SHA256 signature for cmd (excluding sig field)."""
    data = {k: v for k, v in cmd.items() if k != "sig"}
    msg = canonical_json(data).encode("utf-8")
    return hmac.new(secret.encode("utf-8"), msg, hashlib.sha256).hexdigest()


def sign_cmd(secret: str, cmd: Dict[str, Any]) -> Dict[str, Any]:
    out = dict(cmd)
    # Always include ts + nonce so commands can't be replayed.
    out.setdefault("ts", int(time.time()))
    out.setdefault("nonce", secrets.token_urlsafe(16))
    out["sig"] = cmd_signature(secret, out)
    return out


def single_rule_ops(base_pool: Dict[str, Any], desired_pool: Dict[str, Any]) -> Optional[List[Dict[str, Any]]]:
    """Return ops when there is exactly ONE rule change between base_pool and desired_pool.

    ops format:
      - {op: 'upsert', endpoint: {...}}
      - {op: 'remove', listen: '0.0.0.0:443'}

    If there are 0 changes -> returns []
    If changes > 1 -> returns None
    """

    def key_of(ep: Any) -> str:
        if not isinstance(ep, dict):
            return ""
        return str(ep.get("listen") or "").strip()

    base_eps = base_pool.get("endpoints") if isinstance(base_pool, dict) else None
    desired_eps = desired_pool.get("endpoints") if isinstance(desired_pool, dict) else None
    if not isinstance(base_eps, list) or not isinstance(desired_eps, list):
        return None

    base_map = {key_of(e): e for e in base_eps if key_of(e)}
    desired_map = {key_of(e): e for e in desired_eps if key_of(e)}

    changes: list[tuple[str, Any]] = []

    # add or update
    for listen, ep in desired_map.items():
        if listen not in base_map:
            changes.append(("upsert", ep))
        else:
            if canonical_json(ep) != canonical_json(base_map[listen]):
                changes.append(("upsert", ep))

    # remove
    for listen in base_map.keys():
        if listen not in desired_map:
            changes.append(("remove", listen))

    if len(changes) == 0:
        return []
    if len(changes) != 1:
        return None

    op, payload = changes[0]
    if op == "upsert":
        return [{"op": "upsert", "endpoint": payload}]
    return [{"op": "remove", "listen": payload}]
