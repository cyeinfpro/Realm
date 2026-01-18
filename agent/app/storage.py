import json
import os
import time
from dataclasses import dataclass
from typing import Any, Dict, List

from .utils import ensure_dir


@dataclass
class Paths:
    conf_dir: str = "/etc/realm"

    @property
    def pool_full(self) -> str:
        return os.path.join(self.conf_dir, "pool_full.json")

    @property
    def pool_active(self) -> str:
        return os.path.join(self.conf_dir, "pool.json")

    @property
    def jq_filter(self) -> str:
        return os.path.join(self.conf_dir, "pool_to_run.jq")

    @property
    def config_json(self) -> str:
        return os.path.join(self.conf_dir, "config.json")


def _default_pool() -> Dict[str, Any]:
    return {"endpoints": []}


def load_json(path: str) -> Dict[str, Any]:
    if not os.path.exists(path) or os.path.getsize(path) == 0:
        return _default_pool()
    try:
        with open(path, "r", encoding="utf-8") as f:
            obj = json.load(f)
        if not isinstance(obj, dict):
            return _default_pool()
        if "endpoints" not in obj or not isinstance(obj.get("endpoints"), list):
            obj["endpoints"] = []
        return obj
    except Exception:
        # backup corrupted
        try:
            ts = int(time.time())
            os.rename(path, f"{path}.corrupt.{ts}")
        except Exception:
            pass
        return _default_pool()


def save_json_atomic(path: str, obj: Dict[str, Any]) -> None:
    ensure_dir(os.path.dirname(path))
    tmp = f"{path}.tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(obj, f, ensure_ascii=False, indent=2)
    os.replace(tmp, path)


def ensure_pool_full(paths: Paths) -> Dict[str, Any]:
    """Ensure pool_full exists. If not, migrate from pool.json if present."""
    full = load_json(paths.pool_full)
    if full["endpoints"]:
        return full

    # migrate from active pool
    active = load_json(paths.pool_active)
    if active.get("endpoints"):
        migrated = {
            "endpoints": [
                {**ep, "disabled": False} if isinstance(ep, dict) else ep
                for ep in active.get("endpoints", [])
                if isinstance(ep, dict)
            ]
        }
        save_json_atomic(paths.pool_full, migrated)
        return migrated

    save_json_atomic(paths.pool_full, full)
    return full


def sync_active_from_full(paths: Paths, full: Dict[str, Any]) -> Dict[str, Any]:
    active_eps: List[Dict[str, Any]] = []
    for ep in full.get("endpoints", []):
        if not isinstance(ep, dict):
            continue
        if ep.get("disabled", False):
            continue
        ep2 = dict(ep)
        ep2.pop("disabled", None)
        active_eps.append(ep2)
    active = {"endpoints": active_eps}
    save_json_atomic(paths.pool_active, active)
    return active
