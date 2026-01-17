from __future__ import annotations

import json
import os
import time
from typing import List, Optional

from .config import CFG
from .models import Rule, RuleCreate, RuleUpdate


def _ensure_dirs() -> None:
    os.makedirs(CFG.data_dir, exist_ok=True)


def load_rules() -> List[Rule]:
    _ensure_dirs()
    if not os.path.exists(CFG.rules_file):
        return []
    try:
        with open(CFG.rules_file, "r", encoding="utf-8") as f:
            data = json.load(f)
        return [Rule(**r) for r in data.get("rules", [])]
    except Exception:
        return []


def save_rules(rules: List[Rule]) -> None:
    _ensure_dirs()
    tmp = CFG.rules_file + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump({"updated_at": int(time.time()), "rules": [r.model_dump() for r in rules]}, f, ensure_ascii=False, indent=2)
    os.replace(tmp, CFG.rules_file)


def get_rule(rule_id: str) -> Optional[Rule]:
    rules = load_rules()
    for r in rules:
        if r.id == rule_id:
            return r
    return None


def create_rule(payload: RuleCreate) -> Rule:
    rules = load_rules()
    # Unique id based on time + length
    rid = f"r{int(time.time())}{len(rules)+1}"
    listen = f"0.0.0.0:{payload.listen_port}"
    rule = Rule(
        id=rid,
        name=payload.name,
        listen=listen,
        type=payload.type,
        protocol=payload.protocol,
        targets=payload.targets,
        balance=payload.balance,
        enabled=payload.enabled,
        wss_host=payload.wss_host,
        wss_path=payload.wss_path,
        wss_sni=payload.wss_sni,
        wss_insecure=payload.wss_insecure,
    )
    rules.append(rule)
    save_rules(rules)
    return rule


def update_rule(rule_id: str, payload: RuleUpdate) -> Optional[Rule]:
    rules = load_rules()
    updated = None
    for i, r in enumerate(rules):
        if r.id != rule_id:
            continue
        data = r.model_dump()
        patch = payload.model_dump(exclude_unset=True)
        data.update(patch)
        updated = Rule(**data)
        rules[i] = updated
        break
    if updated is not None:
        save_rules(rules)
    return updated


def delete_rule(rule_id: str) -> bool:
    rules = load_rules()
    new_rules = [r for r in rules if r.id != rule_id]
    if len(new_rules) == len(rules):
        return False
    save_rules(new_rules)
    return True


def toggle_rule(rule_id: str, enabled: bool) -> Optional[Rule]:
    return update_rule(rule_id, RuleUpdate(enabled=enabled))
