from __future__ import annotations

import asyncio
import os
import time
from typing import Any, Dict, List

import httpx
from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse

from .config import CFG
from .models import ApplyResult, LogsResponse, Rule, RuleCreate, RuleUpdate, ServiceStatus
from .storage import create_rule, delete_rule, load_rules, toggle_rule, update_rule
from .realmctl import build_realm_config, journal_tail, restart_realm, status_snapshot, write_realm_config

app = FastAPI(title="Realm Agent API", version="14.0")


def _auth_dep(request: Request) -> None:
    if not CFG.token:
        # token missing => deny by default
        raise HTTPException(status_code=503, detail="Agent token not configured")
    hdr = request.headers.get("authorization", "")
    if not hdr.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing bearer token")
    token = hdr.split(" ", 1)[1].strip()
    if token != CFG.token:
        raise HTTPException(status_code=403, detail="Invalid token")


async def _maybe_apply() -> ApplyResult:
    if not CFG.auto_apply:
        return ApplyResult(ok=True, message="saved (auto-apply disabled)")
    return await apply_and_restart()


async def apply_and_restart() -> ApplyResult:
    rules = load_rules()
    toml_text = build_realm_config(rules)
    try:
        write_realm_config(toml_text)
    except Exception as e:
        return ApplyResult(ok=False, message=f"write config failed: {e}")

    ok, msg = restart_realm()
    if not ok:
        return ApplyResult(ok=False, message=f"realm restart failed: {msg}")
    return ApplyResult(ok=True, message="applied and restarted")


@app.get("/api/ping")
async def ping() -> Dict[str, Any]:
    return {"ok": True, "ts": int(time.time())}


@app.get("/api/status", dependencies=[Depends(_auth_dep)])
async def get_status() -> Dict[str, Any]:
    rules = load_rules()
    return status_snapshot(rules)


@app.get("/api/service", response_model=ServiceStatus, dependencies=[Depends(_auth_dep)])
async def service_status() -> ServiceStatus:
    snap = status_snapshot(load_rules())
    return ServiceStatus(
        realm_active=bool(snap["realm_active"]),
        realm_status=str(snap["realm_status"]),
        rules_enabled=int(snap["rules_enabled"]),
        rules_total=int(snap["rules_total"]),
        now=int(time.time()),
        connections=dict(snap.get("conn_counts", {})),
        target_status=dict(snap.get("target_status", {})),
    )


@app.get("/api/rules", response_model=List[Rule], dependencies=[Depends(_auth_dep)])
async def list_rules() -> List[Rule]:
    return load_rules()


@app.post("/api/rules", response_model=Rule, dependencies=[Depends(_auth_dep)])
async def add_rule(payload: RuleCreate) -> Rule:
    rule = create_rule(payload)
    res = await _maybe_apply()
    if not res.ok:
        raise HTTPException(status_code=500, detail=res.message)
    return rule


@app.put("/api/rules/{rule_id}", response_model=Rule, dependencies=[Depends(_auth_dep)])
async def edit_rule(rule_id: str, payload: RuleUpdate) -> Rule:
    rule = update_rule(rule_id, payload)
    if not rule:
        raise HTTPException(status_code=404, detail="rule not found")
    res = await _maybe_apply()
    if not res.ok:
        raise HTTPException(status_code=500, detail=res.message)
    return rule


@app.post("/api/rules/{rule_id}/toggle", response_model=Rule, dependencies=[Depends(_auth_dep)])
async def toggle(rule_id: str, payload: Dict[str, Any]) -> Rule:
    enabled = bool(payload.get("enabled", True))
    rule = toggle_rule(rule_id, enabled)
    if not rule:
        raise HTTPException(status_code=404, detail="rule not found")
    res = await _maybe_apply()
    if not res.ok:
        raise HTTPException(status_code=500, detail=res.message)
    return rule


@app.delete("/api/rules/{rule_id}", response_model=ApplyResult, dependencies=[Depends(_auth_dep)])
async def remove_rule(rule_id: str) -> ApplyResult:
    ok = delete_rule(rule_id)
    if not ok:
        raise HTTPException(status_code=404, detail="rule not found")
    return await _maybe_apply()


@app.post("/api/apply", response_model=ApplyResult, dependencies=[Depends(_auth_dep)])
async def apply_now() -> ApplyResult:
    return await apply_and_restart()


@app.get("/api/logs/{unit}", response_model=LogsResponse, dependencies=[Depends(_auth_dep)])
async def logs(unit: str, lines: int = 200) -> LogsResponse:
    if unit not in ("realm", "realm-agent"):
        raise HTTPException(status_code=400, detail="invalid unit")
    u = f"{unit}.service" if not unit.endswith(".service") else unit
    data = journal_tail(u, lines=lines)
    return LogsResponse(unit=u, lines=data)


# --------- Agent heartbeat to panel ---------

async def _heartbeat_loop() -> None:
    if not CFG.panel_url or not CFG.agent_id or not CFG.token:
        return

    url = CFG.panel_url.rstrip("/") + "/api/agent/heartbeat"
    async with httpx.AsyncClient(verify=CFG.panel_verify_tls, timeout=10.0) as client:
        while True:
            try:
                await client.post(
                    url,
                    json={"agent_id": CFG.agent_id, "ts": int(time.time())},
                    headers={"Authorization": f"Bearer {CFG.token}"},
                )
            except Exception:
                pass
            await asyncio.sleep(CFG.heartbeat_interval)


@app.on_event("startup")
async def on_startup() -> None:
    # Start heartbeat in background
    asyncio.create_task(_heartbeat_loop())


@app.exception_handler(Exception)
async def unhandled_exception_handler(request: Request, exc: Exception):
    return JSONResponse(status_code=500, content={"detail": str(exc)})
