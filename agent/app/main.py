import os
import time
from typing import Any, Dict

from fastapi import Depends, FastAPI, HTTPException
from fastapi.responses import JSONResponse

from .auth import require_key
from .metrics import gather_metrics
from .realmctl import apply_realm_config, ensure_pool_jq
from .rules import (
    add_rule,
    delete_rule,
    get_rule,
    list_rules,
    toggle_rule,
    update_rule,
)
from .storage import Paths
from .utils import sh

app = FastAPI(title="Realm Agent API", version="1.0.0")

START_TS = int(time.time())


def _paths() -> Paths:
    return Paths(conf_dir=os.environ.get("REALM_CONF_DIR", "/etc/realm"))


@app.get("/api/status")
def status(_: None = Depends(require_key)):
    code, out, _ = sh("systemctl is-active realm.service 2>/dev/null || true", timeout=5)
    active = (out.strip() == "active")
    code2, out2, _ = sh("realm -v 2>/dev/null || true", timeout=5)
    return {
        "ok": True,
        "realm_active": active,
        "realm_version": out2.strip(),
        "uptime_sec": int(time.time()) - START_TS,
    }


@app.get("/api/rules")
def api_list_rules(_: None = Depends(require_key)):
    rules = list_rules(_paths())
    return {"endpoints": rules}


@app.get("/api/rules/{rule_id}")
def api_get_rule(rule_id: str, _: None = Depends(require_key)):
    r = get_rule(_paths(), rule_id)
    if not r:
        raise HTTPException(status_code=404, detail="rule not found")
    return r


@app.post("/api/rules")
def api_add_rule(payload: Dict[str, Any], _: None = Depends(require_key)):
    try:
        r = add_rule(_paths(), payload)
        return r
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.put("/api/rules/{rule_id}")
def api_update_rule(rule_id: str, payload: Dict[str, Any], _: None = Depends(require_key)):
    try:
        r = update_rule(_paths(), rule_id, payload)
        return r
    except KeyError:
        raise HTTPException(status_code=404, detail="rule not found")
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.delete("/api/rules/{rule_id}")
def api_delete_rule(rule_id: str, _: None = Depends(require_key)):
    try:
        delete_rule(_paths(), rule_id)
        return {"ok": True}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.post("/api/rules/{rule_id}/toggle")
def api_toggle_rule(rule_id: str, payload: Dict[str, Any], _: None = Depends(require_key)):
    disabled = bool(payload.get("disabled", False))
    try:
        r = toggle_rule(_paths(), rule_id, disabled)
        return r
    except KeyError:
        raise HTTPException(status_code=404, detail="rule not found")


@app.post("/api/apply")
def api_apply(_: None = Depends(require_key)):
    paths = _paths()
    ensure_pool_jq(paths)
    ok, msg = apply_realm_config(paths)
    return {"ok": ok, "message": msg}


@app.get("/api/metrics")
def api_metrics(_: None = Depends(require_key)):
    rules = list_rules(_paths())
    return gather_metrics(rules)


@app.get("/api/health")
def api_health():
    return JSONResponse({"ok": True})
