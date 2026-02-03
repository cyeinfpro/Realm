from __future__ import annotations

from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse

from ..core.deps import require_login
from ..db import upsert_group_order

router = APIRouter()


@router.post("/api/groups/order")
async def api_groups_order(request: Request, user: str = Depends(require_login)):
    """Update group sort order (UI only)."""
    try:
        data = await request.json()
    except Exception:
        data = {}

    name = str(data.get("group_name") or "").strip() or "默认分组"
    raw = data.get("sort_order", data.get("order", 1000))
    try:
        order = int(raw)
    except Exception:
        return JSONResponse({"ok": False, "error": "排序序号必须是数字"}, status_code=400)

    # keep within a reasonable range to prevent weird UI
    if order < -999999:
        order = -999999
    if order > 999999:
        order = 999999

    upsert_group_order(name, order)
    return {"ok": True, "group_name": name, "sort_order": order}
