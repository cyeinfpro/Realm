from __future__ import annotations

import json
import time
import uuid
from datetime import datetime
from typing import Any, Dict, List

from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse

from ..core.deps import require_login
from ..core.paths import STATIC_DIR
from ..db import (
    get_desired_pool,
    get_group_orders,
    get_node,
    list_nodes,
    set_agent_rollout_all,
    set_desired_pool_exact,
    set_desired_pool_version_exact,
    update_agent_status,
    update_node_report,
)
from ..services.agent_commands import sign_cmd, single_rule_ops
from ..services.assets import agent_asset_urls, file_sha256, panel_public_base_url, parse_agent_version_from_ua, read_latest_agent_version
from ..services.node_status import is_report_fresh
from ..services.stats_history import ingest_stats_snapshot

router = APIRouter()


# ------------------------ Agent push-report API (no login) ------------------------


@router.post("/api/agent/report")
async def api_agent_report(request: Request, payload: Dict[str, Any]):
    """Agent 主动上报接口。

    认证：HTTP Header `X-API-Key: <node.api_key>`。
    载荷：至少包含 node_id 字段。

    返回：commands（例如同步规则池 / 自更新）。
    """

    api_key = (request.headers.get("x-api-key") or request.headers.get("X-API-Key") or "").strip()
    node_id_raw = payload.get("node_id")
    try:
        node_id = int(node_id_raw)
    except Exception:
        return JSONResponse({"ok": False, "error": "节点 ID 无效"}, status_code=400)

    node = get_node(node_id)
    if not node:
        return JSONResponse({"ok": False, "error": "节点不存在"}, status_code=404)
    if not api_key or api_key != node.get("api_key"):
        return JSONResponse({"ok": False, "error": "无权限（API Key 不正确）"}, status_code=403)

    # Agent software/update meta (optional)
    agent_version = str(payload.get("agent_version") or "").strip()
    if not agent_version:
        agent_version = parse_agent_version_from_ua(
            (request.headers.get("User-Agent") or request.headers.get("user-agent") or "").strip()
        )

    agent_update = payload.get("agent_update")
    if not isinstance(agent_update, dict):
        agent_update = {}

    # report_json：尽量只保存 report 字段（更干净），但也兼容直接上报全量
    report = payload.get("report") if isinstance(payload, dict) else None
    if report is None:
        report = payload

    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    ack_version = payload.get("ack_version")

    # Parse agent ack version early (used for version realignment)
    try:
        agent_ack = int(ack_version) if ack_version is not None else 0
    except Exception:
        agent_ack = 0

    traffic_ack_version = payload.get("traffic_ack_version")
    try:
        traffic_ack = int(traffic_ack_version) if traffic_ack_version is not None else None
    except Exception:
        traffic_ack = None

    try:
        update_node_report(
            node_id=node_id,
            report_json=json.dumps(report, ensure_ascii=False),
            last_seen_at=now,
            agent_ack_version=int(ack_version) if ack_version is not None else None,
            traffic_ack_version=traffic_ack,
        )
    except Exception:
        # 不要让写库失败影响 agent
        pass

    # Persist rule traffic/connection history (best-effort, never block agent report)
    try:
        if isinstance(report, dict) and isinstance(report.get("stats"), dict):
            ingest_stats_snapshot(node_id=node_id, stats=report.get("stats"))
    except Exception:
        pass

    # Persist agent version + update status (best-effort)
    # ⚠️ 关键：面板触发新一轮更新（desired_agent_update_id 改变）时，
    # Agent 可能还在上报「上一轮」的状态（甚至旧版本 Agent 的状态里没有 update_id）。
    # 如果直接用 agent_update.state 覆盖 DB，就会把面板刚设置的 queued/sent 覆盖成 done。
    # 解决：
    #   - 若面板当前存在 desired_update_id：只接受 update_id == desired_update_id 的状态回报。
    #   - 若面板未在滚动更新：允许无 update_id 的旧状态回报（仅用于展示历史状态）。
    try:
        desired_update_id_now = str(node.get("desired_agent_update_id") or "").strip()
        rep_update_id = str(agent_update.get("update_id") or "").strip() if isinstance(agent_update, dict) else ""
        st = str(agent_update.get("state") or "").strip() if isinstance(agent_update, dict) else ""
        msg = (
            str(agent_update.get("error") or agent_update.get("msg") or "").strip()
            if isinstance(agent_update, dict)
            else ""
        )

        if desired_update_id_now:
            # 正在更新：必须强制对齐 update_id，否则视为“旧状态/噪声”不覆盖
            if rep_update_id and rep_update_id == desired_update_id_now:
                update_agent_status(
                    node_id=node_id,
                    agent_reported_version=agent_version or None,
                    state=st or None,
                    msg=msg or None,
                )
            else:
                # 仅更新版本号，不覆盖面板当前批次的状态
                update_agent_status(node_id=node_id, agent_reported_version=agent_version or None)
        else:
            # 未处于滚动更新中：允许旧版 agent（无 update_id）也能回报“上次更新状态”
            update_agent_status(
                node_id=node_id,
                agent_reported_version=agent_version or None,
                state=st or None,
                msg=msg or None,
            )
    except Exception:
        pass

    # 若面板尚无 desired_pool，则尝试把 agent 当前 pool 作为初始 desired_pool。
    # ⚠️ 关键：当面板重装/恢复后，Agent 可能还保留旧的 ack_version（例如 33），
    # 如果面板把 desired_pool_version 从 1 开始，后续新增规则会一直小于 ack_version，
    # 导致面板永远不下发 commands，看起来像“不同步”。
    # 这里将面板 desired_pool_version 对齐到 agent_ack（至少 1），避免版本回退。
    desired_ver, desired_pool = get_desired_pool(node_id)
    if desired_pool is None:
        rep_pool = None
        if isinstance(report, dict):
            rep_pool = report.get("pool")
        if isinstance(rep_pool, dict):
            init_ver = max(1, agent_ack)
            desired_ver, desired_pool = set_desired_pool_exact(node_id, rep_pool, init_ver)
    else:
        # Desired exists but version is behind agent ack (panel DB reset or migrated)
        if agent_ack > desired_ver:
            rep_pool = None
            if isinstance(report, dict):
                rep_pool = report.get("pool")
            if isinstance(rep_pool, dict):
                # Trust agent as source of truth when panel version went backwards (e.g. DB restore).
                desired_ver, desired_pool = set_desired_pool_exact(node_id, rep_pool, agent_ack)
            else:
                desired_ver = set_desired_pool_version_exact(node_id, agent_ack)

    # 下发命令：规则池同步
    cmds: List[Dict[str, Any]] = []
    if isinstance(desired_pool, dict) and desired_ver > agent_ack:
        # ✅ 单条规则增量下发：仅当 agent 落后 1 个版本，且报告中存在当前 pool 时才尝试 patch
        base_pool = None
        if isinstance(report, dict):
            base_pool = report.get("pool") if isinstance(report.get("pool"), dict) else None

        cmd: Dict[str, Any]
        ops = None
        if desired_ver == agent_ack + 1 and isinstance(base_pool, dict):
            ops = single_rule_ops(base_pool, desired_pool)

        if isinstance(ops, list) and len(ops) == 1:
            cmd = {
                "type": "pool_patch",
                "version": desired_ver,
                "base_version": agent_ack,
                "ops": ops,
                "apply": True,
            }
        else:
            cmd = {
                "type": "sync_pool",
                "version": desired_ver,
                "pool": desired_pool,
                "apply": True,
            }

        cmds.append(sign_cmd(str(node.get("api_key") or ""), cmd))

    # 下发命令：Agent 自更新（可选）
    try:
        desired_agent_ver = str(node.get("desired_agent_version") or "").strip()
        desired_update_id = str(node.get("desired_agent_update_id") or "").strip()
        cur_agent_ver = (agent_version or str(node.get("agent_reported_version") or "")).strip()

        rep_update_id = str(agent_update.get("update_id") or "").strip() if isinstance(agent_update, dict) else ""
        rep_state = (
            str(agent_update.get("state") or "").strip().lower() if isinstance(agent_update, dict) else ""
        )

        if desired_agent_ver and desired_update_id:
            # ✅ “一键更新”=强制按面板/GitHub 文件重装：不再用版本号短路。
            # 只有当 agent 明确回报「本批次 update_id 已 done」时才停止下发。
            already_done = rep_update_id == desired_update_id and rep_state == "done"

            if already_done:
                if str(node.get("agent_update_state") or "").strip() != "done":
                    try:
                        update_agent_status(node_id=node_id, state="done", msg="")
                    except Exception:
                        pass
            else:
                # ✅ 不对旧版本做“硬阻断”。
                # 有些环境里节点上跑的 Agent 版本可能很旧/无法准确上报版本号。
                # 这里仍然尝试下发 update_agent，让节点“尽最大可能”自更新。

                panel_base = panel_public_base_url(request)
                sh_url, zip_url, github_only = agent_asset_urls(panel_base)
                zip_sha256 = "" if github_only else file_sha256(STATIC_DIR / "realm-agent.zip")

                # ✅ 强制更新关键：
                # 旧版 Agent 的 update_agent 实现里存在“版本号短路”逻辑：
                #   - 当 current_version >= desired_version 时，直接标记 done 并返回
                # 为了做到“无论当前版本如何，点更新就必须重装”，我们给 desired_version
                # 加一个批次后缀，让旧版 Agent 的 int() 解析失败，从而不会短路。
                desired_ver_for_cmd = desired_agent_ver
                try:
                    suf = (desired_update_id or "")[:8] or str(int(time.time()))
                    if desired_ver_for_cmd:
                        desired_ver_for_cmd = f"{desired_ver_for_cmd}-force-{suf}"
                except Exception:
                    pass

                ucmd: Dict[str, Any] = {
                    "type": "update_agent",
                    "update_id": desired_update_id,
                    "desired_version": desired_ver_for_cmd,
                    "panel_url": panel_base,
                    "sh_url": sh_url,
                    "zip_url": zip_url,
                    "zip_sha256": zip_sha256,
                    "github_only": bool(github_only),
                    "force": True,
                }

                cmds.append(sign_cmd(str(node.get("api_key") or ""), ucmd))

                # mark queued->sent (best-effort)
                if str(node.get("agent_update_state") or "").strip() in ("", "queued"):
                    try:
                        update_agent_status(node_id=node_id, state="sent")
                    except Exception:
                        pass

    except Exception:
        pass


    # 下发命令：一键重置规则流量（可选）
    try:
        desired_reset_ver = int(node.get("desired_traffic_reset_version") or 0)
    except Exception:
        desired_reset_ver = 0

    try:
        ack_reset_ver = int(traffic_ack) if traffic_ack is not None else int(node.get("agent_traffic_reset_ack_version") or 0)
    except Exception:
        ack_reset_ver = 0

    try:
        if desired_reset_ver > 0 and desired_reset_ver > ack_reset_ver:
            rcmd = {
                "type": "reset_traffic",
                "version": desired_reset_ver,
                "reset_iptables": True,
                "reset_baseline": True,
                "reset_ss_cache": True,
                "reset_conn_history": True,
            }
            cmds.append(sign_cmd(str(node.get("api_key") or ""), rcmd))
    except Exception:
        pass

    return {"ok": True, "server_time": now, "desired_version": desired_ver, "commands": cmds}


# ------------------------ API (needs login) ------------------------


@router.get("/api/agents/latest")
async def api_agents_latest(_: Request, user: str = Depends(require_login)):
    """Return the latest agent version bundled with this panel."""
    latest = read_latest_agent_version()
    zip_sha256 = file_sha256(STATIC_DIR / "realm-agent.zip")
    return {
        "ok": True,
        "latest_version": latest,
        "zip_sha256": zip_sha256,
    }


@router.post("/api/agents/update_all")
async def api_agents_update_all(request: Request, user: str = Depends(require_login)):
    """Trigger an agent rollout to all nodes."""
    target = (read_latest_agent_version() or "").strip()
    if not target:
        return JSONResponse(
            {
                "ok": False,
                "error": "无法确定当前面板内置的 Agent 版本（realm-agent.zip 缺失或不可解析）",
            },
            status_code=500,
        )

    update_id = uuid.uuid4().hex
    affected = 0
    try:
        affected = set_agent_rollout_all(desired_version=target, update_id=update_id, state="queued", msg="")
    except Exception:
        affected = 0

    return {
        "ok": True,
        "update_id": update_id,
        "target_version": target,
        "affected": affected,
        "server_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    }


@router.get("/api/agents/update_progress")
async def api_agents_update_progress(update_id: str = "", user: str = Depends(require_login)):
    """Return rollout progress."""
    uid = (update_id or "").strip()
    nodes = list_nodes()
    orders = get_group_orders()

    items: List[Dict[str, Any]] = []
    summary = {
        "total": 0,
        "done": 0,
        "failed": 0,
        "installing": 0,
        "sent": 0,
        "queued": 0,
        "offline": 0,
        "other": 0,
    }

    for n in nodes:
        nuid = str(n.get("desired_agent_update_id") or "").strip()
        if uid and nuid != uid:
            continue

        summary["total"] += 1
        online = is_report_fresh(n)
        desired = str(n.get("desired_agent_version") or "").strip()
        cur = str(n.get("agent_reported_version") or "").strip()
        st = str(n.get("agent_update_state") or "").strip() or "queued"

        # ✅ 一键更新进度：以 agent_update_state 为准。
        # 不再用“当前版本 >= 目标版本”来直接判定 done。
        if not online:
            st2 = "offline"
        else:
            st2 = st

        if st2 in summary:
            summary[st2] += 1
        else:
            summary["other"] += 1

        group_name = str(n.get("group_name") or "").strip() or "默认分组"
        group_order = int(orders.get(group_name, 9999) or 9999)

        items.append(
            {
                "id": n.get("id"),
                "name": n.get("name"),
                "group_name": group_name,
                "group_order": group_order,
                "online": bool(online),
                "agent_version": cur,
                "desired_version": desired,
                "state": st2,
                "msg": str(n.get("agent_update_msg") or "").strip(),
                "last_seen_at": n.get("last_seen_at"),
            }
        )

    # Deterministic ordering (group order -> group -> name -> id)
    try:
        items.sort(
            key=lambda x: (
                int(x.get("group_order") or 9999),
                str(x.get("group_name") or ""),
                str(x.get("name") or ""),
                int(x.get("id") or 0),
            )
        )
    except Exception:
        pass

    return {"ok": True, "update_id": uid, "summary": summary, "nodes": items}
