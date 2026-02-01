from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, Header, Request
from fastapi.responses import PlainTextResponse

from ..core.settings import DEFAULT_AGENT_PORT
from ..db import get_node_by_api_key
from ..services.assets import agent_asset_urls, panel_public_base_url

router = APIRouter()


@router.get("/join", response_class=PlainTextResponse)
async def join_script_header(
    request: Request,
    token: Optional[str] = Header(default=None, alias="X-Join-Token"),
):
    """Join script endpoint without putting token in URL path."""
    token = (token or "").strip()
    if not token:
        return PlainTextResponse(
            "echo '[错误] 缺少接入 token（请在请求头 X-Join-Token 中提供）' >&2\nexit 1\n",
            status_code=401,
        )
    return await join_script(request, token)


@router.get("/uninstall", response_class=PlainTextResponse)
async def uninstall_script_header(
    request: Request,
    token: Optional[str] = Header(default=None, alias="X-Join-Token"),
):
    """Uninstall script endpoint without putting token in URL path."""
    token = (token or "").strip()
    if not token:
        return PlainTextResponse(
            "echo '[错误] 缺少接入 token（请在请求头 X-Join-Token 中提供）' >&2\nexit 1\n",
            status_code=401,
        )
    return await uninstall_script(request, token)


@router.get("/join/{token}", response_class=PlainTextResponse)
async def join_script(request: Request, token: str):
    """短命令接入脚本：curl .../join/<token> | bash

    token = node.api_key（用于定位节点），脚本内部会写入 /etc/realm-agent/api.key。

    资产拉取策略：
    - 默认：从面板 /static 拉取 realm_agent.sh + realm-agent.zip
    - 若 REALM_PANEL_ASSET_SOURCE=github：从 GitHub 拉取（适用于面板非公网可达）
    """

    node = get_node_by_api_key(token)
    if not node:
        return PlainTextResponse(
            """echo '[错误] 接入链接无效：token 不存在或已失效' >&2
exit 1
""",
            status_code=404,
        )

    base_url = panel_public_base_url(request)
    node_id = int(node.get("id"))
    api_key = str(node.get("api_key"))
    agent_port = int(node.get("agent_port") or DEFAULT_AGENT_PORT)
    agent_sh_url, repo_zip_url, github_only = agent_asset_urls(base_url)
    gh_only_env = "  REALM_AGENT_GITHUB_ONLY=1 \\\n" if github_only else ""

    script = f"""#!/usr/bin/env bash
set -euo pipefail

PANEL_URL=\"{base_url}\"
NODE_ID=\"{node_id}\"
API_KEY=\"{api_key}\"

if [[ \"$(id -u)\" -ne 0 ]]; then
  if command -v sudo >/dev/null 2>&1; then
    echo \"[提示] 需要 root，自动尝试 sudo...\" >&2
    exec sudo -E bash -c \"curl -fsSL -H \\\"X-Join-Token: {api_key}\\\" \\\"$PANEL_URL/join\\\" | bash\"
  fi
  echo \"[错误] 需要 root 权限运行，但系统未安装 sudo。请切换到 root 后重试（sudo -i / su -）。\" >&2
  exit 1
fi

install -d -m 700 /etc/realm-agent
umask 077

echo \"$API_KEY\" > /etc/realm-agent/api.key
chmod 600 /etc/realm-agent/api.key 2>/dev/null || true

echo \"[提示] 正在安装/更新 Realm Agent…\" >&2
curl -fsSL \"{agent_sh_url}\" | \
{gh_only_env}  REALM_AGENT_REPO_ZIP_URL=\"{repo_zip_url}\" \
  REALM_AGENT_FORCE_UPDATE=1 \
  REALM_AGENT_MODE=1 \
  REALM_AGENT_PORT={agent_port} \
  REALM_AGENT_ASSUME_YES=1 \
  REALM_PANEL_URL=\"$PANEL_URL\" \
  REALM_AGENT_ID=\"$NODE_ID\" \
  REALM_AGENT_HEARTBEAT_INTERVAL=3 \
  bash
"""
    return PlainTextResponse(script, media_type="text/plain; charset=utf-8")


@router.get("/uninstall/{token}", response_class=PlainTextResponse)
async def uninstall_script(request: Request, token: str):
    """短命令卸载脚本：curl .../uninstall/<token> | bash"""

    node = get_node_by_api_key(token)
    if not node:
        return PlainTextResponse(
            """echo '[错误] 接入链接无效：token 不存在或已失效' >&2
exit 1
""",
            status_code=404,
        )

    base_url = panel_public_base_url(request)
    api_key = str(node.get("api_key"))

    script = f"""#!/usr/bin/env bash
set -euo pipefail

PANEL_URL=\"{base_url}\"

if [[ \"$(id -u)\" -ne 0 ]]; then
  if command -v sudo >/dev/null 2>&1; then
    echo \"[提示] 需要 root，自动尝试 sudo...\" >&2
    exec sudo -E bash -c \"curl -fsSL -H \\\"X-Join-Token: {api_key}\\\" \\\"$PANEL_URL/uninstall\\\" | bash\"
  fi
  echo \"[错误] 需要 root 权限运行，但系统未安装 sudo。请切换到 root 后重试（sudo -i / su -）。\" >&2
  exit 1
fi

echo \"[提示] 正在卸载 Realm Agent / Realm…\" >&2
systemctl disable --now realm-agent.service realm-agent-https.service realm.service realm \
  >/dev/null 2>&1 || true
rm -f /etc/systemd/system/realm-agent.service /etc/systemd/system/realm-agent-https.service \
  /etc/systemd/system/realm.service || true
systemctl daemon-reload || true

rm -rf /opt/realm-agent /etc/realm-agent /etc/realm /opt/realm || true
rm -f /usr/local/bin/realm /usr/bin/realm || true

echo \"[OK] 卸载完成\" >&2
"""
    return PlainTextResponse(script, media_type="text/plain; charset=utf-8")
