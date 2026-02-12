from __future__ import annotations

from typing import Optional

from urllib.parse import urlparse, urlunparse

from fastapi import APIRouter, Header, Request
from fastapi.responses import PlainTextResponse

from ..core.settings import DEFAULT_AGENT_PORT
from ..db import get_node_by_api_key
from ..services.assets import agent_asset_urls, panel_bootstrap_base_url, panel_bootstrap_insecure_tls, panel_public_base_url

router = APIRouter()


def _alt_http_candidate(url: str) -> str:
    """Return http:// variant for https://<host>:<port> candidate when likely plain-http endpoint."""
    raw = str(url or "").strip()
    if not raw:
        return ""
    try:
        p = urlparse(raw)
    except Exception:
        return ""
    if str(p.scheme or "").lower() != "https":
        return ""
    host = str(p.hostname or "").strip()
    if not host:
        return ""
    # Keep default 443 as-is; non-443 https endpoints are often panel http ports.
    if p.port in (None, 443):
        return ""
    hostport = host
    if p.port:
        hostport = f"{host}:{int(p.port)}"
    return urlunparse(("http", hostport, "", "", "", "")).rstrip("/")


def _unique_join_url_candidates(*urls: str) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    for raw in urls:
        u = str(raw or "").strip().rstrip("/")
        if not u:
            continue
        candidates = [u]
        alt = _alt_http_candidate(u)
        if alt:
            # Prefer downgraded http candidate to avoid TLS wrong-version on plain http ports.
            candidates = [alt, u]
        for x in candidates:
            if x and x not in seen:
                seen.add(x)
                out.append(x)
    return out


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

    public_base_url = panel_public_base_url(request)
    request_base_url = str(request.base_url).rstrip("/")
    bootstrap_base_url = panel_bootstrap_base_url(request).rstrip("/")
    insecure_tls = panel_bootstrap_insecure_tls(default=True)
    curl_tls_opt = "-k " if insecure_tls else ""
    # Prefer the exact scheme/host used by this request; then configured/public URLs.
    panel_url_candidates = _unique_join_url_candidates(request_base_url, bootstrap_base_url, public_base_url)
    bootstrap_for_script = panel_url_candidates[0] if panel_url_candidates else bootstrap_base_url
    node_id = int(node.get("id"))
    api_key = str(node.get("api_key"))
    node_base_url = str(node.get("base_url") or "")
    agent_port = DEFAULT_AGENT_PORT
    try:
        p = urlparse(node_base_url)
        if p.port:
            agent_port = int(p.port)
    except Exception:
        agent_port = DEFAULT_AGENT_PORT
    agent_sh_url, repo_zip_url, github_only = agent_asset_urls(public_base_url)
    panel_candidates_literal = " ".join(f"\"{u}\"" for u in panel_url_candidates)
    panel_candidates_assign = (
        f"PANEL_URL_CANDIDATES=({panel_candidates_literal})"
        if panel_candidates_literal
        else "PANEL_URL_CANDIDATES=()"
    )
    if github_only:
        installer_download_block = f"""curl {curl_tls_opt}-fL --retry 5 ${{CURL_RETRY_ALL_ERRORS}} --connect-timeout 10 \"{agent_sh_url}\" -o \"$INSTALLER_PATH\"
chmod 700 \"$INSTALLER_PATH\" 2>/dev/null || true
export REALM_AGENT_GITHUB_ONLY=1
export REALM_AGENT_REPO_ZIP_URL=\"{repo_zip_url}\""""
    else:
        installer_download_block = """INSTALLER_READY=0
for CANDIDATE_PANEL_URL in "${PANEL_URL_CANDIDATES[@]}"; do
  [[ -n "${CANDIDATE_PANEL_URL}" ]] || continue
  if curl __CURL_TLS_OPT__-fL --retry 5 $CURL_RETRY_ALL_ERRORS --connect-timeout 10 "${CANDIDATE_PANEL_URL}/static/realm_agent.sh" -o "$INSTALLER_PATH"; then
    PANEL_URL="${CANDIDATE_PANEL_URL}"
    export REALM_AGENT_REPO_ZIP_URL="${CANDIDATE_PANEL_URL}/static/realm-agent.zip"
    INSTALLER_READY=1
    break
  fi
done
if [[ "${INSTALLER_READY}" != "1" ]]; then
  echo "[错误] 无法从面板下载安装器（已尝试：${PANEL_URL_CANDIDATES[*]}）" >&2
  exit 1
fi
chmod 700 "$INSTALLER_PATH" 2>/dev/null || true""".replace("__CURL_TLS_OPT__", curl_tls_opt)

    script = f"""#!/usr/bin/env bash
set -euo pipefail

PANEL_URL=\"{bootstrap_for_script}\"
BOOTSTRAP_URL=\"{bootstrap_for_script}\"
{panel_candidates_assign}
NODE_ID=\"{node_id}\"
API_KEY=\"{api_key}\"

CURL_RETRY_ALL_ERRORS=\"\"
if curl --help all 2>/dev/null | grep -q -- '--retry-all-errors'; then
  CURL_RETRY_ALL_ERRORS=\"--retry-all-errors\"
fi

if [[ -z \"$BOOTSTRAP_URL\" ]]; then
  BOOTSTRAP_URL=\"$PANEL_URL\"
fi
if [[ -z \"$PANEL_URL\" && \"${{#PANEL_URL_CANDIDATES[@]}}\" -gt 0 ]]; then
  PANEL_URL=\"${{PANEL_URL_CANDIDATES[0]}}\"
fi
if [[ \"${{#PANEL_URL_CANDIDATES[@]}}\" -eq 0 && -n \"$PANEL_URL\" ]]; then
  PANEL_URL_CANDIDATES=(\"$PANEL_URL\")
fi

if [[ \"$(id -u)\" -ne 0 ]]; then
  if command -v sudo >/dev/null 2>&1; then
    echo \"[提示] 需要 root，自动尝试 sudo...\" >&2
    exec sudo -E bash -c \"curl {curl_tls_opt}-fL --retry 5 $CURL_RETRY_ALL_ERRORS --connect-timeout 10 -H \\\"X-Join-Token: {api_key}\\\" \\\"$BOOTSTRAP_URL/join\\\" -o /tmp/realm-join.sh && bash /tmp/realm-join.sh && rm -f /tmp/realm-join.sh\"
  fi
  echo \"[错误] 需要 root 权限运行，但系统未安装 sudo。请切换到 root 后重试（sudo -i / su -）。\" >&2
  exit 1
fi

install -d -m 700 /etc/realm-agent
umask 077

echo \"$API_KEY\" > /etc/realm-agent/api.key
chmod 600 /etc/realm-agent/api.key 2>/dev/null || true

echo \"[提示] 正在安装/更新 Realm Agent…\" >&2
INSTALLER_PATH=\"/tmp/realm-agent-installer-${{NODE_ID}}.sh\"
{installer_download_block}
export REALM_AGENT_FORCE_UPDATE=1
export REALM_AGENT_MODE=1
export REALM_AGENT_PORT={agent_port}
export REALM_AGENT_ASSUME_YES=1
export REALM_PANEL_URL=\"$PANEL_URL\"
export REALM_AGENT_ID=\"$NODE_ID\"
export REALM_AGENT_HEARTBEAT_INTERVAL=3
bash \"$INSTALLER_PATH\"
rm -f \"$INSTALLER_PATH\" || true
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

    request_base_url = str(request.base_url).rstrip("/")
    bootstrap_base_url = panel_bootstrap_base_url(request).rstrip("/")
    public_base_url = panel_public_base_url(request)
    panel_url_candidates = _unique_join_url_candidates(request_base_url, bootstrap_base_url, public_base_url)
    bootstrap_for_script = panel_url_candidates[0] if panel_url_candidates else bootstrap_base_url
    insecure_tls = panel_bootstrap_insecure_tls(default=True)
    curl_tls_opt = "-k " if insecure_tls else ""
    api_key = str(node.get("api_key"))

    script = f"""#!/usr/bin/env bash
set -euo pipefail

BOOTSTRAP_URL=\"{bootstrap_for_script}\"

CURL_RETRY_ALL_ERRORS=\"\"
if curl --help all 2>/dev/null | grep -q -- '--retry-all-errors'; then
  CURL_RETRY_ALL_ERRORS=\"--retry-all-errors\"
fi

if [[ \"$(id -u)\" -ne 0 ]]; then
  if command -v sudo >/dev/null 2>&1; then
    echo \"[提示] 需要 root，自动尝试 sudo...\" >&2
    exec sudo -E bash -c \"curl {curl_tls_opt}-fL --retry 5 $CURL_RETRY_ALL_ERRORS --connect-timeout 10 -H \\\"X-Join-Token: {api_key}\\\" \\\"$BOOTSTRAP_URL/uninstall\\\" -o /tmp/realm-uninstall.sh && bash /tmp/realm-uninstall.sh && rm -f /tmp/realm-uninstall.sh\"
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
