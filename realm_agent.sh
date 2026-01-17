#!/usr/bin/env bash
set -euo pipefail

# Realm Pro Agent Installer (v18.1)
# Repo: https://github.com/cyeinfpro/Realm

REPO_OWNER="cyeinfpro"
REPO_NAME="Realm"
REPO_BRANCH="main"

ARCHIVE_URL="https://github.com/${REPO_OWNER}/${REPO_NAME}/archive/refs/heads/${REPO_BRANCH}.tar.gz"

AGENT_HOME="/opt/realm-agent"
ETC_DIR="/etc/realm-agent"

# Log helpers - send to STDERR to keep stdout clean (command substitution safe)
_red(){ echo -e "\033[31m$*\033[0m" >&2; }
_green(){ echo -e "\033[32m$*\033[0m" >&2; }
_yellow(){ echo -e "\033[33m$*\033[0m" >&2; }

need_root(){
  if [[ $EUID -ne 0 ]]; then
    _red "[ERR] 请用 root 运行：sudo bash realm_agent.sh"
    exit 1
  fi
}

pick_source(){
  local tmp
  tmp="$(mktemp -d)"
  # Capture value now; otherwise EXIT trap may run when local var is unset under `set -u`
  trap "rm -rf '$tmp'" EXIT

  _yellow "[1/6] 下载 Agent 文件..."
  curl -fsSL "$ARCHIVE_URL" -o "${tmp}/src.tgz"
  tar -xzf "${tmp}/src.tgz" -C "$tmp"

  local root
  root="$(find "$tmp" -maxdepth 4 -type f -path '*/agent/requirements.txt' -print -quit | sed 's|/agent/requirements.txt||')"
  if [[ -z "$root" || ! -d "$root/agent" ]]; then
    _red "[ERR] 找不到 agent 目录。请确认仓库里包含 agent/requirements.txt"
    _red "[ERR] 当前下载：$ARCHIVE_URL"
    exit 1
  fi
  echo "$root"
}

ensure_realm(){
  if command -v realm >/dev/null 2>&1; then
    return 0
  fi
  _yellow "[2/6] 未检测到 realm 二进制，尝试安装..."
  # Best effort install (Debian)
  apt-get update -y >/dev/null
  apt-get install -y curl ca-certificates >/dev/null
  # Try GitHub release
  local url
  url="https://github.com/zhboner/realm/releases/latest/download/realm-x86_64-unknown-linux-gnu.tar.gz"
  mkdir -p /tmp/realm-install
  curl -fsSL "$url" -o /tmp/realm-install/realm.tgz || true
  if [[ -f /tmp/realm-install/realm.tgz ]]; then
    tar -xzf /tmp/realm-install/realm.tgz -C /tmp/realm-install
    if [[ -f /tmp/realm-install/realm ]]; then
      install -m 0755 /tmp/realm-install/realm /usr/local/bin/realm
      _green "[OK] realm 已安装到 /usr/local/bin/realm"
      return 0
    fi
  fi
  _yellow "[WARN] realm 安装失败（可忽略），你也可以自行安装 realm"
}

install_agent(){
  local src_root="$1"

  mkdir -p "$AGENT_HOME" "$ETC_DIR" /var/log/realm-agent

  _yellow "[3/6] 拷贝 Agent 文件到 $AGENT_HOME ..."
  rm -rf "$AGENT_HOME/agent"
  cp -a "$src_root/agent" "$AGENT_HOME/agent"

  _yellow "[4/6] 创建 Python 虚拟环境并安装依赖..."
  apt-get update -y >/dev/null
  apt-get install -y python3 python3-venv python3-pip ca-certificates curl iproute2 >/dev/null

  python3 -m venv "$AGENT_HOME/venv"
  "$AGENT_HOME/venv/bin/pip" -q install --upgrade pip
  "$AGENT_HOME/venv/bin/pip" -q install -r "$AGENT_HOME/agent/requirements.txt"

  _yellow "[5/6] 写入配置 & Systemd 服务..."
  chmod 700 "$ETC_DIR"

  local port public_host token
  read -rp "Agent 端口 (默认 18700) > " port
  port="${port:-18700}"

  read -rp "此机器外网域名/IP (用于生成 WSS 配对参数，可留空自动探测) > " public_host
  if [[ -z "$public_host" ]]; then
    public_host="$(ip -4 route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="src") print $(i+1)}' | head -n1)"
    public_host="${public_host:-127.0.0.1}"
  fi

  token="$(python3 - <<'PY'
import secrets
print(secrets.token_urlsafe(32))
PY
)"

  mkdir -p "$ETC_DIR"
  cat > "$ETC_DIR/env" <<ENV
AGENT_PORT=${port}
ENV
  chmod 600 "$ETC_DIR/env"

  cat > "$ETC_DIR/config.json" <<JSON
{
  "token": "${token}",
  "public_host": "${public_host}"
}
JSON
  chmod 600 "$ETC_DIR/config.json"

  # rules file init
  if [[ ! -f "$ETC_DIR/rules.json" ]]; then
    echo '[]' > "$ETC_DIR/rules.json"
    chmod 600 "$ETC_DIR/rules.json"
  fi

  cp -a "$AGENT_HOME/agent/systemd/realm-agent.service" /etc/systemd/system/realm-agent.service

  systemctl daemon-reload
  systemctl enable realm-agent --now

  _yellow "[6/6] 启动检查..."
  sleep 1
  if systemctl is-active --quiet realm-agent; then
    _green "[OK] Agent 已启动"
  else
    _red "[ERR] Agent 启动失败，请查看：journalctl -u realm-agent -n 120 --no-pager"
    exit 1
  fi

  _green "\nAgent API:  http://<服务器IP>:${port}"
  _green "Token:      ${token}"
  _green "PublicHost: ${public_host}"
  _yellow "把上面的 Agent 地址 + Token 填到面板里即可管理此节点。"
}

main(){
  need_root
  local root
  root="$(pick_source)"
  ensure_realm || true
  install_agent "$root"
}

main "$@"
