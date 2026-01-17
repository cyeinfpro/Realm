#!/usr/bin/env bash
set -euo pipefail

# Realm Pro Agent v14
# 你的仓库 RAW 地址（你给的）：
# https://raw.githubusercontent.com/cyeinfpro/Realm/refs/heads/main
# 如果你未来更换仓库或分支，只需替换这一行。
REPO_RAW_BASE="https://raw.githubusercontent.com/cyeinfpro/Realm/refs/heads/main"

AGENT_DIR="/opt/realm-agent"
AGENT_ETC="/etc/realm-agent"
AGENT_PORT_DEFAULT="18700"

is_root() { [ "$(id -u)" = "0" ]; }
say() { echo "[Realm-Agent] $*"; }

install_deps() {
  say "安装依赖..."
  apt-get update -y >/dev/null
  apt-get install -y curl ca-certificates python3 python3-venv python3-pip jq openssl net-tools >/dev/null
}

ensure_dirs() {
  mkdir -p "$AGENT_DIR" "$AGENT_ETC"
}

fetch_or_copy_agent_files() {
  local mode="$1"
  ensure_dirs
  rm -rf "$AGENT_DIR/app" "$AGENT_DIR/start.sh" "$AGENT_DIR/requirements.txt"
  mkdir -p "$AGENT_DIR/app"

  if [ "$mode" = "local" ]; then
    local script_dir
    script_dir="$(cd "$(dirname "$0")" && pwd)"
    cp -r "$script_dir/agent/app"/* "$AGENT_DIR/app/"
    cp "$script_dir/agent/requirements.txt" "$AGENT_DIR/requirements.txt"
    cp "$script_dir/agent/start.sh" "$AGENT_DIR/start.sh"
  else
    curl -fsSL "$REPO_RAW_BASE/agent/requirements.txt" -o "$AGENT_DIR/requirements.txt"
    curl -fsSL "$REPO_RAW_BASE/agent/start.sh" -o "$AGENT_DIR/start.sh"
    # python files
    for f in config.py models.py storage.py realmctl.py main.py; do
      curl -fsSL "$REPO_RAW_BASE/agent/app/$f" -o "$AGENT_DIR/app/$f"
    done
  fi

  chmod +x "$AGENT_DIR/start.sh"
}

setup_venv() {
  say "创建 Python 虚拟环境..."
  python3 -m venv "$AGENT_DIR/venv"
  "$AGENT_DIR/venv/bin/pip" install -U pip >/dev/null
  "$AGENT_DIR/venv/bin/pip" install -r "$AGENT_DIR/requirements.txt" >/dev/null
}

install_systemd() {
  say "安装 systemd 服务..."
  if [ -f "$(dirname "$0")/agent/systemd/realm-agent.service" ]; then
    cp "$(dirname "$0")/agent/systemd/realm-agent.service" /etc/systemd/system/realm-agent.service
  else
    curl -fsSL "$REPO_RAW_BASE/agent/systemd/realm-agent.service" -o /etc/systemd/system/realm-agent.service
  fi
  systemctl daemon-reload
  systemctl enable realm-agent.service >/dev/null
}

prompt_pairing() {
  echo ""
  echo "================= Agent 配对到 Panel ================="
  echo "说明：先在面板里生成 6 位配对码，然后在此处填写。"
  echo "====================================================="
  read -r -p "Panel 地址（例如 http://1.2.3.4:18750 ）: " panel_url
  read -r -p "配对码（6位数字）: " pair_code
  read -r -p "Agent 名称（回车=默认主机名）: " agent_name
  agent_name="${agent_name:-$(hostname)}"

  # 自动推断本机可访问的 Agent API URL
  read -r -p "Agent API 对外地址（回车=自动： http://本机IP:${AGENT_PORT_DEFAULT} ）: " agent_api
  if [ -z "${agent_api}" ]; then
    local ip
    ip="$(hostname -I 2>/dev/null | awk '{print $1}')"
    ip="${ip:-127.0.0.1}"
    agent_api="http://${ip}:${AGENT_PORT_DEFAULT}"
  fi

  say "向 Panel 申请 Token..."
  local resp
  resp="$(curl -fsSL -X POST "$panel_url/api/pair/claim" \
    -H 'Content-Type: application/json' \
    -d "{\"code\":\"$pair_code\",\"agent_name\":\"$agent_name\",\"api_url\":\"$agent_api\"}")"

  local token agent_id
  token="$(echo "$resp" | jq -r '.token // empty')"
  agent_id="$(echo "$resp" | jq -r '.agent_id // empty')"

  if [ -z "$token" ] || [ -z "$agent_id" ]; then
    echo "$resp" | sed -n '1,120p'
    say "配对失败：请确认 Panel 地址和配对码是否正确"
    return 1
  fi

  mkdir -p "$AGENT_ETC"
  cat > "$AGENT_ETC/agent.env" <<EOF
REALM_AGENT_TOKEN=$token
REALM_AGENT_ID=$agent_id
REALM_PANEL_URL=$panel_url
REALM_AGENT_PORT=$AGENT_PORT_DEFAULT
REALM_AGENT_DATA_DIR=$AGENT_ETC
EOF

  say "配对成功：AgentID=$agent_id"
}

start_agent() {
  systemctl restart realm-agent.service
  systemctl status realm-agent.service --no-pager || true
}

uninstall_agent() {
  say "卸载 Agent..."
  systemctl stop realm-agent.service >/dev/null 2>&1 || true
  systemctl disable realm-agent.service >/dev/null 2>&1 || true
  rm -f /etc/systemd/system/realm-agent.service
  systemctl daemon-reload || true
  rm -rf "$AGENT_DIR"
  rm -rf "$AGENT_ETC"
  say "完成"
}

install_or_update() {
  local mode="remote"
  if [ "${1:-}" = "--local" ]; then
    mode="local"
  fi

  install_deps
  fetch_or_copy_agent_files "$mode"
  setup_venv
  install_systemd

  if [ ! -f "$AGENT_ETC/agent.env" ]; then
    prompt_pairing
  else
    say "检测到已有配对配置：$AGENT_ETC/agent.env（如需重新配对，选择菜单里的重新配对）"
  fi

  start_agent
  local ip
  ip="$(hostname -I 2>/dev/null | awk '{print $1}')"
  ip="${ip:-127.0.0.1}"
  say "Agent API： http://${ip}:${AGENT_PORT_DEFAULT}"
}

show_status() {
  systemctl status realm-agent.service --no-pager || true
}

main_menu() {
  if ! is_root; then
    say "请使用 root 运行：sudo bash realm_agent.sh"
    exit 1
  fi

  while true; do
    echo ""
    echo "================== Realm Pro Agent v14 =================="
    echo "1) 安装 / 更新（在线从仓库拉取）"
    echo "2) 安装 / 更新（本地文件）"
    echo "3) 查看服务状态"
    echo "4) 查看最近日志"
    echo "5) 重新配对到 Panel"
    echo "6) 卸载"
    echo "0) 退出"
    echo "========================================================="
    read -r -p "> " choice

    case "$choice" in
      1) install_or_update ;;
      2) install_or_update --local ;;
      3) show_status ;;
      4) journalctl -u realm-agent.service -n 120 --no-pager || true ;;
      5) prompt_pairing && start_agent ;;
      6) uninstall_agent ;;
      0) exit 0 ;;
      *) echo "无效选择" ;;
    esac
  done
}

main_menu
