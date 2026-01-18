#!/usr/bin/env bash
set -euo pipefail

# Realm Agent Installer (v30)

INSTALL_ROOT="/opt/realm-agent"
ENV_FILE="$INSTALL_ROOT/.env"
SERVICE_FILE="/etc/systemd/system/realm-agent.service"

DEFAULT_REPO_ZIP_URL="https://github.com/Liangcye/Realm/archive/refs/heads/main.zip"
REPO_ZIP_URL="${REPO_ZIP_URL:-$DEFAULT_REPO_ZIP_URL}"

say(){ echo -e "[RealmAgent] $*"; }
err(){ echo -e "[RealmAgent][ERR] $*" >&2; }

need_root(){
  if [[ "$(id -u)" -ne 0 ]]; then
    err "请使用 root 运行。"; exit 1
  fi
}

choose_mode(){
  echo "Realm Pro Agent Installer v30"
  echo "------------------------------------------------------------"
  echo "1) 在线安装（推荐）"
  echo "2) 离线安装（手动下载）"
  read -r -p "请选择安装模式 [1-2] (默认 1): " mode
  mode="${mode:-1}"
  if [[ "$mode" != "1" && "$mode" != "2" ]]; then
    err "无效选择"; exit 1
  fi
  echo "$mode"
}

fetch_repo(){
  local mode="$1"
  local tmp
  tmp="$(mktemp -d)"

  if [[ "$mode" == "1" ]]; then
    say "正在下载仓库..."
    if ! command -v curl >/dev/null 2>&1; then
      apt-get update -y && apt-get install -y curl
    fi
    local zip="$tmp/repo.zip"
    curl -fsSL "$REPO_ZIP_URL" -o "$zip"
    say "解压中..."
    apt-get update -y >/dev/null 2>&1 || true
    apt-get install -y unzip >/dev/null 2>&1 || true
    unzip -q "$zip" -d "$tmp"
  else
    echo "\n离线安装说明："
    echo "1) 请在可联网的机器下载仓库 zip："
    echo "   $REPO_ZIP_URL"
    echo "2) 上传到本机 /root/realm_repo.zip"
    echo "3) 然后回到这里继续"
    read -r -p "已放好 /root/realm_repo.zip？(回车继续) " _
    if [[ ! -f /root/realm_repo.zip ]]; then
      err "未找到 /root/realm_repo.zip"; exit 1
    fi
    apt-get update -y >/dev/null 2>&1 || true
    apt-get install -y unzip >/dev/null 2>&1 || true
    unzip -q /root/realm_repo.zip -d "$tmp"
  fi

  echo "$tmp"
}

find_agent_dir(){
  local tmp="$1"
  local agent_dir=""
  if [[ -d "$tmp/agent" ]]; then
    agent_dir="$tmp/agent"
  else
    agent_dir="$(find "$tmp" -maxdepth 3 -type d -name agent | head -n 1 || true)"
  fi
  if [[ -z "$agent_dir" || ! -f "$agent_dir/requirements.txt" ]]; then
    err "找不到 agent 目录。请确认仓库里包含 agent/ 目录。"
    err "建议结构：仓库根目录/agent  或  仓库根目录/realm-pro-suite-vXX/agent"
    exit 1
  fi
  echo "$agent_dir"
}

install_deps(){
  say "安装系统依赖..."
  apt-get update -y >/dev/null 2>&1 || true
  apt-get install -y python3 python3-venv python3-pip jq iproute2 >/dev/null 2>&1 || true
}

setup_agent(){
  local agent_src="$1"
  say "部署到 $INSTALL_ROOT ..."
  mkdir -p "$INSTALL_ROOT"
  rm -rf "$INSTALL_ROOT/agent"
  cp -a "$agent_src" "$INSTALL_ROOT/agent"

  say "创建虚拟环境..."
  python3 -m venv "$INSTALL_ROOT/venv"
  "$INSTALL_ROOT/venv/bin/pip" -q install --upgrade pip
  "$INSTALL_ROOT/venv/bin/pip" -q install -r "$INSTALL_ROOT/agent/requirements.txt"

  local api_key
  api_key="${AGENT_API_KEY:-}"
  if [[ -z "$api_key" ]]; then
    read -r -p "设置 Agent API Key（回车=随机生成）: " api_key
    api_key="${api_key:-}"
  fi
  if [[ -z "$api_key" ]]; then
    api_key="$($INSTALL_ROOT/venv/bin/python - <<'PY'
import secrets
print(secrets.token_urlsafe(24))
PY
)"
  fi

  read -r -p "Agent 端口 (默认 18700): " port
  port="${port:-18700}"

  cat > "$ENV_FILE" <<EOF
AGENT_PORT=$port
AGENT_API_KEY=$api_key
EOF

  cat > "$SERVICE_FILE" <<'EOF'
[Unit]
Description=Realm Agent API Service
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
EnvironmentFile=/opt/realm-agent/.env
WorkingDirectory=/opt/realm-agent/agent
ExecStart=/opt/realm-agent/venv/bin/python -m uvicorn app.main:app --host 0.0.0.0 --port $AGENT_PORT
Restart=always
RestartSec=2

[Install]
WantedBy=multi-user.target
EOF

  systemctl daemon-reload
  systemctl enable --now realm-agent

  say "安装完成！"
  echo "------------------------------------------------------------"
  echo "Agent 已启动：systemctl status realm-agent --no-pager"
  echo "API 地址: http://<本机IP>:$port"
  echo "API Key : $api_key"
  echo "------------------------------------------------------------"
}

main(){
  need_root
  local mode tmp agent_dir
  mode="$(choose_mode)"
  tmp="$(fetch_repo "$mode")"
  agent_dir="$(find_agent_dir "$tmp")"

  install_deps
  setup_agent "$agent_dir"
}

main "$@"
