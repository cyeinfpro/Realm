#!/usr/bin/env bash
set -euo pipefail

VERSION="v31"
REPO_ZIP_URL_DEFAULT="https://github.com/cyeinfpro/Realm/archive/refs/heads/main.zip"
DEFAULT_MODE="1"
DEFAULT_PORT="18700"

info(){ printf "[提示] %s\n" "$*"; }
ok(){ printf "[OK] %s\n" "$*"; }
err(){ printf "[ERR ] %s\n" "$*" >&2; }

need_root(){
  if [[ "$(id -u)" -ne 0 ]]; then
    err "请使用 root 运行：sudo -i"
    exit 1
  fi
}

apt_install(){
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -y
  apt-get install -y curl ca-certificates unzip jq python3 python3-venv python3-pip
}

ask(){
  local prompt="$1" default="$2" var
  if [[ "${REALM_AGENT_ASSUME_YES:-}" == "1" ]]; then
    echo "${default}"
    return
  fi
  if [[ ! -t 0 ]]; then
    echo "${default}"
    return
  fi
  read -r -p "$prompt" var || true
  if [[ -z "${var}" ]]; then echo "${default}"; else echo "$var"; fi
}

fetch_repo(){
  local mode="$1"
  local tmpdir="$2"
  local zip_path=""

  if [[ "${mode}" == "2" ]]; then
    zip_path="${REALM_AGENT_ZIP_PATH:-}"
    if [[ -z "${zip_path}" ]]; then
      zip_path=$(ask "请输入 ZIP 文件路径（例如 /root/Realm-main.zip）: " "")
    fi
    if [[ -z "${zip_path}" || ! -f "${zip_path}" ]]; then
      err "ZIP 文件不存在：${zip_path}"
      exit 1
    fi
    info "使用离线 ZIP：${zip_path}"
    unzip -q "${zip_path}" -d "${tmpdir}"
  else
    local url
    url="${REALM_AGENT_REPO_ZIP_URL:-}"
    if [[ -z "${url}" ]]; then
      url=$(ask "仓库 ZIP 下载地址（回车=默认）: " "${REPO_ZIP_URL_DEFAULT}")
    fi
    info "正在下载仓库..."
    curl -fsSL "${url}" -o "${tmpdir}/repo.zip"
    info "解压中..."
    unzip -q "${tmpdir}/repo.zip" -d "${tmpdir}"
  fi
}

find_agent_dir(){
  local base="$1"
  local p
  p=$(find "${base}" -maxdepth 5 -type d -name agent -print | head -n 1 || true)
  if [[ -z "${p}" ]]; then
    err "找不到 agent 目录。请确认仓库里包含 agent/ 或 realm-pro-suite-vXX/agent/"
    err "建议仓库结构：仓库根目录/agent  或  仓库根目录/realm-pro-suite-v31/agent"
    exit 1
  fi
  echo "${p}"
}

restart_service(){
  local svc="$1"
  systemctl daemon-reload
  systemctl enable --now "${svc}" >/dev/null 2>&1 || systemctl restart "${svc}" >/dev/null 2>&1
}

main(){
  need_root

  echo "Realm Pro Agent Installer ${VERSION}"
  echo "------------------------------------------------------------"
  echo "1) 在线安装（推荐）"
  echo "2) 离线安装（手动下载）"
  local mode
  mode="${REALM_AGENT_MODE:-}"
  if [[ -z "${mode}" ]]; then
    mode=$(ask "请选择安装模式 [1-2] (默认 1): " "${DEFAULT_MODE}")
  fi

  local port
  port="${REALM_AGENT_PORT:-}"
  if [[ -z "${port}" ]]; then
    port=$(ask "Agent 端口 (默认 18700): " "${DEFAULT_PORT}")
  fi

  info "安装依赖..."
  apt_install

  local tmpdir
  tmpdir=$(mktemp -d)
  cleanup(){ rm -rf "${tmpdir}"; }
  trap cleanup EXIT

  fetch_repo "${mode}" "${tmpdir}"

  local agent_dir
  agent_dir=$(find_agent_dir "${tmpdir}")
  ok "agent 目录：${agent_dir}"

  info "部署到 /opt/realm-agent ..."
  mkdir -p /opt/realm-agent
  rm -rf /opt/realm-agent/agent
  cp -a "${agent_dir}" /opt/realm-agent/agent

  info "创建虚拟环境..."
  python3 -m venv /opt/realm-agent/venv
  /opt/realm-agent/venv/bin/pip install -U pip wheel setuptools >/dev/null
  /opt/realm-agent/venv/bin/pip install -r /opt/realm-agent/agent/requirements.txt >/dev/null

  info "生成 API Key..."
  mkdir -p /etc/realm-agent
  if [[ ! -f /etc/realm-agent/api.key ]]; then
    head -c 32 /dev/urandom | xxd -p -c 32 > /etc/realm-agent/api.key
  fi
  local api_key
  api_key=$(cat /etc/realm-agent/api.key)

  # jq filter
  mkdir -p /etc/realm
  if [[ -f /opt/realm-agent/agent/pool_to_run.jq ]]; then
    cp -a /opt/realm-agent/agent/pool_to_run.jq /etc/realm/pool_to_run.jq
  fi

  info "创建 systemd 服务..."
  cat > /etc/systemd/system/realm-agent.service <<EOF
[Unit]
Description=Realm Pro Agent API Service
After=network.target

[Service]
Type=simple
WorkingDirectory=/opt/realm-agent/agent
ExecStart=/opt/realm-agent/venv/bin/uvicorn app.main:app --host 0.0.0.0 --port ${port} --workers 1
Restart=always
RestartSec=2

[Install]
WantedBy=multi-user.target
EOF

  restart_service realm-agent.service

  ok "Agent 已安装并启动"
  echo "- Agent URL:   http://$(hostname -I 2>/dev/null | awk '{print $1}'):${port}"
  echo "- API Key:     ${api_key}"
  echo "- Service:     systemctl status realm-agent --no-pager"
}

main "$@"
