#!/usr/bin/env bash
set -euo pipefail

VERSION="v33"
REPO_ZIP_URL_DEFAULT="https://github.com/cyeinfpro/Realm/archive/refs/heads/main.zip"

info(){ echo -e "\033[33m[提示]\033[0m $*" >&2; }
ok(){ echo -e "\033[32m[OK]\033[0m $*" >&2; }
err(){ echo -e "\033[31m[ERR]\033[0m $*" >&2; }
need_root(){
  if [[ "$(id -u)" -ne 0 ]]; then
    err "请使用 root 运行：sudo -i"
    exit 1
  fi
}

apt_install(){
  export DEBIAN_FRONTEND=noninteractive
  info "安装依赖..."
  apt-get update -y >/dev/null
  apt-get install -y curl unzip zip jq python3 python3-venv python3-pip ca-certificates >/dev/null
}

prompt(){
  local msg="$1"; local def="${2:-}"; local out
  if [[ -n "$def" ]]; then
    read -r -p "$msg (默认 $def): " out || true
    echo "${out:-$def}"
  else
    read -r -p "$msg: " out || true
    echo "$out"
  fi
}

TMPDIR=""
EXTRACT_ROOT=""
PANEL_DIR=""
cleanup(){
  if [[ -n "${TMPDIR}" && -d "${TMPDIR}" ]]; then
    rm -rf "${TMPDIR}" || true
  fi
}
trap cleanup EXIT

extract_repo(){
  local mode="$1"; local zip_path="$2"
  TMPDIR="$(mktemp -d)"
  if [[ "$mode" == "online" ]]; then
    local url="${REPO_ZIP_URL:-$REPO_ZIP_URL_DEFAULT}"
    info "正在下载仓库..."
    curl -fsSL "$url" -o "$TMPDIR/repo.zip"
    zip_path="$TMPDIR/repo.zip"
  else
    [[ -f "$zip_path" ]] || { err "ZIP 文件不存在：$zip_path"; exit 1; }
  fi
  info "解压中..."
  EXTRACT_ROOT="$TMPDIR/extract"
  unzip -q "$zip_path" -d "$EXTRACT_ROOT"
  PANEL_DIR="$(find "$EXTRACT_ROOT" -maxdepth 6 -type d -name panel -print -quit)"
  if [[ -z "$PANEL_DIR" ]]; then
    err "找不到 panel 目录。请确认仓库里包含 panel/ 或 realm-pro-suite-vXX/panel/"
    err "建议仓库结构：仓库根目录/panel  或  仓库根目录/realm-pro-suite-v33/panel"
    exit 1
  fi
}

find_agent_dir(){
  local base="$1"
  local agent_dir
  agent_dir="$(find "$base" -maxdepth 6 -type d -name agent -print -quit)"
  if [[ -z "$agent_dir" ]]; then
    err "找不到 agent 目录。请确认仓库里包含 agent/ 或 realm-pro-suite-vXX/agent/"
    err "建议仓库结构：仓库根目录/agent  或  仓库根目录/realm-pro-suite-v33/agent"
    exit 1
  fi
  echo "$agent_dir"
}

prepare_agent_bundle(){
  local extract_root="$1"
  local agent_dir
  agent_dir="$(find_agent_dir "$extract_root")"
  info "生成 Agent 离线包..."
  mkdir -p /opt/realm-panel/panel/static
  ( cd "$agent_dir/.." && zip -qr /opt/realm-panel/panel/static/realm-agent.zip "$(basename "$agent_dir")" )
  if [[ -f "/opt/realm-panel/panel/../realm_agent.sh" ]]; then
    cp -a "/opt/realm-panel/panel/../realm_agent.sh" /opt/realm-panel/panel/static/realm_agent.sh
  else
    local script_path
    script_path="$(find "$extract_root" -maxdepth 2 -type f -name realm_agent.sh -print -quit)"
    if [[ -n "$script_path" ]]; then
      cp -a "$script_path" /opt/realm-panel/panel/static/realm_agent.sh
    fi
  fi
  ok "Agent 离线包已就绪：/opt/realm-panel/panel/static/realm-agent.zip"
}

write_systemd(){
  local port="$1"
  cat > /etc/systemd/system/realm-panel.service <<EOF
[Unit]
Description=Realm Pro Panel
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
WorkingDirectory=/opt/realm-panel/panel
Environment=REALM_PANEL_DB=/etc/realm-panel/panel.db
ExecStart=/opt/realm-panel/venv/bin/uvicorn app.main:app --host 0.0.0.0 --port ${port} --workers 1
Restart=on-failure
RestartSec=2

[Install]
WantedBy=multi-user.target
EOF
}

install_panel(){
  need_root
  echo "Realm Pro Panel Installer ${VERSION}"
  echo "------------------------------------------------------------"
  echo "1) 在线安装（推荐）"
  echo "2) 离线安装（手动下载）"
  local choice
  choice="$(prompt "请选择安装模式 [1-2]" "1")"
  local mode="online"
  local zip_path=""
  if [[ "$choice" == "2" ]]; then
    mode="offline"
    zip_path="$(prompt "请输入 ZIP 文件路径（例如 /root/Realm-main.zip）" "")"
  fi

  apt_install

  extract_repo "$mode" "$zip_path"
  ok "panel 目录：$PANEL_DIR"

  local user pass port
  user="$(prompt "设置面板登录用户名" "admin")"
  while true; do
    pass="$(prompt "设置面板登录密码 (必填)" "")"
    [[ -n "$pass" ]] && break
    err "密码不能为空"
  done
  port="$(prompt "面板端口" "6080")"

  info "部署到 /opt/realm-panel ..."
  rm -rf /opt/realm-panel
  mkdir -p /opt/realm-panel
  cp -a "$PANEL_DIR" /opt/realm-panel/panel
  prepare_agent_bundle "$EXTRACT_ROOT"

  info "创建虚拟环境..."
  python3 -m venv /opt/realm-panel/venv
  /opt/realm-panel/venv/bin/pip install -U pip wheel >/dev/null
  /opt/realm-panel/venv/bin/pip install -r /opt/realm-panel/panel/requirements.txt >/dev/null

  info "初始化面板配置..."
  mkdir -p /etc/realm-panel
  export PANEL_USER="$user"
  export PANEL_PASS="$pass"
  ( cd /opt/realm-panel/panel && /opt/realm-panel/venv/bin/python - <<'PY'
import os
from app.auth import ensure_secret_key, save_credentials
ensure_secret_key()
save_credentials(os.environ['PANEL_USER'], os.environ['PANEL_PASS'])
print('OK')
PY
) 

  write_systemd "$port"
  systemctl daemon-reload
  systemctl enable realm-panel.service >/dev/null
  systemctl restart realm-panel.service

  ok "面板已启动"
  echo "访问: http://<你的IP>:${port}"
  echo "用户名: ${user}"
  echo "密码: (你刚刚输入的)"
}

update_panel(){
  need_root
  local mode="online"
  local zip_path=""
  echo "1) 在线更新（推荐）"
  echo "2) 离线更新（手动下载）"
  local choice
  choice="$(prompt "请选择更新模式 [1-2]" "1")"
  if [[ "$choice" == "2" ]]; then
    mode="offline"
    zip_path="$(prompt "请输入 ZIP 文件路径（例如 /root/Realm-main.zip）" "")"
  fi
  apt_install
  extract_repo "$mode" "$zip_path"
  ok "panel 目录：$PANEL_DIR"
  info "更新面板文件..."
  rm -rf /opt/realm-panel/panel
  mkdir -p /opt/realm-panel
  cp -a "$PANEL_DIR" /opt/realm-panel/panel
  prepare_agent_bundle "$EXTRACT_ROOT"
  info "更新依赖..."
  /opt/realm-panel/venv/bin/pip install -r /opt/realm-panel/panel/requirements.txt >/dev/null
  systemctl daemon-reload
  systemctl restart realm-panel.service
  ok "面板已更新并重启"
}

restart_panel(){
  need_root
  systemctl restart realm-panel.service
  ok "面板已重启"
}

uninstall_panel(){
  need_root
  systemctl disable --now realm-panel.service >/dev/null 2>&1 || true
  rm -f /etc/systemd/system/realm-panel.service
  systemctl daemon-reload
  rm -rf /opt/realm-panel /etc/realm-panel
  ok "面板已卸载"
}

main(){
  echo "Realm Pro Panel 管理 ${VERSION}"
  echo "------------------------------------------------------------"
  echo "1) 安装面板"
  echo "2) 更新面板"
  echo "3) 重启面板"
  echo "4) 卸载面板"
  local action
  action="$(prompt "请选择操作 [1-4]" "1")"
  case "$action" in
    1) install_panel ;;
    2) update_panel ;;
    3) restart_panel ;;
    4) uninstall_panel ;;
    *) err "无效选择"; exit 1 ;;
  esac
}

main "$@"
