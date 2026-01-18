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
  apt-get install -y curl unzip jq python3 python3-venv python3-pip ca-certificates >/dev/null
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
  unzip -q "$zip_path" -d "$TMPDIR/extract"
  local panel_dir
  panel_dir="$(find "$TMPDIR/extract" -maxdepth 6 -type d -name panel -print -quit)"
  if [[ -z "$panel_dir" ]]; then
    err "找不到 panel 目录。请确认仓库里包含 panel/ 或 realm-pro-suite-vXX/panel/"
    err "建议仓库结构：仓库根目录/panel  或  仓库根目录/realm-pro-suite-v33/panel"
    exit 1
  fi
  echo "$panel_dir"
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

main(){
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

  local panel_dir
  panel_dir="$(extract_repo "$mode" "$zip_path")"
  ok "panel 目录：$panel_dir"

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
  cp -a "$panel_dir" /opt/realm-panel/panel

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

main "$@"
