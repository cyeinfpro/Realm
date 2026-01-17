#!/usr/bin/env bash
set -euo pipefail

# Realm Pro Panel Installer (stable)
# Repo raw base (your repo):
REPO_RAW_BASE="https://raw.githubusercontent.com/cyeinfpro/Realm/refs/heads/main"
# Repo archive (faster & fewer requests):
REPO_ARCHIVE_URL="https://github.com/cyeinfpro/Realm/archive/refs/heads/main.tar.gz"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
NC='\033[0m'

info(){ echo -e "${GREEN}[INFO]${NC} $*"; }
warn(){ echo -e "${YELLOW}[WARN]${NC} $*"; }
err(){ echo -e "${RED}[ERR ]${NC} $*"; }

need_root(){
  if [[ "$(id -u)" -ne 0 ]]; then
    err "请使用 root 运行：sudo bash $0"
    exit 1
  fi
}

apt_install(){
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -y
  apt-get install -y --no-install-recommends \
    ca-certificates curl git python3 python3-venv python3-pip \
    jq iproute2
}

fetch_repo(){
  local tmpdir
  tmpdir="$(mktemp -d)"
  info "拉取仓库源码（归档下载）..."
  curl -fsSL "$REPO_ARCHIVE_URL" -o "$tmpdir/repo.tar.gz"
  tar -xzf "$tmpdir/repo.tar.gz" -C "$tmpdir"

  local root
  root="$(find "$tmpdir" -maxdepth 1 -type d -name 'Realm-*' | head -n 1)"
  if [[ -z "${root:-}" ]]; then
    err "解压仓库失败"
    exit 1
  fi
  echo "$root"
}

pbkdf2_hash(){
  local pass="$1"
  P="$pass" python3 - <<'PY'
import os, hashlib
pwd = os.environ.get('P','')
salt = os.urandom(16)
iters = 200000
dk = hashlib.pbkdf2_hmac('sha256', pwd.encode('utf-8'), salt, iters)
print(f"pbkdf2_sha256${iters}${salt.hex()}${dk.hex()}")
PY
}

rand_secret(){
  python3 - <<'PY'
import secrets
print(secrets.token_urlsafe(32))
PY
}

find_panel_src(){
  local root="$1"

  # Preferred layout: repo_root/panel
  if [[ -d "$root/panel" ]]; then
    echo "$root/panel"
    return 0
  fi

  # Versioned layout: repo_root/realm-pro-suite-vXX/panel
  local candidate
  candidate="$(find "$root" -maxdepth 4 -type d -path '*/realm-pro-suite-v*/panel' 2>/dev/null | sort -V | tail -n 1)"
  if [[ -n "${candidate:-}" && -d "$candidate" ]]; then
    echo "$candidate"
    return 0
  fi

  # Any nested panel folder (last resort)
  candidate="$(find "$root" -maxdepth 6 -type d -name panel 2>/dev/null | head -n 1)"
  if [[ -n "${candidate:-}" && -d "$candidate" ]]; then
    echo "$candidate"
    return 0
  fi

  return 1
}

main(){
  need_root
  info "Realm Pro Panel 安装开始"

  apt_install

  read -r -p "面板监听端口 (默认 18750): " PANEL_PORT
  PANEL_PORT="${PANEL_PORT:-18750}"

  echo
  read -r -p "设置面板登录用户名 (默认 admin): " ADMIN_USER
  ADMIN_USER="${ADMIN_USER:-admin}"

  while true; do
    read -r -s -p "设置面板登录密码 (必填): " ADMIN_PASS
    echo
    if [[ -n "${ADMIN_PASS:-}" ]]; then
      break
    fi
    echo "密码不能为空，请重新输入。"
  done

  local ADMIN_PASS_HASH
  ADMIN_PASS_HASH="$(pbkdf2_hash "$ADMIN_PASS")"

  local PANEL_SECRET_KEY
  PANEL_SECRET_KEY="$(rand_secret)"

  local repo_root
  repo_root="$(fetch_repo)"

  local panel_src
  if ! panel_src="$(find_panel_src "$repo_root")"; then
    err "找不到 panel 目录。请确认仓库里包含 panel/ 或 realm-pro-suite-vXX/panel/"
    err "建议仓库结构：仓库根目录/panel  或  仓库根目录/realm-pro-suite-v16/panel"
    exit 1
  fi

  info "使用面板源码路径：$panel_src"

  info "写入面板文件到 /opt/realm-panel"
  rm -rf /opt/realm-panel
  mkdir -p /opt/realm-panel
  cp -a "$panel_src"/* /opt/realm-panel/

  info "创建环境文件 /etc/realm-panel/panel.env"
  mkdir -p /etc/realm-panel

  cat > /etc/realm-panel/panel.env <<ENV
REALM_PANEL_HOST=0.0.0.0
REALM_PANEL_PORT=$PANEL_PORT
REALM_PANEL_DB=/etc/realm-panel/panel.db
REALM_REPO_RAW_BASE=$REPO_RAW_BASE
PANEL_AUTH_ENABLED=1
PANEL_ADMIN_USER=$ADMIN_USER
PANEL_ADMIN_PASS_HASH=$ADMIN_PASS_HASH
PANEL_SECRET_KEY=$PANEL_SECRET_KEY
ENV

  info "创建 Python venv"
  python3 -m venv /opt/realm-panel/venv
  /opt/realm-panel/venv/bin/pip install -U pip
  /opt/realm-panel/venv/bin/pip install -r /opt/realm-panel/requirements.txt

  info "安装 systemd 服务"
  cp /opt/realm-panel/systemd/realm-panel.service /etc/systemd/system/realm-panel.service
  systemctl daemon-reload
  systemctl enable realm-panel.service
  systemctl restart realm-panel.service

  info "安装完成"
  local ip
  ip="$(hostname -I 2>/dev/null | awk '{print $1}')"
  echo
  echo "面板地址: http://${ip}:${PANEL_PORT}"
  echo "面板服务: systemctl status realm-panel --no-pager"
  echo
  echo "登录账号: ${ADMIN_USER}"
  echo "登录密码: (安装时输入的密码)"
}

main "$@"
