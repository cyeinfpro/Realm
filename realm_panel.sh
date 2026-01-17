#!/usr/bin/env bash
set -euo pipefail

# Realm Pro Panel Installer v15
# Repo raw base (change this to your own repo):
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
  if [[ -z "$root" ]]; then
    err "解压仓库失败"
    exit 1
  fi
  echo "$root"
}

main(){
  need_root
  info "Realm Pro Panel v15 安装开始"
  apt_install

  read -r -p "面板监听端口 (默认 18750): " PANEL_PORT
  PANEL_PORT="${PANEL_PORT:-18750}"

  echo
  read -r -p "设置面板登录用户名 (默认 admin): " ADMIN_USER
  ADMIN_USER="${ADMIN_USER:-admin}"
  while true; do
    read -r -s -p "设置面板登录密码 (必填): " ADMIN_PASS
    echo
    if [[ -n "$ADMIN_PASS" ]]; then
      break
    fi
    echo "密码不能为空，请重新输入。"
  done

  # Generate password hash using PBKDF2-SHA256
  ADMIN_PASS_HASH=$(P="$ADMIN_PASS" python3 - <<'PY'
import os, hashlib
pwd = os.environ.get('P','')
salt = os.urandom(16)
iters = 200000
dk = hashlib.pbkdf2_hmac('sha256', pwd.encode(), salt, iters)
print(f"pbkdf2_sha256${iters}${salt.hex()}${dk.hex()}")
PY
)
  PANEL_SECRET_KEY=$(python3 - <<'PY'
import secrets
print(secrets.token_hex(32))
PY
)

  local repo_root
  repo_root="$(fetch_repo)"

  if [[ ! -d "$repo_root/realm-pro-suite-v15/panel" ]]; then
    err "找不到 realm-pro-suite-v15/panel 目录。请确认你已将 v15 文件包上传到仓库。"
    err "预期路径：仓库根目录/realm-pro-suite-v15/panel"
    exit 1
  fi

  info "写入面板文件到 /opt/realm-panel"
  rm -rf /opt/realm-panel
  mkdir -p /opt/realm-panel
  cp -r "$repo_root/realm-pro-suite-v15/panel"/* /opt/realm-panel/

  info "创建环境文件 /etc/realm-panel/panel.env"
  mkdir -p /etc/realm-panel

  # 生成面板密码哈希 (pbkdf2_sha256$iterations$salt_hex$hash_hex)
  ADMIN_PASS_HASH="$(PANEL_PWD="$ADMIN_PASS" python3 - <<'PY'
import os, hashlib
pwd = os.environ.get("PANEL_PWD", "")
salt = os.urandom(16)
it = 200000
dk = hashlib.pbkdf2_hmac("sha256", pwd.encode("utf-8"), salt, it)
print(f"pbkdf2_sha256${it}${salt.hex()}${dk.hex()}")
PY
)"

  # Session cookie signing key
  PANEL_SECRET_KEY="$(python3 - <<'PY'
import secrets
print(secrets.token_urlsafe(32))
PY
)"
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
  echo -e "面板地址: http://${ip}:${PANEL_PORT}"
  echo -e "面板服务: systemctl status realm-panel --no-pager"
  echo
  echo -e "登录账号: ${ADMIN_USER}"
  echo -e "登录密码: (安装时输入的密码)"
  echo -e "说明: 面板访问需要登录；Agent 对接仍使用 Token。"
}

main "$@"
