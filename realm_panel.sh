#!/usr/bin/env bash
set -euo pipefail

# Realm Pro Panel Installer (v30)
# Supports online (download repo zip) and offline (use local directory / provided zip).

PANEL_DIR_NAME="panel"
INSTALL_ROOT="/opt/realm-panel"
ENV_FILE="$INSTALL_ROOT/.env"
SERVICE_FILE="/etc/systemd/system/realm-panel.service"

# Default repository zip (override with env REPO_ZIP_URL)
DEFAULT_REPO_ZIP_URL="https://github.com/Liangcye/Realm/archive/refs/heads/main.zip"
REPO_ZIP_URL="${REPO_ZIP_URL:-$DEFAULT_REPO_ZIP_URL}"

_red(){ echo -e "\033[31m$*\033[0m"; }
_grn(){ echo -e "\033[32m$*\033[0m"; }
_yel(){ echo -e "\033[33m$*\033[0m"; }
_cyan(){ echo -e "\033[36m$*\033[0m"; }

need_root(){
  if [[ "${EUID:-$(id -u)}" != "0" ]]; then
    _red "[ERR ] 请使用 root 运行此脚本"
    exit 1
  fi
}

pause(){ read -r -p "按回车继续..." _ || true; }

read_secret(){
  local prompt="$1";
  local v="";
  while true; do
    read -r -s -p "$prompt" v || true
    echo
    [[ -n "$v" ]] && break
    _yel "密码不能为空，请重新输入。"
  done
  echo "$v"
}

choose_mode(){
  echo "Realm Pro Panel Installer v30"
  echo "------------------------------------------------------------"
  echo "1) 在线安装（推荐）"
  echo "2) 离线安装（手动下载）"
  read -r -p "请选择安装模式 [1-2] (默认 1): " mode || true
  mode="${mode:-1}"
  if [[ "$mode" != "1" && "$mode" != "2" ]]; then
    mode="1"
  fi
  echo "$mode"
}

prepare_source_online(){
  local tmp
  tmp="$(mktemp -d)"
  _cyan "[提示] 正在下载仓库..."
  if ! command -v curl >/dev/null 2>&1; then
    apt-get update -y >/dev/null 2>&1 || true
    apt-get install -y curl >/dev/null 2>&1
  fi
  if ! command -v unzip >/dev/null 2>&1; then
    apt-get update -y >/dev/null 2>&1 || true
    apt-get install -y unzip >/dev/null 2>&1
  fi

  local zip="$tmp/repo.zip"
  curl -fsSL -o "$zip" "$REPO_ZIP_URL" || {
    _red "[ERR ] 下载失败：$REPO_ZIP_URL"
    _yel "       你可以通过：export REPO_ZIP_URL=... 重新指定仓库 zip 链接"
    exit 1
  }

  _cyan "[提示] 解压中..."
  unzip -q "$zip" -d "$tmp"

  # Find panel dir
  local panel_path
  panel_path="$(find "$tmp" -maxdepth 3 -type d -name "$PANEL_DIR_NAME" | head -n 1 || true)"
  if [[ -z "$panel_path" ]]; then
    _red "[ERR ] 找不到 panel 目录。请确认仓库里包含 panel/ 或 <repo>/panel/"
    _yel "[ERR ] 建议仓库结构：仓库根目录/panel"
    exit 1
  fi

  echo "$panel_path"
}

prepare_source_offline(){
  echo "Realm Pro Panel Installer v30"
  echo "------------------------------------------------------------"
  _yel "离线安装说明："
  echo "1) 请手动下载你的仓库 ZIP（或把本套件上传到服务器本地）"
  echo "2) 需要包含 panel/ 目录"
  echo
  read -r -p "请输入 ZIP 文件路径（例如 /root/Realm-main.zip）: " zip_path
  if [[ ! -f "$zip_path" ]]; then
    _red "[ERR ] 文件不存在：$zip_path"
    exit 1
  fi
  if ! command -v unzip >/dev/null 2>&1; then
    apt-get update -y >/dev/null 2>&1 || true
    apt-get install -y unzip >/dev/null 2>&1
  fi
  local tmp
  tmp="$(mktemp -d)"
  unzip -q "$zip_path" -d "$tmp"

  local panel_path
  panel_path="$(find "$tmp" -maxdepth 3 -type d -name "$PANEL_DIR_NAME" | head -n 1 || true)"
  if [[ -z "$panel_path" ]]; then
    _red "[ERR ] 找不到 panel 目录。请确认 ZIP 里包含 panel/"
    exit 1
  fi
  echo "$panel_path"
}

ensure_deps(){
  _cyan "[提示] 安装依赖..."
  apt-get update -y >/dev/null 2>&1 || true
  apt-get install -y python3 python3-venv python3-pip >/dev/null 2>&1
}

make_admin_hash(){
  local user="$1"
  local pass="$2"
  python3 - <<'PY'
import base64, hashlib, os, secrets
import sys
user = os.environ.get('U','admin')
password = os.environ.get('P','')
if not password:
    print('')
    sys.exit(0)
iterations = 200_000
salt = secrets.token_bytes(16)
dk = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, iterations)
enc_salt = base64.urlsafe_b64encode(salt).decode('ascii').rstrip('=')
enc_dk = base64.urlsafe_b64encode(dk).decode('ascii').rstrip('=')
print(f"pbkdf2_sha256${iterations}${enc_salt}${enc_dk}")
PY
}

install_panel(){
  local panel_src="$1"

  local admin_user
  read -r -p "设置面板登录用户名 (默认 admin): " admin_user || true
  admin_user="${admin_user:-admin}"

  local admin_pass
  admin_pass="$(read_secret "设置面板登录密码 (必填): ")"

  local port
  read -r -p "面板端口 (默认 6080): " port || true
  port="${port:-6080}"

  ensure_deps

  _cyan "[提示] 部署到 $INSTALL_ROOT ..."
  mkdir -p "$INSTALL_ROOT"
  rm -rf "$INSTALL_ROOT/panel"
  cp -a "$panel_src" "$INSTALL_ROOT/panel"

  _cyan "[提示] 创建虚拟环境..."
  python3 -m venv "$INSTALL_ROOT/venv"

  _cyan "[提示] 安装 Python 依赖..."
  "$INSTALL_ROOT/venv/bin/pip" install -U pip >/dev/null 2>&1
  "$INSTALL_ROOT/venv/bin/pip" install -r "$INSTALL_ROOT/panel/requirements.txt" >/dev/null 2>&1

  _cyan "[提示] 生成密码哈希..."
  export U="$admin_user"
  export P="$admin_pass"
  local admin_hash
  admin_hash="$(make_admin_hash "$admin_user" "$admin_pass")"
  if [[ -z "$admin_hash" ]]; then
    _red "[ERR ] 密码哈希生成失败"
    exit 1
  fi

  local secret
  secret="$(python3 - <<'PY'
import secrets; print(secrets.token_urlsafe(32))
PY
)"

  mkdir -p "$INSTALL_ROOT/data"

  cat > "$ENV_FILE" <<EOF
PANEL_PORT=$port
PANEL_ADMIN_USER=$admin_user
PANEL_ADMIN_HASH=$admin_hash
PANEL_SECRET_KEY=$secret
PANEL_DB=$INSTALL_ROOT/data/panel.db
EOF

  _cyan "[提示] 写入 systemd 服务..."
  cat > "$SERVICE_FILE" <<'EOF'
[Unit]
Description=Realm Pro Panel
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
WorkingDirectory=/opt/realm-panel/panel
EnvironmentFile=/opt/realm-panel/.env
ExecStart=/opt/realm-panel/venv/bin/uvicorn app.main:app --host 0.0.0.0 --port $PANEL_PORT
Restart=always
RestartSec=2

[Install]
WantedBy=multi-user.target
EOF

  systemctl daemon-reload
  systemctl enable --now realm-panel.service

  _grn "[OK] 面板已启动"
  echo "     URL:  http://<你的服务器IP>:$port"
  echo "     User: $admin_user"
}

main(){
  need_root
  local mode
  mode="$(choose_mode)"

  local panel_src
  if [[ "$mode" == "1" ]]; then
    panel_src="$(prepare_source_online)"
  else
    panel_src="$(prepare_source_offline)"
  fi

  _grn "[OK] panel 目录：$panel_src"
  install_panel "$panel_src"
}

main "$@"
