#!/usr/bin/env bash
set -Eeuo pipefail

# Realm Pro Panel Installer (v23)
# Fixes vs v22:
# - remove bcrypt dependency entirely (PBKDF2-SHA256, no 72-byte limit)
# - ask_password newline no longer pollutes captured value
# - password hashing uses env var (no broken bash @Q / $'..' python)
# - EnvironmentFile is now pure KEY=VALUE (no command substitution)
# - cleanup trap no longer breaks with `set -u`

red(){ echo -e "\033[31m$*\033[0m"; }
green(){ echo -e "\033[32m$*\033[0m"; }
yellow(){ echo -e "\033[33m$*\033[0m"; }
blue(){ echo -e "\033[36m$*\033[0m"; }

REPO_OWNER="cyeinfpro"
REPO_NAME="Realm"
REPO_BRANCH="main"
ARCHIVE_URL="https://github.com/${REPO_OWNER}/${REPO_NAME}/archive/refs/heads/${REPO_BRANCH}.tar.gz"

PANEL_DIR="/opt/realm-panel"
ENV_FILE="/etc/realm-panel/env"
SERVICE_FILE="/etc/systemd/system/realm-panel.service"
PANEL_PORT_DEFAULT=6080

TMP_WORKDIR=""
cleanup(){
  if [[ -n "${TMP_WORKDIR:-}" && -d "${TMP_WORKDIR:-}" ]]; then
    rm -rf "${TMP_WORKDIR}" || true
  fi
}
trap cleanup EXIT

need_cmd(){ command -v "$1" >/dev/null 2>&1 || { red "[ERR] 缺少依赖命令: $1"; exit 1; }; }
ensure_root(){ if [[ ${EUID:-$(id -u)} -ne 0 ]]; then red "[ERR] 请使用 root 运行"; exit 1; fi; }

ask(){
  local prompt="$1" def="${2:-}" var
  if [[ -n "$def" ]]; then
    read -r -p "$prompt (默认 $def): " var || true
    echo "${var:-$def}"
  else
    read -r -p "$prompt: " var || true
    echo "$var"
  fi
}

ask_password(){
  local prompt="$1" var
  while true; do
    # prompt is printed by bash `read -p` to stderr, so it won't pollute capture
    read -r -s -p "$prompt (必填): " var || true
    # print newline to stderr to avoid being captured by command substitution
    printf '\n' >&2

    # strip CR/LF just in case terminal injected them
    var=${var//$'\r'/}
    var=${var//$'\n'/}

    if [[ -n "$var" ]]; then
      echo "$var"
      return 0
    fi
    yellow "[提示] 密码不能为空，请重试" >&2
  done
}

extract_from_archive(){
  local src="$1" tmp="$2"
  tar -xzf "$src" -C "$tmp"
}

find_panel_dir(){
  local root="$1" req pdir
  req=$(find "$root" -maxdepth 6 -type f -path "*/panel/requirements.txt" -print -quit 2>/dev/null || true)
  if [[ -n "$req" ]]; then
    dirname "$req"
    return 0
  fi
  pdir=$(find "$root" -maxdepth 6 -type d -name panel -print -quit 2>/dev/null || true)
  if [[ -n "$pdir" ]]; then
    echo "$pdir"
    return 0
  fi
  return 1
}

hash_password(){
  local venv_python="$1"
  local plain="$2"
  ADMIN_PASS="$plain" "$venv_python" - <<'PY'
"""Generate a PBKDF2-SHA256 password hash without external deps."""
import os, base64, hashlib, secrets

pw = (os.environ.get("ADMIN_PASS") or "").encode("utf-8")
iters = 260000
salt = secrets.token_bytes(16)
dk = hashlib.pbkdf2_hmac("sha256", pw, salt, iters, dklen=32)

def b64u_nopad(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode("ascii").rstrip("=")

print(f"pbkdf2_sha256${iters}${b64u_nopad(salt)}${b64u_nopad(dk)}")
PY
}

gen_secret(){
  python3 - <<'PY'
import secrets
print(secrets.token_urlsafe(32))
PY
}

main(){
  ensure_root
  need_cmd curl
  need_cmd tar
  need_cmd python3

  clear || true
  blue "Realm Pro Panel Installer v23"
  echo "------------------------------------------------------------"

  local mode
  echo "1) 在线安装（推荐）"
  echo "2) 离线安装（手动下载）"
  read -r -p "请选择安装模式 [1-2] (默认 1): " mode || true
  mode=${mode:-1}

  TMP_WORKDIR=$(mktemp -d)
  local tmp="$TMP_WORKDIR"

  local archive="$tmp/repo.tar.gz"

  if [[ "$mode" == "2" ]]; then
    yellow "[离线模式] 你需要先手动下载仓库压缩包：" >&2
    echo "  - ${ARCHIVE_URL}" >&2
    echo >&2
    echo "然后把它保存为：/root/${REPO_NAME}.tar.gz" >&2
    echo "保存完成后再继续。" >&2
    read -r -p "按回车键继续..." _ || true

    if [[ ! -f "/root/${REPO_NAME}.tar.gz" ]]; then
      red "[ERR] 未找到 /root/${REPO_NAME}.tar.gz"
      exit 1
    fi
    cp -f "/root/${REPO_NAME}.tar.gz" "$archive"
  else
    yellow "[提示] 正在下载仓库..." >&2
    if ! curl -fsSL -L "$ARCHIVE_URL" -o "$archive"; then
      red "[ERR] 下载失败：$ARCHIVE_URL"
      red "[ERR] 若你的机器无法访问 github.com，请使用离线模式"
      exit 1
    fi
  fi

  yellow "[提示] 解压中..." >&2
  extract_from_archive "$archive" "$tmp"

  local pdir
  if ! pdir=$(find_panel_dir "$tmp"); then
    red "[ERR] 找不到 panel 目录。请确认仓库里包含 panel/"
    yellow "[调试] 解压后的目录结构：" >&2
    find "$tmp" -maxdepth 3 -type d -print | sed 's#^#  - #' >&2 || true
    exit 1
  fi

  green "[OK] panel 目录：$pdir"

  # Ask credentials
  local admin_user admin_pass panel_port
  admin_user=$(ask "设置面板登录用户名" "admin")
  admin_pass=$(ask_password "设置面板登录密码")
  panel_port=$(ask "面板端口" "$PANEL_PORT_DEFAULT")

  # sanitize user/pass minimal
  admin_user=${admin_user//$'\r'/}
  admin_user=${admin_user//$'\n'/}

  yellow "[提示] 安装依赖..." >&2
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -y >/dev/null 2>&1 || true
  apt-get install -y python3-venv python3-pip ca-certificates >/dev/null 2>&1 || true

  yellow "[提示] 部署到 $PANEL_DIR ..." >&2
  rm -rf "$PANEL_DIR"
  mkdir -p "$PANEL_DIR"
  cp -a "$pdir"/* "$PANEL_DIR"/
  mkdir -p "$PANEL_DIR/data"

  yellow "[提示] 创建虚拟环境..." >&2
  python3 -m venv "$PANEL_DIR/venv"
  "$PANEL_DIR/venv/bin/pip" install -U pip >/dev/null
  "$PANEL_DIR/venv/bin/pip" install -r "$PANEL_DIR/requirements.txt" >/dev/null

  yellow "[提示] 生成密码哈希..." >&2
  local pass_hash
  pass_hash=$(hash_password "$PANEL_DIR/venv/bin/python" "$admin_pass")

  local session_secret
  session_secret=$(gen_secret)

  mkdir -p "$(dirname "$ENV_FILE")"
  umask 077
  cat > "$ENV_FILE" <<EENV
PANEL_PORT=$panel_port
ADMIN_USER=$admin_user
ADMIN_PASS_HASH=$pass_hash
SESSION_SECRET=$session_secret
DB_PATH=$PANEL_DIR/data/panel.db
EENV

  cat > "$SERVICE_FILE" <<EOFUNIT
[Unit]
Description=Realm Panel Web UI
After=network.target

[Service]
Type=simple
WorkingDirectory=$PANEL_DIR
EnvironmentFile=$ENV_FILE
ExecStart=$PANEL_DIR/venv/bin/uvicorn app.main:app --host 0.0.0.0 --port $panel_port
Restart=always
RestartSec=2

[Install]
WantedBy=multi-user.target
EOFUNIT

  systemctl daemon-reload
  systemctl enable --now realm-panel.service

  green "[OK] 面板已启动"
  echo "------------------------------------------------------------"
  echo "访问地址： http://$(hostname -I 2>/dev/null | awk '{print $1}' || echo 'SERVER_IP'):$panel_port"
  echo "用户名：$admin_user"
  echo "------------------------------------------------------------"
  echo
  systemctl status realm-panel --no-pager || true
}

main "$@"
