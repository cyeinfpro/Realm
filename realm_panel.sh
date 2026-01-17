#!/usr/bin/env bash
set -euo pipefail

# Realm Pro Panel Installer (v18.1)
# Repo: https://github.com/cyeinfpro/Realm

REPO_OWNER="cyeinfpro"
REPO_NAME="Realm"
REPO_BRANCH="main"

ARCHIVE_URL="https://github.com/${REPO_OWNER}/${REPO_NAME}/archive/refs/heads/${REPO_BRANCH}.tar.gz"

PANEL_HOME="/opt/realm-panel"
ETC_DIR="/etc/realm-panel"

# Log helpers
# IMPORTANT: installer functions may be used in command substitution.
# Therefore, ALL logs must go to STDERR to avoid contaminating stdout.
_red(){ echo -e "\033[31m$*\033[0m" >&2; }
_green(){ echo -e "\033[32m$*\033[0m" >&2; }
_yellow(){ echo -e "\033[33m$*\033[0m" >&2; }

need_root(){
  if [[ $EUID -ne 0 ]]; then
    _red "[ERR] 请用 root 运行：sudo bash realm_panel.sh"
    exit 1
  fi
}

pick_source(){
  local tmp
  tmp="$(mktemp -d)"
  # With "set -u", local vars may be unset by the time the EXIT trap runs.
  # Capture the value NOW.
  trap "rm -rf '$tmp'" EXIT

  _yellow "[1/5] 下载面板文件..."
  curl -fsSL "$ARCHIVE_URL" -o "${tmp}/src.tgz"
  tar -xzf "${tmp}/src.tgz" -C "$tmp"

  # Find repo root that contains panel/requirements.txt
  local root
  root="$(find "$tmp" -maxdepth 4 -type f -path '*/panel/requirements.txt' -print -quit | sed 's|/panel/requirements.txt||')"
  if [[ -z "$root" || ! -d "$root/panel" ]]; then
    _red "[ERR] 找不到 panel 目录。请确认仓库里包含 panel/requirements.txt"
    _red "[ERR] 当前下载：$ARCHIVE_URL"
    exit 1
  fi
  echo "$root"
}

hash_password(){
  local pw="$1"
  python3 - <<PY
import base64, os, hashlib
pw = """$pw""".encode('utf-8')
it = 200000
salt = os.urandom(16)
dk = hashlib.pbkdf2_hmac('sha256', pw, salt, it)
print('pbkdf2_sha256$%d$%s$%s' % (
  it,
  base64.urlsafe_b64encode(salt).decode().rstrip('='),
  base64.urlsafe_b64encode(dk).decode().rstrip('='),
))
PY
}

install_panel(){
  local src_root="$1"

  mkdir -p "$PANEL_HOME" "$ETC_DIR" /var/log/realm-panel

  _yellow "[2/5] 拷贝面板文件到 $PANEL_HOME ..."
  rm -rf "$PANEL_HOME/panel"
  cp -a "$src_root/panel" "$PANEL_HOME/panel"

  _yellow "[3/5] 创建 Python 虚拟环境并安装依赖..."
  apt-get update -y >/dev/null
  apt-get install -y python3 python3-venv python3-pip ca-certificates curl >/dev/null

  python3 -m venv "$PANEL_HOME/venv"
  "$PANEL_HOME/venv/bin/pip" -q install --upgrade pip
  "$PANEL_HOME/venv/bin/pip" -q install -r "$PANEL_HOME/panel/requirements.txt"

  _yellow "[4/5] 写入配置 & Systemd 服务..."
  chmod 700 "$ETC_DIR"

  local port user pw hash secret
  read -rp "面板端口 (默认 6080) > " port
  port="${port:-6080}"

  while true; do
    read -rp "面板登录用户名 (默认 admin) > " user
    user="${user:-admin}"
    [[ -n "$user" ]] && break
  done

  while true; do
    read -rsp "面板登录密码（不会回显）> " pw
    echo
    [[ -n "$pw" ]] && break
    _red "密码不能为空"
  done

  hash="$(hash_password "$pw")"
  secret="$(python3 - <<'PY'
import secrets
print(secrets.token_hex(32))
PY
)"

  cat > "$ETC_DIR/env" <<ENV
PANEL_PORT=${port}
PANEL_USER=${user}
PANEL_PASS_HASH=${hash}
PANEL_SECRET=${secret}
ENV
  chmod 600 "$ETC_DIR/env"

  # install service
  cp -a "$PANEL_HOME/panel/systemd/realm-panel.service" /etc/systemd/system/realm-panel.service

  systemctl daemon-reload
  systemctl enable realm-panel --now

  _yellow "[5/5] 启动检查..."
  sleep 1
  if systemctl is-active --quiet realm-panel; then
    _green "[OK] 面板已启动"
  else
    _red "[ERR] 面板启动失败，请查看：journalctl -u realm-panel -n 120 --no-pager"
    exit 1
  fi

  _green "\n访问地址：http://<服务器IP>:${port}"
  _green "用户名：${user}"
  _green "（密码为你刚刚输入的密码）"
}

main(){
  need_root
  local root
  root="$(pick_source)"
  install_panel "$root"
}

main "$@"
