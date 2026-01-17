#!/usr/bin/env bash
set -euo pipefail

# Realm Pro Web Panel v14
# 你的仓库 RAW 地址（你给的）：
# https://raw.githubusercontent.com/cyeinfpro/Realm/refs/heads/main
# 如果你未来更换仓库或分支，只需替换这一行。
REPO_RAW_BASE="https://raw.githubusercontent.com/cyeinfpro/Realm/refs/heads/main"

PANEL_DIR="/opt/realm-panel"
PANEL_ETC="/etc/realm-panel"
PANEL_PORT_DEFAULT="18750"

is_root() { [ "$(id -u)" = "0" ]; }

say() { echo "[Realm Panel] $*"; }

need_cmd() {
  command -v "$1" >/dev/null 2>&1 || { say "缺少命令：$1"; exit 1; }
}

install_deps() {
  say "安装依赖..."
  apt-get update -y >/dev/null
  apt-get install -y curl ca-certificates python3 python3-venv python3-pip unzip >/dev/null
}

fetch_file() {
  # $1 remote path   $2 dest
  local remote="$1" dest="$2"
  curl -fsSL "${REPO_RAW_BASE}/${remote}" -o "$dest"
}

copy_local_tree() {
  local src="$1" dst="$2"
  mkdir -p "$dst"
  (cd "$src" && tar -cf - .) | (cd "$dst" && tar -xf -)
}

install_panel_files() {
  local mode="$1" # remote|local
  rm -rf "$PANEL_DIR"
  mkdir -p "$PANEL_DIR" "$PANEL_ETC"

  if [ "$mode" = "local" ]; then
    local script_dir
    script_dir="$(cd "$(dirname "$0")" && pwd)"
    copy_local_tree "${script_dir}/panel" "$PANEL_DIR"
  else
    mkdir -p "$PANEL_DIR/app" "$PANEL_DIR/app/templates" "$PANEL_DIR/app/static" "$PANEL_DIR/systemd"
    fetch_file "panel/requirements.txt" "$PANEL_DIR/requirements.txt"
    fetch_file "panel/start.sh" "$PANEL_DIR/start.sh"
    fetch_file "panel/systemd/realm-panel.service" "$PANEL_DIR/systemd/realm-panel.service"

    fetch_file "panel/app/main.py" "$PANEL_DIR/app/main.py"
    fetch_file "panel/app/db.py" "$PANEL_DIR/app/db.py"

    fetch_file "panel/app/templates/base.html" "$PANEL_DIR/app/templates/base.html"
    fetch_file "panel/app/templates/login.html" "$PANEL_DIR/app/templates/login.html"
    fetch_file "panel/app/templates/dashboard.html" "$PANEL_DIR/app/templates/dashboard.html"
    fetch_file "panel/app/templates/agent_detail.html" "$PANEL_DIR/app/templates/agent_detail.html"

    fetch_file "panel/app/static/style.css" "$PANEL_DIR/app/static/style.css"
    fetch_file "panel/app/static/app.js" "$PANEL_DIR/app/static/app.js"
  fi

  chmod +x "$PANEL_DIR/start.sh"
}

setup_venv() {
  say "创建 Python 虚拟环境..."
  python3 -m venv "$PANEL_DIR/venv"
  "$PANEL_DIR/venv/bin/pip" install -U pip >/dev/null
  "$PANEL_DIR/venv/bin/pip" install -r "$PANEL_DIR/requirements.txt" >/dev/null
}

setup_env() {
  mkdir -p "$PANEL_ETC"
  local envf="$PANEL_ETC/panel.env"
  if [ -f "$envf" ]; then
    say "发现已存在配置：$envf（将保留）"
    return 0
  fi

  say "初始化面板配置..."
  read -r -p "面板监听端口（默认 ${PANEL_PORT_DEFAULT}）: " panel_port
  panel_port="${panel_port:-$PANEL_PORT_DEFAULT}"

  read -r -p "管理员账号（默认 admin）: " admin_user
  admin_user="${admin_user:-admin}"

  read -r -s -p "管理员密码（默认 admin）: " admin_pass
  echo
  admin_pass="${admin_pass:-admin}"

  local secret
  secret="$(python3 - <<'PY'
import secrets
print(secrets.token_urlsafe(32))
PY
)"

  cat > "$envf" <<EOF
REALM_PANEL_HOST=0.0.0.0
REALM_PANEL_PORT=${panel_port}
REALM_PANEL_ADMIN_USER=${admin_user}
REALM_PANEL_ADMIN_PASS=${admin_pass}
REALM_PANEL_SECRET=${secret}
REALM_PANEL_DB=/etc/realm-panel/panel.db
EOF

  chmod 600 "$envf"
}

install_systemd() {
  say "安装 systemd 服务..."
  cp -f "$PANEL_DIR/systemd/realm-panel.service" /etc/systemd/system/realm-panel.service
  systemctl daemon-reload
  systemctl enable realm-panel.service >/dev/null
  systemctl restart realm-panel.service
}

show_status() {
  systemctl status realm-panel.service --no-pager || true
}

uninstall_panel() {
  say "卸载面板..."
  systemctl stop realm-panel.service >/dev/null 2>&1 || true
  systemctl disable realm-panel.service >/dev/null 2>&1 || true
  rm -f /etc/systemd/system/realm-panel.service
  systemctl daemon-reload || true
  rm -rf "$PANEL_DIR"
  rm -rf "$PANEL_ETC"
  say "完成"
}

install_or_update() {
  local mode="remote"
  if [ "${1:-}" = "--local" ]; then
    mode="local"
  fi

  install_deps
  install_panel_files "$mode"
  setup_venv
  setup_env
  install_systemd

  local port
  port="$(grep -E '^REALM_PANEL_PORT=' "$PANEL_ETC/panel.env" | cut -d= -f2 || true)"
  port="${port:-$PANEL_PORT_DEFAULT}"
  say "面板已启动： http://<你的服务器IP>:${port}"
  say "默认账号密码：admin / admin （可在 $PANEL_ETC/panel.env 修改）"
}

main_menu() {
  if ! is_root; then
    say "请使用 root 运行：sudo bash realm_panel.sh"
    exit 1
  fi

  while true; do
    echo ""
    echo "================ Realm Pro Web Panel v14 ================"
    echo "1) 安装 / 更新（在线从仓库拉取）"
    echo "2) 安装 / 更新（本地文件）"
    echo "3) 查看服务状态"
    echo "4) 查看最近日志"
    echo "5) 卸载"
    echo "0) 退出"
    echo "========================================================="
    read -r -p "> " choice

    case "$choice" in
      1) install_or_update ;;
      2) install_or_update --local ;;
      3) show_status ;;
      4) journalctl -u realm-panel.service -n 120 --no-pager || true ;;
      5) uninstall_panel ;;
      0) exit 0 ;;
      *) echo "无效选择" ;;
    esac
  done
}

main_menu
