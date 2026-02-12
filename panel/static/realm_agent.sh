#!/usr/bin/env bash
set -euo pipefail

VERSION="v40"
REPO_ZIP_URL_DEFAULT="https://nexus.infpro.me/nexus/archive/refs/heads/main.zip"
REPO_BASE_URL_DEFAULT="https://nexus.infpro.me/nexus"
REPO_MANIFEST_URL_DEFAULT="${REPO_BASE_URL_DEFAULT}/repo.manifest"
REPO_FALLBACK_GITHUB_REPO_DEFAULT="https://github.com/cyeinfpro/NexusControlPlane"
REPO_FALLBACK_BASE_URL_DEFAULT="https://raw.githubusercontent.com/cyeinfpro/NexusControlPlane/main"
REPO_FALLBACK_ZIP_URL_DEFAULT="${REPO_FALLBACK_GITHUB_REPO_DEFAULT}/archive/refs/heads/main.zip"
REPO_FALLBACK_MANIFEST_URL_DEFAULT="${REPO_FALLBACK_BASE_URL_DEFAULT}/repo.manifest"
REPO_MANIFEST_CONCURRENCY_DEFAULT="8"
DEFAULT_MODE="1"
DEFAULT_PORT="18700"
DEFAULT_HOST="0.0.0.0"

info(){ printf "[提示] %s\n" "$*"; }
ok(){ printf "[OK] %s\n" "$*"; }
err(){ printf "[错误] %s\n" "$*" >&2; }

need_root(){
  if [[ "$(id -u)" -ne 0 ]]; then
    err "请使用 root 运行（sudo -i / su -）"
    exit 1
  fi
}

probe_python_runtime(){
  local py="$1"
  if [[ -z "${py}" ]]; then
    return 1
  fi
  if [[ "${py}" == */* ]]; then
    [[ -x "${py}" ]] || return 1
  else
    command_exists "${py}" || return 1
  fi
  "${py}" -c "import venv, ssl, json" >/dev/null 2>&1
}

probe_existing_agent_venv(){
  local py="/opt/realm-agent/venv/bin/python"
  if [[ ! -x "${py}" ]]; then
    return 1
  fi
  "${py}" -c "import ssl, json, fastapi, uvicorn" >/dev/null 2>&1
}

disable_apt_listchanges_hooks(){
  local dir="/etc/apt/apt.conf.d"
  local f moved="0"
  [[ -d "${dir}" ]] || return 0
  for f in "${dir}"/*; do
    [[ -f "${f}" ]] || continue
    if [[ "${f}" == *.disabled-by-realm ]]; then
      continue
    fi
    if grep -qi "apt-listchanges" "${f}" 2>/dev/null; then
      if mv "${f}" "${f}.disabled-by-realm" 2>/dev/null; then
        moved="1"
        info "检测到 apt-listchanges hook 异常风险，已禁用：$(basename "${f}")"
      fi
    fi
  done
  if [[ "${moved}" == "1" ]]; then
    ok "已禁用 apt-listchanges hook，避免 apt 因 Python 崩溃失败"
  fi
}

apt_update_with_repair(){
  local i
  for i in 1 2 3; do
    if apt-get -o Acquire::Languages=none update -y; then
      return 0
    fi
    err "apt 索引异常，尝试修复后重试（${i}/3）..."
    rm -rf /var/lib/apt/lists/* || true
    mkdir -p /var/lib/apt/lists/partial || true
    apt-get clean || true
    dpkg --configure -a >/dev/null 2>&1 || true
    sleep 1
  done
  return 1
}

apt_install(){
  local deps_ok="1"
  local py_ok="0"
  local reuse_existing_venv="0"

  command_exists curl || deps_ok="0"
  command_exists unzip || deps_ok="0"
  command_exists jq || deps_ok="0"
  command_exists openssl || deps_ok="0"
  command_exists python3 || deps_ok="0"
  command_exists rsync || deps_ok="0"
  dpkg-query -W -f='${Status}' python3-venv 2>/dev/null | grep -q "install ok installed" || deps_ok="0"
  dpkg-query -W -f='${Status}' python3-pip 2>/dev/null | grep -q "install ok installed" || deps_ok="0"

  if probe_python_runtime "python3"; then
    py_ok="1"
  fi
  if [[ "${py_ok}" != "1" ]] && probe_existing_agent_venv; then
    reuse_existing_venv="1"
  fi

  if [[ "${deps_ok}" == "1" && ( "${py_ok}" == "1" || "${reuse_existing_venv}" == "1" ) ]]; then
    if [[ "${reuse_existing_venv}" == "1" ]]; then
      export REALM_AGENT_REUSE_VENV=1
      info "系统 Python 异常，检测到可用的现有 Agent venv，将复用 venv 执行更新"
    else
      unset REALM_AGENT_REUSE_VENV || true
    fi
    ok "依赖已满足，跳过 apt 安装"
    return
  fi

  export DEBIAN_FRONTEND=noninteractive
  export APT_LISTCHANGES_FRONTEND=none
  disable_apt_listchanges_hooks
  if ! apt_update_with_repair; then
    err "apt 索引修复失败，请手动执行：rm -rf /var/lib/apt/lists/* && apt-get clean && apt-get update"
    exit 1
  fi
  # rsync 用于更稳的覆盖更新（避免部分文件未更新）
  if ! apt-get install -y --no-install-recommends \
    curl ca-certificates unzip jq openssl python3 python3-venv python3-pip rsync; then
    err "依赖安装失败，尝试自动修复后重试..."
    apt-get -f install -y || true
    apt-get install -y --no-install-recommends \
      curl ca-certificates unzip jq openssl python3 python3-venv python3-pip rsync
  fi

  if ! probe_python_runtime "python3"; then
    info "检测到 Python 环境异常，尝试重装 python3/python3-venv/python3-pip..."
    if ! apt-get install -y --reinstall python3 python3-venv python3-pip; then
      err "重装 python3 失败，尝试更强修复（minimal/runtime 包）..."
      apt-get install -y --reinstall \
        python3-minimal python3.11 python3.11-minimal \
        libpython3.11-minimal libpython3.11-stdlib || true
    fi
  fi

  if probe_python_runtime "python3"; then
    unset REALM_AGENT_REUSE_VENV || true
    return
  fi
  if probe_existing_agent_venv; then
    export REALM_AGENT_REUSE_VENV=1
    info "系统 Python 仍异常，但现有 Agent venv 可用：将复用 venv 继续更新"
    return
  fi

  err "Python 运行环境仍异常，请先修复系统 Python 后再执行安装。"
  err "建议先执行：mv /etc/apt/apt.conf.d/*listchanges* /tmp/ 2>/dev/null || true"
  err "然后执行：apt-get update && apt-get install --reinstall -y python3 python3-minimal python3-venv python3-pip"
  exit 1
}

command_exists(){
  command -v "$1" >/dev/null 2>&1
}

download_file(){
  local url="$1"
  local out="$2"
  local tmp="${out}.tmp"
  if curl -fL --max-redirs 8 --silent --show-error --retry 3 --retry-delay 1 --connect-timeout 10 --max-time 300 "$url" -o "$tmp"; then
    mv -f "$tmp" "$out"
    return 0
  fi
  rm -f "$tmp" || true
  return 1
}

manifest_concurrency(){
  local raw="${REPO_MANIFEST_CONCURRENCY:-${REPO_MANIFEST_CONCURRENCY_DEFAULT}}"
  if [[ ! "${raw}" =~ ^[0-9]+$ ]]; then
    echo "${REPO_MANIFEST_CONCURRENCY_DEFAULT}"
    return
  fi
  if (( raw < 1 )); then
    raw=1
  fi
  if (( raw > 32 )); then
    raw=32
  fi
  echo "${raw}"
}

download_repo_manifest_path(){
  local base_url="${1%/}"
  local out_dir="$2"
  local path="$3"
  local bust="$4"
  local src="${base_url}/${path}"
  local dest="${out_dir}/${path}"
  mkdir -p "$(dirname "${dest}")"
  if ! download_file "${src}?${bust}" "${dest}"; then
    if ! download_file "${src}" "${dest}"; then
      err "下载文件失败：${src}"
      return 1
    fi
  fi
}

render_manifest_progress(){
  local done="$1"
  local total="$2"
  local width=28
  local percent filled i
  local bar=""
  if (( total <= 0 )); then
    return
  fi
  if (( done < 0 )); then
    done=0
  fi
  if (( done > total )); then
    done="${total}"
  fi
  percent=$(( done * 100 / total ))
  filled=$(( done * width / total ))
  for ((i=0; i<filled; i++)); do
    bar="${bar}#"
  done
  for ((i=filled; i<width; i++)); do
    bar="${bar}-"
  done
  printf "\r[提示] 文件拉取进度 [%s] %3d%% (%d/%d)" "${bar}" "${percent}" "${done}" "${total}"
  if (( done >= total )); then
    printf "\n"
  fi
}

guess_repo_base_from_zip_url(){
  local zip_url="$1"
  case "$zip_url" in
    */archive/refs/heads/*.zip) echo "${zip_url%/archive/refs/heads/*.zip}" ;;
    */archive/*.zip) echo "${zip_url%/archive/*.zip}" ;;
    */static/realm-agent.zip) echo "${zip_url%/static/realm-agent.zip}" ;;
    *) echo "${REPO_BASE_URL_DEFAULT}" ;;
  esac
}

repo_fallback_base_url(){
  local url="${REALM_AGENT_REPO_FALLBACK_BASE_URL:-${REPO_FALLBACK_BASE_URL_DEFAULT}}"
  echo "${url%/}"
}

repo_fallback_manifest_url(){
  if [[ -n "${REALM_AGENT_REPO_FALLBACK_MANIFEST_URL:-}" ]]; then
    echo "${REALM_AGENT_REPO_FALLBACK_MANIFEST_URL}"
    return
  fi
  echo "$(repo_fallback_base_url)/repo.manifest"
}

repo_fallback_zip_url(){
  echo "${REALM_AGENT_REPO_FALLBACK_ZIP_URL:-${REPO_FALLBACK_ZIP_URL_DEFAULT}}"
}

download_repo_from_manifest(){
  local base_url="${1%/}"
  local manifest_url="$2"
  local out_dir="$3"
  local manifest_file="${out_dir}/repo.manifest"
  local bust downloaded=0
  local -a paths=()
  local concurrency running failed completed
  bust="ts=$(date +%s)"
  mkdir -p "${out_dir}"

  info "拉取仓库文件清单..."
  if ! download_file "${manifest_url}?${bust}" "${manifest_file}"; then
    if ! download_file "${manifest_url}" "${manifest_file}"; then
      err "下载仓库文件清单失败"
      return 1
    fi
  fi

  while IFS= read -r path || [[ -n "${path}" ]]; do
    path="${path%$'\r'}"
    [[ -z "${path}" ]] && continue
    [[ "${path}" == \#* ]] && continue
    if [[ "${path}" == /* || "${path}" == *".."* ]]; then
      err "清单包含非法路径：${path}"
      return 1
    fi
    paths+=("${path}")
  done < "${manifest_file}"

  downloaded="${#paths[@]}"
  if [[ "${downloaded}" -eq 0 ]]; then
    err "仓库文件清单为空"
    return 1
  fi

  concurrency="$(manifest_concurrency)"
  info "开始拉取文件（并发 ${concurrency}，共 ${downloaded} 个）"
  running=0
  failed=0
  completed=0
  render_manifest_progress "${completed}" "${downloaded}"
  for path in "${paths[@]}"; do
    while (( running >= concurrency )); do
      if ! wait -n; then
        failed=1
      fi
      running=$((running-1))
      completed=$((completed+1))
      render_manifest_progress "${completed}" "${downloaded}"
    done
    (
      download_repo_manifest_path "${base_url}" "${out_dir}" "${path}" "${bust}"
    ) &
    running=$((running+1))
  done
  while (( running > 0 )); do
    if ! wait -n; then
      failed=1
    fi
    running=$((running-1))
    completed=$((completed+1))
    render_manifest_progress "${completed}" "${downloaded}"
  done
  if [[ "${failed}" -ne 0 ]]; then
    return 1
  fi
  ok "仓库文件拉取完成（共 ${downloaded} 个）"
}

download_repo_from_manifest_with_fallback(){
  local base_url="${1%/}"
  local manifest_url="$2"
  local out_dir="$3"
  local fallback_base fallback_manifest

  if download_repo_from_manifest "${base_url}" "${manifest_url}" "${out_dir}"; then
    return 0
  fi

  fallback_base="$(repo_fallback_base_url)"
  fallback_manifest="$(repo_fallback_manifest_url)"
  if [[ "${base_url}" == "${fallback_base}" && "${manifest_url}" == "${fallback_manifest}" ]]; then
    return 1
  fi

  info "主源清单拉取失败，切换 GitHub 备用源..."
  rm -rf "${out_dir}" || true
  mkdir -p "${out_dir}"
  if download_repo_from_manifest "${fallback_base}" "${fallback_manifest}" "${out_dir}"; then
    ok "已从 GitHub 备用源拉取仓库文件"
    return 0
  fi
  return 1
}

install_tcping(){
  if command_exists tcping; then
    ok "检测到 tcping 已安装：$(command -v tcping)"
    return
  fi
  info "未检测到 tcping，开始安装..."
  bash <(curl -Ls https://pub-f97d920473f14f6cb25df639ef970ecf.r2.dev/Tcping.sh)
  if command_exists tcping; then
    ok "tcping 安装完成"
  else
    err "tcping 安装失败，请检查网络或脚本"
  fi
}

normalize_panel_url(){
  local url="$1"
  if [[ -z "${url}" ]]; then
    echo ""
    return
  fi
  if [[ "${url}" != http://* && "${url}" != https://* ]]; then
    url="http://${url}"
  fi
  echo "${url%/}"
}

read_env_value(){
  local file="$1"
  local key="$2"
  local line value
  if [[ ! -f "${file}" ]]; then
    return 1
  fi
  line="$(grep -E "^(export[[:space:]]+)?${key}=" "${file}" 2>/dev/null | head -n 1 || true)"
  if [[ -z "${line}" ]]; then
    return 1
  fi
  if [[ "${line}" == export* ]]; then
    line="${line#export }"
  fi
  value="${line#${key}=}"
  value="${value%$'\r'}"
  # trim leading/trailing spaces
  value="${value#"${value%%[![:space:]]*}"}"
  value="${value%"${value##*[![:space:]]}"}"
  if [[ "${value}" == \"*\" ]]; then
    value="${value#\"}"
    value="${value%\"}"
  fi
  if [[ "${value}" == \'*\' ]]; then
    value="${value#\'}"
    value="${value%\'}"
  fi
  printf "%s" "${value}"
}

hydrate_panel_context(){
  local v env_file
  local -a env_files=(/etc/realm-agent/panel.env /etc/realm-agent/agent.env)
  for env_file in "${env_files[@]}"; do
    if [[ ! -f "${env_file}" ]]; then
      continue
    fi
    if [[ -z "${REALM_PANEL_URL:-}" ]]; then
      v="$(read_env_value "${env_file}" "REALM_PANEL_URL" || true)"
      if [[ -n "${v}" ]]; then
        export REALM_PANEL_URL="${v}"
        info "未显式指定 REALM_PANEL_URL，已从 Agent 记录读取（${env_file}）：${REALM_PANEL_URL}"
      fi
    fi
    if [[ -z "${REALM_AGENT_ID:-}" ]]; then
      v="$(read_env_value "${env_file}" "REALM_AGENT_ID" || true)"
      if [[ -n "${v}" ]]; then
        export REALM_AGENT_ID="${v}"
      fi
    fi
    if [[ -z "${REALM_AGENT_HEARTBEAT_INTERVAL:-}" ]]; then
      v="$(read_env_value "${env_file}" "REALM_AGENT_HEARTBEAT_INTERVAL" || true)"
      if [[ -n "${v}" ]]; then
        export REALM_AGENT_HEARTBEAT_INTERVAL="${v}"
      fi
    fi
    if [[ -n "${REALM_PANEL_URL:-}" && -n "${REALM_AGENT_ID:-}" ]]; then
      break
    fi
  done

  # 兼容老版本：如果 panel.env 不在，但 systemd runtime env 中有值，也尝试提取。
  if [[ -z "${REALM_PANEL_URL:-}" && -z "${REALM_AGENT_ID:-}" ]] && command_exists systemctl; then
    local env_blob
    env_blob="$(systemctl show -p Environment --value realm-agent.service 2>/dev/null || true)"
    if [[ -n "${env_blob}" ]]; then
      if [[ -z "${REALM_PANEL_URL:-}" ]]; then
        v="$(printf "%s\n" "${env_blob}" | tr ' ' '\n' | grep -E '^REALM_PANEL_URL=' | head -n 1 | cut -d= -f2- || true)"
        if [[ -n "${v}" ]]; then
          export REALM_PANEL_URL="${v}"
          info "已从 realm-agent.service 运行环境读取面板地址：${REALM_PANEL_URL}"
        fi
      fi
      if [[ -z "${REALM_AGENT_ID:-}" ]]; then
        v="$(printf "%s\n" "${env_blob}" | tr ' ' '\n' | grep -E '^REALM_AGENT_ID=' | head -n 1 | cut -d= -f2- || true)"
        if [[ -n "${v}" ]]; then
          export REALM_AGENT_ID="${v}"
        fi
      fi
      if [[ -z "${REALM_AGENT_HEARTBEAT_INTERVAL:-}" ]]; then
        v="$(printf "%s\n" "${env_blob}" | tr ' ' '\n' | grep -E '^REALM_AGENT_HEARTBEAT_INTERVAL=' | head -n 1 | cut -d= -f2- || true)"
        if [[ -n "${v}" ]]; then
          export REALM_AGENT_HEARTBEAT_INTERVAL="${v}"
        fi
      fi
    fi
  fi

  # 再兜底：从正在运行的 realm-agent 主进程环境变量读取（/proc/<pid>/environ）。
  if [[ -z "${REALM_PANEL_URL:-}" ]] && command_exists systemctl; then
    local pid
    pid="$(systemctl show -p MainPID --value realm-agent.service 2>/dev/null | tr -d '[:space:]' || true)"
    if [[ "${pid}" =~ ^[0-9]+$ ]] && [[ "${pid}" -gt 1 ]] && [[ -r "/proc/${pid}/environ" ]]; then
      local proc_env
      proc_env="$(tr '\0' '\n' < "/proc/${pid}/environ" 2>/dev/null || true)"
      if [[ -n "${proc_env}" ]]; then
        if [[ -z "${REALM_PANEL_URL:-}" ]]; then
          v="$(printf "%s\n" "${proc_env}" | grep -E '^REALM_PANEL_URL=' | head -n 1 | cut -d= -f2- || true)"
          if [[ -n "${v}" ]]; then
            export REALM_PANEL_URL="${v}"
            info "已从 realm-agent 进程环境读取面板地址：${REALM_PANEL_URL}"
          fi
        fi
        if [[ -z "${REALM_AGENT_ID:-}" ]]; then
          v="$(printf "%s\n" "${proc_env}" | grep -E '^REALM_AGENT_ID=' | head -n 1 | cut -d= -f2- || true)"
          if [[ -n "${v}" ]]; then
            export REALM_AGENT_ID="${v}"
          fi
        fi
        if [[ -z "${REALM_AGENT_HEARTBEAT_INTERVAL:-}" ]]; then
          v="$(printf "%s\n" "${proc_env}" | grep -E '^REALM_AGENT_HEARTBEAT_INTERVAL=' | head -n 1 | cut -d= -f2- || true)"
          if [[ -n "${v}" ]]; then
            export REALM_AGENT_HEARTBEAT_INTERVAL="${v}"
          fi
        fi
      fi
    fi
  fi
}

install_realm(){
  if command_exists realm; then
    ok "检测到 realm 已安装：$(command -v realm)"
    return
  fi

  info "未检测到 realm，开始安装..."
  local arch
  arch=$(uname -m)
  case "${arch}" in
    x86_64|amd64) arch="x86_64" ;;
    aarch64|arm64) arch="aarch64" ;;
    *) err "不支持的架构：${arch}，请手动安装 realm"; exit 1 ;;
  esac

  local urls=()
  local panel_base
  panel_base="$(normalize_panel_url "${REALM_PANEL_URL:-}")"
  # 当面板机器非公网可达时，可通过 REALM_AGENT_GITHUB_ONLY=1 强制所有安装资产走 GitHub，
  # 避免依赖面板提供 /static 下载（例如 realm 二进制）。
  if [[ -n "${panel_base}" && "${REALM_AGENT_GITHUB_ONLY:-}" != "1" ]]; then
    urls+=(
      "${panel_base}/static/realm/realm-${arch}-unknown-linux-gnu.tar.gz"
      "${panel_base}/static/realm/realm-${arch}-unknown-linux-musl.tar.gz"
    )
  fi
  urls+=(
    "https://github.com/zhboner/realm/releases/latest/download/realm-${arch}-unknown-linux-gnu.tar.gz"
    "https://github.com/zhboner/realm/releases/latest/download/realm-${arch}-unknown-linux-musl.tar.gz"
    "https://github.com/zhboner/realm/releases/latest/download/realm-${arch}-unknown-linux-gnu"
    "https://github.com/zhboner/realm/releases/latest/download/realm-${arch}-unknown-linux-musl"
  )

  local tmpdir bin_path downloaded="0"
  tmpdir=$(mktemp -d)
  for url in "${urls[@]}"; do
    if curl -fsSL "${url}" -o "${tmpdir}/realm.pkg"; then
      downloaded="1"
      if tar -tzf "${tmpdir}/realm.pkg" >/dev/null 2>&1; then
        tar -xzf "${tmpdir}/realm.pkg" -C "${tmpdir}"
        bin_path=$(find "${tmpdir}" -maxdepth 2 -type f -name realm -print -quit)
      else
        bin_path="${tmpdir}/realm.pkg"
      fi
      if [[ -n "${bin_path}" ]]; then
        install -m 0755 "${bin_path}" /usr/local/bin/realm
        ok "realm 已安装至 /usr/local/bin/realm"
        rm -rf "${tmpdir}"
        return
      fi
    fi
  done
  rm -rf "${tmpdir}"
  if [[ "${downloaded}" != "1" ]]; then
    err "realm 下载失败，请检查网络或手动安装"
  else
    err "realm 安装失败，请手动安装"
  fi
  exit 1
}


install_realm_service(){
  if ! command_exists systemctl; then
    info "未检测到 systemd，跳过 realm.service 生成"
    return
  fi

  # 主 unit：不存在则创建；已存在则保留用户自定义
  if [[ ! -f /etc/systemd/system/realm.service ]]; then
    info "创建 realm.service..."
    cat > /etc/systemd/system/realm.service <<'EOF'
[Unit]
Description=Realm Proxy Service
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/realm -c /etc/realm/config.json -n 1048576
Restart=always
RestartSec=2

[Install]
WantedBy=multi-user.target
EOF
  else
    ok "检测到 realm.service 已存在"
  fi

  # Drop-in：尽量不覆盖用户的 ExecStart，仅补充性能/稳定性参数
  mkdir -p /etc/systemd/system/realm.service.d
  cat > /etc/systemd/system/realm.service.d/override.conf <<'EOF'
[Service]
LimitNOFILE=1048576
TasksMax=infinity
EOF

  systemctl daemon-reload
}

apply_sysctl_tuning(){
  # 只写入一次，避免覆盖用户已有调优
  local f="/etc/sysctl.d/99-realm.conf"
  if [[ -f "${f}" ]]; then
    ok "检测到 ${f} 已存在，跳过 sysctl 调优写入"
    return
  fi
  info "写入内核网络调优（/etc/sysctl.d/99-realm.conf）..."
  cat > "${f}" <<'EOF'
# Realm forwarding tuning (TCP为主、少量UDP、含ws/wss)
net.core.somaxconn = 65535
net.ipv4.tcp_max_syn_backlog = 65535
net.core.netdev_max_backlog = 250000

net.core.rmem_max = 33554432
net.core.wmem_max = 33554432
net.core.rmem_default = 262144
net.core.wmem_default = 262144
net.ipv4.tcp_rmem = 4096 87380 33554432
net.ipv4.tcp_wmem = 4096 65536 33554432
net.ipv4.udp_rmem_min = 16384
net.ipv4.udp_wmem_min = 16384

net.ipv4.ip_local_port_range = 10240 65535

# Keepalive（结合 realm 的 tcp_keepalive/tcp_keepalive_probe 使用更佳）
net.ipv4.tcp_keepalive_time = 600
net.ipv4.tcp_keepalive_intvl = 30
net.ipv4.tcp_keepalive_probes = 5

# Queue + CC（BBR 可能在旧内核不可用，sysctl 应用失败会被忽略）
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr
EOF

  # best-effort apply
  sysctl --system >/dev/null 2>&1 || true
}

fetch_repo(){
  local mode="$1"
  local tmpdir="$2"
  local zip_path=""

  if [[ "${mode}" == "2" ]]; then
    zip_path="${REALM_AGENT_ZIP_PATH:-}"
    if [[ -z "${zip_path}" || ! -f "${zip_path}" ]]; then
      err "离线模式需要设置 REALM_AGENT_ZIP_PATH=/path/to/Realm-main.zip"
      exit 1
    fi
    info "使用离线 ZIP：${zip_path}"
    unzip -q "${zip_path}" -d "${tmpdir}"
  else
    local url panel_base panel_zip repo_base manifest_url fallback_zip
    local -a candidates=()
    local fetched="0"

    # ✅ 显式传入地址时优先级最高（比如 join 脚本注入）
    url="${REALM_AGENT_REPO_ZIP_URL:-}"
    if [[ -n "${url}" ]]; then
      candidates+=("${url}")
      fallback_zip="$(repo_fallback_zip_url)"
      if [[ -n "${fallback_zip}" && "${fallback_zip}" != "${url}" ]]; then
        candidates+=("${fallback_zip}")
      fi
      info "使用自定义仓库 ZIP 地址：${url}"
    else
      panel_base="$(normalize_panel_url "${REALM_PANEL_URL:-}")"
      if [[ -n "${panel_base}" && "${REALM_AGENT_GITHUB_ONLY:-}" != "1" ]]; then
        panel_zip="${panel_base}/static/realm-agent.zip"
        candidates+=("${panel_zip}")
      fi
      candidates+=("${REPO_ZIP_URL_DEFAULT}")
      fallback_zip="$(repo_fallback_zip_url)"
      if [[ -n "${fallback_zip}" ]]; then
        candidates+=("${fallback_zip}")
      fi
      info "未指定仓库 ZIP 地址，按内置优先级尝试"
    fi

    local bust candidate
    bust="ts=$(date +%s)"
    info "正在下载仓库（优先面板静态文件，失败自动回退）..."
    for candidate in "${candidates[@]}"; do
      if curl -fsSL \
        -H 'Cache-Control: no-cache' \
        -H 'Pragma: no-cache' \
        "${candidate}?${bust}" -o "${tmpdir}/repo.zip"; then
        if unzip -tq "${tmpdir}/repo.zip" >/dev/null 2>&1; then
          fetched="1"
          info "下载成功：${candidate}"
          break
        fi
        err "下载内容不是有效 ZIP，尝试下一个源：${candidate}"
      fi
      if curl -fsSL "${candidate}" -o "${tmpdir}/repo.zip"; then
        if unzip -tq "${tmpdir}/repo.zip" >/dev/null 2>&1; then
          fetched="1"
          info "下载成功：${candidate}"
          break
        fi
        err "下载内容不是有效 ZIP，尝试下一个源：${candidate}"
      fi
      err "下载失败，尝试下一个源：${candidate}"
    done
    if [[ "${fetched}" != "1" ]]; then
      repo_base="${REALM_AGENT_REPO_BASE_URL:-}"
      if [[ -z "${repo_base}" ]]; then
        if [[ ${#candidates[@]} -gt 0 ]]; then
          repo_base="$(guess_repo_base_from_zip_url "${candidates[0]}")"
        else
          repo_base="${REPO_BASE_URL_DEFAULT}"
        fi
      fi
      manifest_url="${REALM_AGENT_REPO_MANIFEST_URL:-${REPO_MANIFEST_URL_DEFAULT}}"
      if [[ -n "${repo_base}" && -z "${REALM_AGENT_REPO_MANIFEST_URL:-}" ]]; then
        manifest_url="${repo_base%/}/repo.manifest"
      fi
      info "仓库 ZIP 下载失败，尝试文件清单拉取..."
      if ! download_repo_from_manifest_with_fallback "${repo_base}" "${manifest_url}" "${tmpdir}/raw"; then
        if [[ -z "${REALM_AGENT_REPO_BASE_URL:-}" && -z "${REALM_AGENT_REPO_MANIFEST_URL:-}" && "${repo_base}" != "${REPO_BASE_URL_DEFAULT}" ]]; then
          info "文件清单拉取失败，回退默认源重试..."
          if ! download_repo_from_manifest_with_fallback "${REPO_BASE_URL_DEFAULT}" "${REPO_MANIFEST_URL_DEFAULT}" "${tmpdir}/raw"; then
            err "仓库下载失败（ZIP 与清单模式均不可用）"
            exit 1
          fi
        else
          err "仓库下载失败（ZIP 与清单模式均不可用）"
          exit 1
        fi
      fi
      return 0
    fi
    info "解压中..."
    unzip -q "${tmpdir}/repo.zip" -d "${tmpdir}"
  fi
}

stop_service_if_running(){
  if command_exists systemctl; then
    if systemctl is-active --quiet realm-agent.service 2>/dev/null; then
      info "停止旧 Agent 服务..."
      systemctl stop realm-agent.service >/dev/null 2>&1 || true
    fi
  fi
}

parse_nonneg_int(){
  local raw="$1"
  local def="$2"
  if [[ "${raw}" =~ ^[0-9]+$ ]]; then
    printf "%s" "${raw}"
  else
    printf "%s" "${def}"
  fi
}

prune_agent_artifacts(){
  local base="/opt/realm-agent"
  local keep_bak log_days tmp_days
  keep_bak="$(parse_nonneg_int "${REALM_AGENT_KEEP_BAK:-1}" "1")"
  log_days="$(parse_nonneg_int "${REALM_AGENT_UPDATE_LOG_RETENTION_DAYS:-7}" "7")"
  tmp_days="$(parse_nonneg_int "${REALM_AGENT_UPDATE_TMP_RETENTION_DAYS:-1}" "1")"

  # Keep the newest N backups only to avoid disk growth on small nodes.
  local -a bak_dirs=()
  local d
  while IFS= read -r d; do
    bak_dirs+=("${d}")
  done < <(find "${base}" -maxdepth 1 -mindepth 1 -type d -name '.bak.*' -print 2>/dev/null | sort -r)

  if (( ${#bak_dirs[@]} > keep_bak )); then
    local i removed=0
    for ((i=keep_bak; i<${#bak_dirs[@]}; i++)); do
      rm -rf "${bak_dirs[$i]}" || true
      removed=$((removed + 1))
    done
    if (( removed > 0 )); then
      info "已清理旧 Agent 备份目录：${removed} 个（保留 ${keep_bak} 个）"
    fi
  fi

  find /var/log -maxdepth 1 -type f -name 'realm-agent-update-*.log' -mtime +"${log_days}" -delete 2>/dev/null || true
  find /tmp -maxdepth 1 -type f -name 'realm-agent-update-*.sh' -mtime +"${tmp_days}" -delete 2>/dev/null || true
  find /tmp -maxdepth 1 -type f -name 'realm-agent-repo-*.zip' -mtime +"${tmp_days}" -delete 2>/dev/null || true
}

atomic_update_agent(){
  # 将新版本先部署到 staging，成功后再整体替换，避免“更新不到位 / 半更新”
  local src_agent_dir="$1"
  local host="$2"
  local port="$3"

  local base="/opt/realm-agent"
  local stage="${base}/.staging"
  local bak="${base}/.bak.$(date +%s)"
  local reuse_venv="${REALM_AGENT_REUSE_VENV:-0}"

  rm -rf "${stage}" || true
  mkdir -p "${stage}"

  info "准备更新包（staging）..."
  mkdir -p "${stage}/agent"
  # 用 rsync 强制覆盖 + 删除旧文件，保证“全量更新到最新”
  rsync -a --delete "${src_agent_dir%/}/" "${stage}/agent/"

  if [[ "${reuse_venv}" == "1" ]]; then
    if [[ ! -x "${base}/venv/bin/python" ]]; then
      err "系统 Python 异常且未找到可复用 venv，无法继续更新"
      exit 1
    fi
    info "复用现有 venv，仅更新 Agent 代码（跳过重建 venv）"
  else
    info "创建虚拟环境（staging）..."
    python3 -m venv "${stage}/venv"
    export PIP_DISABLE_PIP_VERSION_CHECK=1
    export PIP_ROOT_USER_ACTION=ignore
    if [[ "${REALM_AGENT_UPGRADE_PIP:-0}" == "1" ]]; then
      "${stage}/venv/bin/pip" install -U pip wheel setuptools >/dev/null
    fi
    # 先装 requirements（仓库内）
    "${stage}/venv/bin/pip" install \
      --no-input --prefer-binary --timeout 60 --retries 2 \
      -r "${stage}/agent/requirements.txt" >/dev/null || true
    # 兜底确保核心依赖一定存在（避免 requirements 缺失/变更导致服务无法启动）
    "${stage}/venv/bin/python" -c "import fastapi,uvicorn" >/dev/null 2>&1 || \
      "${stage}/venv/bin/pip" install \
        --no-input --prefer-binary --timeout 60 --retries 2 \
        -U "fastapi" "uvicorn[standard]" "requests" >/dev/null
  fi

  # 生成 API Key（持久化不变）
  install -d -m 700 /etc/realm-agent
  # Create api.key with 600 permissions (umask 077) to avoid leaking credentials.
  (umask 077
    if [[ ! -f /etc/realm-agent/api.key ]]; then
      head -c 32 /dev/urandom | xxd -p -c 32 > /etc/realm-agent/api.key
    fi
  )
  chmod 600 /etc/realm-agent/api.key 2>/dev/null || true

  # jq filter
  mkdir -p /etc/realm
  if [[ -f "${stage}/agent/pool_to_run.jq" ]]; then
    cp -a "${stage}/agent/pool_to_run.jq" /etc/realm/pool_to_run.jq
  fi

  # Push-report 配置（Agent -> Panel）
  # 通过面板一键安装时，会注入这些环境变量；这里持久化到文件供 systemd 读取。
  mkdir -p /etc/realm-agent
  if [[ -n "${REALM_PANEL_URL:-}" && -n "${REALM_AGENT_ID:-}" ]]; then
    cat > /etc/realm-agent/panel.env <<EOF
REALM_PANEL_URL=${REALM_PANEL_URL}
REALM_AGENT_ID=${REALM_AGENT_ID}
REALM_AGENT_HEARTBEAT_INTERVAL=${REALM_AGENT_HEARTBEAT_INTERVAL:-3}
EOF
  fi

  info "写入/更新 systemd 服务..."
  cat > /etc/systemd/system/realm-agent.service <<EOF
[Unit]
Description=Realm Pro Agent API Service
After=network.target

[Service]
Type=simple
WorkingDirectory=${base}/agent
EnvironmentFile=-/etc/realm-agent/panel.env
# ⚠️ 不要直接 ExecStart=.../uvicorn：因为本脚本使用 staging venv 再切换，
#    uvicorn 入口脚本的 shebang 可能指向 staging 路径，导致 systemd 报 203/EXEC。
# ✅ 使用 python -m uvicorn 永远可用（只要 venv 的 python 存在）
ExecStart=${base}/venv/bin/python -m uvicorn app.main:app --host ${host} --port ${port} --workers 1
Restart=always
RestartSec=2

[Install]
WantedBy=multi-user.target
EOF

  stop_service_if_running

  info "切换到最新版本（原子替换）..."
  mkdir -p "${bak}"
  if [[ -d "${base}/agent" ]]; then mv "${base}/agent" "${bak}/agent"; fi
  if [[ "${reuse_venv}" != "1" ]] && [[ -d "${base}/venv" ]]; then
    mv "${base}/venv" "${bak}/venv"
  fi

  mkdir -p "${base}"
  mv "${stage}/agent" "${base}/agent"
  if [[ "${reuse_venv}" != "1" ]]; then
    mv "${stage}/venv" "${base}/venv"
  fi
  rm -rf "${stage}" || true

  # 写入标记，方便你一眼知道“是否已更新到这次执行”
  date -u +"%Y-%m-%dT%H:%M:%SZ" > "${base}/agent/.installed_at" || true
  echo "${VERSION}" > "${base}/agent/.installer_version" || true

  restart_service realm-agent.service

  # 最终兜底：若启动失败，自动重建 venv 并改用 python -m uvicorn 再拉起
  if command_exists systemctl; then
    if ! systemctl is-active --quiet realm-agent.service 2>/dev/null; then
      if [[ "${reuse_venv}" == "1" ]]; then
        err "Agent 服务启动失败：当前处于复用 venv 模式且系统 Python 不可用，无法自动重建 venv。"
        exit 1
      fi
      err "Agent 服务启动失败，尝试自动修复（重建 venv + 重新安装核心依赖）..."
      systemctl stop realm-agent.service >/dev/null 2>&1 || true
      rm -rf "${base}/venv" || true
      python3 -m venv "${base}/venv"
      export PIP_DISABLE_PIP_VERSION_CHECK=1
      export PIP_ROOT_USER_ACTION=ignore
      if [[ "${REALM_AGENT_UPGRADE_PIP:-0}" == "1" ]]; then
        "${base}/venv/bin/pip" install -U pip wheel setuptools >/dev/null
      fi
      "${base}/venv/bin/pip" install \
        --no-input --prefer-binary --timeout 60 --retries 2 \
        -U "fastapi" "uvicorn[standard]" "requests" >/dev/null
      # 尝试安装 requirements（若存在）
      if [[ -f "${base}/agent/requirements.txt" ]]; then
        "${base}/venv/bin/pip" install \
          --no-input --prefer-binary --timeout 60 --retries 2 \
          -r "${base}/agent/requirements.txt" >/dev/null || true
      fi
      systemctl daemon-reload
      systemctl restart realm-agent.service >/dev/null 2>&1 || true
    fi
  fi

  prune_agent_artifacts
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

get_bindv6only(){
  if [[ -f /proc/sys/net/ipv6/bindv6only ]]; then
    cat /proc/sys/net/ipv6/bindv6only 2>/dev/null || echo "0"
  else
    echo "0"
  fi
}

get_ipv4(){
  local ip
  ip=$(ip -o -4 addr show scope global 2>/dev/null | awk '{print $4}' | cut -d/ -f1 | head -n 1 || true)
  if [[ -z "${ip}" ]]; then
    ip=$(hostname -I 2>/dev/null | awk '{for (i=1;i<=NF;i++) if ($i ~ /^[0-9.]+$/) {print $i; exit}}' || true)
  fi
  echo "${ip}"
}

get_ipv6(){
  local ip
  ip=$(ip -o -6 addr show scope global 2>/dev/null | awk '{print $4}' | cut -d/ -f1 | head -n 1 || true)
  if [[ -z "${ip}" ]]; then
    ip=$(hostname -I 2>/dev/null | awk '{for (i=1;i<=NF;i++) if ($i ~ /:/) {print $i; exit}}' || true)
  fi
  echo "${ip}"
}

main(){
  need_root

  echo "Realm Pro Agent Installer ${VERSION}"
  echo "------------------------------------------------------------"
  local mode
  mode="${REALM_AGENT_MODE:-${DEFAULT_MODE}}"
  if [[ "${mode}" != "1" && "${mode}" != "2" ]]; then
    err "安装模式仅支持 1(在线) 或 2(离线)"
    exit 1
  fi

  local port
  port="${REALM_AGENT_PORT:-${DEFAULT_PORT}}"
  if [[ ! "${port}" =~ ^[0-9]+$ || "${port}" -lt 1 || "${port}" -gt 65535 ]]; then
    err "Agent 端口无效：${port}"
    exit 1
  fi
  local host
  host="${REALM_AGENT_HOST:-}"
  if [[ -z "${host}" ]]; then
    host="${DEFAULT_HOST}"
  fi
  if [[ "${host}" == "::" ]]; then
    local bindv6only
    bindv6only=$(get_bindv6only)
    if [[ "${bindv6only}" == "1" ]]; then
      info "检测到 bindv6only=1，IPv6 仅监听将导致 IPv4 无法连接，已切换为 0.0.0.0"
      host="0.0.0.0"
    fi
  fi

  hydrate_panel_context
  local panel_base_for_log
  panel_base_for_log="$(normalize_panel_url "${REALM_PANEL_URL:-}")"
  if [[ -n "${panel_base_for_log}" && -z "${REALM_AGENT_REPO_ZIP_URL:-}" && "${REALM_AGENT_GITHUB_ONLY:-}" != "1" ]]; then
    info "仓库 ZIP 将优先使用面板地址：${panel_base_for_log}/static/realm-agent.zip"
  fi

  info "安装依赖..."
  apt_install
  if [[ "${REALM_AGENT_INSTALL_TCPING:-0}" == "1" ]]; then
    install_tcping
  else
    info "跳过 tcping 安装（设置 REALM_AGENT_INSTALL_TCPING=1 可启用）"
  fi
  # 仅更新 Agent（不更新 Realm 转发）
  if [[ "${REALM_AGENT_ONLY:-0}" != "1" ]]; then
    install_realm
    install_realm_service
    apply_sysctl_tuning
  fi

  local tmpdir
  tmpdir=$(mktemp -d)
  cleanup(){
    if [[ -n "${tmpdir:-}" ]]; then
      rm -rf "${tmpdir}"
    fi
  }
  trap cleanup EXIT

  fetch_repo "${mode}" "${tmpdir}"

  local agent_dir
  agent_dir=$(find_agent_dir "${tmpdir}")
  ok "agent 目录：${agent_dir}"

  # ✅ 再次执行脚本时，自动全量更新到最新（无需卸载重装）
  # - staging + 原子替换，避免“半更新/更新不到位”
  # - 自动 cache-bust，避免下载到旧包
  atomic_update_agent "${agent_dir}" "${host}" "${port}"

  local api_key
  api_key=$(cat /etc/realm-agent/api.key)

  ok "Agent 已安装并启动"
  local ipv4 ipv6
  ipv4=$(get_ipv4)
  ipv6=$(get_ipv6)
  if [[ -n "${ipv4}" ]]; then
    echo "- Agent URL:   http://${ipv4}:${port}"
  fi
  if [[ "${host}" == "::" && -n "${ipv6}" ]]; then
    echo "- Agent URL:   http://[${ipv6}]:${port}"
  fi
  echo "- API Key:     ${api_key}"
  echo "- Service:     systemctl status realm-agent --no-pager"
}

main "$@"
