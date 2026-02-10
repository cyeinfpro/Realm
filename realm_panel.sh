#!/usr/bin/env bash
set -euo pipefail

VERSION="v38"
REPO_ZIP_URL_DEFAULT="https://nexus.infpro.me/nexus/archive/refs/heads/main.zip"
REPO_BASE_URL_DEFAULT="https://nexus.infpro.me/nexus"
REPO_MANIFEST_URL_DEFAULT="${REPO_BASE_URL_DEFAULT}/repo.manifest"
REPO_FALLBACK_GITHUB_REPO_DEFAULT="https://github.com/cyeinfpro/NexusControlPlane"
REPO_FALLBACK_BASE_URL_DEFAULT="https://raw.githubusercontent.com/cyeinfpro/NexusControlPlane/main"
REPO_FALLBACK_ZIP_URL_DEFAULT="${REPO_FALLBACK_GITHUB_REPO_DEFAULT}/archive/refs/heads/main.zip"
REPO_FALLBACK_MANIFEST_URL_DEFAULT="${REPO_FALLBACK_BASE_URL_DEFAULT}/repo.manifest"
REPO_FETCH_MODE_DEFAULT="manifest"
REPO_MANIFEST_CONCURRENCY_DEFAULT="8"
PANEL_ROOT="/opt/realm-panel"
PANEL_STATIC_REALM_DIR="${PANEL_ROOT}/panel/static/realm"
PANEL_REQ_STAMP="${PANEL_ROOT}/.requirements.sha256"
PANEL_REALM_TAG_STAMP="${PANEL_STATIC_REALM_DIR}/.realm_assets_tag"

info(){ echo -e "\033[33m[提示]\033[0m $*" >&2; }
ok(){ echo -e "\033[32m[OK]\033[0m $*" >&2; }
err(){ echo -e "\033[31m[错误]\033[0m $*" >&2; }
need_root(){
  if [[ "$(id -u)" -ne 0 ]]; then
    err "请使用 root 运行（sudo -i / su -）"
    exit 1
  fi
}

apt_install(){
  export DEBIAN_FRONTEND=noninteractive
  local pkgs=(curl unzip zip jq python3 python3-venv python3-pip ca-certificates)
  local missing=()
  local p
  for p in "${pkgs[@]}"; do
    if ! dpkg -s "$p" >/dev/null 2>&1; then
      missing+=("$p")
    fi
  done
  if [[ ${#missing[@]} -eq 0 ]]; then
    ok "依赖已满足，跳过 apt 安装"
    return 0
  fi
  info "安装缺失依赖: ${missing[*]}"
  apt-get update -y >/dev/null
  apt-get install -y "${missing[@]}" >/dev/null
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
  printf "\r\033[33m[提示]\033[0m 文件拉取进度 [%s] %3d%% (%d/%d)" "${bar}" "${percent}" "${done}" "${total}" >&2
  if (( done >= total )); then
    printf "\n" >&2
  fi
}

build_abs_url(){
  local base_url="${1%/}"
  local raw="$2"
  local origin
  if [[ -z "${raw}" ]]; then
    echo ""
    return
  fi
  if [[ "${raw}" == http://* || "${raw}" == https://* ]]; then
    echo "${raw}"
    return
  fi
  origin="$(echo "${base_url}" | sed -E 's#^(https?://[^/]+).*$#\1#')"
  if [[ "${raw}" == /* ]]; then
    echo "${origin}${raw}"
    return
  fi
  raw="${raw#./}"
  echo "${base_url}/${raw}"
}

probe_url_200(){
  local url="$1"
  local code
  code="$(curl -L --max-redirs 5 --connect-timeout 8 --max-time 20 -s -o /dev/null -w '%{http_code}' "${url}" 2>/dev/null || true)"
  [[ "${code}" == "200" ]]
}

discover_repo_zip_url(){
  local base_url="${1%/}"
  local -a candidates=()
  local c

  if [[ -n "${REPO_ZIP_URL:-}" ]]; then
    echo "${REPO_ZIP_URL}"
    return 0
  fi

  candidates+=("${REPO_ZIP_URL_DEFAULT}")
  candidates+=(
    "${base_url}/main.zip"
    "${base_url}/nexus-main.zip"
    "${base_url}/realm-main.zip"
    "${base_url}/repo.zip"
    "${base_url}/latest.zip"
  )

  if [[ -n "${REPO_ZIP_CANDIDATES:-}" ]]; then
    local -a extra=()
    IFS=',' read -r -a extra <<< "${REPO_ZIP_CANDIDATES}"
    for c in "${extra[@]}"; do
      c="${c#"${c%%[![:space:]]*}"}"
      c="${c%"${c##*[![:space:]]}"}"
      [[ -z "${c}" ]] && continue
      candidates+=("$(build_abs_url "${base_url}" "${c}")")
    done
  fi

  for c in "${candidates[@]}"; do
    info "探测仓库 ZIP：${c}"
    if probe_url_200 "${c}"; then
      echo "${c}"
      return 0
    fi
  done

  # 尝试从目录索引里自动发现 zip（如 nexus-20260210-004312.zip）
  local index link url
  local -a discovered=()
  index="$(curl -L --max-redirs 5 --connect-timeout 8 --max-time 20 -fsSL "${base_url}/" 2>/dev/null || true)"
  if [[ -n "${index}" ]]; then
    while IFS= read -r link; do
      [[ -z "${link}" ]] && continue
      url="$(build_abs_url "${base_url}" "${link}")"
      case "${url##*/}" in
        *.zip|*.ZIP) discovered+=("${url}") ;;
      esac
    done < <(printf '%s' "${index}" | grep -oiE 'href="[^"]+"' | sed -E 's/^href="([^"]+)"$/\1/I')
  fi

  if [[ ${#discovered[@]} -gt 0 ]]; then
    local best=""
    local item
    for item in "${discovered[@]}"; do
      case "${item##*/}" in
        *main*.zip|*main*.ZIP|nexus-*.zip|realm-*.zip|*repo*.zip)
          if [[ -z "${best}" || "${item}" > "${best}" ]]; then
            best="${item}"
          fi
          ;;
      esac
    done
    if [[ -z "${best}" ]]; then
      for item in "${discovered[@]}"; do
        if [[ -z "${best}" || "${item}" > "${best}" ]]; then
          best="${item}"
        fi
      done
    fi
    if [[ -n "${best}" ]]; then
      if probe_url_200 "${best}"; then
        info "已自动识别仓库 ZIP：${best}"
        echo "${best}"
        return 0
      fi
    fi
  fi

  return 1
}

guess_repo_base_from_zip_url(){
  local zip_url="$1"
  case "$zip_url" in
    */archive/refs/heads/*.zip) echo "${zip_url%/archive/refs/heads/*.zip}" ;;
    */archive/*.zip) echo "${zip_url%/archive/*.zip}" ;;
    *) echo "${REPO_BASE_URL_DEFAULT}" ;;
  esac
}

repo_fallback_base_url(){
  local url="${REPO_FALLBACK_BASE_URL:-${REPO_FALLBACK_BASE_URL_DEFAULT}}"
  echo "${url%/}"
}

repo_fallback_manifest_url(){
  if [[ -n "${REPO_FALLBACK_MANIFEST_URL:-}" ]]; then
    echo "${REPO_FALLBACK_MANIFEST_URL}"
    return
  fi
  echo "$(repo_fallback_base_url)/repo.manifest"
}

repo_fallback_zip_url(){
  echo "${REPO_FALLBACK_ZIP_URL:-${REPO_FALLBACK_ZIP_URL_DEFAULT}}"
}

download_repo_from_manifest(){
  local base_url="${1%/}"
  local manifest_url="$2"
  local out_dir="$3"
  local manifest_file="${TMPDIR}/repo.manifest"
  local bust downloaded=0
  local -a paths=()
  local concurrency running failed completed
  bust="ts=$(date +%s)"

  info "拉取仓库文件清单..."
  if ! download_file "${manifest_url}?${bust}" "${manifest_file}"; then
    if ! download_file "${manifest_url}" "${manifest_file}"; then
      err "下载仓库文件清单失败"
      return 1
    fi
  fi

  mkdir -p "${out_dir}"
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

latest_realm_tag(){
  local final=""
  final="$(curl -fsSL -o /dev/null -w '%{url_effective}' "https://github.com/zhboner/realm/releases/latest" 2>/dev/null || true)"
  if [[ -z "$final" ]]; then
    echo ""
    return 0
  fi
  echo "${final##*/}"
}

prepare_realm_assets(){
  local dest="${PANEL_STATIC_REALM_DIR}"
  mkdir -p "${dest}"
  local latest_tag current_tag
  latest_tag="$(latest_realm_tag)"
  current_tag="$(cat "${PANEL_REALM_TAG_STAMP}" 2>/dev/null || true)"

  local archs=("x86_64" "aarch64")
  local flavors=("unknown-linux-gnu.tar.gz" "unknown-linux-musl.tar.gz")

  if [[ -n "$latest_tag" && "$latest_tag" == "$current_tag" ]]; then
    local all_present=1
    local a f
    for a in "${archs[@]}"; do
      for f in "${flavors[@]}"; do
        local fn="realm-${a}-${f}"
        if [[ ! -s "${dest}/${fn}" ]]; then
          all_present=0
          break
        fi
      done
    done
    if [[ "$all_present" -eq 1 ]]; then
      ok "realm 资源已是最新（${latest_tag}），跳过下载"
      return 0
    fi
  fi

  info "同步 realm 二进制到面板..."
  local pids=()
  local names=()
  for arch in "${archs[@]}"; do
    for flavor in "${flavors[@]}"; do
      local filename="realm-${arch}-${flavor}"
      local url="https://github.com/zhboner/realm/releases/latest/download/${filename}"
      (
        download_file "${url}" "${dest}/${filename}"
      ) &
      pids+=($!)
      names+=("${filename}")
    done
  done

  local failed=0
  local i
  for i in "${!pids[@]}"; do
    if wait "${pids[$i]}"; then
      ok "已下载 ${names[$i]}"
    else
      err "下载失败：${names[$i]}"
      failed=$((failed+1))
    fi
  done

  if [[ "$failed" -eq 0 && -n "$latest_tag" ]]; then
    echo "${latest_tag}" > "${PANEL_REALM_TAG_STAMP}"
  fi
}

install_python_deps(){
  local venv_dir="${PANEL_ROOT}/venv"
  local req="${PANEL_ROOT}/panel/requirements.txt"
  local req_hash old_hash
  req_hash="$(sha256sum "$req" | awk '{print $1}')"
  old_hash="$(cat "${PANEL_REQ_STAMP}" 2>/dev/null || true)"
  if [[ -d "$venv_dir" && "$req_hash" == "$old_hash" ]]; then
    ok "Python 依赖未变化，跳过 pip install"
    return 0
  fi
  info "安装/更新 Python 依赖..."
  "${venv_dir}/bin/pip" install --disable-pip-version-check -U pip wheel >/dev/null
  "${venv_dir}/bin/pip" install --disable-pip-version-check --prefer-binary -r "$req" >/dev/null
  echo "$req_hash" > "${PANEL_REQ_STAMP}"
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

prompt_secret(){
  local msg="$1"; local out
  # -s：输入不回显；用于密码/密钥类信息
  # 注意：该函数常用于命令替换：pass="$(prompt_secret ...)"
  # 如果把换行输出到 stdout，会被命令替换捕获，导致密码前多出不可见字符（\n），登录会失败。
  # 因此：换行输出到 /dev/tty（或 stderr），stdout 只输出纯密码。
  if [[ -r /dev/tty && -w /dev/tty ]]; then
    read -r -s -p "$msg: " out </dev/tty || true
    echo >/dev/tty
  else
    read -r -s -p "$msg: " out || true
    echo >&2
  fi
  printf '%s' "$out"
}

# --- Panel public URL (domain / reverse proxy) ---

normalize_public_url(){
  local v="${1:-}"
  v="${v%%[[:space:]]*}"
  v="${v%/}"
  if [[ -z "$v" ]]; then
    echo ""
    return
  fi
  if [[ "$v" == http://* || "$v" == https://* ]]; then
    echo "${v%/}"
    return
  fi
  # 默认 https（常见反代/证书场景）；如需 http 请显式输入 http://
  echo "https://${v}"
}

detect_ip(){
  local ip=""
  if command -v curl >/dev/null 2>&1; then
    ip="$(curl -fsSL -4 https://api.ipify.org 2>/dev/null || true)"
  fi
  if [[ -z "$ip" ]]; then
    ip="$(hostname -I 2>/dev/null | awk '{print $1}' || true)"
  fi
  if [[ -z "$ip" ]] && command -v ip >/dev/null 2>&1; then
    ip="$(ip -4 route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="src") {print $(i+1); exit}}' || true)"
  fi
  echo "${ip:-127.0.0.1}"
}

# 当面板机器不是公网 IP（例如内网部署/无反代暴露）时，
# 需要优先使用本机内网 IP 来生成访问地址（避免误用出口公网 IP）。
detect_local_ip(){
  local ip=""
  ip="$(hostname -I 2>/dev/null | awk '{print $1}' || true)"
  if [[ -z "$ip" ]] && command -v ip >/dev/null 2>&1; then
    ip="$(ip -4 route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="src") {print $(i+1); exit}}' || true)"
  fi
  echo "${ip:-127.0.0.1}"
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
  if [[ -z "$TMPDIR" || ! -d "$TMPDIR" ]]; then
    err "创建临时目录失败"
    exit 1
  fi
  EXTRACT_ROOT="$TMPDIR/extract"
  mkdir -p "$EXTRACT_ROOT"
  if [[ "$mode" == "online" ]]; then
    local url repo_base manifest_url fetch_mode fallback_zip_url zip_ok
    local used_manifest="0"
    local tried_manifest="0"
    repo_base="${REPO_BASE_URL:-$(guess_repo_base_from_zip_url "${REPO_ZIP_URL:-$REPO_ZIP_URL_DEFAULT}")}"
    manifest_url="${REPO_MANIFEST_URL:-${repo_base}/repo.manifest}"
    fetch_mode="${REPO_FETCH_MODE:-${REPO_FETCH_MODE_DEFAULT}}"
    fetch_mode="$(echo "${fetch_mode}" | tr '[:upper:]' '[:lower:]')"
    case "${fetch_mode}" in
      manifest|zip|auto) ;;
      *) fetch_mode="${REPO_FETCH_MODE_DEFAULT}" ;;
    esac

    if [[ "${fetch_mode}" != "zip" ]]; then
      tried_manifest="1"
      info "优先使用文件清单拉取..."
      if download_repo_from_manifest_with_fallback "$repo_base" "$manifest_url" "$EXTRACT_ROOT/raw"; then
        used_manifest="1"
        EXTRACT_ROOT="$EXTRACT_ROOT/raw"
      else
        err "文件清单拉取失败，改用 ZIP 包..."
      fi
    fi

    if [[ "${used_manifest}" != "1" ]]; then
      url="$(discover_repo_zip_url "${repo_base}" || true)"
      [[ -n "${url}" ]] || url="${REPO_ZIP_URL:-$REPO_ZIP_URL_DEFAULT}"
      fallback_zip_url="$(repo_fallback_zip_url)"
      zip_ok="0"
      info "正在下载 ZIP 包..."
      if download_file "$url" "$TMPDIR/repo.zip" && unzip -tq "$TMPDIR/repo.zip" >/dev/null 2>&1; then
        zip_ok="1"
      else
        if [[ -f "$TMPDIR/repo.zip" ]]; then
          err "仓库 ZIP 校验失败：${url}"
        fi
        if [[ -n "${fallback_zip_url}" && "${fallback_zip_url}" != "${url}" ]]; then
          info "主源 ZIP 下载失败，切换 GitHub 备用源..."
          if download_file "${fallback_zip_url}" "$TMPDIR/repo.zip" && unzip -tq "$TMPDIR/repo.zip" >/dev/null 2>&1; then
            zip_ok="1"
            url="${fallback_zip_url}"
            ok "已从 GitHub 备用源下载仓库 ZIP"
          elif [[ -f "$TMPDIR/repo.zip" ]]; then
            err "备用源 ZIP 校验失败：${fallback_zip_url}"
          fi
        fi
        if [[ "${zip_ok}" != "1" && "${tried_manifest}" != "1" ]]; then
          info "ZIP 包不可用，尝试文件清单拉取..."
          if download_repo_from_manifest_with_fallback "$repo_base" "$manifest_url" "$EXTRACT_ROOT/raw"; then
            used_manifest="1"
            EXTRACT_ROOT="$EXTRACT_ROOT/raw"
          fi
        fi
      fi
      if [[ "${zip_ok}" == "1" ]]; then
        zip_path="$TMPDIR/repo.zip"
        info "解压中..."
        unzip -q "$zip_path" -d "$EXTRACT_ROOT"
      fi
    fi

    if [[ "${used_manifest}" != "1" && "${zip_ok:-0}" != "1" ]]; then
      err "仓库下载失败：ZIP 与清单模式均不可用"
      err "可手动指定 REPO_MANIFEST_URL，或设置 REPO_ZIP_URL 为可直接下载的 ZIP"
      exit 1
    fi
    if [[ "${used_manifest}" != "1" && "${zip_ok:-0}" == "1" && ! -d "${EXTRACT_ROOT}/panel" ]]; then
      # zip 下载流程在上面已尝试解压；若解压后结构不完整，仍按失败处理。
      PANEL_DIR="$(find "$EXTRACT_ROOT" -maxdepth 6 -type d -name panel -print -quit)"
      if [[ -z "$PANEL_DIR" ]]; then
        err "仓库 ZIP 解压后结构不正确，且清单模式不可用"
        err "可手动指定 REPO_MANIFEST_URL，或设置 REPO_ZIP_URL 为可直接下载的 ZIP"
        exit 1
      fi
    fi
  else
    [[ -f "$zip_path" ]] || { err "ZIP 文件不存在：$zip_path"; exit 1; }
    info "解压中..."
    unzip -q "$zip_path" -d "$EXTRACT_ROOT"
  fi
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
  if [[ -z "$extract_root" || ! -d "$extract_root" ]]; then
    err "解压目录不存在：$extract_root"
    exit 1
  fi
  local agent_dir
  agent_dir="$(find_agent_dir "$extract_root")"
  info "打包 Agent 离线安装包..."
  mkdir -p /opt/realm-panel/panel/static
  ( cd "$agent_dir/.." && zip -qr /opt/realm-panel/panel/static/realm-agent.zip "$(basename "$agent_dir")" )
  local script_path
  script_path="$(find "$extract_root" -maxdepth 6 -type f -name realm_agent.sh -print -quit)"
  if [[ -z "$script_path" ]]; then
    err "找不到 realm_agent.sh，无法生成 Agent 安装脚本"
    exit 1
  fi
  cp -a "$script_path" /opt/realm-panel/panel/static/realm_agent.sh
  ok "Agent 离线包就绪：/opt/realm-panel/panel/static/realm-agent.zip"
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
EnvironmentFile=-/etc/realm-panel/panel.env
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
  echo "Realm Pro Panel 安装向导 ${VERSION}"
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
  if [[ -z "$EXTRACT_ROOT" || ! -d "$EXTRACT_ROOT" ]]; then
    err "解压目录不存在：$EXTRACT_ROOT"
    exit 1
  fi
  ok "已定位 panel 目录：$PANEL_DIR"

  local user pass port
  user="$(prompt "设置面板登录用户名" "admin")"
  while true; do
    pass="$(prompt_secret "设置面板登录密码（输入时不显示，必填）")"
    [[ -n "$pass" ]] || { err "密码不能为空"; continue; }
    if [[ ${#pass} -lt 6 ]]; then
      err "密码至少 6 位"
      continue
    fi
    local pass2
    pass2="$(prompt_secret "再次输入密码确认")"
    [[ "$pass" == "$pass2" ]] || { err "两次输入的密码不一致"; continue; }
    break
  done
  port="$(prompt "面板端口" "6080")"

  # ✅ 新增：是否为公网 IP
  # - 是：继续询问是否输入域名（反代/HTTPS）；否则使用公网 IP+端口
  # - 否：后续给节点拉取安装文件统一走 GitHub（包括 agent），面板仅用于控制/上报
  local is_public asset_source
  is_public="$(prompt "当前面板机器是否为公网 IP？(y/n)" "y")"
  is_public="${is_public,,}"
  if [[ "$is_public" == "n" || "$is_public" == "no" || "$is_public" == "0" ]]; then
    asset_source="github"
  else
    asset_source="panel"
  fi

  local panel_domain public_url
  if [[ "$asset_source" == "panel" ]]; then
    panel_domain="$(prompt "面板域名/外网地址（可选：反向代理/HTTPS 场景；留空使用 IP+端口）" "")"
    if [[ -n "$panel_domain" ]]; then
      public_url="$(normalize_public_url "$panel_domain")"
    else
      public_url="http://$(detect_ip):${port}"
    fi
  else
    panel_domain=""
    public_url="http://$(detect_local_ip):${port}"
    info "检测为非公网 IP：节点安装文件将默认从 GitHub 拉取（包括 Agent/realm），面板不再作为下载源。"
  fi

  info "部署到 /opt/realm-panel ..."
  rm -rf "${PANEL_ROOT}"
  mkdir -p "${PANEL_ROOT}"
  cp -a "$PANEL_DIR" "${PANEL_ROOT}/panel"

  if [[ "$asset_source" == "panel" ]]; then
    prepare_agent_bundle "$EXTRACT_ROOT"
    prepare_realm_assets
  else
    # 仍确保静态目录存在（面板自身静态资源需要）
    mkdir -p "${PANEL_ROOT}/panel/static"
  fi

  info "创建虚拟环境..."
  python3 -m venv "${PANEL_ROOT}/venv"
  install_python_deps

  info "初始化面板配置..."
  mkdir -p /etc/realm-panel
  cat > /etc/realm-panel/panel.env <<EOF
REALM_PANEL_PUBLIC_URL=${public_url}
REALM_PANEL_DB=/etc/realm-panel/panel.db
REALM_PANEL_ASSET_SOURCE=${asset_source}
EOF
  export PANEL_USER="$user"
  export PANEL_PASS="$pass"
  ( cd "${PANEL_ROOT}/panel" && "${PANEL_ROOT}/venv/bin/python" - <<'PY'
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
  echo "访问地址：${public_url}"
  echo "用户名：${user}"
  echo "密码：（你刚刚设置的）"
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
  if [[ -z "$EXTRACT_ROOT" || ! -d "$EXTRACT_ROOT" ]]; then
    err "解压目录不存在：$EXTRACT_ROOT"
    exit 1
  fi
  ok "已定位 panel 目录：$PANEL_DIR"
  info "更新面板程序文件..."
  rm -rf "${PANEL_ROOT}/panel"
  mkdir -p "${PANEL_ROOT}"
  cp -a "$PANEL_DIR" "${PANEL_ROOT}/panel"
  prepare_agent_bundle "$EXTRACT_ROOT"
  prepare_realm_assets
  if [[ ! -x "${PANEL_ROOT}/venv/bin/python" ]]; then
    info "虚拟环境不存在，重新创建..."
    python3 -m venv "${PANEL_ROOT}/venv"
  fi
  install_python_deps
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
