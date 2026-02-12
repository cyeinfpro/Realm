#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DEFAULT="$(cd "${SCRIPT_DIR}/.." && pwd)"
ROOT="${REALM_PANEL_ROOT:-${ROOT:-${ROOT_DEFAULT}}}"
HOST="${REALM_PANEL_HOST:-0.0.0.0}"
PORT="${REALM_PANEL_PORT:-6080}"
PYTHON_BIN="${ROOT}/venv/bin/python"
APP="app.main:app"
CRASH_LOG_FILE="${REALM_PANEL_CRASH_LOG_FILE:-/var/log/realm-panel/crash.log}"
CRASH_LOG_MAX_BYTES="${REALM_PANEL_CRASH_LOG_MAX_BYTES:-5242880}"
CRASH_LOG_BACKUP_COUNT="${REALM_PANEL_CRASH_LOG_BACKUP_COUNT:-5}"

parse_int() {
  local raw="${1:-}"
  local fallback="${2:-0}"
  if [[ "${raw}" =~ ^[0-9]+$ ]]; then
    printf '%s\n' "${raw}"
    return 0
  fi
  printf '%s\n' "${fallback}"
}

rotate_log_if_needed() {
  local path="${1:-}"
  local max_bytes backups size i
  [[ -n "${path}" ]] || return 0
  [[ -f "${path}" ]] || return 0
  max_bytes="$(parse_int "${CRASH_LOG_MAX_BYTES}" "5242880")"
  backups="$(parse_int "${CRASH_LOG_BACKUP_COUNT}" "5")"
  (( max_bytes >= 1024 )) || max_bytes=1024
  (( backups >= 1 )) || backups=1
  size="$(wc -c < "${path}" 2>/dev/null || echo 0)"
  [[ "${size}" =~ ^[0-9]+$ ]] || size=0
  (( size >= max_bytes )) || return 0
  for ((i = backups; i >= 2; i--)); do
    if [[ -f "${path}.$((i - 1))" ]]; then
      mv -f "${path}.$((i - 1))" "${path}.${i}" 2>/dev/null || true
    fi
  done
  mv -f "${path}" "${path}.1" 2>/dev/null || true
}

log_startup_crash() {
  local message="${1:-unknown startup failure}"
  local log_file="${CRASH_LOG_FILE}"
  local now
  now="$(date '+%Y-%m-%d %H:%M:%S%z' 2>/dev/null || true)"
  mkdir -p "$(dirname "${log_file}")" 2>/dev/null || true
  rotate_log_if_needed "${log_file}"
  printf '%s CRITICAL %s\n' "${now}" "${message}" >> "${log_file}" 2>/dev/null || true
}

APP_DIR=""
for CANDIDATE in \
  "${ROOT}/panel" \
  "${ROOT}" \
  "${SCRIPT_DIR}" \
  "${SCRIPT_DIR}/panel"
do
  if [[ -d "${CANDIDATE}/app" ]]; then
    APP_DIR="${CANDIDATE}"
    break
  fi
done

if [[ -z "${APP_DIR}" ]]; then
  echo "panel app directory not found. ROOT=${ROOT} SCRIPT_DIR=${SCRIPT_DIR}" >&2
  log_startup_crash "panel app directory not found ROOT=${ROOT} SCRIPT_DIR=${SCRIPT_DIR}"
  for CANDIDATE in "${ROOT}" "${ROOT}/panel" "${ROOT}/app" "${SCRIPT_DIR}" "${SCRIPT_DIR}/panel"; do
    if [[ -e "${CANDIDATE}" ]]; then
      echo "  exists: ${CANDIDATE}" >&2
    fi
  done
  exit 1
fi

if [[ ! -x "${PYTHON_BIN}" ]]; then
  echo "python runtime missing: ${PYTHON_BIN}" >&2
  log_startup_crash "python runtime missing ${PYTHON_BIN}"
  exit 1
fi

cd "${APP_DIR}"
exec "${PYTHON_BIN}" -m uvicorn "$APP" --host "$HOST" --port "$PORT" --proxy-headers
