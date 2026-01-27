#!/usr/bin/env bash
set -euo pipefail

HOST="${REALM_PANEL_HOST:-0.0.0.0}"
PORT="${REALM_PANEL_PORT:-18750}"

VENV="/opt/realm-panel/venv/bin"
APP="app.main:app"

exec "${VENV}/python" -m uvicorn "$APP" --host "$HOST" --port "$PORT" --proxy-headers
