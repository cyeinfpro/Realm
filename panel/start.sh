#!/usr/bin/env bash
set -euo pipefail
cd /opt/realm-panel
HOST=${REALM_PANEL_HOST:-0.0.0.0}
PORT=${REALM_PANEL_PORT:-18750}
exec /opt/realm-panel/venv/bin/python -m uvicorn app.main:app --host "$HOST" --port "$PORT" --proxy-headers
