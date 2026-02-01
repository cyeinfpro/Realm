#!/usr/bin/env bash
set -euo pipefail

PORT="${REALM_AGENT_PORT:-18700}"
HOST="${REALM_AGENT_HOST:-0.0.0.0}"

VENV="/opt/realm-agent/venv/bin"
APP="app.main:app"

SSL_CERT="${REALM_AGENT_SSL_CERT:-/etc/realm-agent/certs/server.crt}"
SSL_KEY="${REALM_AGENT_SSL_KEY:-/etc/realm-agent/certs/server.key}"

ARGS=("${VENV}/python" -m uvicorn "$APP" --host "$HOST" --port "$PORT" --proxy-headers)

if [[ -f "$SSL_CERT" && -f "$SSL_KEY" ]]; then
  ARGS+=(--ssl-certfile "$SSL_CERT" --ssl-keyfile "$SSL_KEY")
fi

exec "${ARGS[@]}"
