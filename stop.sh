#!/usr/bin/env bash
# Stop the Hybrid IDS dashboard launched by start.sh
set -u

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PORT="${PORT:-8050}"
PID_FILE="${PROJECT_DIR}/.dashboard.pid"

if [[ -f "${PID_FILE}" ]]; then
  PID=$(cat "${PID_FILE}" 2>/dev/null || true)
  if [[ -n "${PID:-}" ]] && kill -0 "${PID}" 2>/dev/null; then
    echo "[stop] killing pid ${PID}"
    kill "${PID}" 2>/dev/null || true
    sleep 1
    kill -9 "${PID}" 2>/dev/null || true
  fi
  rm -f "${PID_FILE}"
fi

if command -v fuser >/dev/null 2>&1; then
  fuser -k "${PORT}/tcp" >/dev/null 2>&1 || true
fi
if command -v lsof >/dev/null 2>&1; then
  lsof -i ":${PORT}" -t 2>/dev/null | xargs -r kill -9 2>/dev/null || true
fi

echo "[stop] port ${PORT} cleared."
