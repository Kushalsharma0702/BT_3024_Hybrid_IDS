#!/usr/bin/env bash
# Hybrid IDS — one-shot startup script
set -u

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PORT="${PORT:-8050}"
HOST="${HOST:-127.0.0.1}"
LOG_FILE="${PROJECT_DIR}/dashboard.log"

cd "${PROJECT_DIR}"

if [[ -t 1 ]]; then
  C_GREEN=$'\e[32m'; C_BLUE=$'\e[34m'; C_YELLOW=$'\e[33m'
  C_RED=$'\e[31m';   C_BOLD=$'\e[1m';   C_OFF=$'\e[0m'
else
  C_GREEN=""; C_BLUE=""; C_YELLOW=""; C_RED=""; C_BOLD=""; C_OFF=""
fi

log(){  printf "%s[ids]%s %s\n"  "${C_BLUE}"   "${C_OFF}" "$*"; }
ok(){   printf "%s[ok ]%s %s\n"  "${C_GREEN}"  "${C_OFF}" "$*"; }
warn(){ printf "%s[warn]%s %s\n" "${C_YELLOW}" "${C_OFF}" "$*"; }
err(){  printf "%s[err]%s %s\n"  "${C_RED}"    "${C_OFF}" "$*" >&2; }

pick_python(){
  for cand in \
      "${PROJECT_DIR}/.venv/bin/python" \
      "${PROJECT_DIR}/venv/bin/python" \
      "/bin/python" \
      "/usr/bin/python3" \
      "$(command -v python3)" \
      "$(command -v python)"; do
    [[ -x "${cand}" ]] || continue
    if "${cand}" - <<'PY' >/dev/null 2>&1
import flask, sklearn, joblib  # noqa
PY
    then
      printf "%s" "${cand}"
      return 0
    fi
  done
  return 1
}

free_port(){
  if command -v lsof >/dev/null 2>&1 && lsof -i ":${PORT}" -t >/dev/null 2>&1; then
    warn "port ${PORT} busy — killing prior process(es)"
    lsof -i ":${PORT}" -t | xargs -r kill -9 2>/dev/null || true
    sleep 1
  fi
  if command -v fuser >/dev/null 2>&1; then
    fuser -k "${PORT}/tcp" >/dev/null 2>&1 || true
  fi
  sleep 1
}

wait_ready(){
  local url="http://${HOST}:${PORT}/api/live"
  for i in $(seq 1 30); do
    curl -sf "${url}" >/dev/null 2>&1 && return 0
    sleep 0.5
  done
  return 1
}

printf "\n%s%s════════════════════════════════════════════════════%s\n"   "${C_BOLD}" "${C_BLUE}" "${C_OFF}"
printf "%s%s   Hybrid IDS — Security Dashboard Launcher%s\n"               "${C_BOLD}" "${C_BLUE}" "${C_OFF}"
printf "%s%s════════════════════════════════════════════════════%s\n\n"    "${C_BOLD}" "${C_BLUE}" "${C_OFF}"

log "project dir : ${PROJECT_DIR}"
log "host:port   : ${HOST}:${PORT}"
log "log file    : ${LOG_FILE}"
echo

log "step 1/4 — selecting python interpreter…"
PY="$(pick_python)" || { err "no python with flask+sklearn found"; exit 1; }
ok "using ${PY}"

log "step 2/4 — freeing port ${PORT}…"
free_port
ok "port ${PORT} ready"

log "step 3/4 — booting dashboard…"
: > "${LOG_FILE}"
nohup "${PY}" "${PROJECT_DIR}/ids_dashboard.py" >>"${LOG_FILE}" 2>&1 &
PID=$!
echo "${PID}" > "${PROJECT_DIR}/.dashboard.pid"
ok "spawned pid=${PID}"

log "step 4/4 — waiting for http://${HOST}:${PORT} to respond…"
if ! wait_ready; then
  err "dashboard did not respond in 15 s. last log lines:"
  tail -n 30 "${LOG_FILE}" >&2
  exit 1
fi

ALERTS=$(curl -s "http://${HOST}:${PORT}/api/live" | "${PY}" -c \
  "import json,sys;print(json.load(sys.stdin)['summary']['total_alerts'])" 2>/dev/null || echo "?")
RUNS=$(curl -s "http://${HOST}:${PORT}/api/history" | "${PY}" -c \
  "import json,sys;print(len(json.load(sys.stdin).get('runs',[])))" 2>/dev/null || echo "?")

printf "\n%s%s════════════════════════════════════════════════════%s\n"   "${C_BOLD}" "${C_GREEN}" "${C_OFF}"
printf "%s%s   ✓ DASHBOARD UP AND HEALTHY%s\n"                            "${C_BOLD}" "${C_GREEN}" "${C_OFF}"
printf "%s%s════════════════════════════════════════════════════%s\n"    "${C_BOLD}" "${C_GREEN}" "${C_OFF}"
printf "   URL          : %shttp://%s:%s%s\n" "${C_BOLD}" "${HOST}" "${PORT}" "${C_OFF}"
printf "   PID          : %s\n" "${PID}"
printf "   Live alerts  : %s\n" "${ALERTS}"
printf "   History runs : %s\n" "${RUNS}"
printf "   Live logs    : tail -f %s\n" "${LOG_FILE}"
printf "   Stop server  : ./stop.sh    (or kill %s)\n\n" "${PID}"

printf "%sTip:%s if the page looks empty, hard-refresh with %sCtrl+Shift+R%s\n" \
  "${C_YELLOW}" "${C_OFF}" "${C_BOLD}" "${C_OFF}"
printf "     or open %shttp://%s:%s%s in an incognito window.\n\n"          \
  "${C_BOLD}" "${HOST}" "${PORT}" "${C_OFF}"
