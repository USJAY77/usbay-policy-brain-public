#!/usr/bin/env bash
# USBAY TMUX RUNTIME SUPERVISOR — start
# Creates the local development/runtime session "usbay-runtime" with four
# isolated panes: gateway, tests, audit-log, health-watch.
#
# SAFETY BOUNDARIES (fail-closed):
# - Local development supervision only. No production commands.
# - No provider/API/LLM calls. No credentials or secrets are read or printed.
# - Does not alter governance decision logic; it only runs existing local
#   commands that are already safe (uvicorn dev server, pytest, log tail,
#   read-only health polling).
set -euo pipefail

SESSION="usbay-runtime"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
GATEWAY_PORT="${PORT:-5000}"
AUDIT_LOG="${ROOT}/evidence/audit/GAME_DEMO_STABILITY_GATE_010R.md"

fail() { echo "usbay_tmux_start: ERROR: $*" >&2; exit 1; }

command -v tmux >/dev/null 2>&1 \
  || fail "tmux is not installed. Fail-closed: refusing to continue. Install tmux locally first."

tmux has-session -t "$SESSION" 2>/dev/null \
  && fail "session '$SESSION' already exists. Run scripts/usbay_tmux_status.sh or stop it first."

# Pane 0: gateway (local dev server only — binds localhost dev port)
tmux new-session -d -s "$SESSION" -n runtime -c "$ROOT" \
  "echo '[gateway pane] local dev server (no production activation)'; \
   python3 -m uvicorn gateway.app:app --host 127.0.0.1 --port ${GATEWAY_PORT}"

# Pane 1: tests (idle shell prepared with the standard local suites)
tmux split-window -t "$SESSION":0 -h -c "$ROOT" \
  "echo '[tests pane] run: pytest tests/test_api_route_precedence.py tests/test_live_api_routing.py -q -p no:cacheprovider'; \
   exec bash"

# Pane 2: audit-log (read-only tail of the local audit evidence file)
tmux split-window -t "$SESSION":0.0 -v -c "$ROOT" \
  "echo '[audit-log pane] read-only tail'; \
   tail -n 40 -F '${AUDIT_LOG}' 2>/dev/null || { echo 'audit log not present yet (read-only pane, nothing created)'; exec bash; }"

# Pane 3: health-watch (read-only GET polling of local health endpoints)
tmux split-window -t "$SESSION":0.1 -v -c "$ROOT" \
  "echo '[health-watch pane] read-only local polling'; \
   while true; do \
     printf '%s health=%s runtime=%s execute_get=%s\n' \
       \"\$(date -u +%H:%M:%SZ)\" \
       \"\$(curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:${GATEWAY_PORT}/health)\" \
       \"\$(curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:${GATEWAY_PORT}/api/runtime/health)\" \
       \"\$(curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:${GATEWAY_PORT}/execute)\"; \
     sleep 10; \
   done"

tmux select-pane -t "$SESSION":0.0
echo "usbay_tmux_start: session '$SESSION' created (panes: gateway, tests, audit-log, health-watch)."
echo "usbay_tmux_start: attach with: tmux attach -t $SESSION"
