#!/usr/bin/env bash
# USBAY TMUX RUNTIME SUPERVISOR — stop
# Safely stops ONLY the "usbay-runtime" session. Never touches other tmux
# sessions, never kills the tmux server, never prints environment contents.
set -euo pipefail

SESSION="usbay-runtime"

fail() { echo "usbay_tmux_stop: ERROR: $*" >&2; exit 1; }

command -v tmux >/dev/null 2>&1 \
  || fail "tmux is not installed. Fail-closed: nothing to stop, refusing to guess."

if tmux has-session -t "$SESSION" 2>/dev/null; then
  tmux kill-session -t "$SESSION"
  echo "usbay_tmux_stop: session '$SESSION' stopped."
else
  echo "usbay_tmux_stop: session '$SESSION' does not exist. Nothing to do."
fi
