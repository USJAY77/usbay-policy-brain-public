#!/usr/bin/env bash
# USBAY TMUX RUNTIME SUPERVISOR — status
# Reports whether the "usbay-runtime" session exists and lists its panes.
# Read-only: prints no environment variables, no secrets, no command output
# from inside the panes — only tmux structural metadata.
set -euo pipefail

SESSION="usbay-runtime"

fail() { echo "usbay_tmux_status: ERROR: $*" >&2; exit 1; }

command -v tmux >/dev/null 2>&1 \
  || fail "tmux is not installed. Fail-closed: cannot report status."

if tmux has-session -t "$SESSION" 2>/dev/null; then
  echo "usbay_tmux_status: session '$SESSION' EXISTS"
  echo "panes:"
  tmux list-panes -t "$SESSION" -F "  pane #{pane_index}: #{pane_title} (#{pane_width}x#{pane_height}, active=#{pane_active})"
  exit 0
else
  echo "usbay_tmux_status: session '$SESSION' NOT RUNNING"
  exit 1
fi
