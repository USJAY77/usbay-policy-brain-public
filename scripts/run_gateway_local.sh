#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

PORT="${PORT:-8000}"

existing_pids="$(lsof -ti tcp:${PORT} -sTCP:LISTEN || true)"
if [[ -n "$existing_pids" ]]; then
  echo "Stopping existing gateway process on port ${PORT}: ${existing_pids}"
  for pid in $existing_pids; do
    command="$(ps -p "$pid" -o command= || true)"
    if [[ "$command" != *"uvicorn"* || "$command" != *"gateway.app:app"* ]]; then
      echo "Port ${PORT} is occupied by a non-gateway process: ${command}" >&2
      exit 1
    fi
    kill "$pid" 2>/dev/null || true
  done
  sleep 1
fi

remaining_pids="$(lsof -ti tcp:${PORT} -sTCP:LISTEN || true)"
if [[ -n "$remaining_pids" ]]; then
  echo "Unable to stop existing gateway process on port ${PORT}: ${remaining_pids}" >&2
  exit 1
fi

echo "Starting exactly one gateway server on http://127.0.0.1:${PORT}"
echo "Use another terminal for curl tests."
exec python3 -m uvicorn gateway.app:app --host 127.0.0.1 --port "$PORT"
