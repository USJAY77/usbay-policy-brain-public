#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

BASE_URL="${BASE_URL:-http://127.0.0.1:8000}"

echo "ALLOW request:"
allow_response="$(curl -sS -w "\n%{http_code}" -X POST "${BASE_URL}/execute" \
  -H "Content-Type: application/json" \
  -d '{"action":"read","user_id":"local-gateway-test","device":"local-terminal"}')"
allow_body="${allow_response%$'\n'*}"
allow_status="${allow_response##*$'\n'}"
printf '%s\nHTTP %s\n\n' "$allow_body" "$allow_status"
if [[ "$allow_status" != "200" ]]; then
  echo "Expected ALLOW request to return HTTP 200" >&2
  exit 1
fi

echo "BLOCK request:"
block_response="$(curl -sS -w "\n%{http_code}" -X POST "${BASE_URL}/execute" \
  -H "Content-Type: application/json" \
  -d '{"action":"write","user_id":"local-gateway-test","device":"local-terminal"}')"
block_body="${block_response%$'\n'*}"
block_status="${block_response##*$'\n'}"
printf '%s\nHTTP %s\n\n' "$block_body" "$block_status"
if [[ "$block_status" != "403" ]]; then
  echo "Expected BLOCK request to return HTTP 403" >&2
  exit 1
fi

echo "Last 5 audit log entries:"
tail -n 5 audit/audit_log.jsonl
