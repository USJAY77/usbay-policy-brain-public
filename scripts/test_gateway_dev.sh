#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

BASE_URL="${BASE_URL:-http://127.0.0.1:8000/execute}"
FAILURES=0

check_status() {
  local name="$1"
  local expected="$2"
  local body="$3"

  local response
  local status
  response="$(curl -sS -w $'\n%{http_code}' -X POST "$BASE_URL" \
    -H "Content-Type: application/json" \
    -d "$body")"
  status="${response##*$'\n'}"

  if [[ "$status" == "$expected" ]]; then
    echo "PASS ${name}: HTTP ${status}"
  else
    echo "FAIL ${name}: expected HTTP ${expected}, got HTTP ${status}"
    echo "${response%$'\n'*}"
    FAILURES=$((FAILURES + 1))
  fi
}

echo "==== USBAY DEV GATEWAY TEST ===="

check_status "unsigned read allowed" "200" \
  '{"action":"read","user_id":"u1","device":"laptop-1"}'

check_status "unsigned delete blocked" "403" \
  '{"action":"delete","user_id":"u1","device":"laptop-1"}'

if [[ "$FAILURES" -eq 0 ]]; then
  echo "PASS DEV gateway checks"
else
  echo "FAIL DEV gateway checks: ${FAILURES} failure(s)"
  exit 1
fi
