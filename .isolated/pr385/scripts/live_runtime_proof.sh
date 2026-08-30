#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

if [[ -f "venv/bin/activate" ]]; then
  # shellcheck disable=SC1091
  source "venv/bin/activate"
elif [[ -f ".venv/bin/activate" ]]; then
  # shellcheck disable=SC1091
  source ".venv/bin/activate"
fi

export PYTHONPATH="$ROOT"
export REDIS_URL="${REDIS_URL:-redis://127.0.0.1:6379/0}"
export USBAY_DECISION_SIGNING_KEY="${USBAY_DECISION_SIGNING_KEY:-usbay-live-runtime-proof-signing-key}"

GATEWAY_HOST="127.0.0.1"
GATEWAY_PORT="8001"
GATEWAY_URL="http://${GATEWAY_HOST}:${GATEWAY_PORT}"
PROOF_FILE="$ROOT/AUDIT_PROOF.txt"
TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/usbay-live-proof.XXXXXX")"
UVICORN_PID=""
OUTCOMES=()

record() {
  OUTCOMES+=("$1")
}

write_proof() {
  local summary="$1"
  {
    echo "USBAY LIVE RUNTIME PROOF"
    echo "timestamp=$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
    echo "endpoint_tested=${GATEWAY_URL}"
    echo
    echo "outcomes:"
    for outcome in "${OUTCOMES[@]}"; do
      echo "- ${outcome}"
    done
    echo
    echo "summary=${summary}"
    echo "secrets_logged=false"
  } > "$PROOF_FILE"
}

cleanup() {
  if [[ -n "$UVICORN_PID" ]]; then
    kill "$UVICORN_PID" >/dev/null 2>&1 || true
    wait "$UVICORN_PID" 2>/dev/null || true
  fi
  if [[ -n "${TMP_DIR:-}" && -d "$TMP_DIR" ]]; then
    find "$TMP_DIR" -mindepth 1 -maxdepth 1 -delete
    rmdir "$TMP_DIR"
  fi
}
trap cleanup EXIT

fail() {
  record "FAIL: $1"
  write_proof "FAIL"
  echo "FAIL: $1" >&2
  echo "proof_file=${PROOF_FILE}" >&2
  exit 1
}

require_command() {
  command -v "$1" >/dev/null 2>&1 || fail "$2"
}

json_field() {
  python3 - "$1" "$2" <<'PY'
import json
import sys

with open(sys.argv[1], "r", encoding="utf-8") as handle:
    data = json.load(handle)
value = data.get(sys.argv[2], "")
if isinstance(value, bool):
    print("true" if value else "false")
else:
    print(value)
PY
}

assert_json() {
  local file="$1"
  local reason="$2"
  python3 - "$file" <<'PY' || fail "$reason"
import json
import sys

with open(sys.argv[1], "r", encoding="utf-8") as handle:
    json.load(handle)
PY
}

http_post() {
  local path="$1"
  local payload_file="$2"
  local body_file="$3"
  local code_file="$4"

  curl -sS \
    -X POST "${GATEWAY_URL}${path}" \
    -H "Content-Type: application/json" \
    --data-binary "@${payload_file}" \
    -w "%{http_code}" \
    -o "$body_file" > "$code_file" || fail "gateway_unreachable"
}

make_signed_payload() {
  local output_file="$1"
  local command_text="$2"
  python3 - "$output_file" "$command_text" <<'PY'
import hashlib
import hmac
import json
import sys
import time
import uuid
from pathlib import Path

key = Path("secrets/t1/devices/laptop-1.key").read_bytes().strip()
payload = {
    "type": "execution",
    "action": "execute_command",
    "actor_id": "live-runtime-proof-actor",
    "command": sys.argv[2],
    "device": "laptop-1",
    "nonce": f"live-proof-{uuid.uuid4()}",
    "tenant_id": "t1",
    "timestamp": int(time.time()),
    "user_id": "live-runtime-proof",
    "policy_version": "policy-v1",
}
message = json.dumps(payload, sort_keys=True, separators=(",", ":"))
payload["signature"] = hmac.new(key, message.encode("utf-8"), hashlib.sha256).hexdigest()
Path(sys.argv[1]).write_text(json.dumps(payload, separators=(",", ":")), encoding="utf-8")
PY
}

attach_decision() {
  local payload_file="$1"
  local decision_id="$2"
  local decision_signature_classic="$3"
  local decision_signature_pqc="$4"
  local output_file="$5"
  python3 - "$payload_file" "$decision_id" "$decision_signature_classic" "$decision_signature_pqc" "$output_file" <<'PY'
import json
import sys

with open(sys.argv[1], "r", encoding="utf-8") as handle:
    payload = json.load(handle)
payload["decision_id"] = sys.argv[2]
payload["decision_signature"] = sys.argv[3]
payload["decision_signature_classic"] = sys.argv[3]
payload["decision_signature_pqc"] = sys.argv[4]
with open(sys.argv[5], "w", encoding="utf-8") as handle:
    json.dump(payload, handle, separators=(",", ":"))
PY
}

require_command curl "gateway_unreachable"
require_command python3 "gateway_unreachable"
require_command redis-cli "redis_unavailable"
require_command redis-server "redis_unavailable"

if ! redis-cli -u "$REDIS_URL" ping >/dev/null 2>&1 && ! redis-cli ping >/dev/null 2>&1; then
  redis-server --daemonize yes >/dev/null 2>&1 || fail "redis_unavailable"
  for _ in $(seq 1 30); do
    if redis-cli -u "$REDIS_URL" ping >/dev/null 2>&1 || redis-cli ping >/dev/null 2>&1; then
      break
    fi
    sleep 1
  done
fi

REDIS_PING="$(redis-cli -u "$REDIS_URL" ping 2>/dev/null || redis-cli ping 2>/dev/null || true)"
if [[ "$REDIS_PING" != "PONG" ]]; then
  fail "redis_unavailable"
fi
record "redis_ping=PONG"

if command -v lsof >/dev/null 2>&1; then
  EXISTING_PIDS="$(lsof -ti "tcp:${GATEWAY_PORT}" -sTCP:LISTEN || true)"
  if [[ -n "$EXISTING_PIDS" ]]; then
    for pid in $EXISTING_PIDS; do
      kill "$pid" >/dev/null 2>&1 || true
    done
    sleep 1
  fi
elif command -v fuser >/dev/null 2>&1; then
  fuser -k "${GATEWAY_PORT}/tcp" >/dev/null 2>&1 || true
  sleep 1
fi

python3 -m uvicorn gateway.app:app \
  --host "$GATEWAY_HOST" \
  --port "$GATEWAY_PORT" \
  > "$TMP_DIR/uvicorn.log" 2>&1 &
UVICORN_PID="$!"
record "uvicorn_started=true port=${GATEWAY_PORT}"

for _ in $(seq 1 30); do
  if curl -fsS "${GATEWAY_URL}/openapi.json" >/dev/null 2>&1; then
    break
  fi
  if ! kill -0 "$UVICORN_PID" >/dev/null 2>&1; then
    fail "gateway_unreachable"
  fi
  sleep 1
done

if ! curl -fsS "${GATEWAY_URL}/openapi.json" >/dev/null 2>&1; then
  fail "gateway_unreachable"
fi
record "gateway_openapi=reachable"

make_signed_payload "$TMP_DIR/decide_payload.json" "bash -lc 'echo blocked-by-usbay'"
http_post "/decide" "$TMP_DIR/decide_payload.json" "$TMP_DIR/decide_body.json" "$TMP_DIR/decide_code.txt"
assert_json "$TMP_DIR/decide_body.json" "decide_not_json"
DECIDE_CODE="$(cat "$TMP_DIR/decide_code.txt")"
DECISION_ID="$(json_field "$TMP_DIR/decide_body.json" decision_id)"
DECISION_SIGNATURE_CLASSIC="$(json_field "$TMP_DIR/decide_body.json" decision_signature_classic)"
DECISION_SIGNATURE_PQC="$(json_field "$TMP_DIR/decide_body.json" decision_signature_pqc)"
if [[ "$DECIDE_CODE" != "200" || -z "$DECISION_ID" || -z "$DECISION_SIGNATURE_CLASSIC" || -z "$DECISION_SIGNATURE_PQC" ]]; then
  fail "decide_not_json"
fi
python3 - "$DECISION_ID" <<'PY' || fail "decide_not_json"
import sys
import uuid

uuid.UUID(sys.argv[1])
PY
record "decide_http=200 decision_id_is_uuid=true signature_present=true"

attach_decision "$TMP_DIR/decide_payload.json" "$DECISION_ID" "$DECISION_SIGNATURE_CLASSIC" "$DECISION_SIGNATURE_PQC" "$TMP_DIR/execute_payload.json"
http_post "/execute" "$TMP_DIR/execute_payload.json" "$TMP_DIR/execute1_body.json" "$TMP_DIR/execute1_code.txt"
assert_json "$TMP_DIR/execute1_body.json" "policy_denied_missing"
EXECUTE1_CODE="$(cat "$TMP_DIR/execute1_code.txt")"
EXECUTE1_REASON="$(json_field "$TMP_DIR/execute1_body.json" error)"
if [[ "$EXECUTE1_CODE" != "403" || "$EXECUTE1_REASON" != "policy_denied" ]]; then
  fail "policy_denied_missing"
fi
record "execute_first_http=403 reason=policy_denied"

http_post "/execute" "$TMP_DIR/execute_payload.json" "$TMP_DIR/execute2_body.json" "$TMP_DIR/execute2_code.txt"
assert_json "$TMP_DIR/execute2_body.json" "replay_missing"
EXECUTE2_CODE="$(cat "$TMP_DIR/execute2_code.txt")"
EXECUTE2_REASON="$(json_field "$TMP_DIR/execute2_body.json" error)"
if [[ "$EXECUTE2_CODE" != "403" || "$EXECUTE2_REASON" != "replay_detected" ]]; then
  fail "replay_missing"
fi
record "execute_second_http=403 reason=replay_detected"

make_signed_payload "$TMP_DIR/tamper_decide_payload.json" "bash -lc 'echo blocked-by-usbay-tamper'"
http_post "/decide" "$TMP_DIR/tamper_decide_payload.json" "$TMP_DIR/tamper_decide_body.json" "$TMP_DIR/tamper_decide_code.txt"
assert_json "$TMP_DIR/tamper_decide_body.json" "tamper_missing"
TAMPER_DECIDE_CODE="$(cat "$TMP_DIR/tamper_decide_code.txt")"
TAMPER_DECISION_ID="$(json_field "$TMP_DIR/tamper_decide_body.json" decision_id)"
TAMPER_DECISION_SIGNATURE_CLASSIC="$(json_field "$TMP_DIR/tamper_decide_body.json" decision_signature_classic)"
TAMPER_DECISION_SIGNATURE_PQC="$(json_field "$TMP_DIR/tamper_decide_body.json" decision_signature_pqc)"
if [[ "$TAMPER_DECIDE_CODE" != "200" || -z "$TAMPER_DECISION_ID" || -z "$TAMPER_DECISION_SIGNATURE_CLASSIC" || -z "$TAMPER_DECISION_SIGNATURE_PQC" ]]; then
  fail "tamper_missing"
fi
attach_decision "$TMP_DIR/tamper_decide_payload.json" "$TAMPER_DECISION_ID" "abc123X" "$TAMPER_DECISION_SIGNATURE_PQC" "$TMP_DIR/tampered_payload.json"
http_post "/execute" "$TMP_DIR/tampered_payload.json" "$TMP_DIR/tampered_body.json" "$TMP_DIR/tampered_code.txt"
assert_json "$TMP_DIR/tampered_body.json" "tamper_missing"
TAMPERED_CODE="$(cat "$TMP_DIR/tampered_code.txt")"
TAMPERED_REASON="$(json_field "$TMP_DIR/tampered_body.json" error)"
if [[ "$TAMPERED_CODE" != "403" || "$TAMPERED_REASON" != "invalid_signature" ]]; then
  fail "tamper_missing"
fi
record "execute_tampered_http=403 reason=invalid_signature"

python3 - "$TMP_DIR/execute_payload.json" "$TMP_DIR/unknown_payload.json" <<'PY'
import json
import sys
import uuid

with open(sys.argv[1], "r", encoding="utf-8") as handle:
    payload = json.load(handle)
payload["decision_id"] = str(uuid.uuid4())
with open(sys.argv[2], "w", encoding="utf-8") as handle:
    json.dump(payload, handle, separators=(",", ":"))
PY
http_post "/execute" "$TMP_DIR/unknown_payload.json" "$TMP_DIR/unknown_body.json" "$TMP_DIR/unknown_code.txt"
assert_json "$TMP_DIR/unknown_body.json" "unknown_missing"
UNKNOWN_CODE="$(cat "$TMP_DIR/unknown_code.txt")"
UNKNOWN_REASON="$(json_field "$TMP_DIR/unknown_body.json" error)"
if [[ "$UNKNOWN_CODE" != "403" || "$UNKNOWN_REASON" != "unknown_decision" ]]; then
  fail "unknown_missing"
fi
record "execute_unknown_http=403 reason=unknown_decision"

write_proof "PASS"
echo "PASS"
echo "proof_file=${PROOF_FILE}"
