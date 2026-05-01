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

GATEWAY_URL="${GATEWAY_URL:-http://127.0.0.1:8001}"
TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/usbay-metadata-live.XXXXXX")"
cleanup() {
  if [[ -n "${TMP_DIR:-}" && -d "$TMP_DIR" ]]; then
    find "$TMP_DIR" -mindepth 1 -maxdepth 1 -delete
    rmdir "$TMP_DIR"
  fi
}
trap cleanup EXIT

fail() {
  echo "FAIL: $1" >&2
  exit 1
}

make_payload() {
  local output_file="$1"
  local metadata_json="$2"
  python3 - "$output_file" "$metadata_json" <<'PY'
import hashlib
import hmac
import json
import sys
import time
import uuid
from pathlib import Path

key = Path("secrets/t1/devices/laptop-1.key").read_bytes().strip()
metadata = json.loads(sys.argv[2])
payload = {
    "type": "execution",
    "action": "execute_command",
    "actor_id": "metadata-live-proof-actor",
    "command": "python3 -m pytest tests/test_metadata_governance.py",
    "device": "laptop-1",
    "metadata": metadata,
    "nonce": f"metadata-live-{uuid.uuid4()}",
    "tenant_id": "t1",
    "timestamp": int(time.time()),
    "user_id": "metadata-live-proof",
    "policy_version": "policy-v1",
}
message = json.dumps(payload, sort_keys=True, separators=(",", ":"))
payload["signature"] = hmac.new(key, message.encode("utf-8"), hashlib.sha256).hexdigest()
Path(sys.argv[1]).write_text(json.dumps(payload, separators=(",", ":")), encoding="utf-8")
PY
}

json_field() {
  python3 - "$1" "$2" <<'PY'
import json
import sys

with open(sys.argv[1], "r", encoding="utf-8") as handle:
    data = json.load(handle)
print(data.get(sys.argv[2], ""))
PY
}

curl -fsS "${GATEWAY_URL}/openapi.json" >/dev/null 2>&1 || fail "gateway_unreachable"

make_payload "$TMP_DIR/raw_ip.json" '{"raw_ip":"203.0.113.44"}'
RAW_CODE="$(curl -sS -o "$TMP_DIR/raw_ip_response.json" -w "%{http_code}" \
  -X POST "${GATEWAY_URL}/decide" \
  -H "Content-Type: application/json" \
  --data-binary "@$TMP_DIR/raw_ip.json")"
RAW_DECISION="$(json_field "$TMP_DIR/raw_ip_response.json" decision)"
RAW_REASON="$(json_field "$TMP_DIR/raw_ip_response.json" reason)"
if [[ "$RAW_CODE" != "403" || "$RAW_DECISION" != "DENY" || "$RAW_REASON" != "metadata_forbidden:raw_ip" ]]; then
  fail "raw_ip_metadata_not_denied"
fi

make_payload "$TMP_DIR/hashed_actor.json" '{"actor_hash":"hashed-actor","request_hash":"hashed-request"}'
HASHED_CODE="$(curl -sS -o "$TMP_DIR/hashed_actor_response.json" -w "%{http_code}" \
  -X POST "${GATEWAY_URL}/decide" \
  -H "Content-Type: application/json" \
  --data-binary "@$TMP_DIR/hashed_actor.json")"
HASHED_DECISION="$(json_field "$TMP_DIR/hashed_actor_response.json" decision)"
if [[ "$HASHED_CODE" != "200" || "$HASHED_DECISION" != "ALLOW" ]]; then
  fail "hashed_actor_metadata_not_allowed"
fi

echo "PASS: raw_ip_metadata_denied"
echo "PASS: hashed_actor_metadata_allowed"
