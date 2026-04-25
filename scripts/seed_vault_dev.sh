#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

export VAULT_ADDR="http://127.0.0.1:8200"
export VAULT_TOKEN="root"

TENANT_ID="t1"
DEVICE="laptop-1"
KEY_FILE="$ROOT/secrets/$TENANT_ID/devices/$DEVICE.key"
VAULT_KV_PATH="secret/$TENANT_ID/devices/$DEVICE"

if [[ ! -f "$KEY_FILE" ]]; then
  exit 1
fi

if command -v vault >/dev/null 2>&1; then
  if vault kv get -field=key "$VAULT_KV_PATH" >/dev/null 2>&1; then
    echo "EXISTS"
    exit 0
  fi

  vault kv put "$VAULT_KV_PATH" key="$(tr -d '\r\n' < "$KEY_FILE")" >/dev/null
  echo "SEEDED"
  exit 0
fi

status="$(
  curl --silent --show-error \
    --output /tmp/usbay-vault-device-key-check.json \
    --write-out "%{http_code}" \
    --header "X-Vault-Token: ${VAULT_TOKEN}" \
    "${VAULT_ADDR}/v1/secret/data/${TENANT_ID}/devices/${DEVICE}"
)"

if [[ "$status" == "200" ]]; then
  echo "EXISTS"
  exit 0
fi

if [[ "$status" != "404" ]]; then
  exit 1
fi

python3 - "$KEY_FILE" <<'PY' | curl --silent --show-error --fail \
  --header "X-Vault-Token: root" \
  --header "Content-Type: application/json" \
  --request POST \
  --data-binary @- \
  "http://127.0.0.1:8200/v1/secret/data/t1/devices/laptop-1" >/dev/null
import json
import sys
from pathlib import Path

key = Path(sys.argv[1]).read_text(encoding="utf-8").strip()
print(json.dumps({"data": {"key": key}}, separators=(",", ":")))
PY

echo "SEEDED"
