#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

if [ -f "$ROOT/.env" ]; then
  set -a
  # shellcheck disable=SC1091
  . "$ROOT/.env"
  set +a
fi

: "${VAULT_TOKEN:?FAIL_CLOSED: VAULT_TOKEN must be set in .env}"

TENANT_ID="${TENANT_ID:-t1}"
DEVICE="${DEVICE:-laptop-1}"
export TENANT_ID
export DEVICE
DEVICE_KEY_PATH="$ROOT/secrets/$TENANT_ID/devices/$DEVICE.key"

if [ ! -f "$DEVICE_KEY_PATH" ]; then
  echo "FAIL_CLOSED: missing local device key file for seeding"
  exit 1
fi

docker compose up -d vault

docker compose exec -T vault sh -c '
  export VAULT_ADDR=http://127.0.0.1:8200
  export VAULT_TOKEN="$1"
  vault secrets enable -path=secret kv-v2 >/dev/null 2>&1 || true
' sh "$VAULT_TOKEN"

docker compose exec -T vault sh -c '
  export VAULT_ADDR=http://127.0.0.1:8200
  export VAULT_TOKEN="$1"
  vault policy write "$2" - >/dev/null
' sh "$VAULT_TOKEN" "usbay-${TENANT_ID}-devices" <<EOF
path "secret/data/${TENANT_ID}/devices/*" {
  capabilities = ["create", "read", "update", "delete", "list"]
}

path "secret/metadata/${TENANT_ID}/devices/*" {
  capabilities = ["list", "read", "delete"]
}
EOF

python3 <<'PY' | curl --silent --show-error --fail \
  --header "X-Vault-Token: ${VAULT_TOKEN}" \
  --header "Content-Type: application/json" \
  --request POST \
  --data-binary @- \
  "http://127.0.0.1:8200/v1/secret/data/${TENANT_ID}/devices/${DEVICE}" >/dev/null
import json
import os
from pathlib import Path

root = Path.cwd()
tenant_id = os.environ.get("TENANT_ID", "t1")
device = os.environ.get("DEVICE", "laptop-1")
key_path = root / "secrets" / tenant_id / "devices" / f"{device}.key"
key = key_path.read_bytes().strip().decode()
print(json.dumps({"data": {"key": key}}, separators=(",", ":")))
PY

echo "Seeded Vault path secret/data/${TENANT_ID}/devices/${DEVICE} with hidden key material."
