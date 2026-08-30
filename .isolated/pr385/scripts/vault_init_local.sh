#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

INIT_OUTPUT="$ROOT/vault/init-output.json"
ENV_FILE="$ROOT/.env"

mkdir -p "$ROOT/vault/data"
if [ ! -f "$ENV_FILE" ]; then
  : > "$ENV_FILE"
  chmod 600 "$ENV_FILE"
fi

docker compose up -d vault

for _ in $(seq 1 30); do
  if docker compose exec -T vault vault status >/dev/null 2>&1; then
    break
  fi

  status=$?
  if [ "$status" -eq 2 ]; then
    break
  fi

  sleep 1
done

if [ ! -f "$INIT_OUTPUT" ]; then
  if docker compose exec -T vault vault status 2>/dev/null | grep -q "Initialized.*true"; then
    echo "FAIL_CLOSED: Vault is initialized but vault/init-output.json is missing."
    echo "Provide VAULT_TOKEN in .env and unseal Vault manually, or reset local vault/data."
    exit 1
  fi

  docker compose exec -T vault vault operator init -format=json > "$INIT_OUTPUT"
  chmod 600 "$INIT_OUTPUT"
fi

python3 <<'PY'
import json
from pathlib import Path

root = Path.cwd()
init_output = root / "vault" / "init-output.json"
env_file = root / ".env"

data = json.loads(init_output.read_text(encoding="utf-8"))
token = data["root_token"]
keys = data["unseal_keys_b64"][:3]

env = {}
if env_file.exists():
    for line in env_file.read_text(encoding="utf-8").splitlines():
        if not line.strip() or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        env[key] = value

env["VAULT_TOKEN"] = token
env["USBAY_MODE"] = "PROD"
env["USBAY_SECRET_PROVIDER"] = "vault"

env_file.write_text(
    "".join(f"{key}={value}\n" for key, value in env.items()),
    encoding="utf-8",
)
env_file.chmod(0o600)

(root / "vault" / ".unseal-keys.tmp").write_text("\n".join(keys), encoding="utf-8")
PY

while IFS= read -r key; do
  docker compose exec -T vault sh -c 'vault operator unseal "$1" >/dev/null' sh "$key"
done < "$ROOT/vault/.unseal-keys.tmp"
rm -f "$ROOT/vault/.unseal-keys.tmp"

echo "Vault initialized and unsealed. VAULT_TOKEN was written to .env without printing it."
