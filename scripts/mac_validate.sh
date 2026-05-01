#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

finish_invalid() {
  echo "MAC_VALIDATION_INVALID"
  exit 1
}
trap finish_invalid ERR

PYTHON_BIN="python3"
if [[ -x "venv/bin/python" ]]; then
  if "venv/bin/python" - <<'PY' >/dev/null 2>&1
for module in ("fastapi", "pytest", "cryptography"):
    __import__(module)
PY
  then
    PYTHON_BIN="venv/bin/python"
  fi
elif [[ -x ".venv/bin/python" ]]; then
  if ".venv/bin/python" - <<'PY' >/dev/null 2>&1
for module in ("fastapi", "pytest", "cryptography"):
    __import__(module)
PY
  then
    PYTHON_BIN=".venv/bin/python"
  fi
fi

export PYTHONPATH="$ROOT"
export PYTHONPYCACHEPREFIX="${PYTHONPYCACHEPREFIX:-/tmp/usbay-pycache}"

"$PYTHON_BIN" - <<'PY' >/dev/null
import sys
if sys.version_info < (3, 9):
    raise SystemExit(1)
for module in ("fastapi", "pytest", "cryptography"):
    __import__(module)
PY

"$PYTHON_BIN" -m py_compile gateway/app.py security/*.py scripts/*.py >/dev/null
"$PYTHON_BIN" -m pytest -q >/dev/null

USBAY_PUBLIC_RELEASE_SKIP_TESTS=1 "$PYTHON_BIN" scripts/public_release_check.py >/dev/null

bash demos/edgeguard/run_demo.sh >/dev/null
"$PYTHON_BIN" scripts/verify_decision.py demos/edgeguard/out/edgeguard_npu_allowed_export.json governance/policy_public.key >/dev/null
"$PYTHON_BIN" scripts/hydra_verify_audit.py demos/edgeguard/out/edgeguard_npu_allowed_export.json governance/policy_public.key >/dev/null

ACTOR_ENV_FILE="$(mktemp "${TMPDIR:-/tmp}/usbay-actor-env.XXXXXX")"
ACTOR_TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/usbay-actor-keys.XXXXXX")"
cleanup() {
  mkdir -p demos/edgeguard/archive
  if [[ -f demos/edgeguard/out/reset_audit.log ]]; then
    mv demos/edgeguard/out/reset_audit.log "demos/edgeguard/archive/mac_validate_reset_result_$(date +%s).log"
  fi
  if [[ -n "${ACTOR_ENV_FILE:-}" && -f "$ACTOR_ENV_FILE" ]]; then
    rm -f "$ACTOR_ENV_FILE"
  fi
  if [[ -n "${ACTOR_TMP_DIR:-}" && -d "$ACTOR_TMP_DIR" ]]; then
    find "$ACTOR_TMP_DIR" -mindepth 1 -maxdepth 1 -delete
    rmdir "$ACTOR_TMP_DIR"
  fi
}
trap cleanup EXIT

"$PYTHON_BIN" - "$ACTOR_TMP_DIR" "$ACTOR_ENV_FILE" <<'PY' >/dev/null
import json
import shlex
import sys
from pathlib import Path
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

tmp = Path(sys.argv[1])
env_file = Path(sys.argv[2])
private_key = Ed25519PrivateKey.generate()
private_pem = private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption(),
).decode("utf-8")
public_pem = private_key.public_key().public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo,
)
public_path = tmp / "actor_public.key"
config_path = tmp / "actor_keys.json"
public_path.write_bytes(public_pem)
config_path.write_text(
    json.dumps(
        {
            "active_keys": ["actor_key_2026_01"],
            "revoked_keys": [],
            "key_map": {"actor_key_2026_01": public_path.name},
            "validity": {"actor_key_2026_01": {"valid_from": 0, "valid_until": 1893456000}},
            "default_actor_pubkey_id": "actor_key_2026_01",
            "max_clock_skew_seconds": 60,
        },
        sort_keys=True,
    ),
    encoding="utf-8",
)
env_file.write_text(
    "export USBAY_ACTOR_KEYS_PATH="
    + shlex.quote(str(config_path))
    + "\nexport USBAY_ACTOR_SIGNING_KEY="
    + shlex.quote(private_pem)
    + "\n",
    encoding="utf-8",
)
PY

# shellcheck disable=SC1090
source "$ACTOR_ENV_FILE"
mkdir -p demos/edgeguard/archive
if [[ -f demos/edgeguard/out/reset_audit.log ]]; then
  mv demos/edgeguard/out/reset_audit.log "demos/edgeguard/archive/mac_validate_reset_$(date +%s).log"
fi
bash demos/edgeguard/reset_demo.sh >/dev/null
bash demos/edgeguard/reset_demo.sh --verify-log >/dev/null

trap - ERR
cleanup
echo "MAC_VALIDATION_VALID"
