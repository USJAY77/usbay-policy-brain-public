#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

scripts/vault_init_local.sh
scripts/vault_seed_tenant.sh
python3 scripts/sign_policy.py

docker compose up -d --build gateway

for _ in $(seq 1 30); do
  if curl --silent --fail http://127.0.0.1:8000/openapi.json >/dev/null; then
    ready=1
    break
  fi
  sleep 1
done

if [ "${ready:-0}" -ne 1 ]; then
  echo "FAIL_CLOSED: gateway did not become ready on 127.0.0.1:8000"
  exit 1
fi

python3 <<'PY'
import hashlib
import hmac
import json
import time
import urllib.error
import urllib.request
from pathlib import Path

from utils.canonical import canonical_json

ROOT = Path.cwd()
URL = "http://127.0.0.1:8000/execute"
DEVICE_KEY = (ROOT / "secrets" / "t1" / "devices" / "laptop-1.key").read_bytes().strip()


def signed_payload(action="read", timestamp=None, bad_signature=False):
    payload = {
        "action": action,
        "user_id": "u1",
        "device": "laptop-1",
        "tenant_id": "t1",
        "timestamp": int(time.time()) if timestamp is None else timestamp,
    }
    payload["signature"] = (
        "bad-signature"
        if bad_signature
        else hmac.new(DEVICE_KEY, canonical_json(payload), hashlib.sha256).hexdigest()
    )
    return payload


def post(payload):
    request = urllib.request.Request(
        URL,
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=5) as response:
            body = json.loads(response.read().decode("utf-8"))
            return response.status, body
    except urllib.error.HTTPError as exc:
        body = json.loads(exc.read().decode("utf-8"))
        return exc.code, body


def check(name, payload, expected_status, expected_detail=None):
    status, body = post(payload)
    if status == expected_status and (
        expected_detail is None or body.get("detail") == expected_detail
    ):
        print(f"PASS {name}: HTTP {status}")
        return 0
    print(f"FAIL {name}: expected HTTP {expected_status}, got HTTP {status}")
    if expected_detail is not None:
        print(f"Expected detail: {expected_detail}")
        print(f"Actual detail: {body.get('detail', '<missing>')}")
    return 1


failures = 0
failures += check("valid signed request", signed_payload(), 200)
failures += check(
    "unsigned request fail-closed",
    {"action": "read", "user_id": "u1", "device": "laptop-1", "tenant_id": "t1"},
    500,
    "FAIL_CLOSED",
)
failures += check("bad signature fail-closed", signed_payload(bad_signature=True), 500, "FAIL_CLOSED")
failures += check(
    "stale timestamp fail-closed",
    signed_payload(timestamp=int(time.time()) - 10),
    500,
    "FAIL_CLOSED",
)

if failures:
    raise SystemExit(1)

print("PASS docker PROD gateway checks")
PY
