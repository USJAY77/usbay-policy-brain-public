#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

python3 <<'PY'
import hashlib
import hmac
import json
import os
import tempfile
import time
from pathlib import Path

from fastapi.testclient import TestClient

old_env = os.environ.get("USBAY_MODE")
os.environ["USBAY_MODE"] = "PROD"

import gateway.app as gateway_app
from utils.canonical import canonical_json
from utils.keystore import KeyStore
from utils.secret_provider import LocalFileSecretProvider


def write_signed_policy(policy_path: Path, sig_path: Path, key_path: Path) -> None:
    policy = {
        "policy_version": "v1",
        "rules": [
            {"action": "read", "effect": "ALLOW"},
            {"action": "*", "effect": "BLOCK"},
        ],
    }
    policy_bytes = canonical_json(policy)
    key = b"test-policy-key"

    policy_path.write_bytes(policy_bytes)
    key_path.write_bytes(key)

    digest = hashlib.sha256(policy_bytes).digest()
    sig_path.write_text(hmac.new(key, digest, hashlib.sha256).hexdigest(), encoding="utf-8")


def signed_request(
    *,
    action: str = "read",
    user_id: str = "u1",
    device: str = "laptop-1",
    tenant_id: str = "t1",
    timestamp: int,
    key: bytes = b"device-test-key",
    bad_signature: bool = False,
) -> dict:
    payload = {
        "action": action,
        "user_id": user_id,
        "device": device,
        "tenant_id": tenant_id,
        "timestamp": timestamp,
    }
    payload["signature"] = (
        "bad-signature"
        if bad_signature
        else hmac.new(key, canonical_json(payload), hashlib.sha256).hexdigest()
    )
    return payload


def check(name: str, response, expected_status: int, expected_detail: str = "") -> int:
    body = response.json()
    if response.status_code == expected_status and (
        not expected_detail or body.get("detail") == expected_detail
    ):
        print(f"PASS {name}: HTTP {response.status_code}")
        return 0

    print(f"FAIL {name}: expected HTTP {expected_status}")
    if expected_detail:
        print(f"Expected detail: {expected_detail}")
    print(f"Actual HTTP {response.status_code}")
    print(f"Actual detail: {body.get('detail', '<missing>')}")
    return 1


print("==== USBAY PROD IN-PROCESS GATEWAY TEST ====")

failures = 0
old_cwd = Path.cwd()

with tempfile.TemporaryDirectory() as tmp:
    root = Path(tmp)
    policy_dir = root / "policy" / "t1"
    policy_dir.mkdir(parents=True)
    policy_path = policy_dir / "policy.json"
    sig_path = policy_dir / "policy.sig"
    key_path = root / "secrets" / "policy.key"
    key_path.parent.mkdir(parents=True)
    min_policy_version_path = root / "policy" / "min_policy_version.txt"

    min_policy_version_path.write_text("v1", encoding="utf-8")
    write_signed_policy(policy_path, sig_path, key_path)

    (root / "secrets" / "t1" / "devices").mkdir(parents=True)
    (root / "secrets" / "t1" / "devices" / "laptop-1.key").write_bytes(b"device-test-key")

    gateway_app.POLICY_ROOT = root / "policy"
    gateway_app.SECRETS_ROOT = root / "secrets"
    gateway_app.keystore = KeyStore(LocalFileSecretProvider(root / "secrets"))
    gateway_app.AUDIT_ROOT = root / "audit"
    gateway_app.POLICY_SIGNING_KEY_PATH = key_path
    gateway_app.MIN_POLICY_VERSION_PATH = min_policy_version_path
    gateway_app.POLICY_VERSION = "v1"

    os.chdir(root)

    client = TestClient(gateway_app.app, raise_server_exceptions=False)
    now = int(time.time())

    failures += check(
        "signed read allowed",
        client.post("/execute", json=signed_request(timestamp=now)),
        200,
    )
    failures += check(
        "unsigned read fail-closed",
        client.post("/execute", json={"action": "read", "user_id": "u1", "device": "laptop-1", "tenant_id": "t1"}),
        403,
        "FAIL_CLOSED",
    )
    failures += check(
        "bad signature fail-closed",
        client.post("/execute", json=signed_request(timestamp=now, bad_signature=True)),
        403,
        "FAIL_CLOSED",
    )
    failures += check(
        "stale timestamp fail-closed",
        client.post("/execute", json=signed_request(timestamp=now - 10)),
        403,
        "FAIL_CLOSED",
    )

    os.chdir(old_cwd)

if old_env is None:
    os.environ.pop("USBAY_MODE", None)
else:
    os.environ["USBAY_MODE"] = old_env

if failures:
    print(f"FAIL PROD gateway checks: {failures} failure(s)")
    raise SystemExit(1)

print("PASS PROD gateway checks")
PY
