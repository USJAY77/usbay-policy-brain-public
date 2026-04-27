#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import hmac
import json
import sys
import time
import uuid
from pathlib import Path

from utils.secret_provider import SecretProvider


OUTPUT = Path("tmp/signed_execute_request.json")
TENANT_ID = "t1"
DEVICE = "laptop-1"


def canonical(obj: dict) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"))


def request_signature_message(payload: dict) -> bytes:
    unsigned = dict(payload)
    unsigned.pop("signature", None)
    message = canonical(unsigned)
    if message is None:
        raise RuntimeError("FAIL_CLOSED")
    return message.encode("utf-8")


def _extract_key(secret_data: dict) -> bytes:
    key = secret_data.get("key", secret_data.get("private_key"))
    if key is None:
        raise RuntimeError("FAIL_CLOSED: missing device key in Vault")
    if isinstance(key, str):
        key_bytes = key.encode("utf-8")
    else:
        key_bytes = bytes(key)
    if not key_bytes:
        raise RuntimeError("FAIL_CLOSED: missing device key in Vault")
    return key_bytes


def load_device_key_bytes(tenant_id: str, device: str) -> bytes:
    try:
        secret_data = SecretProvider().get_device_key(tenant_id, device)
        return _extract_key(secret_data)
    except RuntimeError as exc:
        raise RuntimeError("FAIL_CLOSED: missing device key in Vault") from exc
    except Exception as exc:
        raise RuntimeError("FAIL_CLOSED: missing device key in Vault") from exc


def sign_payload(unsigned_payload: dict, key_bytes: bytes) -> str:
    message_bytes = request_signature_message(unsigned_payload)
    if message_bytes is None:
        raise RuntimeError("FAIL_CLOSED")
    return hmac.new(key_bytes, message_bytes, hashlib.sha256).hexdigest()


def build_curl_command(url: str, output_path: Path = OUTPUT) -> str:
    return (
        f'curl -X POST "{url}" '
        '-H "Content-Type: application/json" '
        f"--data-binary @{output_path.resolve()}"
    )


def main() -> int:
    unsigned_payload = {
        "action": "read",
        "device": DEVICE,
        "nonce": uuid.uuid4().hex,
        "tenant_id": TENANT_ID,
        "timestamp": int(time.time()),
        "user_id": "alice",
    }

    try:
        key_bytes = load_device_key_bytes(TENANT_ID, DEVICE)
        signature = sign_payload(unsigned_payload, key_bytes)
    except RuntimeError as exc:
        OUTPUT.unlink(missing_ok=True)
        print(str(exc), file=sys.stderr)
        return 1

    signed_payload = dict(unsigned_payload)
    signed_payload["signature"] = signature

    sign_body = canonical(unsigned_payload)
    final_body = canonical(signed_payload)

    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT.write_text(final_body, encoding="utf-8")

    print(f"SIGN BODY: {sign_body}")
    print(f"FINAL BODY: wrote {OUTPUT} with signature {signature[:8]}...{signature[-8:]}")
    print("Use --data-binary with the generated JSON file.")
    print("Do not remove the @ before the file path.")
    print(build_curl_command("http://127.0.0.1:8000/execute", OUTPUT))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
