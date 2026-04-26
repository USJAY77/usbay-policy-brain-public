#!/usr/bin/env python3
import argparse
import hashlib
import hmac
import json
import time
from pathlib import Path

from utils.canonical import canonical_json
from utils.secret_provider import SecretProvider

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_OUTPUT = ROOT / "tmp" / "signed_execute_request.json"


def sign_payload(payload: dict, secret: str) -> str:
    canonical = canonical_json(payload)

    key = secret if isinstance(secret, bytes) else secret.encode()

    return hmac.new(
        key,
        canonical.encode(),
        hashlib.sha256
    ).hexdigest()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--action", default="read")
    parser.add_argument("--user-id", default="alice")
    parser.add_argument("--device", default="laptop-1")
    parser.add_argument("--tenant-id", default="t1")
    parser.add_argument("--timestamp", type=int, default=int(time.time()))
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)

    args = parser.parse_args()

    payload = {
        "action": args.action,
        "user_id": args.user_id,
        "device": args.device,
        "tenant_id": args.tenant_id,
        "timestamp": args.timestamp
    }

    provider = SecretProvider()
    secret_data = provider.get_device_key(args.tenant_id, args.device)

    secret = secret_data.get("private_key")
    if not secret:
        raise RuntimeError("FAIL_CLOSED")

    signature = sign_payload(payload, secret)
    payload["signature"] = signature

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(payload, indent=2))

    print("SIGNED PAYLOAD:")
    print(json.dumps(payload, indent=2))


if __name__ == "__main__":
    main()
