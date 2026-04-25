#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import os
import shlex
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_OUTPUT = ROOT / "tmp" / "signed_execute_request.json"


def load_dotenv(path: Path) -> None:
    if not path.exists():
        return

    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue

        key, value = line.split("=", 1)
        os.environ.setdefault(key.strip(), value.strip().strip('"').strip("'"))


def configure_env() -> None:
    if os.environ.get("VAULT_ADDR") in {"", None, "http://vault:8200"}:
        os.environ["VAULT_ADDR"] = "http://127.0.0.1:8200"

    os.environ.setdefault("VAULT_TOKEN", "root")
    os.environ.setdefault("USBAY_MODE", "PROD")
    os.environ.setdefault("USBAY_SECRET_PROVIDER", "vault")


def mask(sig: str) -> str:
    return sig[:6] + "..." if sig else "<missing>"


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser()
    p.add_argument("--action", default="read")
    p.add_argument("--user-id", default="alice")
    p.add_argument("--device", default="laptop-1")
    p.add_argument("--tenant-id", default="t1")
    p.add_argument("--timestamp", type=int, default=None)
    p.add_argument("--gateway-url", default="http://127.0.0.1:8000/execute")
    p.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    return p.parse_args()


def build_curl_command(gateway_url: str, output_path: Path) -> str:
    return (
        f"curl {shlex.quote(gateway_url)} "
        f"-X POST "
        f"-H {shlex.quote('Content-Type: application/json')} "
        f"--data-binary @{shlex.quote(str(output_path.resolve()))}"
    )


def hmac_bytes(value) -> bytes:
    if value is None:
        raise RuntimeError("FAIL_CLOSED")
    if isinstance(value, str):
        value = value.encode("utf-8")
    value_bytes = bytes(value)
    if not value_bytes:
        raise RuntimeError("FAIL_CLOSED")
    return value_bytes


def main() -> int:
    args = parse_args()

    os.chdir(ROOT)
    load_dotenv(ROOT / ".env")
    configure_env()

    sys.path.insert(0, str(ROOT))

    from gateway.app import request_signature_message
    from utils.keystore import KeyStore

    payload = {
        "action": args.action,
        "device": args.device,
        "tenant_id": args.tenant_id,
        "timestamp": args.timestamp or int(time.time()),
        "user_id": args.user_id,
    }

    ks = KeyStore()
    try:
        key = ks.load_device_key(args.tenant_id, args.device)
    except RuntimeError as exc:
        message = str(exc)
        if message == "FAIL_CLOSED: missing device key in Vault":
            print(message, file=sys.stderr)
        else:
            print("FAIL_CLOSED", file=sys.stderr)
        return 1

    # 🔐 CRUCIAAL: gebruik EXACT gateway message format
    try:
        message = request_signature_message(payload)
        message_bytes = hmac_bytes(message)
        key_bytes = hmac_bytes(key)
    except RuntimeError:
        print("FAIL_CLOSED", file=sys.stderr)
        return 1

    signature = hmac.new(key_bytes, message_bytes, hashlib.sha256).hexdigest()
    payload["signature"] = signature

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(payload, separators=(",", ":"), sort_keys=True) + "\n",
        encoding="utf-8",
    )

    curl_cmd = build_curl_command(args.gateway_url, args.output)

    print("Signed request ready.")
    provider = os.environ.get("USBAY_SECRET_PROVIDER", "<unset>")
    print(f"Secret provider: {provider}")
    if provider == "vault":
        print(f"Vault: {os.environ.get('VAULT_ADDR')}")
    print(f"Tenant: {args.tenant_id}")
    print(f"Device: {args.device}")
    print(f"Signature prefix: {mask(signature)}")
    print()
    print("Do not remove the @ before the file path.")
    print(curl_cmd)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
