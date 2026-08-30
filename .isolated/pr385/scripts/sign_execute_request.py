#!/usr/bin/env python3
from __future__ import annotations

import json
import os
import sys
import time
import uuid
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from security.request_signing import (
    DEFAULT_REQUEST_KEY_CONFIG_PATH,
    RequestSignatureError,
    default_request_private_key_path,
    default_request_pubkey_id,
    load_request_key_config,
    load_request_public_key,
    resolve_request_public_key_path,
    sign_request_payload,
)


OUTPUT = REPO_ROOT / "tmp" / "signed_execute_request.json"
TENANT_ID = "t1"
DEVICE = "laptop-1"


def canonical(obj: dict) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"))


def request_signature_message(payload: dict) -> bytes:
    unsigned = dict(payload)
    unsigned.pop("signature", None)
    unsigned.pop("decision_id", None)
    unsigned.pop("decision_signature", None)
    unsigned.pop("decision_signature_classic", None)
    unsigned.pop("decision_signature_pqc", None)
    message = canonical(unsigned)
    if message is None:
        raise RuntimeError("FAIL_CLOSED")
    return message.encode("utf-8")


def load_request_private_key() -> bytes:
    private_key = os.getenv("USBAY_REQUEST_SIGNING_KEY")
    if not private_key:
        private_key_path = default_request_private_key_path(DEFAULT_REQUEST_KEY_CONFIG_PATH)
        try:
            return private_key_path.read_bytes()
        except FileNotFoundError as exc:
            raise RequestSignatureError("missing_request_signing_private_key") from exc
    return private_key.replace("\\n", "\n").encode("utf-8")


def validate_request_public_key(pubkey_id: str) -> None:
    config = load_request_key_config(DEFAULT_REQUEST_KEY_CONFIG_PATH)
    public_key_path = resolve_request_public_key_path(pubkey_id, config, DEFAULT_REQUEST_KEY_CONFIG_PATH)
    load_request_public_key(public_key_path)


def build_curl_command(url: str, output_path: Path = OUTPUT) -> str:
    return (
        f'curl -X POST "{url}" '
        '-H "Content-Type: application/json" '
        f"--data-binary @{output_path.resolve()}"
    )


def main() -> int:
    unsigned_payload = {
        "action": "run_simulated_experiment",
        "actor_id": "user1",
        "affected_system": "sandbox",
        "device": DEVICE,
        "human_review": False,
        "metadata": {
            "actor_hash": "0a041b9462caa4a31bac3567e0b6e6fd9100787d50aa557a4308e6c7dc31930b",
            "request_hash": "local-dev-request-hash",
        },
        "nonce": uuid.uuid4().hex,
        "policy_version": "simulation-policy-v1",
        "purpose": "test_execution",
        "real_world_impact": "none",
        "risk_level": "low",
        "simulation_id": f"sim-{uuid.uuid4().hex}",
        "simulation_logs": {
            "actor_hash": "0a041b9462caa4a31bac3567e0b6e6fd9100787d50aa557a4308e6c7dc31930b",
            "request_hash": "local-dev-request-hash",
        },
        "tenant_id": TENANT_ID,
        "timestamp": int(time.time()),
        "type": "simulation",
    }

    try:
        pubkey_id = os.getenv("USBAY_REQUEST_PUBKEY_ID", default_request_pubkey_id(DEFAULT_REQUEST_KEY_CONFIG_PATH))
        validate_request_public_key(pubkey_id)
        signed_payload = sign_request_payload(
            unsigned_payload,
            load_request_private_key(),
            pubkey_id,
        )
    except RequestSignatureError as exc:
        OUTPUT.unlink(missing_ok=True)
        print(str(exc), file=sys.stderr)
        return 1

    final_body = canonical(signed_payload)

    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT.write_text(final_body, encoding="utf-8")

    # Do not remove the @ before the file path.
    print(final_body)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
