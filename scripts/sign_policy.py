#!/usr/bin/env python3
from __future__ import annotations

import json
import sys
from datetime import datetime, timezone
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

import os

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from security.policy_registry import (
    PolicyRegistryError,
    append_policy_log,
    encode_policy_signature,
    file_sha256,
    policy_hash,
    validate_policy_registry_shape,
)


def load_private_key_from_env() -> Ed25519PrivateKey:
    raw_key = os.getenv("POLICY_SIGNING_KEY")
    if not raw_key:
        raise PolicyRegistryError("policy_private_key_missing")
    key_material = raw_key.replace("\\n", "\n").encode("utf-8")
    try:
        key = serialization.load_pem_private_key(key_material, password=None)
    except Exception as exc:
        raise PolicyRegistryError("policy_private_key_invalid") from exc
    if not isinstance(key, Ed25519PrivateKey):
        raise PolicyRegistryError("policy_private_key_invalid")
    return key


def main(argv: list[str]) -> int:
    policy_path = Path(argv[1]) if len(argv) > 1 else REPO_ROOT / "governance" / "policy_registry.json"
    signature_path = Path(argv[2]) if len(argv) > 2 else policy_path.with_suffix(".sig")
    policy_log_path = Path(argv[3]) if len(argv) > 3 else policy_path.parent / "policy_log.jsonl"
    manifest_path = Path(argv[4]) if len(argv) > 4 else policy_path.parent / "policy_release_manifest.json"
    policy = validate_policy_registry_shape(json.loads(policy_path.read_text(encoding="utf-8")))
    private_key = load_private_key_from_env()
    signature = encode_policy_signature(policy, private_key)
    signature_path.write_text(f"{signature}\n", encoding="utf-8")
    manifest = {
        "policy_version": policy["version"],
        "policy_hash": policy_hash(policy),
        "policy_pubkey_id": policy["policy_pubkey_id"],
        "created_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "signed_by_human": os.getenv("USBAY_POLICY_SIGNED_BY_HUMAN", "offline_release_signer"),
        "artifact_hashes": {
            "policy_registry.json": file_sha256(policy_path),
            "policy_registry.json.sig": file_sha256(signature_path),
        },
    }
    manifest_path.write_text(json.dumps(manifest, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    append_policy_log(policy, policy_log_path, signature)
    print(f"signed_policy={policy_path}")
    print(f"signature_file={signature_path}")
    print(f"release_manifest={manifest_path}")
    print(f"policy_log={policy_log_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
