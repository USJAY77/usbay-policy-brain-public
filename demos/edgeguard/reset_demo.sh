#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/../.." && pwd)"
EXPECTED_OUT_DIR="$ROOT_DIR/demos/edgeguard/out"
REQUESTED_OUT_DIR="${EDGEGUARD_OUT_DIR:-$EXPECTED_OUT_DIR}"

if [[ "$REQUESTED_OUT_DIR" != "$EXPECTED_OUT_DIR" ]]; then
  echo "FAIL: wrong_path" >&2
  exit 1
fi

mkdir -p "$EXPECTED_OUT_DIR"
ACTUAL_OUT_DIR="$(cd "$EXPECTED_OUT_DIR" && pwd)"

if [[ "$ACTUAL_OUT_DIR" != "$EXPECTED_OUT_DIR" ]]; then
  echo "FAIL: wrong_path" >&2
  exit 1
fi

export EDGEGUARD_EXPECTED_OUT_DIR="$EXPECTED_OUT_DIR"
export EDGEGUARD_RESET_ACTOR_ID="${EDGEGUARD_RESET_ACTOR_ID:-local_demo_operator}"
export EDGEGUARD_REPO_ROOT="$ROOT_DIR"
export PYTHONPATH="${PYTHONPATH:-$ROOT_DIR}"

python3 - "$@" <<'PY'
from __future__ import annotations

import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from scripts.verify_reset_log import (
    GENESIS_HASH,
    current_chain_hash,
    expected_entry_hash,
    genesis_log_hash,
    load_actor_key_config,
    load_policy_anchor,
    load_retention_policy,
    sha256_text,
    sign_reset_entry,
    verify_reset_log,
)


out_dir = Path(os.environ["EDGEGUARD_EXPECTED_OUT_DIR"]).resolve()
actor_id = os.environ["EDGEGUARD_RESET_ACTOR_ID"]
audit_log = out_dir / "reset_audit.log"
actor_config = load_actor_key_config()
actor_pubkey_id = os.getenv("EDGEGUARD_RESET_ACTOR_PUBKEY_ID", actor_config["default_actor_pubkey_id"])


def ensure_local_demo_actor_key() -> None:
    if os.getenv("USBAY_ACTOR_SIGNING_KEY") or actor_config.get("private_key_path"):
        return
    key_dir = Path(os.getenv("USBAY_EDGEGUARD_KEY_DIR", "/tmp/usbay-edgeguard-reset"))
    key_dir.mkdir(parents=True, exist_ok=True)
    private_path = key_dir / "actor_private.pem"
    if private_path.exists():
        private_pem = private_path.read_text(encoding="utf-8")
        private_key = serialization.load_pem_private_key(private_pem.encode("utf-8"), password=None)
    else:
        private_key = Ed25519PrivateKey.generate()
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ).decode("utf-8")
        private_path.write_text(private_pem, encoding="utf-8")
        private_path.chmod(0o600)
    public_key_path = actor_config["key_map"].get(actor_pubkey_id)
    if not public_key_path:
        raise SystemExit("FAIL: actor_key_config_invalid")
    public_path = (Path(os.environ["EDGEGUARD_REPO_ROOT"]) / public_key_path).resolve()
    public_path.parent.mkdir(parents=True, exist_ok=True)
    public_path.write_bytes(
        private_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
    )
    os.environ["USBAY_ACTOR_SIGNING_KEY"] = private_pem


ensure_local_demo_actor_key()


def canonical(data: dict) -> str:
    return json.dumps(data, sort_keys=True, separators=(",", ":"))


def safe_artifacts() -> list[Path]:
    artifacts: list[Path] = []
    for pattern in ("*.json", "*.txt", "*.log"):
        artifacts.extend(out_dir.glob(pattern))
    result: list[Path] = []
    for artifact in sorted(set(artifacts)):
        resolved = artifact.resolve()
        if resolved == audit_log.resolve():
            continue
        if resolved.name.endswith(".archive.log"):
            continue
        if resolved.parent != out_dir:
            raise SystemExit("FAIL: wrong_path")
        result.append(resolved)
    return result


def append_entry(event_type: str, previous_hash: str, files: list[str], archive_anchor: dict | None = None) -> str:
    _policy_hash, policy_signature = load_policy_anchor()
    entry = {
        "timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "event_type": event_type,
        "actor_id": actor_id,
        "actor_pubkey_id": actor_pubkey_id,
        "file_list_deleted": files,
        "previous_log_hash": previous_hash,
        "genesis_log_hash": genesis_log_hash(),
        "genesis_policy_signature": policy_signature,
    }
    if archive_anchor is not None:
        entry["archive_anchor"] = archive_anchor
    entry["actor_signature"] = sign_reset_entry(entry, actor_config)
    entry["current_log_hash"] = expected_entry_hash(previous_hash, entry)
    with audit_log.open("a", encoding="utf-8") as handle:
        handle.write(canonical(entry) + "\n")
    return entry["current_log_hash"]


def rotate_if_needed(previous_hash: str) -> str:
    policy = load_retention_policy()
    if not policy["rotate_on_start"]:
        return previous_hash
    if not audit_log.exists():
        return previous_hash
    max_bytes = int(policy["max_log_size_mb"] * 1024 * 1024)
    if audit_log.stat().st_size <= max_bytes:
        return previous_hash
    archive_dir = Path(policy["archive_dir"])
    archive_dir.mkdir(parents=True, exist_ok=True)
    archive_name = f"reset_audit.{previous_hash}.archive.log"
    archive_path = archive_dir / archive_name
    archive_path.write_bytes(audit_log.read_bytes())
    archive_hash = sha256_text(archive_path.read_text(encoding="utf-8"))
    audit_log.unlink()
    return append_entry(
        "rotation_anchor",
        previous_hash,
        [],
        {
            "archive_file": str(archive_path),
            "archive_hash": archive_hash,
            "anchor_policy": policy["anchor_policy"],
        },
    )


if len(sys.argv) > 1 and sys.argv[1] == "--verify-log":
    valid = verify_reset_log(audit_log)
    print("VALID" if valid else "INVALID")
    raise SystemExit(0 if valid else 1)

if audit_log.exists() and not verify_reset_log(audit_log):
    print("FAIL: reset_log_tampering_detected", file=sys.stderr)
    raise SystemExit(1)

previous_hash = current_chain_hash(audit_log) if audit_log.exists() else GENESIS_HASH
previous_hash = rotate_if_needed(previous_hash)
files = safe_artifacts()
file_list = [str(path) for path in files]

print("files_before_deletion:")
if files:
    for artifact in files:
        print(str(artifact))
else:
    print("(none)")

previous_hash = append_entry("reset_intent", previous_hash, file_list)

for artifact in files:
    artifact.unlink(missing_ok=True)

append_entry("reset_result", previous_hash, file_list)
out_dir.mkdir(parents=True, exist_ok=True)
print("PASS: edgeguard_demo_reset")
PY
