#!/usr/bin/env python3
"""
USBAY audit ledger helpers.

The ledger is append-only and hash-chained:
- first entry uses previous_hash = "GENESIS"
- each entry_hash = SHA256(previous_hash + canonical_json(entry_without_hashes))
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path


GENESIS_HASH = "GENESIS"
ENTRY_REQUIRED_FIELDS = {
    "entry_type",
    "timestamp",
    "commit_sha",
    "policy_hash",
    "approval_1_hash",
    "approval_2_hash",
    "evidence_snapshot_hash",
    "runtime_attestation_hash",
    "previous_hash",
    "entry_hash",
}


def canonical_json_bytes(payload: dict) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


def sha256_bytes(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest().lower()


def sha256_file(path: Path) -> str:
    return sha256_bytes(path.read_bytes())


def compute_entry_hash(*, previous_hash: str, entry: dict) -> str:
    entry_without_hashes = {
        key: value for key, value in entry.items() if key not in {"previous_hash", "entry_hash"}
    }
    return sha256_bytes(previous_hash.encode("utf-8") + canonical_json_bytes(entry_without_hashes))


def latest_chain_state(log_path: Path) -> tuple[str, int]:
    if not log_path.exists():
        return GENESIS_HASH, 0
    lines = log_path.read_text(encoding="utf-8").splitlines()
    if not lines:
        return GENESIS_HASH, 0
    last_entry = json.loads(lines[-1])
    if not isinstance(last_entry, dict):
        raise RuntimeError("latest audit log entry must be a JSON object")
    entry_hash = str(last_entry.get("entry_hash", ""))
    if len(entry_hash) != 64:
        raise RuntimeError("latest audit log entry_hash must be a 64-character sha256 hex digest")
    return entry_hash, len(lines)


def verify_chain(log_path: Path) -> tuple[str, int, dict]:
    if not log_path.exists():
        raise RuntimeError("AUDIT_LOG_MISSING: audit log missing")
    lines = log_path.read_text(encoding="utf-8").splitlines()
    if not lines:
        raise RuntimeError("AUDIT_LOG_EMPTY: audit log is empty")

    previous_hash = GENESIS_HASH
    last_entry_hash = ""
    entry_count = 0
    last_entry: dict | None = None

    for index, line in enumerate(lines, start=1):
        try:
            entry = json.loads(line)
        except json.JSONDecodeError as exc:
            raise RuntimeError(f"AUDIT_ENTRY_MALFORMED: invalid JSON in audit log entry {index}: {exc}") from exc
        if not isinstance(entry, dict):
            raise RuntimeError(f"AUDIT_ENTRY_MALFORMED: audit log entry {index} must be a JSON object")
        required = ENTRY_REQUIRED_FIELDS
        missing = sorted(required - set(entry.keys()))
        if missing:
            raise RuntimeError(f"AUDIT_ENTRY_MALFORMED: audit log entry {index} missing required fields: {missing}")
        if entry["previous_hash"] != previous_hash:
            raise RuntimeError("AUDIT_PREVIOUS_HASH_MISMATCH: audit log chain previous_hash mismatch")
        expected_hash = compute_entry_hash(previous_hash=previous_hash, entry=entry)
        if entry["entry_hash"] != expected_hash:
            raise RuntimeError(f"AUDIT_ENTRY_HASH_MISMATCH: audit log entry {index} has invalid entry_hash")
        previous_hash = expected_hash
        last_entry_hash = expected_hash
        entry_count += 1
        last_entry = entry

    if last_entry is None:
        raise RuntimeError("AUDIT_LOG_EMPTY: audit log is empty")
    return last_entry_hash, entry_count, last_entry


def append_entry(log_path: Path, entry: dict) -> dict:
    previous_hash, _ = latest_chain_state(log_path)
    entry["previous_hash"] = previous_hash
    entry["entry_hash"] = compute_entry_hash(previous_hash=previous_hash, entry=entry)
    log_path.parent.mkdir(parents=True, exist_ok=True)
    with log_path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(entry, sort_keys=True, separators=(",", ":")) + "\n")
        handle.flush()
    return entry
