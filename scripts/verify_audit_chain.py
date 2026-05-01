#!/usr/bin/env python3
from __future__ import annotations

import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from security.decision_store import decision_record_hash, verify_decision_chain
from security.policy_registry import (
    enforce_public_key_pin,
    enforce_policy_key_trust,
    enforce_policy_validity_window,
    load_policy_key_config,
    load_policy_public_key,
    policy_hash,
    resolve_policy_public_key_path,
    verify_policy_signature,
    verify_policy_log,
)


FORBIDDEN_EXPORT_FIELDS = {
    "actor_id",
    "raw_actor_id",
    "raw_prompt",
    "prompt",
    "command",
    "payment_id",
    "raw_ip",
    "ip_address",
    "device_fingerprint",
    "raw_device_fingerprint",
    "location",
    "precise_location",
}

REQUIRED_DECISION_EVIDENCE_FIELDS = {
    "audit_hash",
    "previous_hash",
    "policy_hash",
    "alg_version",
    "policy_version",
    "policy_pubkey_id",
    "policy_sequence",
    "policy_valid_from",
    "policy_valid_until",
}


def _contains_forbidden_fields(value) -> bool:
    if isinstance(value, dict):
        for key, item in value.items():
            if key in FORBIDDEN_EXPORT_FIELDS:
                return True
            if _contains_forbidden_fields(item):
                return True
    elif isinstance(value, list):
        return any(_contains_forbidden_fields(item) for item in value)
    return False


def _records_from_export(export: dict) -> list[dict]:
    if isinstance(export.get("records"), list):
        return export["records"]
    if isinstance(export.get("decision_record"), dict):
        return [export["decision_record"]]
    return [export]


def _verify_policy_release(record: dict, public_key_path: Path) -> bool:
    config_path = REPO_ROOT / "governance" / "policy_key_config.json"
    log_path = REPO_ROOT / "governance" / "policy_log.jsonl"
    try:
        public_key = load_policy_public_key(public_key_path)
        key_config = load_policy_key_config(config_path)
        policy_key_id = str(record.get("policy_pubkey_id", ""))
        enforce_policy_key_trust(policy_key_id, key_config)
        enforce_public_key_pin(policy_key_id, public_key, key_config)
        resolved_key_path = resolve_policy_public_key_path(
            policy_key_id,
            key_config,
            public_key_path,
            config_path,
        )
        if resolved_key_path.exists() and resolved_key_path.read_bytes() != public_key_path.read_bytes():
            return False
        policy_stub = {
            "valid_from": record.get("policy_valid_from"),
            "valid_until": record.get("policy_valid_until"),
        }
        enforce_policy_validity_window(
            policy_stub,
            drift_window_seconds=key_config["drift_window_seconds"],
        )
        return verify_policy_log(log_path, str(record.get("policy_hash", "")))
    except Exception:
        return False


def verify_export(export: dict, public_key_path: Path) -> bool:
    if not isinstance(export, dict) or _contains_forbidden_fields(export):
        return False

    records = _records_from_export(export)
    if not records or not all(isinstance(record, dict) for record in records):
        return False
    for record in records:
        if any(record.get(field) in (None, "") for field in REQUIRED_DECISION_EVIDENCE_FIELDS):
            return False
        if not _verify_policy_release(record, public_key_path):
            return False

    if len(records) == 1:
        record = records[0]
        try:
            expected_hash = decision_record_hash(record)
        except Exception:
            return False
        return (
            record.get("audit_hash") == expected_hash
            and record.get("current_hash", record.get("audit_hash")) == expected_hash
        )

    return verify_decision_chain(records)


def _sha256_text(value: str) -> str:
    import hashlib

    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _verify_policy_log_entries(entries: list[dict], expected_policy_hash: str) -> bool:
    previous_hash = "0" * 64
    found = False
    required = {
        "policy_hash",
        "previous_hash",
        "policy_sequence",
        "policy_version",
        "timestamp",
        "policy_pubkey_id",
        "signature",
    }
    for entry in entries:
        if not isinstance(entry, dict) or set(entry) != required:
            return False
        if entry.get("previous_hash") != previous_hash:
            return False
        if entry.get("policy_hash") == expected_policy_hash:
            found = True
        previous_hash = _sha256_text(json.dumps(entry, sort_keys=True, separators=(",", ":")))
    return found


def verify_bundle(bundle: dict, public_key_path: Path) -> bool:
    if not isinstance(bundle, dict) or bundle.get("type") != "audit_evidence_bundle":
        return False
    if _contains_forbidden_fields(bundle):
        return False
    try:
        policy = bundle["policy_registry.json"]
        signature = bundle["policy_registry.sig"]
        policy_log_entries = bundle["policy_log"]
        manifest = bundle["manifest.json"]
        decision_record = bundle["decision_record"]
        records = bundle.get("records") or [decision_record]
    except Exception:
        return False
    if not isinstance(policy, dict) or not isinstance(signature, str):
        return False
    if not isinstance(policy_log_entries, list) or not isinstance(manifest, dict):
        return False
    matching_records = [
        record for record in records
        if isinstance(record, dict) and record.get("decision_id") == decision_record.get("decision_id")
    ]
    if not matching_records or matching_records[-1] != decision_record:
        return False
    if not verify_policy_signature(policy, signature, public_key_path):
        return False
    try:
        public_key = load_policy_public_key(public_key_path)
        key_config = load_policy_key_config(REPO_ROOT / "governance" / "policy_key_config.json")
        enforce_policy_key_trust(str(policy.get("policy_pubkey_id", "")), key_config)
        enforce_public_key_pin(str(policy.get("policy_pubkey_id", "")), public_key, key_config)
        enforce_policy_validity_window(policy, drift_window_seconds=key_config["drift_window_seconds"])
    except Exception:
        return False
    if policy_hash(policy) != decision_record.get("policy_hash"):
        return False
    if manifest.get("policy_registry_sha256") != _sha256_text(
        json.dumps(policy, sort_keys=True, separators=(",", ":"))
    ):
        return False
    if manifest.get("policy_signature_sha256") != _sha256_text(signature):
        return False
    if manifest.get("policy_log_sha256") != _sha256_text(
        json.dumps(policy_log_entries, sort_keys=True, separators=(",", ":"))
    ):
        return False
    if manifest.get("decision_record_hash") != _sha256_text(
        json.dumps(decision_record, sort_keys=True, separators=(",", ":"))
    ):
        return False
    policy_hashes = [entry.get("policy_hash") for entry in policy_log_entries if isinstance(entry, dict)]
    if decision_record.get("policy_hash") not in policy_hashes:
        return False
    if not _verify_policy_log_entries(policy_log_entries, str(decision_record.get("policy_hash", ""))):
        return False
    for record in records:
        if any(record.get(field) in (None, "") for field in REQUIRED_DECISION_EVIDENCE_FIELDS):
            return False
    if len(records) == 1:
        try:
            expected_hash = decision_record_hash(records[0])
        except Exception:
            return False
        return records[0].get("audit_hash") == expected_hash
    return verify_decision_chain(records)


def main(argv: list[str]) -> int:
    if len(argv) not in {2, 3}:
        print("usage: python scripts/verify_audit_chain.py <export_or_bundle_file> [policy_public_key]", file=sys.stderr)
        return 2

    try:
        export = json.loads(Path(argv[1]).read_text(encoding="utf-8"))
    except Exception:
        print("INVALID")
        return 1

    public_key_path = Path(argv[2]) if len(argv) == 3 else REPO_ROOT / "governance" / "policy_public.key"
    if export.get("type") == "audit_evidence_bundle":
        is_valid = verify_bundle(export, public_key_path)
    else:
        is_valid = verify_export(export, public_key_path)
    if is_valid:
        print("VALID")
        return 0

    print("INVALID")
    return 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
