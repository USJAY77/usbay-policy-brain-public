#!/usr/bin/env python3
from __future__ import annotations

import json
import sys
import time
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from security.decision_store import DECISION_CHAIN_GENESIS, decision_record_hash, verify_decision_chain, verify_decision_signatures
from security.policy_registry import policy_hash, verify_policy_signature


DEFAULT_SIGNATURE_POLICY_MODE = "STRICT"
REQUIRED_FIELDS = {
    "decision_id",
    "decision",
    "policy_version",
    "policy_hash",
    "policy_pubkey_id",
    "request_hash",
    "signature_valid",
    "expires_at_epoch",
    "nonce_hash",
    "gateway_id",
    "previous_hash",
    "audit_hash",
    "current_hash",
    "genesis_hash",
    "genesis_signature",
}


def _records_from_export(export: dict) -> list[dict]:
    if isinstance(export.get("records"), list):
        return export["records"]
    if isinstance(export.get("decision_record"), dict):
        return [export["decision_record"]]
    return [export]


def _target_record(export: dict) -> dict | None:
    if isinstance(export.get("decision_record"), dict):
        return export["decision_record"]
    records = _records_from_export(export)
    return records[-1] if records else None


def _load_policy() -> tuple[dict, str] | None:
    try:
        policy = json.loads((REPO_ROOT / "governance" / "policy_registry.json").read_text(encoding="utf-8"))
        signature = (REPO_ROOT / "governance" / "policy_registry.sig").read_text(encoding="utf-8").strip()
        return policy, signature
    except Exception:
        return None


def _policy_signature_mode(policy: dict) -> str | None:
    mode = str(policy.get("signature_policy_mode", DEFAULT_SIGNATURE_POLICY_MODE)).upper()
    if mode not in {"STRICT", "COMPAT", "TRANSITION"}:
        return None
    return mode


def _verify_expiry(record: dict) -> bool:
    try:
        return int(time.time()) <= int(record.get("expires_at_epoch"))
    except Exception:
        return False


def _verify_nonce_uniqueness(records: list[dict]) -> bool:
    seen = set()
    for record in records:
        nonce_hash = record.get("nonce_hash")
        if not isinstance(nonce_hash, str) or not nonce_hash:
            return False
        if nonce_hash in seen:
            return False
        seen.add(nonce_hash)
    return True


def _verify_genesis_anchor(records: list[dict], policy: dict, policy_signature: str, public_key_path: Path) -> bool:
    if not records:
        return False
    first = records[0]
    genesis_hash = first.get("genesis_hash")
    genesis_signature = first.get("genesis_signature")
    if genesis_hash != DECISION_CHAIN_GENESIS:
        return False
    if first.get("previous_hash") != genesis_hash:
        return False
    if genesis_signature != policy_signature:
        return False
    return verify_policy_signature(policy, genesis_signature, public_key_path)


def verify_decision_export(export: dict, public_key_path: Path) -> bool:
    if not isinstance(export, dict):
        return False
    record = _target_record(export)
    records = _records_from_export(export)
    if not isinstance(record, dict) or not records or not all(isinstance(item, dict) for item in records):
        return False
    if any(record.get(field) in (None, "") for field in REQUIRED_FIELDS):
        return False
    if any(item.get(field) in (None, "") for item in records for field in REQUIRED_FIELDS):
        return False
    if export.get("decision_id") and export.get("decision_id") != record.get("decision_id"):
        return False
    if export.get("previous_hash") and export.get("previous_hash") != record.get("previous_hash"):
        return False
    if export.get("audit_hash") and export.get("audit_hash") != record.get("audit_hash"):
        return False
    if record.get("signature_valid") is not True:
        return False
    policy_bundle = _load_policy()
    if policy_bundle is None:
        return False
    policy, policy_signature = policy_bundle
    signature_mode = _policy_signature_mode(policy)
    if signature_mode is None:
        return False
    if record.get("decision_signature") and record.get("decision_signature_classic"):
        if record.get("decision_signature") != record.get("decision_signature_classic"):
            return False
    if record.get("decision_signature") and not record.get("decision_signature_classic"):
        return False
    if not verify_decision_signatures(record, mode=signature_mode):
        return False
    if not all(verify_decision_signatures(item, mode=signature_mode) for item in records):
        return False
    if not all(_verify_expiry(item) for item in records):
        return False
    if not _verify_nonce_uniqueness(records):
        return False

    if not verify_policy_signature(policy, policy_signature, public_key_path):
        return False
    if not _verify_genesis_anchor(records, policy, policy_signature, public_key_path):
        return False
    if policy_hash(policy) != record.get("policy_hash"):
        return False
    if policy.get("version") != record.get("policy_version") and export.get("type") != "decision_audit_export":
        return False

    try:
        expected_hash = decision_record_hash(record)
    except Exception:
        return False
    if record.get("audit_hash") != expected_hash:
        return False
    if record.get("current_hash") != expected_hash:
        return False
    if len(records) == 1:
        return True
    return verify_decision_chain(records)


def main(argv: list[str]) -> int:
    if len(argv) not in {2, 3}:
        print("usage: python scripts/verify_decision.py <decision_export_json> [policy_public_key]", file=sys.stderr)
        return 2
    try:
        export = json.loads(Path(argv[1]).read_text(encoding="utf-8"))
    except Exception:
        print("INVALID")
        return 1
    public_key_path = Path(argv[2]) if len(argv) == 3 else REPO_ROOT / "governance" / "policy_public.key"
    if verify_decision_export(export, public_key_path):
        print("VALID")
        return 0
    print("INVALID")
    return 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
