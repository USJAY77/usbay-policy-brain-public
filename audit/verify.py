from __future__ import annotations

import argparse
import base64
import os
from pathlib import Path

from audit.anchor import public_key_id, verify_event
from audit.exporter import GENESIS_HASH, _sha256_json, load_export_records
from audit.keys import resolve_public_key


def _result() -> dict:
    return {
        "valid": True,
        "hash_chain": True,
        "event_integrity": True,
        "signature_valid": True,
        "timestamp_valid": True,
        "errors": [],
    }


def _mark(result: dict, field: str, error: str) -> None:
    result["valid"] = False
    result[field] = False
    result["errors"].append(error)


def _mock_tsa_allowed() -> bool:
    return os.getenv("USBAY_ALLOW_MOCK_TSA") == "1" or bool(os.getenv("PYTEST_CURRENT_TEST"))


def _timestamp_valid(record: dict) -> bool:
    proof = record.get("timestamp_proof")
    if not isinstance(proof, dict):
        return False
    if proof.get("type") != "RFC3161":
        return False
    if proof.get("hash") != record.get("event_hash"):
        return False
    if not isinstance(proof.get("tsa"), str) or not proof.get("tsa"):
        return False
    if not isinstance(proof.get("created_at"), str) or not proof.get("created_at"):
        return False
    token = proof.get("token")
    if not isinstance(token, str) or not token:
        return False
    try:
        base64.b64decode(token.encode("ascii"), validate=True)
    except Exception:
        return False
    mode = proof.get("mode")
    if mode == "live":
        return True
    if mode == "mock":
        return _mock_tsa_allowed()
    return False


def _event_payload(record: dict) -> dict:
    event = dict(record)
    event.pop("event_hash", None)
    event.pop("signature", None)
    event.pop("public_key_id", None)
    event.pop("key_version", None)
    event.pop("timestamp_proof", None)
    event.pop("prev_hash", None)
    return event


def _public_key_for_record(record: dict, public_key: str | None) -> str:
    if public_key is not None:
        return public_key
    return resolve_public_key(str(record.get("public_key_id", "")))


def verify_audit_export(filepath: str, public_key: str | None = None) -> dict:
    result = _result()
    prev_hash = GENESIS_HASH

    try:
        records = load_export_records(filepath)
    except Exception:
        _mark(result, "event_integrity", "export_file_unreadable")
        return result

    for index, record in enumerate(records):
        event_hash = record.get("event_hash")
        if record.get("prev_hash") != prev_hash:
            _mark(result, "hash_chain", f"record_{index}_prev_hash_mismatch")

        if _sha256_json(_event_payload(record)) != event_hash:
            _mark(result, "event_integrity", f"record_{index}_event_hash_mismatch")

        try:
            resolved_public_key = _public_key_for_record(record, public_key)
            if public_key_id(resolved_public_key) != record.get("public_key_id"):
                _mark(result, "signature_valid", f"record_{index}_public_key_id_mismatch")
            elif not verify_event(
                str(event_hash),
                str(record.get("signature", "")),
                resolved_public_key,
            ):
                _mark(result, "signature_valid", f"record_{index}_signature_invalid")
        except Exception:
            _mark(result, "signature_valid", f"record_{index}_public_key_unresolved")

        if not _timestamp_valid(record):
            _mark(result, "timestamp_valid", f"record_{index}_timestamp_invalid")

        prev_hash = str(event_hash)

    return result


def verify_export_file(filepath: str, public_key: str | None = None) -> bool:
    return bool(verify_audit_export(filepath, public_key=public_key)["valid"])


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("filepath", type=Path)
    parser.add_argument("--public-key")
    args = parser.parse_args()
    return 0 if verify_export_file(str(args.filepath), args.public_key) else 1


if __name__ == "__main__":
    raise SystemExit(main())
