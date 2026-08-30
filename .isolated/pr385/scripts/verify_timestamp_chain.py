#!/usr/bin/env python3
"""Verify RFC3161-compatible governance timestamp chains.

This verifier is local and read-only. It does not call a TSA, create AWS
resources, load credentials, close blockers, or make certification claims.
"""

from __future__ import annotations

import argparse
import json
import re
from datetime import datetime
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_SCHEMA = ROOT / "governance" / "timestamps" / "timestamp_schema.json"
DEFAULT_CHAIN = ROOT / "governance" / "timestamps" / "timestamp_example.json"
HEX64 = re.compile(r"^[0-9a-f]{64}$")
PLACEHOLDER = {"", "Information not provided."}
GENERIC_FAILURE_ORDER = [
    "TIMESTAMP_MISSING",
    "TIMESTAMP_INVALID",
    "TIMESTAMP_CHAIN_INCOMPLETE",
]


def _load_json(path: Path) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise ValueError(f"FILE_MISSING:{path}") from exc
    except json.JSONDecodeError as exc:
        raise ValueError(f"JSON_INVALID:{path.name}:{exc.msg}") from exc
    if not isinstance(payload, dict):
        raise ValueError(f"JSON_OBJECT_REQUIRED:{path.name}")
    return payload


def _contains_placeholder(value: Any) -> bool:
    if isinstance(value, str):
        return value in PLACEHOLDER
    if isinstance(value, list):
        return not value or any(_contains_placeholder(item) for item in value)
    if isinstance(value, dict):
        return any(_contains_placeholder(item) for item in value.values())
    return value is None


def _timestamp_valid(value: Any) -> bool:
    if not isinstance(value, str) or value in PLACEHOLDER:
        return False
    normalized = value.replace("Z", "+00:00")
    try:
        datetime.fromisoformat(normalized)
    except ValueError:
        return False
    return True


def verify(schema_path: Path, chain_path: Path) -> list[str]:
    errors: list[str] = []
    try:
        schema = _load_json(schema_path)
        chain = _load_json(chain_path)
    except ValueError as exc:
        return ["TIMESTAMP_MISSING", str(exc)]

    if chain.get("decision") != "BLOCKED":
        errors.append("TIMESTAMP_INVALID:CHAIN_DECISION_MUST_REMAIN_BLOCKED")
    if chain.get("certification_status") != "BLOCKED":
        errors.append("TIMESTAMP_INVALID:CERTIFICATION_MUST_REMAIN_BLOCKED")
    if chain.get("certification_claim") is not False:
        errors.append("TIMESTAMP_INVALID:CERTIFICATION_CLAIM_PROHIBITED")
    if chain.get("runtime_behavior_change") is not False:
        errors.append("TIMESTAMP_INVALID:RUNTIME_BEHAVIOR_CHANGE_PROHIBITED")
    if chain.get("aws_resource_creation") is not False:
        errors.append("TIMESTAMP_INVALID:AWS_RESOURCE_CREATION_PROHIBITED")
    if chain.get("credentials_included") is not False:
        errors.append("TIMESTAMP_INVALID:CREDENTIALS_PROHIBITED")
    blocker_status = chain.get("blocker_status")
    if not isinstance(blocker_status, dict) or blocker_status.get("BLOCKER-003") != "OPEN":
        errors.append("TIMESTAMP_INVALID:BLOCKER_003_MUST_REMAIN_OPEN")

    relationships = chain.get("relationships")
    if not isinstance(relationships, dict):
        errors.append("TIMESTAMP_CHAIN_INCOMPLETE:RELATIONSHIPS_MISSING")
    else:
        for relationship in schema.get("required_relationships", []):
            value = relationships.get(relationship)
            if not isinstance(value, str) or value in PLACEHOLDER:
                errors.append(f"TIMESTAMP_CHAIN_INCOMPLETE:{relationship}")

    records = chain.get("timestamp_records")
    if not isinstance(records, list) or not records:
        errors.append("TIMESTAMP_MISSING:timestamp_records")
        return errors

    required_fields = schema.get("required_record_fields", [])
    required_subject_types = set(schema.get("required_subject_types", []))
    seen_subject_types: set[str] = set()
    previous_record_hash = ""

    for index, record in enumerate(records):
        if not isinstance(record, dict):
            errors.append(f"TIMESTAMP_INVALID:record_{index}:NOT_OBJECT")
            continue
        for field in required_fields:
            if field not in record:
                errors.append(f"TIMESTAMP_MISSING:record_{index}:{field}")
        subject_type = record.get("timestamp_subject_type")
        if isinstance(subject_type, str):
            seen_subject_types.add(subject_type)
        if subject_type not in required_subject_types:
            errors.append(f"TIMESTAMP_INVALID:record_{index}:SUBJECT_TYPE")
        subject_path = record.get("timestamp_subject_path")
        if not isinstance(subject_path, str) or not subject_path or not (ROOT / subject_path).exists():
            errors.append(f"TIMESTAMP_MISSING:record_{index}:timestamp_subject_path")
        audit_reference = record.get("linked_audit_reference")
        if not isinstance(audit_reference, str) or audit_reference in PLACEHOLDER:
            errors.append(f"TIMESTAMP_MISSING:record_{index}:linked_audit_reference")
        for hash_field in (
            "timestamp_subject_sha256",
            "rfc3161_token_sha256",
            "tsa_certificate_sha256",
            "timestamp_record_sha256",
        ):
            value = record.get(hash_field)
            if not isinstance(value, str) or not HEX64.fullmatch(value):
                errors.append(f"TIMESTAMP_INVALID:record_{index}:{hash_field}")
        if not _timestamp_valid(record.get("timestamp_utc")):
            errors.append(f"TIMESTAMP_INVALID:record_{index}:timestamp_utc")
        previous_value = record.get("previous_timestamp_record_sha256")
        if index == 0:
            if not isinstance(previous_value, str) or previous_value in PLACEHOLDER:
                errors.append(f"TIMESTAMP_CHAIN_INCOMPLETE:record_{index}:previous_timestamp_record_sha256")
        elif previous_value != previous_record_hash:
            errors.append(f"TIMESTAMP_CHAIN_INCOMPLETE:record_{index}:previous_hash_mismatch")
        current_hash = record.get("timestamp_record_sha256")
        previous_record_hash = current_hash if isinstance(current_hash, str) else ""

    missing_subject_types = sorted(required_subject_types - seen_subject_types)
    for subject_type in missing_subject_types:
        errors.append(f"TIMESTAMP_MISSING:subject_type:{subject_type}")

    if _contains_placeholder(chain):
        errors.append("TIMESTAMP_MISSING")
        errors.append("TIMESTAMP_INVALID")
        errors.append("TIMESTAMP_CHAIN_INCOMPLETE")

    return sorted(set(errors))


def main() -> int:
    parser = argparse.ArgumentParser(description="Verify RFC3161-compatible governance timestamp chain.")
    parser.add_argument("--schema", default=DEFAULT_SCHEMA.as_posix())
    parser.add_argument("--chain", default=DEFAULT_CHAIN.as_posix())
    args = parser.parse_args()
    errors = verify(Path(args.schema), Path(args.chain))
    if errors:
        print("Decision = BLOCKED")
        ordered_errors = [code for code in GENERIC_FAILURE_ORDER if code in errors]
        ordered_errors.extend(error for error in errors if error not in GENERIC_FAILURE_ORDER)
        for error in ordered_errors:
            print(error)
        return 1
    print("Decision = READY_FOR_REVIEW")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
