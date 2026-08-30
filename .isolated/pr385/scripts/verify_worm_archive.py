#!/usr/bin/env python3
"""Verify WORM archive evidence packages.

This verifier is local and read-only. It does not perform runtime enforcement,
create AWS resources, load credentials, store private keys, close blockers, or
make certification claims.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from datetime import datetime
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_SCHEMA = ROOT / "governance" / "worm_archive" / "worm_archive_schema.json"
DEFAULT_ARCHIVE = ROOT / "governance" / "worm_archive" / "worm_archive_example.json"
HEX64 = re.compile(r"^[0-9a-f]{64}$")
PLACEHOLDER = {"", "Information not provided."}
GENERIC_FAILURE_ORDER = [
    "WORM_ARCHIVE_MISSING",
    "WORM_HASH_MISMATCH",
    "WORM_RETENTION_INCOMPLETE",
    "WORM_IMMUTABILITY_UNVERIFIED",
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


def _is_sha256(value: Any) -> bool:
    return isinstance(value, str) and HEX64.fullmatch(value) is not None


def _sha256_path(path: Path) -> str:
    if path.is_file():
        return hashlib.sha256(path.read_bytes()).hexdigest()
    if path.is_dir():
        digest = hashlib.sha256()
        for child in sorted(item for item in path.rglob("*") if item.is_file()):
            digest.update(child.relative_to(path).as_posix().encode("utf-8"))
            digest.update(b"\0")
            digest.update(child.read_bytes())
            digest.update(b"\0")
        return digest.hexdigest()
    raise FileNotFoundError(path)


def _timestamp_valid(value: Any) -> bool:
    if not isinstance(value, str) or value in PLACEHOLDER:
        return False
    try:
        datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return False
    return True


def verify(schema_path: Path, archive_path: Path) -> list[str]:
    errors: list[str] = []
    try:
        schema = _load_json(schema_path)
        archive = _load_json(archive_path)
    except ValueError as exc:
        return ["WORM_ARCHIVE_MISSING", str(exc)]

    if archive.get("decision") != "BLOCKED":
        errors.append("WORM_ARCHIVE_MISSING:DECISION_MUST_REMAIN_BLOCKED")
    if archive.get("certification_status") != "BLOCKED":
        errors.append("WORM_ARCHIVE_MISSING:CERTIFICATION_MUST_REMAIN_BLOCKED")
    if archive.get("certification_claim") is not False:
        errors.append("WORM_ARCHIVE_MISSING:CERTIFICATION_CLAIM_PROHIBITED")
    if archive.get("runtime_behavior_change") is not False:
        errors.append("WORM_ARCHIVE_MISSING:RUNTIME_BEHAVIOR_CHANGE_PROHIBITED")
    if archive.get("aws_resource_creation") is not False:
        errors.append("WORM_ARCHIVE_MISSING:AWS_RESOURCE_CREATION_PROHIBITED")
    if archive.get("credentials_included") is not False:
        errors.append("WORM_ARCHIVE_MISSING:CREDENTIALS_PROHIBITED")
    if archive.get("private_keys_included") is not False:
        errors.append("WORM_ARCHIVE_MISSING:PRIVATE_KEYS_PROHIBITED")

    blocker_status = archive.get("blocker_status")
    if not isinstance(blocker_status, dict) or blocker_status.get("BLOCKER-003") != "OPEN":
        errors.append("WORM_ARCHIVE_MISSING:BLOCKER_003_MUST_REMAIN_OPEN")

    relationships = archive.get("relationships")
    if not isinstance(relationships, dict):
        errors.append("WORM_ARCHIVE_MISSING:RELATIONSHIPS_MISSING")
    else:
        for relationship in schema.get("required_relationships", []):
            value = relationships.get(relationship)
            if not isinstance(value, str) or value in PLACEHOLDER:
                errors.append(f"WORM_ARCHIVE_MISSING:{relationship}")

    archive_record = archive.get("archive_record")
    if not isinstance(archive_record, dict):
        errors.append("WORM_ARCHIVE_MISSING:archive_record")
    else:
        for field in schema.get("required_archive_fields", []):
            if field not in archive_record:
                errors.append(f"WORM_ARCHIVE_MISSING:archive_record:{field}")

        manifest_path = archive_record.get("archive_manifest_path")
        if not isinstance(manifest_path, str) or manifest_path in PLACEHOLDER or not (ROOT / manifest_path).exists():
            errors.append("WORM_ARCHIVE_MISSING:archive_record:archive_manifest_path")

        for hash_field in (
            "archive_manifest_sha256",
            "provider_write_receipt_sha256",
            "provider_retention_evidence_sha256",
            "provider_legal_hold_evidence_sha256",
            "export_verification_sha256",
        ):
            if not _is_sha256(archive_record.get(hash_field)):
                errors.append(f"WORM_HASH_MISMATCH:archive_record:{hash_field}")

        if archive_record.get("retention_mode") not in set(schema.get("allowed_retention_modes", [])):
            errors.append("WORM_RETENTION_INCOMPLETE:archive_record:retention_mode")
        if not _timestamp_valid(archive_record.get("retention_until_utc")):
            errors.append("WORM_RETENTION_INCOMPLETE:archive_record:retention_until_utc")
        if archive_record.get("legal_hold_status") in PLACEHOLDER:
            errors.append("WORM_RETENTION_INCOMPLETE:archive_record:legal_hold_status")
        if archive_record.get("immutability_status") != schema.get("required_immutability_status"):
            errors.append("WORM_IMMUTABILITY_UNVERIFIED:archive_record:immutability_status")

    artifacts = archive.get("archived_artifacts")
    if not isinstance(artifacts, list) or not artifacts:
        errors.append("WORM_ARCHIVE_MISSING:archived_artifacts")
        return sorted(set(errors))

    required_artifact_types = set(schema.get("required_artifact_types", []))
    seen_artifact_types: set[str] = set()
    required_artifact_fields = schema.get("required_artifact_fields", [])

    for index, artifact in enumerate(artifacts):
        if not isinstance(artifact, dict):
            errors.append(f"WORM_ARCHIVE_MISSING:artifact_{index}:NOT_OBJECT")
            continue

        for field in required_artifact_fields:
            if field not in artifact:
                errors.append(f"WORM_ARCHIVE_MISSING:artifact_{index}:{field}")

        artifact_type = artifact.get("artifact_type")
        if isinstance(artifact_type, str):
            seen_artifact_types.add(artifact_type)
        if artifact_type not in required_artifact_types:
            errors.append(f"WORM_ARCHIVE_MISSING:artifact_{index}:artifact_type")

        artifact_path = artifact.get("artifact_path")
        source_path = ROOT / artifact_path if isinstance(artifact_path, str) else None
        if source_path is None or artifact_path in PLACEHOLDER or not source_path.exists():
            errors.append(f"WORM_ARCHIVE_MISSING:artifact_{index}:artifact_path")

        expected_hash = artifact.get("expected_sha256")
        archived_hash = artifact.get("archived_sha256")
        if not _is_sha256(expected_hash):
            errors.append(f"WORM_HASH_MISMATCH:artifact_{index}:expected_sha256")
        if not _is_sha256(archived_hash):
            errors.append(f"WORM_HASH_MISMATCH:artifact_{index}:archived_sha256")
        if _is_sha256(expected_hash) and _is_sha256(archived_hash) and expected_hash != archived_hash:
            errors.append(f"WORM_HASH_MISMATCH:artifact_{index}:expected_archived_hash")
        if source_path is not None and source_path.exists() and _is_sha256(expected_hash):
            current_hash = _sha256_path(source_path)
            if current_hash != expected_hash:
                errors.append(f"WORM_HASH_MISMATCH:artifact_{index}:current_source_hash")

        if artifact.get("archive_object_reference") in PLACEHOLDER:
            errors.append(f"WORM_ARCHIVE_MISSING:artifact_{index}:archive_object_reference")
        if artifact.get("retention_metadata_reference") in PLACEHOLDER:
            errors.append(f"WORM_RETENTION_INCOMPLETE:artifact_{index}:retention_metadata_reference")
        if artifact.get("immutability_status") != schema.get("required_immutability_status"):
            errors.append(f"WORM_IMMUTABILITY_UNVERIFIED:artifact_{index}:immutability_status")

    missing_artifact_types = sorted(required_artifact_types - seen_artifact_types)
    for artifact_type in missing_artifact_types:
        errors.append(f"WORM_ARCHIVE_MISSING:artifact_type:{artifact_type}")

    if _contains_placeholder(archive):
        errors.append("WORM_ARCHIVE_MISSING")
        errors.append("WORM_HASH_MISMATCH")
        errors.append("WORM_RETENTION_INCOMPLETE")
        errors.append("WORM_IMMUTABILITY_UNVERIFIED")

    return sorted(set(errors))


def main() -> int:
    parser = argparse.ArgumentParser(description="Verify WORM archive evidence package.")
    parser.add_argument("--schema", default=DEFAULT_SCHEMA.as_posix())
    parser.add_argument("--archive", default=DEFAULT_ARCHIVE.as_posix())
    args = parser.parse_args()
    errors = verify(Path(args.schema), Path(args.archive))
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
