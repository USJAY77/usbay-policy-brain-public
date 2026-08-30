#!/usr/bin/env python3
"""Verify real provider evidence intake packages.

This verifier is local and read-only. It does not perform runtime enforcement,
create AWS resources, load credentials, store private keys, close blockers, or
make certification claims.
"""

from __future__ import annotations

import argparse
import json
import re
from datetime import datetime
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_SCHEMA = ROOT / "governance" / "provider_evidence" / "provider_evidence_schema.json"
DEFAULT_PACKAGE = ROOT / "governance" / "provider_evidence" / "provider_evidence_example.json"
HEX64 = re.compile(r"^[0-9a-f]{64}$")
PLACEHOLDER = {"", "Information not provided."}
GENERIC_FAILURE_ORDER = [
    "PROVIDER_EVIDENCE_MISSING",
    "PROVIDER_EVIDENCE_INVALID",
    "PROVIDER_EVIDENCE_UNVERIFIED",
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


def _timestamp_valid(value: Any) -> bool:
    if not isinstance(value, str) or value in PLACEHOLDER:
        return False
    try:
        datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return False
    return True


def _path_exists(value: Any) -> bool:
    return isinstance(value, str) and value not in PLACEHOLDER and (ROOT / value).exists()


def verify(schema_path: Path, package_path: Path) -> list[str]:
    errors: list[str] = []
    try:
        schema = _load_json(schema_path)
        package = _load_json(package_path)
    except ValueError as exc:
        return ["PROVIDER_EVIDENCE_MISSING", str(exc)]

    if package.get("decision") != "BLOCKED":
        errors.append("PROVIDER_EVIDENCE_INVALID:DECISION_MUST_REMAIN_BLOCKED")
    if package.get("certification_status") != "BLOCKED":
        errors.append("PROVIDER_EVIDENCE_INVALID:CERTIFICATION_MUST_REMAIN_BLOCKED")
    if package.get("certification_claim") is not False:
        errors.append("PROVIDER_EVIDENCE_INVALID:CERTIFICATION_CLAIM_PROHIBITED")
    if package.get("runtime_behavior_change") is not False:
        errors.append("PROVIDER_EVIDENCE_INVALID:RUNTIME_BEHAVIOR_CHANGE_PROHIBITED")
    if package.get("aws_resource_creation") is not False:
        errors.append("PROVIDER_EVIDENCE_INVALID:AWS_RESOURCE_CREATION_PROHIBITED")
    if package.get("credentials_included") is not False:
        errors.append("PROVIDER_EVIDENCE_INVALID:CREDENTIALS_PROHIBITED")
    if package.get("private_keys_included") is not False:
        errors.append("PROVIDER_EVIDENCE_INVALID:PRIVATE_KEYS_PROHIBITED")

    blocker_status = package.get("blocker_status")
    if not isinstance(blocker_status, dict) or blocker_status.get("BLOCKER-003") != "OPEN":
        errors.append("PROVIDER_EVIDENCE_INVALID:BLOCKER_003_MUST_REMAIN_OPEN")

    relationships = package.get("relationships")
    if not isinstance(relationships, dict):
        errors.append("PROVIDER_EVIDENCE_MISSING:RELATIONSHIPS_MISSING")
    else:
        for relationship in schema.get("required_relationships", []):
            value = relationships.get(relationship)
            if not isinstance(value, str) or value in PLACEHOLDER:
                errors.append(f"PROVIDER_EVIDENCE_UNVERIFIED:{relationship}")

    control_links = package.get("control_links")
    if not isinstance(control_links, dict):
        errors.append("PROVIDER_EVIDENCE_MISSING:control_links")
    else:
        for control_name, control_path in control_links.items():
            if not _path_exists(control_path):
                errors.append(f"PROVIDER_EVIDENCE_UNVERIFIED:control_link:{control_name}")

    evidence_package = package.get("provider_evidence_package")
    if not isinstance(evidence_package, dict):
        errors.append("PROVIDER_EVIDENCE_MISSING:provider_evidence_package")
    else:
        for field in schema.get("required_package_fields", []):
            if field not in evidence_package:
                errors.append(f"PROVIDER_EVIDENCE_MISSING:provider_evidence_package:{field}")

        for field in (
            "provider_name",
            "provider_submission_reference",
            "chain_of_custody_reference",
            "review_decision_reference",
            "export_bundle_reference",
            "worm_archive_reference",
        ):
            value = evidence_package.get(field)
            if not isinstance(value, str) or value in PLACEHOLDER:
                errors.append(f"PROVIDER_EVIDENCE_MISSING:provider_evidence_package:{field}")

        if not _timestamp_valid(evidence_package.get("submission_timestamp_utc")):
            errors.append("PROVIDER_EVIDENCE_INVALID:provider_evidence_package:submission_timestamp_utc")
        if not _path_exists(evidence_package.get("evidence_manifest_path")):
            errors.append("PROVIDER_EVIDENCE_MISSING:provider_evidence_package:evidence_manifest_path")
        for hash_field in ("evidence_manifest_sha256", "provider_receipt_sha256"):
            if not _is_sha256(evidence_package.get(hash_field)):
                errors.append(f"PROVIDER_EVIDENCE_INVALID:provider_evidence_package:{hash_field}")

    artifacts = package.get("provider_artifacts")
    if not isinstance(artifacts, list) or not artifacts:
        errors.append("PROVIDER_EVIDENCE_MISSING:provider_artifacts")
        return sorted(set(errors))

    required_artifact_types = set(schema.get("required_artifact_types", []))
    seen_artifact_types: set[str] = set()
    required_artifact_fields = schema.get("required_artifact_fields", [])

    for index, artifact in enumerate(artifacts):
        if not isinstance(artifact, dict):
            errors.append(f"PROVIDER_EVIDENCE_INVALID:artifact_{index}:NOT_OBJECT")
            continue

        for field in required_artifact_fields:
            if field not in artifact:
                errors.append(f"PROVIDER_EVIDENCE_MISSING:artifact_{index}:{field}")

        artifact_type = artifact.get("artifact_type")
        if isinstance(artifact_type, str):
            seen_artifact_types.add(artifact_type)
        if artifact_type not in required_artifact_types:
            errors.append(f"PROVIDER_EVIDENCE_INVALID:artifact_{index}:artifact_type")

        if not _path_exists(artifact.get("artifact_path")):
            errors.append(f"PROVIDER_EVIDENCE_MISSING:artifact_{index}:artifact_path")
        if not _is_sha256(artifact.get("artifact_sha256")):
            errors.append(f"PROVIDER_EVIDENCE_INVALID:artifact_{index}:artifact_sha256")

        for missing_field in ("provider_reference",):
            value = artifact.get(missing_field)
            if not isinstance(value, str) or value in PLACEHOLDER:
                errors.append(f"PROVIDER_EVIDENCE_MISSING:artifact_{index}:{missing_field}")

        for unverified_field in (
            "validation_reference",
            "signature_reference",
            "timestamp_reference",
            "audit_lineage_reference",
            "review_reference",
            "export_reference",
            "worm_reference",
        ):
            value = artifact.get(unverified_field)
            if not isinstance(value, str) or value in PLACEHOLDER:
                errors.append(f"PROVIDER_EVIDENCE_UNVERIFIED:artifact_{index}:{unverified_field}")

        if artifact.get("verification_status") != schema.get("required_verification_status"):
            errors.append(f"PROVIDER_EVIDENCE_UNVERIFIED:artifact_{index}:verification_status")

    missing_artifact_types = sorted(required_artifact_types - seen_artifact_types)
    for artifact_type in missing_artifact_types:
        errors.append(f"PROVIDER_EVIDENCE_MISSING:artifact_type:{artifact_type}")

    if _contains_placeholder(package):
        errors.append("PROVIDER_EVIDENCE_MISSING")
        errors.append("PROVIDER_EVIDENCE_INVALID")
        errors.append("PROVIDER_EVIDENCE_UNVERIFIED")

    return sorted(set(errors))


def main() -> int:
    parser = argparse.ArgumentParser(description="Verify real provider evidence intake package.")
    parser.add_argument("--schema", default=DEFAULT_SCHEMA.as_posix())
    parser.add_argument("--package", default=DEFAULT_PACKAGE.as_posix())
    args = parser.parse_args()
    errors = verify(Path(args.schema), Path(args.package))
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
