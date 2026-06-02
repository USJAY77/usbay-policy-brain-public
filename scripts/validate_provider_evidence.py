#!/usr/bin/env python3
"""Validate AWS Object Lock provider evidence scaffold completeness.

This script is local-only. It does not call AWS, load credentials, create
resources, or make certification claims.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_SUBMISSIONS_DIR = ROOT / "governance" / "evidence" / "aws-object-lock" / "provider-submissions"

DEFAULT_REQUIRED_FILES = [
    "object_lock_write_receipt.json",
    "retention_configuration_evidence.json",
    "legal_hold_evidence.json",
    "export_verification_record.json",
    "provider_audit_reference.md",
    "chain_of_custody.md",
    "evidence_manifest.json",
]

PILOT_REQUIRED_FILES = [
    "pilot_object_lock_write_receipt.json",
    "pilot_retention_configuration.json",
    "pilot_legal_hold_evidence.json",
    "pilot_export_verification_record.json",
    "pilot_provider_audit_reference.md",
    "pilot_chain_of_custody.md",
    "pilot_evidence_manifest.json",
]

PLACEHOLDER_VALUES = {"", "Information not provided.", "BLOCKED", "OPEN"}


def _load_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ValueError(f"{path.name}:JSON_INVALID:{exc.msg}") from exc
    if not isinstance(value, dict):
        raise ValueError(f"{path.name}:JSON_OBJECT_REQUIRED")
    return value


def _contains_placeholder(value: Any) -> bool:
    if isinstance(value, str):
        return value in PLACEHOLDER_VALUES
    if isinstance(value, bool):
        return value is False
    if isinstance(value, list):
        return any(_contains_placeholder(item) for item in value)
    if isinstance(value, dict):
        return any(_contains_placeholder(item) for item in value.values())
    return value is None


def _required_files(submissions_dir: Path) -> list[str]:
    if submissions_dir.name == "pilot-submission":
        return PILOT_REQUIRED_FILES
    return DEFAULT_REQUIRED_FILES


def _manifest_name(submissions_dir: Path) -> str:
    if submissions_dir.name == "pilot-submission":
        return "pilot_evidence_manifest.json"
    return "evidence_manifest.json"


def _chain_of_custody_name(submissions_dir: Path) -> str:
    if submissions_dir.name == "pilot-submission":
        return "pilot_chain_of_custody.md"
    return "chain_of_custody.md"


def _validate_required_files(submissions_dir: Path, required_files: list[str]) -> list[str]:
    errors: list[str] = []
    if not submissions_dir.is_dir():
        return [f"SUBMISSIONS_DIR_MISSING:{submissions_dir}"]
    for filename in required_files:
        if not (submissions_dir / filename).is_file():
            errors.append(f"REQUIRED_FILE_MISSING:{filename}")
    return errors


def _validate_manifest(submissions_dir: Path, required_files: list[str]) -> list[str]:
    manifest_path = submissions_dir / _manifest_name(submissions_dir)
    if not manifest_path.is_file():
        return [f"MANIFEST_MISSING:{manifest_path.name}"]
    try:
        manifest = _load_json(manifest_path)
    except ValueError as exc:
        return [str(exc)]
    errors: list[str] = []
    manifest_files = manifest.get("required_files")
    if manifest_files != required_files:
        errors.append("MANIFEST_REQUIRED_FILES_MISMATCH")
    if manifest.get("decision") != "BLOCKED":
        errors.append("MANIFEST_DECISION_MUST_BE_BLOCKED_UNTIL_COMPLETE")
    if manifest.get("blocker_003_status") != "OPEN":
        errors.append("MANIFEST_BLOCKER_003_MUST_REMAIN_OPEN")
    if manifest.get("certification_status") != "BLOCKED":
        errors.append("MANIFEST_CERTIFICATION_MUST_REMAIN_BLOCKED")
    if manifest.get("required_evidence_complete") is not True:
        errors.append("EVIDENCE_INCOMPLETE")
    return errors


def _validate_chain_of_custody(submissions_dir: Path) -> list[str]:
    path = submissions_dir / _chain_of_custody_name(submissions_dir)
    if not path.is_file():
        return [f"CHAIN_OF_CUSTODY_MISSING:{path.name}"]
    text = path.read_text(encoding="utf-8")
    errors: list[str] = []
    for required in (
        "Package identifier.",
        "Artifact names.",
        "Artifact hashes.",
        "Collection actor.",
        "Submission actor.",
        "Review actor.",
        "Decision: BLOCKED.",
    ):
        if required not in text:
            errors.append(f"CHAIN_OF_CUSTODY_FIELD_MISSING:{required}")
    if "Information not provided." in text:
        errors.append("CHAIN_OF_CUSTODY_INCOMPLETE")
    return errors


def _validate_json_artifacts(submissions_dir: Path, required_files: list[str]) -> list[str]:
    errors: list[str] = []
    manifest_name = _manifest_name(submissions_dir)
    for filename in required_files:
        if not filename.endswith(".json") or filename == manifest_name:
            continue
        path = submissions_dir / filename
        if not path.is_file():
            continue
        try:
            artifact = _load_json(path)
        except ValueError as exc:
            errors.append(str(exc))
            continue
        if artifact.get("decision") != "BLOCKED":
            errors.append(f"{filename}:DECISION_MUST_BE_BLOCKED_UNTIL_COMPLETE")
        if artifact.get("blocker_003_status") != "OPEN":
            errors.append(f"{filename}:BLOCKER_003_MUST_REMAIN_OPEN")
        if artifact.get("certification_status") != "BLOCKED":
            errors.append(f"{filename}:CERTIFICATION_MUST_REMAIN_BLOCKED")
        if _contains_placeholder(artifact):
            errors.append(f"{filename}:EVIDENCE_INCOMPLETE")
    return errors


def main() -> int:
    submissions_dir = Path(sys.argv[1]).resolve() if len(sys.argv) > 1 else DEFAULT_SUBMISSIONS_DIR
    required_files = _required_files(submissions_dir)
    errors = []
    errors.extend(_validate_required_files(submissions_dir, required_files))
    errors.extend(_validate_manifest(submissions_dir, required_files))
    errors.extend(_validate_chain_of_custody(submissions_dir))
    errors.extend(_validate_json_artifacts(submissions_dir, required_files))

    if errors:
        print("Decision: BLOCKED")
        print("BLOCKER-003: OPEN")
        print("Certification: BLOCKED")
        for error in errors:
            print(error)
        return 1

    print("Decision: READY_FOR_BLOCKER_003_REASSESSMENT")
    print("BLOCKER-003: OPEN")
    print("Certification: BLOCKED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
