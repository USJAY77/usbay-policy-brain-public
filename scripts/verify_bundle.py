#!/usr/bin/env python3
"""Verify an AWS Object Lock evidence export bundle.

This verifier is local and read-only. It does not call AWS, load credentials,
create resources, close BLOCKER-003, or make certification claims.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_BUNDLE_DIR = ROOT / "exports" / "evidence_bundle"
REQUIRED_BUNDLE_FILES = [
    "manifest.json",
    "evidence_hashes.json",
    "chain_of_custody.json",
    "validation_results.json",
    "review_decision.json",
    "bundle_sha256.txt",
]
HEX64 = re.compile(r"^[0-9a-f]{64}$")
PLACEHOLDER_VALUES = {"", "Information not provided.", "PENDING", "BLOCKED", "OPEN", "PLACEHOLDER_ONLY"}


def _load_json(path: Path) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ValueError(f"{path.name}:JSON_INVALID:{exc.msg}") from exc
    if not isinstance(payload, dict):
        raise ValueError(f"{path.name}:JSON_OBJECT_REQUIRED")
    return payload


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _contains_placeholder(value: Any) -> bool:
    if isinstance(value, str):
        return value in PLACEHOLDER_VALUES
    if isinstance(value, bool):
        return value is False
    if isinstance(value, list):
        return not value or any(_contains_placeholder(item) for item in value)
    if isinstance(value, dict):
        return any(_contains_placeholder(item) for item in value.values())
    return value is None


def _validate_required_files(bundle_dir: Path) -> list[str]:
    errors: list[str] = []
    if not bundle_dir.is_dir():
        return [f"BUNDLE_DIR_MISSING:{bundle_dir}"]
    for filename in REQUIRED_BUNDLE_FILES:
        if not (bundle_dir / filename).is_file():
            errors.append(f"REQUIRED_BUNDLE_FILE_MISSING:{filename}")
    return errors


def _validate_manifest(bundle_dir: Path) -> list[str]:
    path = bundle_dir / "manifest.json"
    if not path.is_file():
        return ["MANIFEST_MISSING"]
    try:
        manifest = _load_json(path)
    except ValueError as exc:
        return [str(exc)]
    errors: list[str] = []
    if manifest.get("required_files") != REQUIRED_BUNDLE_FILES:
        errors.append("MANIFEST_REQUIRED_FILES_MISMATCH")
    if manifest.get("decision") != "BLOCKED":
        errors.append("MANIFEST_DECISION_MUST_BE_BLOCKED")
    if manifest.get("blocker_003_status") != "OPEN":
        errors.append("MANIFEST_BLOCKER_003_MUST_REMAIN_OPEN")
    if manifest.get("certification_status") != "BLOCKED":
        errors.append("MANIFEST_CERTIFICATION_MUST_REMAIN_BLOCKED")
    if _contains_placeholder(manifest):
        errors.append("MANIFEST_PLACEHOLDER_OR_INCOMPLETE")
    return errors


def _validate_hashes(bundle_dir: Path) -> list[str]:
    path = bundle_dir / "evidence_hashes.json"
    if not path.is_file():
        return ["EVIDENCE_HASHES_MISSING"]
    try:
        payload = _load_json(path)
    except ValueError as exc:
        return [str(exc)]
    errors: list[str] = []
    hashes = payload.get("artifact_hashes")
    if not isinstance(hashes, dict) or not hashes:
        errors.append("ARTIFACT_HASHES_MISSING")
        return errors
    for artifact, expected_hash in sorted(hashes.items()):
        if not isinstance(expected_hash, str) or not HEX64.fullmatch(expected_hash):
            errors.append(f"ARTIFACT_HASH_INVALID:{artifact}")
            continue
        source_path = ROOT / "governance" / "evidence" / "aws-object-lock" / "provider-submissions" / artifact
        if not source_path.is_file():
            errors.append(f"SOURCE_ARTIFACT_MISSING:{artifact}")
            continue
        actual_hash = _sha256(source_path)
        if actual_hash != expected_hash:
            errors.append(f"ARTIFACT_HASH_MISMATCH:{artifact}")
    if _contains_placeholder(payload):
        errors.append("EVIDENCE_HASHES_PLACEHOLDER_OR_INCOMPLETE")
    return errors


def _validate_bundle_hash(bundle_dir: Path) -> list[str]:
    path = bundle_dir / "bundle_sha256.txt"
    if not path.is_file():
        return ["BUNDLE_SHA256_MISSING"]
    expected = path.read_text(encoding="utf-8").strip()
    if not HEX64.fullmatch(expected):
        return ["BUNDLE_SHA256_INVALID"]
    digest = hashlib.sha256()
    for filename in REQUIRED_BUNDLE_FILES:
        if filename == "bundle_sha256.txt":
            continue
        file_path = bundle_dir / filename
        if not file_path.is_file():
            return [f"BUNDLE_ARTIFACT_MISSING:{filename}"]
        digest.update(filename.encode("utf-8"))
        digest.update(b"\0")
        digest.update(file_path.read_bytes())
    actual = digest.hexdigest()
    if actual != expected:
        return ["BUNDLE_SHA256_MISMATCH"]
    return []


def _validate_review_and_custody(bundle_dir: Path) -> list[str]:
    errors: list[str] = []
    for filename in ("chain_of_custody.json", "validation_results.json", "review_decision.json"):
        path = bundle_dir / filename
        if not path.is_file():
            errors.append(f"BUNDLE_ARTIFACT_MISSING:{filename}")
            continue
        try:
            payload = _load_json(path)
        except ValueError as exc:
            errors.append(str(exc))
            continue
        if payload.get("decision") != "BLOCKED":
            errors.append(f"{filename}:DECISION_MUST_BE_BLOCKED")
        if payload.get("blocker_003_status") != "OPEN":
            errors.append(f"{filename}:BLOCKER_003_MUST_REMAIN_OPEN")
        if payload.get("certification_status") != "BLOCKED":
            errors.append(f"{filename}:CERTIFICATION_MUST_REMAIN_BLOCKED")
        if _contains_placeholder(payload):
            errors.append(f"{filename}:PLACEHOLDER_OR_INCOMPLETE")
    return errors


def verify(bundle_dir: Path) -> list[str]:
    errors: list[str] = []
    errors.extend(_validate_required_files(bundle_dir))
    errors.extend(_validate_manifest(bundle_dir))
    errors.extend(_validate_hashes(bundle_dir))
    errors.extend(_validate_bundle_hash(bundle_dir))
    errors.extend(_validate_review_and_custody(bundle_dir))
    return errors


def main() -> int:
    parser = argparse.ArgumentParser(description="Verify local AWS Object Lock evidence export bundle.")
    parser.add_argument("bundle_dir", nargs="?", default=DEFAULT_BUNDLE_DIR.as_posix())
    args = parser.parse_args()
    bundle_dir = Path(args.bundle_dir).resolve()
    errors = verify(bundle_dir)
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
