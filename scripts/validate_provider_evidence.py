#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]

DEFAULT_SUBMISSIONS_DIR = ROOT / "governance" / "evidence" / "aws-object-lock" / "provider-submissions"
PILOT_SUBMISSIONS_DIR = ROOT / "governance" / "evidence" / "aws-object-lock" / "pilot-submission"

REQUIRED_FILES = [
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

PLACEHOLDER_VALUES = {
    "",
    "information not provided",
    "not provided",
    "blocked",
    "open",
    "placeholder",
    "todo",
    "tbd",
    None,
}


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def contains_placeholder(value: Any) -> bool:
    if value is None:
        return True
    if isinstance(value, str):
        return value.strip().lower() in PLACEHOLDER_VALUES
    if isinstance(value, dict):
        return any(contains_placeholder(v) for v in value.values())
    if isinstance(value, list):
        return any(contains_placeholder(v) for v in value)
    return False


def load_json(path: Path) -> Any:
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def validate(submissions_dir: Path, required_files: list[str]) -> int:
    errors: list[str] = []

    if not submissions_dir.exists():
        errors.append(f"MISSING_SUBMISSIONS_DIR:{submissions_dir}")

    for name in required_files:
        path = submissions_dir / name
        if not path.exists():
            errors.append(f"MISSING_FILE:{name}")
            continue

        if path.suffix == ".json":
            try:
                data = load_json(path)
            except Exception as exc:
                errors.append(f"INVALID_JSON:{name}:{exc}")
                continue

            if contains_placeholder(data):
                errors.append(f"EVIDENCE_INCOMPLETE:{name}")

    manifest_candidates = [
        submissions_dir / "evidence_manifest.json",
        submissions_dir / "pilot_evidence_manifest.json",
    ]
    manifest = next((m for m in manifest_candidates if m.exists()), None)
    if manifest is None:
        errors.append("MANIFEST_MISSING")
    else:
        try:
            manifest_data = load_json(manifest)
            if contains_placeholder(manifest_data):
                errors.append("EVIDENCE_INCOMPLETE:manifest")
        except Exception as exc:
            errors.append(f"INVALID_JSON:manifest:{exc}")

    chain_candidates = [
        submissions_dir / "chain_of_custody.md",
        submissions_dir / "pilot_chain_of_custody.md",
    ]
    chain = next((c for c in chain_candidates if c.exists()), None)
    if chain is None:
        errors.append("CHAIN_OF_CUSTODY_MISSING")
    else:
        chain_text = chain.read_text(encoding="utf-8").lower()
        if "information not provided" in chain_text or "missing" in chain_text:
            errors.append("CHAIN_OF_CUSTODY_INCOMPLETE")

    print("Decision: BLOCKED")
    print("BLOCKER-003: OPEN")
    print("Certification: BLOCKED")

    if errors:
        for error in errors:
            print(error)
        return 1

    print("Evidence package structurally complete but still requires human review.")
    return 0


def main() -> int:
    submissions_dir = Path(sys.argv[1]).resolve() if len(sys.argv) > 1 else DEFAULT_SUBMISSIONS_DIR

    if submissions_dir.name == "pilot-submission":
        return validate(submissions_dir, PILOT_REQUIRED_FILES)

    return validate(submissions_dir, REQUIRED_FILES)


if __name__ == "__main__":
    raise SystemExit(main())
