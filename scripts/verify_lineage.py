#!/usr/bin/env python3
"""Verify normalized audit lineage records.

This verifier is local and read-only. It does not change runtime behavior,
create AWS resources, store credentials, close blockers, or make certification
claims.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_SCHEMA = ROOT / "governance" / "audit_lineage" / "lineage_schema.json"
DEFAULT_LINEAGE = ROOT / "governance" / "audit_lineage" / "lineage_example.json"
HEX64 = re.compile(r"^[0-9a-f]{64}$")
PLACEHOLDERS = {"", "Information not provided.", "BLOCKED", "OPEN", "PARTIAL"}


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
        return value in PLACEHOLDERS
    if isinstance(value, bool):
        return value is False
    if isinstance(value, list):
        return not value or any(_contains_placeholder(item) for item in value)
    if isinstance(value, dict):
        return any(_contains_placeholder(item) for item in value.values())
    return value is None


def _nested_value(payload: dict[str, Any], dotted: str) -> Any:
    current: Any = payload
    for part in dotted.split("."):
        if not isinstance(current, dict):
            return None
        current = current.get(part)
    return current


def _canonical_hash(payload: dict[str, Any]) -> str:
    sanitized = dict(payload)
    sanitized["lineage_hash"] = ""
    rendered = json.dumps(sanitized, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(rendered.encode("utf-8")).hexdigest()


def verify(schema_path: Path, lineage_path: Path) -> list[str]:
    errors: list[str] = []
    try:
        schema = _load_json(schema_path)
        lineage = _load_json(lineage_path)
    except ValueError as exc:
        return [str(exc)]

    for field in schema.get("required_fields", []):
        if field not in lineage:
            errors.append(f"REQUIRED_FIELD_MISSING:{field}")

    if lineage.get("decision") != "BLOCKED":
        errors.append("LINEAGE_DECISION_MUST_REMAIN_BLOCKED")
    blocker_status = lineage.get("blocker_status")
    if not isinstance(blocker_status, dict):
        errors.append("BLOCKER_STATUS_MISSING")
    else:
        if blocker_status.get("BLOCKER-003") != "OPEN":
            errors.append("BLOCKER_003_MUST_REMAIN_OPEN")
    if lineage.get("certification_status") != "BLOCKED":
        errors.append("CERTIFICATION_MUST_REMAIN_BLOCKED")
    if lineage.get("certification_claim") is not False:
        errors.append("CERTIFICATION_CLAIM_PROHIBITED")
    if lineage.get("runtime_behavior_change") is not False:
        errors.append("RUNTIME_BEHAVIOR_CHANGE_PROHIBITED")

    relationships = lineage.get("relationships")
    if not isinstance(relationships, dict):
        errors.append("RELATIONSHIPS_MISSING")
    else:
        for relationship in schema.get("required_relationships", []):
            value = relationships.get(relationship)
            if not isinstance(value, str) or not value or value == "Information not provided.":
                errors.append(f"RELATIONSHIP_MISSING:{relationship}")

    for dotted in schema.get("required_hash_fields", []):
        value = _nested_value(lineage, dotted)
        if not isinstance(value, str) or not HEX64.fullmatch(value):
            errors.append(f"HASH_INVALID:{dotted}")

    for section in (
        "policy_decision",
        "evidence_package",
        "validation_result",
        "review_outcome",
        "export_bundle",
        "certification_assessment",
    ):
        value = lineage.get(section)
        if not isinstance(value, dict):
            errors.append(f"LINEAGE_SECTION_MISSING:{section}")
            continue
        path_value = value.get("path")
        if not isinstance(path_value, str) or not path_value:
            errors.append(f"LINEAGE_PATH_MISSING:{section}")
            continue
        if not (ROOT / path_value).exists():
            errors.append(f"LINEAGE_PATH_NOT_FOUND:{section}:{path_value}")

    if _contains_placeholder(lineage):
        errors.append("LINEAGE_PLACEHOLDER_OR_INCOMPLETE")

    lineage_hash = lineage.get("lineage_hash")
    if isinstance(lineage_hash, str) and HEX64.fullmatch(lineage_hash):
        expected = _canonical_hash(lineage)
        if lineage_hash != expected:
            errors.append("LINEAGE_HASH_MISMATCH")

    return errors


def main() -> int:
    parser = argparse.ArgumentParser(description="Verify normalized audit lineage.")
    parser.add_argument("--schema", default=DEFAULT_SCHEMA.as_posix())
    parser.add_argument("--lineage", default=DEFAULT_LINEAGE.as_posix())
    args = parser.parse_args()

    errors = verify(Path(args.schema), Path(args.lineage))
    if errors:
        print("Decision = BLOCKED")
        for error in errors:
            print(error)
        return 1
    print("Decision = READY_FOR_REVIEW")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
