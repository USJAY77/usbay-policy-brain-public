from __future__ import annotations

import json
import sys

import pytest

from governance.audit_lineage_validator import validate_audit_lineage
from governance.audit_registry_contracts import REGISTRY_RECORD_TYPES, build_registry_record
from scripts import verify_lineage


pytestmark = pytest.mark.governance


def chain():
    records = []
    parent_id = ""
    previous_hash = ""
    for index, record_type in enumerate(REGISTRY_RECORD_TYPES):
        record = build_registry_record(
            record_id=f"record-{index}",
            record_type=record_type,
            parent_id=parent_id,
            previous_hash=previous_hash,
            created_at=f"2026-06-18T08:{index:02d}:00Z",
            audit_hash="a" * 64,
            lineage_hash="l" * 64,
            source_component="governance registry",
        )
        records.append(record)
        parent_id = record["record_id"]
        previous_hash = record["current_hash"]
    return records


def test_valid_lineage_verifies():
    result = validate_audit_lineage(chain())

    assert result["lineage_status"] == "VERIFIED"
    assert result["tamper_status"] == "NO_TAMPER_DETECTED"
    assert result["fail_closed"] is False


def test_missing_parent_blocks():
    records = chain()
    parent_id = "missing"
    previous_hash = "p" * 64
    for index in range(2, len(REGISTRY_RECORD_TYPES)):
        records[index] = build_registry_record(
            record_id=f"record-{index}",
            record_type=REGISTRY_RECORD_TYPES[index],
            parent_id=parent_id,
            previous_hash=previous_hash,
            created_at=f"2026-06-18T08:{index:02d}:00Z",
            audit_hash="a" * 64,
            lineage_hash="l" * 64,
            source_component="governance registry",
        )
        parent_id = records[index]["record_id"]
        previous_hash = records[index]["current_hash"]

    result = validate_audit_lineage(records)

    assert result["lineage_status"] == "BLOCKED"
    assert "AUDIT_LINEAGE_PARENT_MISSING:record-2" in result["reason_codes"]


def test_missing_hash_blocks():
    records = chain()
    parent_id = records[0]["record_id"]
    previous_hash = ""
    for index in range(1, len(REGISTRY_RECORD_TYPES)):
        records[index] = build_registry_record(
            record_id=f"record-{index}",
            record_type=REGISTRY_RECORD_TYPES[index],
            parent_id=parent_id,
            previous_hash=previous_hash,
            created_at=f"2026-06-18T08:{index:02d}:00Z",
            audit_hash="a" * 64,
            lineage_hash="l" * 64,
            source_component="governance registry",
        )
        parent_id = records[index]["record_id"]
        previous_hash = records[index]["current_hash"]

    result = validate_audit_lineage(records)

    assert result["lineage_status"] == "BLOCKED"
    assert "AUDIT_LINEAGE_PREVIOUS_HASH_MISSING:record-1" in result["reason_codes"]


def test_timestamp_inversion_blocks():
    records = chain()
    parent_id = records[2]["record_id"]
    previous_hash = records[2]["current_hash"]
    for index in range(3, len(REGISTRY_RECORD_TYPES)):
        created_at = "2026-06-18T07:00:00Z" if index == 3 else f"2026-06-18T08:{index:02d}:00Z"
        records[index] = build_registry_record(
            record_id=f"record-{index}",
            record_type=REGISTRY_RECORD_TYPES[index],
            parent_id=parent_id,
            previous_hash=previous_hash,
            created_at=created_at,
            audit_hash="a" * 64,
            lineage_hash="l" * 64,
            source_component="governance registry",
        )
        parent_id = records[index]["record_id"]
        previous_hash = records[index]["current_hash"]

    result = validate_audit_lineage(records)

    assert result["lineage_status"] == "BLOCKED"
    assert "AUDIT_LINEAGE_TIMESTAMP_INVERSION:record-3" in result["reason_codes"]


def test_hash_mismatch_detects_tamper():
    records = chain()
    records[4]["source_component"] = "changed"

    result = validate_audit_lineage(records)

    assert result["lineage_status"] == "TAMPER_DETECTED"
    assert result["tamper_status"] == "TAMPER_DETECTED"


def _canonical_lineage_fixture() -> dict:
    lineage = {
        "lineage_id": "canonical-test-lineage",
        "lineage_schema": "usbay.governance.audit_lineage_schema.v1",
        "decision": "BLOCKED",
        "blocker_status": {"BLOCKER-003": "OPEN"},
        "certification_status": "BLOCKED",
        "policy_decision": {
            "id": "policy-decision",
            "path": "docs/governance/AUDIT_LINEAGE_FRAMEWORK.md",
            "hash": "a" * 64,
        },
        "evidence_package": {
            "id": "evidence-package",
            "path": "governance/audit_lineage/lineage_schema.json",
            "hash": "b" * 64,
        },
        "validation_result": {
            "id": "validation-result",
            "path": "scripts/verify_lineage.py",
            "hash": "c" * 64,
        },
        "review_outcome": {
            "id": "review-outcome",
            "path": "tests/test_audit_lineage_validator.py",
            "hash": "d" * 64,
        },
        "export_bundle": {
            "id": "export-bundle",
            "path": "governance/audit_lineage/lineage_relationships.md",
            "hash": "e" * 64,
        },
        "certification_assessment": {
            "id": "certification-assessment",
            "path": "governance/audit_lineage/lineage_example.json",
            "hash": "f" * 64,
        },
        "relationships": {
            "policy_decision_to_evidence_package": "policy-decision -> evidence-package",
            "evidence_package_to_validation_result": "evidence-package -> validation-result",
            "validation_result_to_review_outcome": "validation-result -> review-outcome",
            "review_outcome_to_export_bundle": "review-outcome -> export-bundle",
            "export_bundle_to_certification_assessment": "export-bundle -> certification-assessment",
        },
        "lineage_hash": "",
        "certification_claim": False,
        "runtime_behavior_change": False,
    }
    lineage["lineage_hash"] = verify_lineage._canonical_hash(lineage)
    return lineage


def _write_lineage(path, payload):
    path.write_text(json.dumps(payload, sort_keys=True, separators=(",", ":")), encoding="utf-8")


def test_verify_lineage_accepts_canonical_fixture_source(tmp_path):
    lineage_path = tmp_path / "lineage.json"
    _write_lineage(lineage_path, _canonical_lineage_fixture())

    assert verify_lineage.verify(verify_lineage.DEFAULT_SCHEMA, lineage_path) == []


@pytest.mark.parametrize(
    ("mutate", "expected"),
    [
        (lambda payload: payload["policy_decision"].update({"hash": "not-a-hash"}), "HASH_INVALID:policy_decision.hash"),
        (
            lambda payload: payload["relationships"].update({"validation_result_to_review_outcome": ""}),
            "RELATIONSHIP_MISSING:validation_result_to_review_outcome",
        ),
        (lambda payload: payload["validation_result"].pop("path"), "LINEAGE_PATH_MISSING:validation_result"),
    ],
)
def test_verify_lineage_corruption_fixtures_fail_closed(tmp_path, mutate, expected):
    lineage = _canonical_lineage_fixture()
    mutate(lineage)
    lineage_path = tmp_path / "corrupted-lineage.json"
    _write_lineage(lineage_path, lineage)

    errors = verify_lineage.verify(verify_lineage.DEFAULT_SCHEMA, lineage_path)

    assert expected in errors
    assert errors


def test_verify_lineage_cli_fails_closed_on_hash_corruption(tmp_path, monkeypatch, capsys):
    lineage = _canonical_lineage_fixture()
    lineage["lineage_hash"] = "0" * 64
    lineage_path = tmp_path / "hash-corrupted-lineage.json"
    _write_lineage(lineage_path, lineage)
    monkeypatch.setattr(sys, "argv", ["verify_lineage.py", "--lineage", str(lineage_path)])

    assert verify_lineage.main() == 1
    output = capsys.readouterr().out
    assert "Decision = BLOCKED" in output
    assert "LINEAGE_HASH_MISMATCH" in output


def test_invalid_parent_and_orphan_lineage_nodes_fail_closed():
    records = chain()
    records[1]["parent_id"] = "missing-parent"
    records[1]["current_hash"] = "0" * 64
    orphan = build_registry_record(
        record_id="orphan-node",
        record_type="Evidence",
        parent_id="",
        previous_hash="",
        created_at="2026-06-18T09:00:00Z",
        audit_hash="a" * 64,
        lineage_hash="l" * 64,
        source_component="governance registry",
    )
    records.append(orphan)

    result = validate_audit_lineage(records)

    assert result["fail_closed"] is True
    assert "AUDIT_LINEAGE_PARENT_MISSING:record-1" in result["reason_codes"]
    assert "AUDIT_REGISTRY_PARENT_MISSING" in result["reason_codes"]


def test_missing_provenance_source_component_blocks_lineage():
    records = chain()
    records[2] = build_registry_record(
        record_id="record-2",
        record_type=REGISTRY_RECORD_TYPES[2],
        parent_id=records[1]["record_id"],
        previous_hash=records[1]["current_hash"],
        created_at="2026-06-18T08:02:00Z",
        audit_hash="a" * 64,
        lineage_hash="l" * 64,
        source_component="",
    )

    result = validate_audit_lineage(records)

    assert result["fail_closed"] is True
    assert "AUDIT_REGISTRY_SOURCE_COMPONENT_MISSING" in result["reason_codes"]
