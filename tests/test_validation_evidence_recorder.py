from __future__ import annotations

import pytest

from governance.validation_evidence_recorder import (
    VALIDATION_EVIDENCE_RECORDER_VERSION,
    ValidationEvidenceRecord,
    redact_validation_summary,
    validate_evidence_record,
    validation_evidence_contract,
)


pytestmark = pytest.mark.governance


def _record(summary: str = "5 passed") -> ValidationEvidenceRecord:
    return ValidationEvidenceRecord(
        command="pytest -q tests/test_example.py",
        result="PASS",
        duration_seconds=1.25,
        timestamp="2026-06-14T00:00:00Z",
        actor="codex",
        branch="usbay/pb-338-validation-evidence-recorder",
        commit="a" * 40,
        changed_files=("governance/validation_evidence_recorder.py",),
        validation_output_summary=summary,
    )


def test_validation_evidence_contract_declares_required_fields_and_no_execution() -> None:
    contract = validation_evidence_contract()

    assert contract["policy_version"] == VALIDATION_EVIDENCE_RECORDER_VERSION
    assert "command" in contract["required_fields"]
    assert "validation_output_summary" in contract["required_fields"]
    assert contract["command_execution_performed"] is False


def test_record_contains_required_metadata_and_hash() -> None:
    payload = _record().to_dict()

    assert payload["policy_version"] == VALIDATION_EVIDENCE_RECORDER_VERSION
    assert payload["command"] == "pytest -q tests/test_example.py"
    assert payload["changed_files"] == ["governance/validation_evidence_recorder.py"]
    assert len(payload["record_hash"]) == 64
    assert validate_evidence_record(payload)["decision"] == "RECORDED"


def test_missing_required_metadata_fails_closed() -> None:
    payload = _record().to_dict()
    payload["actor"] = ""

    result = validate_evidence_record(payload)

    assert result["decision"] == "FAIL_CLOSED"
    assert "VALIDATION_EVIDENCE_ACTOR_MISSING" in result["gaps"]


def test_sensitive_summary_is_redacted_and_rejected_for_raw_record_validation() -> None:
    raw_summary = "Authorization: bearer token leaked"
    payload = _record(raw_summary).to_dict()
    raw_payload = _record(raw_summary).__dict__ | {"policy_version": VALIDATION_EVIDENCE_RECORDER_VERSION}

    assert redact_validation_summary(raw_summary) == "REDACTED_SENSITIVE_VALIDATION_SUMMARY"
    assert payload["validation_output_summary"] == "REDACTED_SENSITIVE_VALIDATION_SUMMARY"
    assert validate_evidence_record(raw_payload)["decision"] == "FAIL_CLOSED"
