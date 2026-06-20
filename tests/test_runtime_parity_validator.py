from __future__ import annotations

import pytest

from governance.runtime_parity_validator import (
    REASON_RUNTIME_EVALUATION_BLOCKED,
    runtime_validation_report,
    validate_runtime_parity,
)


pytestmark = pytest.mark.governance


def test_runtime_parity_validator_passes_for_canonical_read_only_state():
    report = validate_runtime_parity()
    validation = runtime_validation_report()

    assert report["runtime_parity_status"] == "VALID"
    assert report["blocked_checks"] == []
    assert report["read_only"] is True
    assert report["execution_enabled"] is False
    assert report["deployment_enabled"] is False
    assert report["runtime_modification_enabled"] is False
    assert report["policy_mutation_enabled"] is False
    assert report["connector_write_enabled"] is False
    assert report["auto_remediation_enabled"] is False
    assert report["auto_approval_enabled"] is False
    assert validation["runtime_validation_status"] == "VALID"
    assert validation["runtime_validation_score"] == 100


def test_runtime_parity_validator_fails_closed_for_blocked_runtime_evaluation():
    report = validate_runtime_parity(runtime_evaluation={"runtime_evaluation_status": "BLOCKED"})
    validation = runtime_validation_report(runtime_evaluation={"runtime_evaluation_status": "BLOCKED"})

    assert report["runtime_parity_status"] == "BLOCKED"
    assert "runtime_evaluation" in report["blocked_checks"]
    assert REASON_RUNTIME_EVALUATION_BLOCKED in report["reason_codes"]
    assert validation["runtime_validation_status"] == "BLOCKED"
    assert "runtime_parity" in validation["blockers"]


def test_runtime_parity_validator_fails_closed_for_duplicate_status(monkeypatch):
    from governance import runtime_parity_validator as validator

    def duplicate_block():
        return {
            "duplicate_status": "BLOCKED",
            "duplicate_owner_count": 1,
            "duplicate_dashboard_owner_count": 0,
            "duplicate_reason_code_owner_count": 0,
            "duplicate_audit_owner_count": 0,
            "duplicate_evidence_owner_count": 0,
            "duplicate_lineage_owner_count": 0,
            "reason_codes": ["DUPLICATE_OWNER"],
        }

    monkeypatch.setattr(validator, "detect_governance_duplicates", duplicate_block)

    report = validate_runtime_parity()
    validation = runtime_validation_report()

    assert report["runtime_parity_status"] == "BLOCKED"
    assert "duplicate_registry" in report["blocked_checks"]
    assert validation["runtime_validation_status"] == "BLOCKED"
    assert "runtime_parity" in validation["blockers"]
