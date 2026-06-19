from __future__ import annotations

import pytest

from governance.runtime_parity_validator import REASON_RUNTIME_EVALUATION_BLOCKED, validate_runtime_parity


pytestmark = pytest.mark.governance


def test_runtime_parity_validator_passes_for_canonical_read_only_state():
    report = validate_runtime_parity()

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


def test_runtime_parity_validator_fails_closed_for_blocked_runtime_evaluation():
    report = validate_runtime_parity(runtime_evaluation={"runtime_evaluation_status": "BLOCKED"})

    assert report["runtime_parity_status"] == "BLOCKED"
    assert "runtime_evaluation" in report["blocked_checks"]
    assert REASON_RUNTIME_EVALUATION_BLOCKED in report["reason_codes"]
