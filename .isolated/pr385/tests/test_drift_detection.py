from __future__ import annotations

import pytest

from governance.drift_detection import BLOCKED, DRIFT_DETECTED, NO_DRIFT, detect_drift


pytestmark = pytest.mark.governance


def state(**overrides):
    payload = {
        "policy_version": "policy-v1",
        "audit_hash": "a" * 64,
        "lineage_hash": "l" * 64,
        "configuration_hash": "c" * 64,
    }
    payload.update(overrides)
    return payload


def test_no_drift_when_state_matches():
    result = detect_drift(baseline=state(), current=state())

    assert result["drift_status"] == NO_DRIFT
    assert result["fail_closed"] is False
    assert result["auto_remediation_enabled"] is False


def test_policy_audit_lineage_and_configuration_drift_detected():
    result = detect_drift(
        baseline=state(),
        current=state(policy_version="policy-v2", audit_hash="b" * 64, lineage_hash="m" * 64, configuration_hash="d" * 64),
    )

    assert result["drift_status"] == DRIFT_DETECTED
    assert result["policy_drift"] is True
    assert result["audit_drift"] is True
    assert result["lineage_drift"] is True
    assert result["configuration_drift"] is True
    assert result["fail_closed"] is True


def test_unknown_drift_inputs_block():
    result = detect_drift(baseline=None, current=state())

    assert result["drift_status"] == BLOCKED
    assert result["fail_closed"] is True


def test_missing_drift_field_blocks():
    result = detect_drift(baseline=state(audit_hash=""), current=state())

    assert result["drift_status"] == BLOCKED
    assert "AUDIT_DRIFT_UNKNOWN" in result["reason_codes"]
