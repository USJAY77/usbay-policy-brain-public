from __future__ import annotations

from datetime import datetime, timezone

import pytest

from governance.recovery_validation import validate_recovery_readiness


pytestmark = pytest.mark.governance


NOW = datetime(2026, 6, 18, tzinfo=timezone.utc)


def recovery(**overrides):
    payload = {
        "recovery_plan": "plan-1",
        "recovery_owner": "ops-owner",
        "recovery_test": "PASSED",
        "recovery_evidence": "evidence-hash",
        "recovery_timestamp": "2026-06-18T00:00:00Z",
        "audit_hash": "a" * 64,
        "lineage_hash": "l" * 64,
    }
    payload.update(overrides)
    return payload


def test_valid_recovery_readiness():
    result = validate_recovery_readiness(recovery(), now=NOW)

    assert result["recovery_validation_status"] == "READY"
    assert result["rollback_enabled"] is False


def test_missing_plan_blocks():
    result = validate_recovery_readiness(recovery(recovery_plan=""), now=NOW)

    assert "RECOVERY_PLAN_MISSING" in result["reason_codes"]


def test_missing_owner_blocks():
    result = validate_recovery_readiness(recovery(recovery_owner=""), now=NOW)

    assert "RECOVERY_OWNER_MISSING" in result["reason_codes"]


def test_missing_evidence_blocks():
    result = validate_recovery_readiness(recovery(recovery_evidence=""), now=NOW)

    assert "RECOVERY_EVIDENCE_MISSING" in result["reason_codes"]


def test_expired_recovery_test_blocks():
    result = validate_recovery_readiness(recovery(recovery_timestamp="2026-06-01T00:00:00Z"), now=NOW)

    assert "RECOVERY_TEST_EXPIRED" in result["reason_codes"]
