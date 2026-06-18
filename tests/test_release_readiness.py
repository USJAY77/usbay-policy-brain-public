from __future__ import annotations

import pytest

from governance.release_readiness import evaluate_release_readiness


pytestmark = pytest.mark.governance


def readiness(**overrides):
    payload = {
        "human_approval": {"approved": True, "approved_by": "human-1"},
        "policy_registry_status": "ACTIVE",
        "audit_registry_status": "READY",
        "evidence_trust_status": "READY",
        "test_summary_hash": "t" * 64,
        "rollback_plan_hash": "r" * 64,
        "tenant_boundary_status": "READY",
        "production_readiness_status": "READY",
        "release_manifest_hash": "m" * 64,
    }
    payload.update(overrides)
    return evaluate_release_readiness(**payload)


def test_ready_when_all_requirements_present():
    result = readiness()

    assert result["release_readiness_status"] == "READY"
    assert result["fail_closed"] is False


def test_missing_human_approval_blocks():
    result = readiness(human_approval=None)

    assert result["release_readiness_status"] == "BLOCKED"
    assert "RELEASE_HUMAN_APPROVAL_MISSING" in result["reason_codes"]


def test_missing_rollback_plan_blocks():
    result = readiness(rollback_plan_hash="")

    assert result["rollback_plan_status"] == "MISSING"
    assert "RELEASE_ROLLBACK_PLAN_MISSING" in result["reason_codes"]


def test_missing_tenant_boundary_blocks_with_specific_status():
    result = readiness(tenant_boundary_status="NOT_IMPLEMENTED")

    assert result["release_readiness_status"] == "BLOCKED"
    assert "BLOCKED_WITH_MISSING_TENANT_BOUNDARY" in result["reason_codes"]


def test_missing_production_readiness_blocks_with_specific_status():
    result = readiness(production_readiness_status="NOT_IMPLEMENTED")

    assert result["release_readiness_status"] == "BLOCKED"
    assert "BLOCKED_WITH_MISSING_PRODUCTION_READINESS" in result["reason_codes"]


def test_missing_release_manifest_hash_blocks():
    result = readiness(release_manifest_hash="")

    assert "RELEASE_MANIFEST_HASH_MISSING" in result["reason_codes"]
