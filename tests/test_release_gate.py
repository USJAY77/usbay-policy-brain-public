from __future__ import annotations

import pytest

from governance.release_gate import evaluate_release_decision, evaluate_release_readiness, evaluate_release_request, empty_release_gate_dashboard_state
from governance.release_gate_contracts import RELEASE_GATE_POLICY_VERSION, RELEASE_REQUEST_SCHEMA


pytestmark = pytest.mark.governance


def request(**overrides):
    payload = {
        "schema": RELEASE_REQUEST_SCHEMA,
        "release_id": "rel-1",
        "release_name": "Governed release",
        "release_type": "PATCH",
        "target_environment": "STAGING",
        "policy_version": RELEASE_GATE_POLICY_VERSION,
        "policy_hash": "p" * 64,
        "evidence_hash": "e" * 64,
        "audit_registry_hash": "a" * 64,
        "release_manifest_hash": "m" * 64,
        "requested_by": "human-1",
        "approved_by": "human-2",
        "created_at": "2026-06-18T08:00:00Z",
        "approved_at": "2026-06-18T09:00:00Z",
        "decision": "APPROVED_FOR_RELEASE",
        "reason_codes": [],
        "fail_closed": False,
    }
    payload.update(overrides)
    return payload


def ready():
    return {"release_readiness_status": "READY", "reason_codes": []}


def test_release_request_valid_requires_review():
    result = evaluate_release_request(request(decision="REVIEW_REQUIRED", approved_by="", approved_at="", fail_closed=True))

    assert result["release_gate_status"] == "REVIEW_REQUIRED"
    assert result["deploy_enabled"] is False
    assert result["rollback_enabled"] is False


def test_release_decision_approved_when_request_and_readiness_ready():
    result = evaluate_release_decision(request=request(), readiness=ready())

    assert result["release_decision"] == "APPROVED_FOR_RELEASE"
    assert result["publish_enabled"] is False
    assert result["push_enabled"] is False


def test_missing_policy_hash_blocks_decision():
    result = evaluate_release_decision(request=request(policy_hash=""), readiness=ready())

    assert result["release_decision"] == "BLOCKED"
    assert any("POLICY_HASH" in reason for reason in result["reason_codes"])


def test_readiness_block_blocks_decision():
    result = evaluate_release_readiness({"release_readiness_status": "BLOCKED", "reason_codes": ["RELEASE_ROLLBACK_PLAN_MISSING"]})

    assert result["release_decision"] == "BLOCKED"
    assert result["rollback_enabled"] is False


def test_empty_dashboard_state_is_blocked_and_no_auto_actions():
    state = empty_release_gate_dashboard_state()

    assert state["release_gate_status"] == "BLOCKED"
    assert state["release_manifest_status"] == "BLOCKED"
    assert state["rollback_plan_status"] == "MISSING"
    assert state["auto_deployed"] is False
    assert state["auto_released"] is False
    assert state["auto_rolled_back"] is False
    assert state["auto_promoted"] is False
