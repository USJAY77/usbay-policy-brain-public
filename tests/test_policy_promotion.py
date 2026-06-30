from __future__ import annotations

import pytest

from governance.policy_promotion import evaluate_policy_promotion
from governance.policy_registry_contracts import build_policy_record


pytestmark = pytest.mark.governance


def policy(status="DRAFT"):
    return build_policy_record(
        policy_id="policy-1",
        policy_name="Runtime Governance",
        policy_version="v1",
        status=status,
        created_at="2026-06-18T08:00:00Z",
        approved_at="2026-06-18T09:00:00Z" if status in {"APPROVED", "ACTIVE"} else "",
        approved_by="human-1" if status in {"APPROVED", "ACTIVE"} else "",
        audit_hash="a" * 64,
        lineage_hash="l" * 64,
    )


def audit():
    return {"audit_hash": "b" * 64}


def test_promotion_without_approval_blocks():
    result = evaluate_policy_promotion(policy=policy(), target_status="REVIEW_REQUIRED", human_approval=None, audit_record=audit())

    assert result["promotion_status"] == "BLOCKED"
    assert "POLICY_HUMAN_APPROVAL_MISSING" in result["reason_codes"]


def test_promotion_with_approval_allowed():
    result = evaluate_policy_promotion(
        policy=policy(),
        target_status="REVIEW_REQUIRED",
        human_approval={"approved": True, "approved_by": "human-1"},
        audit_record=audit(),
    )

    assert result["promotion_status"] == "PROMOTION_ALLOWED"
    assert result["auto_promoted"] is False
    assert result["auto_approved"] is False
    assert result["auto_activated"] is False


def test_promotion_missing_audit_blocks():
    result = evaluate_policy_promotion(
        policy=policy(),
        target_status="REVIEW_REQUIRED",
        human_approval={"approved": True, "approved_by": "human-1"},
        audit_record=None,
    )

    assert result["promotion_status"] == "BLOCKED"
    assert "POLICY_PROMOTION_AUDIT_RECORD_MISSING" in result["reason_codes"]


def test_invalid_promotion_transition_blocks():
    result = evaluate_policy_promotion(
        policy=policy(),
        target_status="ACTIVE",
        human_approval={"approved": True, "approved_by": "human-1"},
        audit_record=audit(),
    )

    assert result["promotion_status"] == "BLOCKED"
