from __future__ import annotations

import pytest

from governance.policy_deprecation import evaluate_policy_deprecation
from governance.policy_registry_contracts import build_policy_record


pytestmark = pytest.mark.governance


def policy(status="ACTIVE"):
    return build_policy_record(
        policy_id="policy-1",
        policy_name="Runtime Governance",
        policy_version="v1",
        status=status,
        created_at="2026-06-18T08:00:00Z",
        approved_at="2026-06-18T09:00:00Z",
        approved_by="human-1",
        audit_hash="a" * 64,
        lineage_hash="l" * 64,
    )


def audit():
    return {"audit_hash": "b" * 64}


def test_deprecation_without_replacement_blocks():
    result = evaluate_policy_deprecation(
        policy=policy(),
        target_status="DEPRECATED",
        reason="superseded",
        replacement_policy_id="",
        audit_record=audit(),
    )

    assert result["deprecation_status"] == "BLOCKED"
    assert "POLICY_REPLACEMENT_POLICY_MISSING" in result["reason_codes"]


def test_deprecation_with_replacement_allowed():
    result = evaluate_policy_deprecation(
        policy=policy(),
        target_status="DEPRECATED",
        reason="superseded",
        replacement_policy_id="policy-2",
        audit_record=audit(),
    )

    assert result["deprecation_status"] == "DEPRECATION_ALLOWED"
    assert result["auto_retired"] is False
    assert result["auto_promoted"] is False


def test_deprecation_missing_reason_blocks():
    result = evaluate_policy_deprecation(
        policy=policy(),
        target_status="DEPRECATED",
        reason="",
        replacement_policy_id="policy-2",
        audit_record=audit(),
    )

    assert result["deprecation_status"] == "BLOCKED"
    assert "POLICY_DEPRECATION_REASON_MISSING" in result["reason_codes"]


def test_retirement_from_deprecated_allowed_with_replacement():
    result = evaluate_policy_deprecation(
        policy=policy(status="DEPRECATED"),
        target_status="RETIRED",
        reason="retired after replacement",
        replacement_policy_id="policy-2",
        audit_record=audit(),
    )

    assert result["deprecation_status"] == "DEPRECATION_ALLOWED"
