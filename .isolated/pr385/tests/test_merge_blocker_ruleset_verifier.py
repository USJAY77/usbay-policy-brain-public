from __future__ import annotations

import pytest

from governance.merge_blocker_ruleset_verifier import (
    MERGE_BLOCKER_RULESET_VERSION,
    REQUIRED_CHECKS,
    merge_blocker_ruleset_contract,
    verify_merge_ruleset,
)


pytestmark = pytest.mark.governance


def _passing_checks() -> dict[str, str]:
    return {check: "success" for check in REQUIRED_CHECKS}


def test_merge_blocker_contract_declares_required_checks_and_decisions() -> None:
    contract = merge_blocker_ruleset_contract()

    assert contract["policy_version"] == MERGE_BLOCKER_RULESET_VERSION
    assert contract["required_checks"] == list(REQUIRED_CHECKS)
    assert contract["branch_protection_required"] is True
    assert contract["policy_verification_required"] is True
    assert contract["audit_evidence_required"] is True
    assert contract["allowed_decisions"] == ["MERGE_ELIGIBLE", "BLOCKED"]


def test_merge_eligible_only_when_all_governance_requirements_pass() -> None:
    decision = verify_merge_ruleset(
        checks=_passing_checks(),
        branch_protection_active=True,
        policy_verification_active=True,
        audit_evidence_available=True,
    )

    assert decision.decision == "MERGE_ELIGIBLE"
    assert decision.blockers == ()


def test_missing_required_check_blocks_merge() -> None:
    checks = _passing_checks()
    checks["codeql-quality"] = "failure"

    decision = verify_merge_ruleset(
        checks=checks,
        branch_protection_active=True,
        policy_verification_active=True,
        audit_evidence_available=True,
    )

    assert decision.decision == "BLOCKED"
    assert "REQUIRED_CHECK_NOT_SUCCESS:codeql-quality" in decision.blockers


def test_inactive_branch_protection_policy_or_audit_blocks_merge() -> None:
    decision = verify_merge_ruleset(
        checks=_passing_checks(),
        branch_protection_active=False,
        policy_verification_active=False,
        audit_evidence_available=False,
    )

    assert decision.decision == "BLOCKED"
    assert "BRANCH_PROTECTION_INACTIVE" in decision.blockers
    assert "POLICY_VERIFICATION_INACTIVE" in decision.blockers
    assert "AUDIT_EVIDENCE_UNAVAILABLE" in decision.blockers


def test_unresolved_blockers_are_preserved_and_block_merge() -> None:
    decision = verify_merge_ruleset(
        checks=_passing_checks(),
        branch_protection_active=True,
        policy_verification_active=True,
        audit_evidence_available=True,
        unresolved_blockers=("human_review_missing",),
    )

    assert decision.decision == "BLOCKED"
    assert decision.blockers == ("UNRESOLVED_BLOCKER:human_review_missing",)
