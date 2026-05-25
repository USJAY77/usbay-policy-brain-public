from __future__ import annotations

import pytest

from scripts.governed_dependabot_pr_automation import GOVERNANCE_REVIEW_MISSING, validate_governance_review
from tests.resilience.conftest import fail_closed_evidence


pytestmark = [pytest.mark.resilience, pytest.mark.stress, pytest.mark.slow]

REVIEW_REQUIRED = "governance-review-required"
REVIEW_APPROVED = "governance-review-approved"


def test_human_review_backlog_blocks_without_approval() -> None:
    decisions = []
    for index in range(512):
        ok, blockers, reason_codes, audit = validate_governance_review((REVIEW_REQUIRED, f"backlog-{index}"))
        decisions.append((ok, blockers, reason_codes, audit))

    assert all(ok is False for ok, *_ in decisions)
    assert all("governance_review_missing" in blockers for _, blockers, _, _ in decisions)
    assert all(GOVERNANCE_REVIEW_MISSING in reason_codes for _, _, reason_codes, _ in decisions)
    assert all(audit["status"] == "BLOCK" for *_, audit in decisions)


def test_human_review_escalation_flood_requires_explicit_approval_label() -> None:
    ok, blockers, reason_codes, audit = validate_governance_review(tuple([REVIEW_REQUIRED] * 10_000))

    assert ok is False
    assert blockers == ("governance_review_missing",)
    assert GOVERNANCE_REVIEW_MISSING in reason_codes
    assert audit["status"] == "BLOCK"
    assert audit["review_required"] is True
    assert audit["review_approved"] is False


def test_human_review_flood_with_explicit_approval_does_not_silently_relax_policy() -> None:
    ok, blockers, reason_codes, audit = validate_governance_review((REVIEW_REQUIRED, REVIEW_APPROVED))

    assert ok is True
    assert blockers == ()
    assert reason_codes == ()
    assert audit["status"] == "PASS"
    assert audit["review_required"] is True
    assert audit["review_approved"] is True


def test_review_queue_overload_evidence_is_fail_closed() -> None:
    evidence = fail_closed_evidence(
        reason="HUMAN_REVIEW_QUEUE_OVERLOADED",
        pressure_model="human_review_flood",
        details={"pending_reviews": 10_000, "max_without_escalation": 512},
    )

    assert evidence["decision"] == "FAIL_CLOSED"
    assert evidence["silent_pass"] is False
    assert evidence["details"]["pending_reviews"] == 10_000
