from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

from governance.github_pr_review_authorization import (
    verify_github_pr_review_authorization,
    verify_placeholder_approvals_are_non_production,
)
from tests.helpers.github_actions_policy import evaluate_action_ref, load_github_actions_policy


ROOT = Path(__file__).resolve().parents[1]
NOW = datetime(2026, 8, 9, 12, 0, tzinfo=timezone.utc)
HEAD_SHA = "a" * 40
OLD_HEAD_SHA = "b" * 40
POLICY_HASH = "c" * 64
MANIFEST_HASH = "d" * 64


def _review(login: str, *, state: str = "APPROVED", review_id: str = "review-1", head_sha: str = HEAD_SHA, days_old: int = 1) -> dict:
    return {
        "author": {"login": login},
        "commit": {"oid": head_sha},
        "id": review_id,
        "state": state,
        "submittedAt": (NOW - timedelta(days=days_old)).isoformat().replace("+00:00", "Z"),
    }


def _payload(*, reviews: list[dict] | None = None, pr_number: int = 322, repository: str = "USJAY77/usbay-policy-brain-public", head_sha: str = HEAD_SHA) -> dict:
    return {
        "expected_head_sha": HEAD_SHA,
        "expected_pr_number": 322,
        "expected_repository": "USJAY77/usbay-policy-brain-public",
        "head_sha": head_sha,
        "manifest_sha256": MANIFEST_HASH,
        "policy_sha256": POLICY_HASH,
        "pr_number": pr_number,
        "repository": repository,
        "reviews": reviews,
    }


def test_two_distinct_valid_approvals_bound_to_current_head_pass() -> None:
    evidence = verify_github_pr_review_authorization(
        _payload(reviews=[_review("USBAY-AUDIT", review_id="r1"), _review("USBAY-GLOBAL23", review_id="r2")]),
        now=NOW,
    )

    assert evidence["decision"] == "PASS"
    assert evidence["approval_count"] == 2
    assert evidence["production_authorization"] is True
    assert evidence["placeholder_production_authorization"] is False


def test_one_valid_approval_blocks() -> None:
    evidence = verify_github_pr_review_authorization(_payload(reviews=[_review("USBAY-AUDIT")]), now=NOW)

    assert evidence["decision"] == "BLOCKED"
    assert evidence["reason"] == "GITHUB_PR_APPROVALS_INSUFFICIENT"


def test_duplicate_reviewer_blocks() -> None:
    evidence = verify_github_pr_review_authorization(
        _payload(reviews=[_review("USBAY-AUDIT", review_id="r1"), _review("USBAY-AUDIT", review_id="r2")]),
        now=NOW,
    )

    assert evidence["decision"] == "BLOCKED"
    assert evidence["reason"] == "GITHUB_PR_APPROVALS_INSUFFICIENT"


def test_dismissed_or_revoked_review_blocks() -> None:
    evidence = verify_github_pr_review_authorization(
        _payload(reviews=[_review("USBAY-AUDIT", review_id="r1"), _review("USBAY-GLOBAL23", state="DISMISSED", review_id="r2")]),
        now=NOW,
    )

    assert evidence["decision"] == "BLOCKED"
    assert evidence["reason"] == "GITHUB_PR_APPROVAL_REVIEW_REVOKED_OR_DISMISSED"


def test_approval_for_previous_head_blocks() -> None:
    evidence = verify_github_pr_review_authorization(
        _payload(reviews=[_review("USBAY-AUDIT", review_id="r1", head_sha=OLD_HEAD_SHA), _review("USBAY-GLOBAL23", review_id="r2")]),
        now=NOW,
    )

    assert evidence["decision"] == "BLOCKED"
    assert evidence["reason"] == "GITHUB_PR_APPROVAL_HEAD_SHA_MISMATCH"


def test_missing_github_review_data_blocks() -> None:
    evidence = verify_github_pr_review_authorization(_payload(reviews=None), now=NOW)

    assert evidence["decision"] == "BLOCKED"
    assert evidence["reason"] == "GITHUB_PR_APPROVAL_REVIEWS_MISSING"


def test_malformed_review_payload_blocks() -> None:
    evidence = verify_github_pr_review_authorization(_payload(reviews=[{"id": "r1"}]), now=NOW)

    assert evidence["decision"] == "BLOCKED"
    assert evidence["reason"] == "GITHUB_PR_APPROVAL_REVIEWER_MISSING"


def test_placeholder_approval_json_alone_blocks_production_authorization() -> None:
    approvals = json.loads((ROOT / "governance" / "approved_github_actions_policy.approvals.json").read_text(encoding="utf-8"))

    evidence = verify_placeholder_approvals_are_non_production(approvals)

    assert evidence["decision"] == "BLOCKED"
    assert evidence["reason"] == "GITHUB_ACTIONS_POLICY_PLACEHOLDER_APPROVALS_NON_PRODUCTION"
    assert evidence["production_authorization"] is False


def test_wrong_pr_repository_or_head_binding_blocks() -> None:
    base = _payload(reviews=[_review("USBAY-AUDIT", review_id="r1"), _review("USBAY-GLOBAL23", review_id="r2")])
    cases = (
        {**base, "pr_number": 321},
        {**base, "repository": "USJAY77/other"},
        {**base, "head_sha": OLD_HEAD_SHA},
    )

    for payload in cases:
        evidence = verify_github_pr_review_authorization(payload, now=NOW)
        assert evidence["decision"] == "BLOCKED"


def test_valid_approval_evidence_is_redacted() -> None:
    evidence = verify_github_pr_review_authorization(
        _payload(reviews=[_review("USBAY-AUDIT", review_id="r1"), _review("USBAY-GLOBAL23", review_id="r2")]),
        now=NOW,
    )

    serialized = json.dumps(evidence, sort_keys=True)
    assert "USBAY-AUDIT" not in serialized
    assert "USBAY-GLOBAL23" not in serialized
    assert "token" not in serialized.lower()
    assert "secret" not in serialized.lower()
    assert "credential" not in serialized.lower()


def test_current_pr322_dependency_change_remains_only_functional_target() -> None:
    workflow = (ROOT / ".github" / "workflows" / "governance-export-attestation.yml").read_text(encoding="utf-8")
    policy = load_github_actions_policy()

    assert "uses: actions/attest-build-provenance@v3" in workflow
    assert policy["actions"]["actions/attest-build-provenance"]["allowed_version"] == "v3"
    assert set(policy["actions"]) == {
        "actions/attest-build-provenance",
        "actions/checkout",
        "actions/download-artifact",
        "actions/setup-python",
        "actions/upload-artifact",
    }


def test_unknown_action_or_version_remains_fail_closed() -> None:
    policy = load_github_actions_policy()

    unknown = evaluate_action_ref("actions/unapproved-example@v1", context="manual_resilience", policy=policy)
    wrong_version = evaluate_action_ref("actions/attest-build-provenance@v2", context="manual_resilience", policy=policy)

    assert unknown["decision"] == "FAIL_CLOSED"
    assert wrong_version["decision"] == "FAIL_CLOSED"


def test_stale_approval_blocks() -> None:
    evidence = verify_github_pr_review_authorization(
        _payload(reviews=[_review("USBAY-AUDIT", review_id="r1", days_old=20), _review("USBAY-GLOBAL23", review_id="r2")]),
        now=NOW,
    )

    assert evidence["decision"] == "BLOCKED"
    assert evidence["reason"] == "GITHUB_PR_APPROVAL_REVIEW_STALE"


def test_replayed_review_id_blocks() -> None:
    first = _review("USBAY-AUDIT", review_id="same")
    second = _review("USBAY-GLOBAL23", review_id="same")

    evidence = verify_github_pr_review_authorization(_payload(reviews=[first, second]), now=NOW)

    assert evidence["decision"] == "BLOCKED"
    assert evidence["reason"] == "GITHUB_PR_APPROVAL_REVIEW_REPLAYED"


def test_required_approvers_remains_exactly_two() -> None:
    approvals = json.loads((ROOT / "governance" / "approved_github_actions_policy.approvals.json").read_text(encoding="utf-8"))

    evidence = verify_github_pr_review_authorization(
        _payload(reviews=[_review("USBAY-AUDIT", review_id="r1"), _review("USBAY-GLOBAL23", review_id="r2")]),
        now=NOW,
    )

    assert approvals["required_approvers"] == 2
    assert evidence["decision"] == "PASS"
    assert verify_github_pr_review_authorization(_payload(reviews=[]), required_approvers=1, now=NOW)["decision"] == "BLOCKED"
