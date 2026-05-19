from __future__ import annotations

import json

from governance.ci_status_normalization import (
    CI_STATUS_CONTRADICTORY,
    CI_STATUS_MISSING,
    CI_STATUS_PARTIAL,
    CI_STATUS_PROPAGATING,
    CI_STATUS_STALE,
    CI_STATUS_VERIFIED,
    normalize_ci_status,
    reconcile_ci_propagation,
)


REQUIRED = ("audit-artifact-guard", "production-readiness", "governance-check")
HEAD_SHA = "a" * 40


def _check(name: str, *, status: str = "completed", conclusion: str = "success", sha: str = HEAD_SHA) -> dict:
    return {"name": name, "status": status, "conclusion": conclusion, "headSha": sha}


def _checks() -> tuple[dict, ...]:
    return tuple(_check(name) for name in REQUIRED)


def test_verified_ci_status_grants_merge_authority() -> None:
    result = normalize_ci_status(checks=_checks(), required_checks=REQUIRED, pr_head_sha=HEAD_SHA, mergeable=True)

    assert result.canonical_state == CI_STATUS_VERIFIED
    assert result.merge_authority is True
    assert result.audit["final_merge_authority_verdict"] == "ALLOW"
    assert "CI_REQUIRED_CHECKS_PASSED" in result.reason_codes


def test_stale_pr_check_context_fails_closed() -> None:
    result = normalize_ci_status(
        checks=(_check("audit-artifact-guard", sha="b" * 40), _check("production-readiness"), _check("governance-check")),
        required_checks=REQUIRED,
        pr_head_sha=HEAD_SHA,
    )

    assert result.canonical_state == CI_STATUS_STALE
    assert result.merge_authority is False
    assert "ci_required_check_stale:audit-artifact-guard" in result.blockers
    assert result.audit["stale_detection"] == "STALE_CONTEXTS_INVALIDATED"


def test_superseded_dependency_pr_is_rejected() -> None:
    result = normalize_ci_status(
        checks=_checks(),
        required_checks=REQUIRED,
        pr_head_sha=HEAD_SHA,
        superseded_by="cryptography==48.0.0",
    )

    assert result.canonical_state == CI_STATUS_STALE
    assert result.merge_authority is False
    assert "CI_SUPERSEDED_PR_REJECTED" in result.reason_codes


def test_delayed_workflow_propagation_is_not_green() -> None:
    result = normalize_ci_status(
        checks=(
            _check("audit-artifact-guard"),
            _check("production-readiness", status="in_progress", conclusion=""),
            _check("governance-check"),
        ),
        required_checks=REQUIRED,
        pr_head_sha=HEAD_SHA,
    )

    assert result.canonical_state == CI_STATUS_PROPAGATING
    assert result.merge_authority is False
    assert result.audit["propagation_delays"] == "DETECTED"
    assert "CI_DELAYED_PROPAGATION_DETECTED" in result.reason_codes


def test_missing_contexts_fail_closed() -> None:
    result = normalize_ci_status(checks=(), required_checks=REQUIRED, pr_head_sha=HEAD_SHA)

    assert result.canonical_state == CI_STATUS_MISSING
    assert result.merge_authority is False
    assert "ci_required_check_missing:audit-artifact-guard" in result.blockers


def test_partial_workflow_visibility_fails_closed() -> None:
    result = normalize_ci_status(checks=(_check("audit-artifact-guard"),), required_checks=REQUIRED, pr_head_sha=HEAD_SHA)

    assert result.canonical_state == CI_STATUS_PARTIAL
    assert result.merge_authority is False
    assert "CI_PARTIAL_WORKFLOW_VISIBILITY" in result.reason_codes


def test_contradictory_status_fails_closed() -> None:
    result = normalize_ci_status(
        checks=(
            _check("audit-artifact-guard"),
            _check("audit-artifact-guard", conclusion="failure"),
            _check("production-readiness"),
            _check("governance-check"),
        ),
        required_checks=REQUIRED,
        pr_head_sha=HEAD_SHA,
    )

    assert result.canonical_state == CI_STATUS_CONTRADICTORY
    assert result.merge_authority is False
    assert "ci_required_check_contradictory:audit-artifact-guard" in result.blockers


def test_mergeable_false_contradicts_verified_workflow_evidence() -> None:
    result = normalize_ci_status(checks=_checks(), required_checks=REQUIRED, pr_head_sha=HEAD_SHA, mergeable=False)

    assert result.canonical_state == CI_STATUS_CONTRADICTORY
    assert result.merge_authority is False
    assert "CI_MERGEABILITY_CONTRADICTORY" in result.reason_codes


def test_audit_evidence_is_hash_only_and_redacted() -> None:
    result = normalize_ci_status(checks=_checks(), required_checks=REQUIRED, pr_head_sha=HEAD_SHA)
    encoded = json.dumps(result.audit, sort_keys=True)

    assert result.audit["normalized_workflow_list_hash"]
    assert result.audit["required_checks_hash"]
    assert "PRIVATE KEY" not in encoded
    assert "token=" not in encoded.lower()
    assert ("raw_" + "payload") not in encoded


def test_propagation_reconciliation_converges_within_window() -> None:
    result = reconcile_ci_propagation(
        snapshots=[
            (_check("audit-artifact-guard", status="in_progress", conclusion=""),),
            _checks(),
        ],
        required_checks=REQUIRED,
        pr_head_sha=HEAD_SHA,
        max_reconciliation_attempts=3,
        timestamp_utc="2026-05-19T00:00:00Z",
    )

    assert result.canonical_state == CI_STATUS_VERIFIED
    assert result.merge_authority is True
    assert "CI_PROPAGATION_PENDING" in result.reason_codes
    assert "CI_RECONCILIATION_SUCCEEDED" in result.reason_codes
    assert result.audit["attempt_count"] == 2


def test_propagation_reconciliation_times_out_fail_closed() -> None:
    result = reconcile_ci_propagation(
        snapshots=[
            (_check("audit-artifact-guard", status="in_progress", conclusion=""),),
            (_check("audit-artifact-guard", status="in_progress", conclusion=""),),
        ],
        required_checks=REQUIRED,
        pr_head_sha=HEAD_SHA,
        max_reconciliation_attempts=2,
        timestamp_utc="2026-05-19T00:00:00Z",
    )

    assert result.canonical_state == CI_STATUS_PROPAGATING
    assert result.merge_authority is False
    assert "CI_PROPAGATION_TIMEOUT" in result.reason_codes
    assert "CI_RECONCILIATION_DENIED" in result.reason_codes
    assert "ci_propagation_timeout" in result.blockers


def test_incomplete_workflow_fanout_is_distinct_from_missing_all_checks() -> None:
    result = reconcile_ci_propagation(
        snapshots=[(_check("audit-artifact-guard"),)],
        required_checks=REQUIRED,
        pr_head_sha=HEAD_SHA,
        max_reconciliation_attempts=1,
    )

    assert result.canonical_state == CI_STATUS_PARTIAL
    assert result.merge_authority is False
    assert "CI_WORKFLOW_FANOUT_INCOMPLETE" in result.reason_codes


def test_stale_metadata_denies_without_waiting_for_success() -> None:
    result = reconcile_ci_propagation(
        snapshots=[
            (_check("audit-artifact-guard", sha="b" * 40), _check("production-readiness"), _check("governance-check")),
            _checks(),
        ],
        required_checks=REQUIRED,
        pr_head_sha=HEAD_SHA,
        max_reconciliation_attempts=2,
    )

    assert result.canonical_state == CI_STATUS_STALE
    assert result.merge_authority is False
    assert "CI_RECONCILIATION_DENIED" in result.reason_codes
    assert "CI_RECONCILIATION_SUCCEEDED" not in result.reason_codes


def test_missing_checks_remain_missing_until_bounded_reconciliation_timeout() -> None:
    result = reconcile_ci_propagation(
        snapshots=[()],
        required_checks=REQUIRED,
        pr_head_sha=HEAD_SHA,
        max_reconciliation_attempts=1,
    )

    assert result.canonical_state == CI_STATUS_MISSING
    assert result.merge_authority is False
    assert "CI_PROPAGATION_TIMEOUT" in result.reason_codes
    assert "CI_WORKFLOW_FANOUT_INCOMPLETE" not in result.reason_codes


def test_propagation_reconciliation_audit_is_hash_only() -> None:
    result = reconcile_ci_propagation(snapshots=[_checks()], required_checks=REQUIRED, pr_head_sha=HEAD_SHA)
    encoded = json.dumps(result.audit, sort_keys=True)

    assert result.audit["attempts_hash"]
    assert "PRIVATE KEY" not in encoded
    assert "token=" not in encoded.lower()
    assert ("raw_" + "payload") not in encoded
