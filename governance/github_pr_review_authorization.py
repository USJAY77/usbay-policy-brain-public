from __future__ import annotations

import hashlib
import json
from datetime import datetime, timedelta, timezone
from typing import Any, Mapping, Sequence


DEFAULT_REQUIRED_APPROVERS = 2
DEFAULT_TRUSTED_REVIEWERS = ("USBAY-AUDIT", "USBAY-GLOBAL23")
DEFAULT_MAX_APPROVAL_AGE = timedelta(days=14)
PLACEHOLDER_SIGNATURE = "SIGNATURE_PLACEHOLDER_NON_PRODUCTION_DO_NOT_TRUST"


def verify_github_pr_review_authorization(
    payload: Mapping[str, Any],
    *,
    trusted_reviewers: Sequence[str] = DEFAULT_TRUSTED_REVIEWERS,
    required_approvers: int = DEFAULT_REQUIRED_APPROVERS,
    now: datetime | None = None,
    max_approval_age: timedelta = DEFAULT_MAX_APPROVAL_AGE,
) -> dict[str, Any]:
    """Validate GitHub PR reviews as production approval evidence.

    The caller supplies GitHub review metadata. This verifier never treats
    repository placeholder approval records as production authorization.
    """

    if not isinstance(payload, Mapping):
        return _blocked("GITHUB_PR_APPROVAL_PAYLOAD_MALFORMED")
    if required_approvers != DEFAULT_REQUIRED_APPROVERS:
        return _blocked("GITHUB_PR_APPROVAL_REQUIRED_APPROVERS_INVALID")

    expected_repository = _string(payload.get("expected_repository"))
    repository = _string(payload.get("repository"))
    expected_pr_number = payload.get("expected_pr_number")
    pr_number = payload.get("pr_number")
    expected_head_sha = _string(payload.get("expected_head_sha"))
    head_sha = _string(payload.get("head_sha"))
    policy_sha256 = _string(payload.get("policy_sha256"))
    manifest_sha256 = _string(payload.get("manifest_sha256"))
    reviews = payload.get("reviews")

    if not expected_repository or not repository or repository != expected_repository:
        return _blocked("GITHUB_PR_APPROVAL_REPOSITORY_MISMATCH")
    if not isinstance(expected_pr_number, int) or not isinstance(pr_number, int) or pr_number != expected_pr_number:
        return _blocked("GITHUB_PR_APPROVAL_PR_NUMBER_MISMATCH")
    if not _is_sha256(policy_sha256):
        return _blocked("GITHUB_PR_APPROVAL_POLICY_HASH_INVALID")
    if not _is_sha256(manifest_sha256):
        return _blocked("GITHUB_PR_APPROVAL_MANIFEST_HASH_INVALID")
    if not _is_commit_sha(expected_head_sha) or not _is_commit_sha(head_sha) or head_sha != expected_head_sha:
        return _blocked("GITHUB_PR_APPROVAL_HEAD_SHA_MISMATCH")
    if not isinstance(reviews, list):
        return _blocked("GITHUB_PR_APPROVAL_REVIEWS_MISSING")
    if not trusted_reviewers or len({_normalize_reviewer(value) for value in trusted_reviewers}) < required_approvers:
        return _blocked("GITHUB_PR_APPROVAL_TRUSTED_REVIEWERS_INVALID")

    trusted = {_normalize_reviewer(value) for value in trusted_reviewers}
    observed_review_ids: set[str] = set()
    latest_by_reviewer: dict[str, Mapping[str, Any]] = {}
    for review in reviews:
        if not isinstance(review, Mapping):
            return _blocked("GITHUB_PR_APPROVAL_REVIEW_MALFORMED")
        review_id = _review_id(review)
        if not review_id:
            return _blocked("GITHUB_PR_APPROVAL_REVIEW_ID_MISSING")
        if review_id in observed_review_ids:
            return _blocked("GITHUB_PR_APPROVAL_REVIEW_REPLAYED")
        observed_review_ids.add(review_id)

        reviewer = _reviewer_login(review)
        if not reviewer:
            return _blocked("GITHUB_PR_APPROVAL_REVIEWER_MISSING")
        normalized = _normalize_reviewer(reviewer)
        if normalized not in trusted:
            return _blocked("GITHUB_PR_APPROVAL_REVIEWER_UNTRUSTED")

        submitted_at = _parse_utc_timestamp(_string(review.get("submittedAt") or review.get("submitted_at")))
        if submitted_at is None:
            return _blocked("GITHUB_PR_APPROVAL_REVIEW_TIMESTAMP_INVALID")
        current_latest = latest_by_reviewer.get(normalized)
        if current_latest is None:
            latest_by_reviewer[normalized] = review
            continue
        current_timestamp = _parse_utc_timestamp(_string(current_latest.get("submittedAt") or current_latest.get("submitted_at")))
        if current_timestamp is None:
            return _blocked("GITHUB_PR_APPROVAL_REVIEW_TIMESTAMP_INVALID")
        if submitted_at >= current_timestamp:
            latest_by_reviewer[normalized] = review

    effective_approvals: dict[str, Mapping[str, Any]] = {}
    validation_now = now or datetime.now(timezone.utc)
    if validation_now.tzinfo is None:
        validation_now = validation_now.replace(tzinfo=timezone.utc)
    for reviewer, review in latest_by_reviewer.items():
        state = _string(review.get("state")).upper()
        if state in {"DISMISSED", "CHANGES_REQUESTED", "REQUEST_CHANGES", "COMMENTED"}:
            return _blocked("GITHUB_PR_APPROVAL_REVIEW_REVOKED_OR_DISMISSED")
        if state != "APPROVED":
            return _blocked("GITHUB_PR_APPROVAL_REVIEW_STATE_INVALID")
        review_head_sha = _review_head_sha(review)
        if review_head_sha != head_sha:
            return _blocked("GITHUB_PR_APPROVAL_HEAD_SHA_MISMATCH")
        submitted_at = _parse_utc_timestamp(_string(review.get("submittedAt") or review.get("submitted_at")))
        if submitted_at is None:
            return _blocked("GITHUB_PR_APPROVAL_REVIEW_TIMESTAMP_INVALID")
        if submitted_at > validation_now + timedelta(minutes=5):
            return _blocked("GITHUB_PR_APPROVAL_REVIEW_TIMESTAMP_INVALID")
        if submitted_at < validation_now - max_approval_age:
            return _blocked("GITHUB_PR_APPROVAL_REVIEW_STALE")
        effective_approvals[reviewer] = review

    if len(effective_approvals) < required_approvers:
        return _blocked("GITHUB_PR_APPROVALS_INSUFFICIENT")

    approval_hashes = tuple(sorted(_hash_text(reviewer) for reviewer in effective_approvals))
    evidence_payload = {
        "approval_hashes": approval_hashes,
        "head_sha": head_sha,
        "manifest_sha256": manifest_sha256,
        "policy_sha256": policy_sha256,
        "pr_number": pr_number,
        "repository": repository,
        "required_approvers": required_approvers,
    }
    return {
        "approval_count": len(effective_approvals),
        "decision": "PASS",
        "evidence_hash": _hash_payload(evidence_payload),
        "fail_closed": False,
        "head_sha": head_sha,
        "manifest_sha256": manifest_sha256,
        "placeholder_production_authorization": False,
        "policy_sha256": policy_sha256,
        "pr_number": pr_number,
        "production_authorization": True,
        "reason": "GITHUB_PR_APPROVALS_BOUND_TO_CURRENT_HEAD",
        "repository_hash": _hash_text(repository),
        "reviewer_hashes": approval_hashes,
    }


def verify_placeholder_approvals_are_non_production(approvals: Mapping[str, Any]) -> dict[str, Any]:
    if not isinstance(approvals, Mapping):
        return _blocked("GITHUB_ACTIONS_POLICY_APPROVALS_MALFORMED")
    entries = approvals.get("approvals")
    if not isinstance(entries, list):
        return _blocked("GITHUB_ACTIONS_POLICY_APPROVALS_MALFORMED")
    for entry in entries:
        if not isinstance(entry, Mapping):
            return _blocked("GITHUB_ACTIONS_POLICY_APPROVALS_MALFORMED")
        if entry.get("signature_placeholder") != PLACEHOLDER_SIGNATURE:
            return _blocked("GITHUB_ACTIONS_POLICY_APPROVAL_SIGNATURE_UNEXPECTED")
    return _blocked("GITHUB_ACTIONS_POLICY_PLACEHOLDER_APPROVALS_NON_PRODUCTION")


def _blocked(reason: str) -> dict[str, Any]:
    return {
        "decision": "BLOCKED",
        "fail_closed": True,
        "placeholder_production_authorization": False,
        "production_authorization": False,
        "reason": reason,
        "silent_pass": False,
    }


def _hash_payload(payload: Mapping[str, Any]) -> str:
    return hashlib.sha256(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()


def _hash_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _is_sha256(value: str) -> bool:
    return len(value) == 64 and all(character in "0123456789abcdef" for character in value.lower())


def _is_commit_sha(value: str) -> bool:
    return len(value) == 40 and all(character in "0123456789abcdef" for character in value.lower())


def _normalize_reviewer(value: str) -> str:
    return value.strip().lower()


def _parse_utc_timestamp(value: str) -> datetime | None:
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return None
    return parsed.astimezone(timezone.utc)


def _review_id(review: Mapping[str, Any]) -> str:
    return _string(review.get("id") or review.get("databaseId") or review.get("node_id"))


def _reviewer_login(review: Mapping[str, Any]) -> str:
    author = review.get("author") or review.get("user")
    if isinstance(author, Mapping):
        return _string(author.get("login"))
    return _string(review.get("author_login") or review.get("reviewer"))


def _review_head_sha(review: Mapping[str, Any]) -> str:
    commit = review.get("commit")
    if isinstance(commit, Mapping):
        return _string(commit.get("oid") or commit.get("sha"))
    return _string(review.get("commitId") or review.get("commit_id") or review.get("head_sha"))


def _string(value: Any) -> str:
    return value.strip() if isinstance(value, str) else ""
