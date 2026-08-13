#!/usr/bin/env python3
"""PB-024 post-merge governance finalization.

The finalizer consumes governed branch hygiene audit evidence and produces a
terminal governance state. It converts verified merged-and-deleted branch
cleanup into VERIFIED_SUCCESS while preserving fail-closed behavior whenever
merge authorization or cleanup evidence is incomplete.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


VERIFIED_SUCCESS = "VERIFIED_SUCCESS"
FAIL_CLOSED = "FAIL_CLOSED"
PASS = "PASS"
BLOCK = "BLOCK"
COMMIT_ANCESTRY = "COMMIT_ANCESTRY"
REVIEWED_CONTENT_EQUIVALENCE = "REVIEWED_CONTENT_EQUIVALENCE"
MERGE_COMMIT = "MERGE_COMMIT"
SQUASH = "SQUASH"
REBASE = "REBASE"
PROVEN_MERGE_STRATEGIES = {MERGE_COMMIT, SQUASH, REBASE}
BRANCH_DELETED_AFTER_MERGE_VERIFIED = "BRANCH_DELETED_AFTER_MERGE_VERIFIED"
PROTECTED_BRANCH_CLEANUP_ALLOWED = "PROTECTED_BRANCH_CLEANUP_ALLOWED"
REASON_MERGE_AUTHORIZATION_FINALIZED = "MERGE_AUTHORIZATION_FINALIZED"
REASON_DUAL_REVIEWER_AUTHORIZATION_VERIFIED = "DUAL_REVIEWER_AUTHORIZATION_VERIFIED"
REFUSAL_COMMENT_SUPPRESSED = "REFUSAL_COMMENT_SUPPRESSED_AFTER_VERIFIED_FINALIZATION"
REFUSAL_COMMENT_REQUIRED = "REFUSAL_COMMENT_REQUIRED_FOR_UNVERIFIED_FINALIZATION"
PROTECTED_BRANCHES = {"main", "master", "develop", "release"}
MERGE_EVIDENCE_HEAD_MISMATCH = "MERGE_EVIDENCE_HEAD_MISMATCH"
MERGE_EVIDENCE_APPROVAL_MISSING = "MERGE_EVIDENCE_APPROVAL_MISSING"
MERGE_EVIDENCE_APPROVAL_STALE = "MERGE_EVIDENCE_APPROVAL_STALE"
MERGE_EVIDENCE_CHECK_FAILED = "MERGE_EVIDENCE_CHECK_FAILED"
MERGE_EVIDENCE_CHECK_PENDING = "MERGE_EVIDENCE_CHECK_PENDING"
MERGE_EVIDENCE_CHECK_UNPROVEN = "MERGE_EVIDENCE_CHECK_UNPROVEN"
MERGE_EVIDENCE_STRATEGY_UNPROVEN = "MERGE_EVIDENCE_STRATEGY_UNPROVEN"
MERGE_EVIDENCE_BOUNDARY_MISMATCH = "MERGE_EVIDENCE_BOUNDARY_MISMATCH"
MERGE_EVIDENCE_BLOB_MISMATCH = "MERGE_EVIDENCE_BLOB_MISMATCH"
MERGE_EVIDENCE_UNEXPECTED_FILES = "MERGE_EVIDENCE_UNEXPECTED_FILES"
MERGE_EVIDENCE_UNEXPECTED_TREE_CHANGE = "MERGE_EVIDENCE_UNEXPECTED_TREE_CHANGE"
MERGE_EVIDENCE_ANCESTRY_FAILED = "MERGE_EVIDENCE_ANCESTRY_FAILED"
MERGE_EVIDENCE_INCOMPLETE = "MERGE_EVIDENCE_INCOMPLETE"
COMMIT_ANCESTRY_VERIFIED = "COMMIT_ANCESTRY_VERIFIED"
REVIEWED_CONTENT_EQUIVALENCE_VERIFIED = "REVIEWED_CONTENT_EQUIVALENCE_VERIFIED"


class FinalizationBlocked(RuntimeError):
    """Raised when post-merge governance cannot be finalized safely."""


def _now_utc() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _canonical_json(payload: Any) -> str:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"))


def _sha256_payload(payload: Any) -> str:
    return hashlib.sha256(_canonical_json(payload).encode("utf-8")).hexdigest()


def _is_sha(value: Any, length: int = 40) -> bool:
    return isinstance(value, str) and len(value) == length and all(character in "0123456789abcdef" for character in value.lower())


def _as_tuple_of_strings(value: Any) -> tuple[str, ...]:
    if not isinstance(value, list | tuple):
        return ()
    return tuple(str(item) for item in value)


def _hash_mapping(value: Any) -> dict[str, str]:
    if not isinstance(value, dict):
        return {}
    return {str(path): str(blob_hash) for path, blob_hash in value.items()}


def _same_boundary(left: tuple[str, ...], right: tuple[str, ...]) -> bool:
    return tuple(sorted(left)) == tuple(sorted(right)) and len(left) == len(set(left)) and len(right) == len(set(right))


def _normalize_check_statuses(value: Any) -> tuple[dict[str, Any], ...]:
    if isinstance(value, dict):
        checks = value.get("checks")
        if isinstance(checks, list | tuple):
            return tuple(check for check in checks if isinstance(check, dict))
        if "status" in value or "conclusion" in value:
            return (value,)
    if isinstance(value, list | tuple):
        return tuple(check for check in value if isinstance(check, dict))
    return ()


def _approval_reason(evidence: dict[str, Any], reviewed_head_sha: str) -> str | None:
    approval = evidence.get("human_approval_status")
    if not isinstance(approval, dict):
        return MERGE_EVIDENCE_APPROVAL_MISSING
    if approval.get("status") != PASS:
        return MERGE_EVIDENCE_APPROVAL_MISSING
    if int(approval.get("approved_reviewer_count", 0)) < 2:
        return MERGE_EVIDENCE_APPROVAL_MISSING
    if approval.get("stale") is True:
        return MERGE_EVIDENCE_APPROVAL_STALE
    approved_head = str(approval.get("approved_head_sha") or approval.get("head_sha") or "")
    if approved_head != reviewed_head_sha:
        return MERGE_EVIDENCE_HEAD_MISMATCH
    return None


def _check_reason(evidence: dict[str, Any], reviewed_head_sha: str) -> str | None:
    checks = _normalize_check_statuses(evidence.get("required_check_status"))
    if not checks:
        return MERGE_EVIDENCE_CHECK_UNPROVEN
    for check in checks:
        status = str(check.get("status") or "").lower()
        conclusion = str(check.get("conclusion") or "").lower()
        head_sha = str(check.get("head_sha") or check.get("headSha") or reviewed_head_sha)
        if head_sha != reviewed_head_sha:
            return MERGE_EVIDENCE_CHECK_UNPROVEN
        if status in {"queued", "pending", "in_progress", "waiting", "requested"} or conclusion in {"pending", ""}:
            return MERGE_EVIDENCE_CHECK_PENDING
        if status != "completed" or conclusion != "success":
            return MERGE_EVIDENCE_CHECK_FAILED
    return None


def verify_authoritative_merge_evidence(evidence: dict[str, Any]) -> dict[str, Any]:
    """Validate reviewed-head to authoritative-main merge evidence.

    This verifier supports commit ancestry and reviewed content equivalence.
    Every unknown or incomplete proof returns BLOCK; filenames or semantic
    similarity are never accepted as a substitute for deterministic blob hashes.
    """

    if not isinstance(evidence, dict):
        return _merge_evidence_result(
            {},
            evidence_model="UNPROVEN",
            decision=BLOCK,
            reason_code=MERGE_EVIDENCE_INCOMPLETE,
            blockers=[MERGE_EVIDENCE_INCOMPLETE],
        )

    blockers: list[str] = []
    reviewed_head_sha = str(evidence.get("reviewed_head_sha") or "")
    integration_commit_sha = str(evidence.get("integration_commit_sha") or "")
    authoritative_main_sha = str(evidence.get("authoritative_main_sha") or "")
    merge_strategy = str(evidence.get("merge_strategy") or "UNPROVEN")
    reviewed_hashes = _hash_mapping(evidence.get("reviewed_file_hashes"))
    integration_hashes = _hash_mapping(evidence.get("integration_file_hashes"))
    reviewed_files = _as_tuple_of_strings(evidence.get("reviewed_file_boundary") or evidence.get("reviewed_files"))
    integration_files = _as_tuple_of_strings(evidence.get("integration_file_boundary") or evidence.get("integration_effect_files"))
    if not reviewed_files:
        reviewed_files = tuple(reviewed_hashes)
    if not integration_files:
        integration_files = tuple(integration_hashes)

    if not _is_sha(reviewed_head_sha) or not _is_sha(integration_commit_sha) or not _is_sha(authoritative_main_sha):
        blockers.append(MERGE_EVIDENCE_INCOMPLETE)
    if evidence.get("authenticated_reviewed_head_sha") not in (reviewed_head_sha, True):
        blockers.append(MERGE_EVIDENCE_HEAD_MISMATCH)
    if evidence.get("integration_commit_reachable_from_main") is not True:
        blockers.append(MERGE_EVIDENCE_ANCESTRY_FAILED)
    if merge_strategy not in PROVEN_MERGE_STRATEGIES:
        blockers.append(MERGE_EVIDENCE_STRATEGY_UNPROVEN)

    approval_blocker = _approval_reason(evidence, reviewed_head_sha)
    if approval_blocker:
        blockers.append(approval_blocker)
    check_blocker = _check_reason(evidence, reviewed_head_sha)
    if check_blocker:
        blockers.append(check_blocker)

    if not reviewed_hashes or not integration_hashes or not reviewed_files or not integration_files:
        blockers.append(MERGE_EVIDENCE_INCOMPLETE)
    if not _same_boundary(reviewed_files, integration_files) or set(reviewed_hashes) != set(integration_hashes):
        blockers.append(MERGE_EVIDENCE_BOUNDARY_MISMATCH)
    else:
        for path in sorted(reviewed_hashes):
            if reviewed_hashes[path] != integration_hashes[path] or not _is_sha(reviewed_hashes[path]):
                blockers.append(MERGE_EVIDENCE_BLOB_MISMATCH)
                break

    if _as_tuple_of_strings(evidence.get("unexpected_files")):
        blockers.append(MERGE_EVIDENCE_UNEXPECTED_FILES)
    if _as_tuple_of_strings(evidence.get("unexpected_tree_changes")):
        blockers.append(MERGE_EVIDENCE_UNEXPECTED_TREE_CHANGE)
    if evidence.get("unreviewed_post_review_mutation") not in (False, None):
        blockers.append(MERGE_EVIDENCE_UNEXPECTED_TREE_CHANGE)

    ancestry_preserved = evidence.get("reviewed_commit_ancestor_of_main") is True
    if merge_strategy == MERGE_COMMIT:
        evidence_model = COMMIT_ANCESTRY
        if not ancestry_preserved:
            blockers.append(MERGE_EVIDENCE_ANCESTRY_FAILED)
        success_reason = COMMIT_ANCESTRY_VERIFIED
    elif merge_strategy in {SQUASH, REBASE}:
        evidence_model = REVIEWED_CONTENT_EQUIVALENCE
        success_reason = REVIEWED_CONTENT_EQUIVALENCE_VERIFIED
    else:
        evidence_model = "UNPROVEN"
        success_reason = MERGE_EVIDENCE_STRATEGY_UNPROVEN

    unique_blockers = sorted(set(blockers))
    return _merge_evidence_result(
        evidence,
        evidence_model=evidence_model,
        decision=PASS if not unique_blockers else BLOCK,
        reason_code=success_reason if not unique_blockers else unique_blockers[0],
        blockers=unique_blockers,
    )


def _merge_evidence_result(
    evidence: dict[str, Any],
    *,
    evidence_model: str,
    decision: str,
    reason_code: str,
    blockers: list[str],
) -> dict[str, Any]:
    reviewed_hashes = _hash_mapping(evidence.get("reviewed_file_hashes"))
    integration_hashes = _hash_mapping(evidence.get("integration_file_hashes"))
    result = {
        "schema_version": "usbay.authoritative_merge_evidence.v1",
        "evidence_model": evidence_model,
        "repository_identity": evidence.get("repository_identity"),
        "pr_number": evidence.get("pr_number"),
        "base_ref": evidence.get("base_ref"),
        "reviewed_head_sha": evidence.get("reviewed_head_sha"),
        "integration_commit_sha": evidence.get("integration_commit_sha"),
        "authoritative_main_sha": evidence.get("authoritative_main_sha"),
        "merge_strategy": evidence.get("merge_strategy", "UNPROVEN"),
        "reviewed_file_count": len(reviewed_hashes),
        "integration_file_count": len(integration_hashes),
        "reviewed_file_hashes": dict(sorted(reviewed_hashes.items())),
        "integration_file_hashes": dict(sorted(integration_hashes.items())),
        "human_approval_status": {
            "approved_reviewer_count": (evidence.get("human_approval_status") or {}).get("approved_reviewer_count")
            if isinstance(evidence.get("human_approval_status"), dict)
            else None,
            "status": (evidence.get("human_approval_status") or {}).get("status") if isinstance(evidence.get("human_approval_status"), dict) else None,
        },
        "required_check_status": "PASS" if _check_reason(evidence, str(evidence.get("reviewed_head_sha") or "")) is None else "BLOCK",
        "unexpected_files": list(_as_tuple_of_strings(evidence.get("unexpected_files"))),
        "unexpected_tree_changes": list(_as_tuple_of_strings(evidence.get("unexpected_tree_changes"))),
        "verification_result": decision,
        "reason_code": reason_code,
        "blockers": blockers,
        "sensitive_payload_included": False,
    }
    result["evidence_hash"] = _sha256_payload(result)
    return result


def load_json(path: Path) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise FinalizationBlocked("AUDIT_EVIDENCE_MISSING") from exc
    except json.JSONDecodeError as exc:
        raise FinalizationBlocked("AUDIT_EVIDENCE_INVALID_JSON") from exc
    if not isinstance(payload, dict):
        raise FinalizationBlocked("AUDIT_EVIDENCE_INVALID_SCHEMA")
    return payload


def _reason_codes(payload: dict[str, Any]) -> set[str]:
    values = payload.get("reason_codes", ())
    if isinstance(values, str):
        return {values}
    if isinstance(values, (list, tuple)):
        return {str(value) for value in values}
    return set()


def _merge_authorization_verified(audit: dict[str, Any]) -> tuple[bool, list[str]]:
    gaps: list[str] = []
    governance = audit.get("governance_enforcement")
    if not isinstance(governance, dict):
        return False, ["governance_enforcement_missing"]
    if governance.get("merge_authorization_finalized") is not True:
        gaps.append("merge_authorization_not_finalized")
    if REASON_MERGE_AUTHORIZATION_FINALIZED not in _reason_codes(governance):
        gaps.append("merge_authorization_reason_missing")
    reviewer = governance.get("reviewer_authorization")
    if not isinstance(reviewer, dict) or reviewer.get("reason_code") != REASON_DUAL_REVIEWER_AUTHORIZATION_VERIFIED:
        gaps.append("dual_reviewer_authorization_unverified")
    if not audit.get("merge_commit_sha"):
        gaps.append("merge_commit_sha_missing")
    if audit.get("main_containment_proof", {}).get("merge_commit_reachable_from_main") is not True:
        gaps.append("merge_commit_not_reachable_from_main")
    return not gaps, gaps


def _cleanup_verified(audit: dict[str, Any]) -> tuple[bool, list[str]]:
    gaps: list[str] = []
    branch_name = str(audit.get("branch_name") or "")
    if branch_name in PROTECTED_BRANCHES:
        gaps.append("protected_branch_cleanup_forbidden")
    if audit.get("hygiene_outcome") != VERIFIED_SUCCESS:
        gaps.append("hygiene_outcome_not_verified_success")
    if audit.get("post_merge_cleanup_verified") is not True:
        gaps.append("post_merge_cleanup_not_verified")
    if audit.get("github_check_conclusion") != "success":
        gaps.append("github_check_conclusion_not_success")
    if audit.get("deletion_decision") != "DELETE":
        gaps.append("deletion_decision_not_delete")
    deletion = audit.get("branch_deletion_reconciliation")
    if not isinstance(deletion, dict) or deletion.get("reason_code") != BRANCH_DELETED_AFTER_MERGE_VERIFIED:
        gaps.append("branch_deletion_reconciliation_unverified")
    protection = audit.get("branch_protection_reconciliation")
    if not isinstance(protection, dict) or protection.get("reason_code") != PROTECTED_BRANCH_CLEANUP_ALLOWED:
        gaps.append("cleanup_authorization_unverified")
    if audit.get("audit_hash") is None:
        gaps.append("source_audit_hash_missing")
    return not gaps, gaps


def build_merge_outcome(audit: dict[str, Any]) -> dict[str, Any]:
    verified, gaps = _merge_authorization_verified(audit)
    outcome = {
        "schema": "usbay.pb024.merge_outcome.v1",
        "decision": VERIFIED_SUCCESS if verified else FAIL_CLOSED,
        "merge_authorization_outcome": "APPROVED_MERGE_COMPLETION_VERIFIED" if verified else "MERGE_COMPLETION_UNVERIFIED",
        "pr_number": audit.get("pr_number"),
        "branch_name": audit.get("branch_name"),
        "merge_commit_sha": audit.get("merge_commit_sha"),
        "source_audit_hash": audit.get("audit_hash"),
        "gaps": gaps,
    }
    outcome["record_hash"] = _sha256_payload(outcome)
    return outcome


def build_cleanup_verification(audit: dict[str, Any]) -> dict[str, Any]:
    verified, gaps = _cleanup_verified(audit)
    outcome = {
        "schema": "usbay.pb024.cleanup_verification.v1",
        "decision": VERIFIED_SUCCESS if verified else FAIL_CLOSED,
        "cleanup_verification_outcome": "APPROVED_BRANCH_DELETION_VERIFIED" if verified else "BRANCH_DELETION_UNVERIFIED",
        "branch_name": audit.get("branch_name"),
        "reason_code": audit.get("reason_code"),
        "post_merge_cleanup_verified": audit.get("post_merge_cleanup_verified") is True,
        "github_check_conclusion": audit.get("github_check_conclusion"),
        "source_audit_hash": audit.get("audit_hash"),
        "gaps": gaps,
    }
    outcome["record_hash"] = _sha256_payload(outcome)
    return outcome


def finalize_post_merge_governance(audit: dict[str, Any]) -> dict[str, Any]:
    merge_outcome = build_merge_outcome(audit)
    cleanup = build_cleanup_verification(audit)
    verified = merge_outcome["decision"] == VERIFIED_SUCCESS and cleanup["decision"] == VERIFIED_SUCCESS
    blockers = list(merge_outcome["gaps"]) + list(cleanup["gaps"])
    report = {
        "schema": "usbay.pb024.post_merge_governance_finalization.v1",
        "decision": VERIFIED_SUCCESS if verified else FAIL_CLOSED,
        "status": "READY FOR REVIEW" if verified else "FAIL_CLOSED",
        "final_merge_authorization_outcome": merge_outcome["merge_authorization_outcome"],
        "final_cleanup_verification_outcome": cleanup["cleanup_verification_outcome"],
        "refusal_comment_allowed": not verified,
        "refusal_comment_outcome": REFUSAL_COMMENT_SUPPRESSED if verified else REFUSAL_COMMENT_REQUIRED,
        "false_refusal_prevented": verified,
        "audit_trail_preserved": bool(audit.get("audit_hash")),
        "source_audit_hash": audit.get("audit_hash"),
        "merge_outcome_hash": merge_outcome["record_hash"],
        "cleanup_verification_hash": cleanup["record_hash"],
        "blockers": blockers,
        "evaluated_at_utc": _now_utc(),
    }
    report["finalization_hash"] = _sha256_payload(report)
    return {
        "merge_outcome": merge_outcome,
        "cleanup_verification": cleanup,
        "finalization_report": report,
    }


def write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def sample_verified_hygiene_audit() -> dict[str, Any]:
    audit = {
        "schema": "usbay.post_merge_branch_hygiene.v1",
        "branch_name": "governance/pb024-finalization",
        "pr_number": 24,
        "merge_commit_sha": "a" * 40,
        "branch_head_sha": None,
        "main_containment_proof": {
            "branch_head_reachable_from_main": None,
            "merge_commit_reachable_from_main": True,
        },
        "branch_deletion_reconciliation": {
            "reason_code": BRANCH_DELETED_AFTER_MERGE_VERIFIED,
            "audit_hash": "b" * 64,
        },
        "branch_protection_reconciliation": {
            "reason_code": PROTECTED_BRANCH_CLEANUP_ALLOWED,
            "audit_hash": "c" * 64,
        },
        "governance_enforcement": {
            "merge_authorization_finalized": True,
            "reason_codes": [REASON_MERGE_AUTHORIZATION_FINALIZED, REASON_DUAL_REVIEWER_AUTHORIZATION_VERIFIED],
            "reviewer_authorization": {
                "reason_code": REASON_DUAL_REVIEWER_AUTHORIZATION_VERIFIED,
                "approved_reviewer_count": 2,
                "audit_hash": "d" * 64,
            },
        },
        "deletion_decision": "DELETE",
        "hygiene_outcome": VERIFIED_SUCCESS,
        "post_merge_cleanup_verified": True,
        "github_check_conclusion": "success",
        "reason_code": BRANCH_DELETED_AFTER_MERGE_VERIFIED,
    }
    audit["audit_hash"] = _sha256_payload(audit)
    return audit


def run_self_test() -> int:
    verified = finalize_post_merge_governance(sample_verified_hygiene_audit())
    blocked_audit = {**sample_verified_hygiene_audit(), "branch_deletion_reconciliation": {"reason_code": "BRANCH_DELETION_UNVERIFIED"}}
    blocked = finalize_post_merge_governance(blocked_audit)
    if (
        verified["finalization_report"]["decision"] != VERIFIED_SUCCESS
        or verified["finalization_report"]["refusal_comment_allowed"] is not False
        or blocked["finalization_report"]["decision"] != FAIL_CLOSED
        or blocked["finalization_report"]["refusal_comment_allowed"] is not True
    ):
        print("PB024_SELF_TEST=false", flush=True)
        return 1
    print("PB024_SELF_TEST=true", flush=True)
    return 0


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="PB-024 post-merge governance finalizer")
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--sample-verified", action="store_true")
    parser.add_argument("--hygiene-audit", type=Path)
    parser.add_argument("--merge-outcome-output", type=Path, required=False)
    parser.add_argument("--cleanup-verification-output", type=Path, required=False)
    parser.add_argument("--finalization-report-output", type=Path, required=False)
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    if args.self_test:
        return run_self_test()
    try:
        if args.sample_verified:
            audit = sample_verified_hygiene_audit()
        elif args.hygiene_audit:
            audit = load_json(args.hygiene_audit)
        else:
            raise FinalizationBlocked("HYGIENE_AUDIT_REQUIRED")
        result = finalize_post_merge_governance(audit)
        if args.merge_outcome_output:
            write_json(args.merge_outcome_output, result["merge_outcome"])
        if args.cleanup_verification_output:
            write_json(args.cleanup_verification_output, result["cleanup_verification"])
        if args.finalization_report_output:
            write_json(args.finalization_report_output, result["finalization_report"])
    except FinalizationBlocked as exc:
        print("Decision: FAIL_CLOSED")
        print(str(exc))
        return 1
    print(json.dumps(result["finalization_report"], indent=2, sort_keys=True))
    return 0 if result["finalization_report"]["decision"] == VERIFIED_SUCCESS else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
