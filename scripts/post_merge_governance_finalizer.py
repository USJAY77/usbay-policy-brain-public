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
BRANCH_DELETED_AFTER_MERGE_VERIFIED = "BRANCH_DELETED_AFTER_MERGE_VERIFIED"
PROTECTED_BRANCH_CLEANUP_ALLOWED = "PROTECTED_BRANCH_CLEANUP_ALLOWED"
REASON_MERGE_AUTHORIZATION_FINALIZED = "MERGE_AUTHORIZATION_FINALIZED"
REASON_DUAL_REVIEWER_AUTHORIZATION_VERIFIED = "DUAL_REVIEWER_AUTHORIZATION_VERIFIED"
REFUSAL_COMMENT_SUPPRESSED = "REFUSAL_COMMENT_SUPPRESSED_AFTER_VERIFIED_FINALIZATION"
REFUSAL_COMMENT_REQUIRED = "REFUSAL_COMMENT_REQUIRED_FOR_UNVERIFIED_FINALIZATION"
PROTECTED_BRANCHES = {"main", "master", "develop", "release"}


class FinalizationBlocked(RuntimeError):
    """Raised when post-merge governance cannot be finalized safely."""


def _now_utc() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _canonical_json(payload: Any) -> str:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"))


def _sha256_payload(payload: Any) -> str:
    return hashlib.sha256(_canonical_json(payload).encode("utf-8")).hexdigest()


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
