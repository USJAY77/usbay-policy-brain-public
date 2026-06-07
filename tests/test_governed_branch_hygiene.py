from __future__ import annotations

import json
from pathlib import Path

from scripts.governed_branch_hygiene import (
    BRANCH_DELETED_AFTER_MERGE_VERIFIED,
    PROTECTED_BRANCH_CLEANUP_ALLOWED,
    PROTECTED_BRANCH_CLEANUP_DENIED,
    REASON_BRANCH_PROTECTION_LOOKUP_FAILED,
    REASON_BRANCH_ALREADY_MERGED,
    REASON_BRANCH_NOT_MERGED_BLOCKED,
    REASON_GOVERNANCE_FEATURE_BRANCH_ALLOWED,
    REASON_GITHUB_WORKFLOW_STATE_UNVERIFIABLE,
    REASON_LINEAGE_UNCLEAR_BLOCKED,
    REASON_MAIN_BRANCH_POLICY_REQUIRED,
    REASON_MAIN_RULESET_VALIDATED,
    REASON_DUAL_REVIEWER_AUTHORIZATION_MISSING,
    REASON_DUAL_REVIEWER_AUTHORIZATION_VERIFIED,
    REASON_MERGE_AUTHORIZATION_FINALIZED,
    REASON_MERGE_AUTHORIZATION_NOT_FINALIZED,
    REASON_OPEN_PR_BRANCH_BLOCKED,
    REASON_PROTECTED_BRANCH_BLOCKED,
    REASON_PROTECTED_BRANCH_REQUIRED,
    REASON_REVIEW_AUTHORIZATION_REQUIRED,
    REASON_RULESET_ENFORCEMENT_ACTIVE,
    REASON_RULESET_ENFORCEMENT_MISSING,
    REASON_RULESET_LOOKUP_FAILED,
    REASON_RESTORED_AFTER_MERGE,
    REASON_VALID_NON_PROTECTED_BRANCH,
    OUTCOME_BLOCKED,
    OUTCOME_VERIFIED_SUCCESS,
    BranchHygieneInput,
    classify_workflow_run_retrieval,
    delete_remote_branch,
    evaluate_branch_hygiene,
    load_state_from_github,
    main,
    normalize_pr_merge_state,
    _branch_head_state,
    _branch_protection_state,
    _main_ruleset_state,
    _protection_lookup_result,
    _pr_state,
    _reviewer_authorization_state,
    write_audit_record,
    write_terminal_state_report,
)
from governance.toolchain_compatibility import GH_PR_VIEW_FIELD_LIST, normalize_gh_pr_merge_state


SHA_MAIN = "a" * 40
SHA_BRANCH = "b" * 40


def _ruleset_verified() -> dict:
    return {
        "schema": "usbay.branch_hygiene.ruleset_governance.v1",
        "target_branch_hash": "a" * 64,
        "active_ruleset_count": 1,
        "ruleset_hash": "b" * 64,
        "reason_code": REASON_MAIN_RULESET_VALIDATED,
        "audit_hash": "c" * 64,
    }


def _reviewers_verified() -> dict:
    return {
        "schema": "usbay.branch_hygiene.reviewer_authorization.v1",
        "required_approver_count": 2,
        "approved_reviewer_count": 2,
        "approved_reviewer_hashes": ["d" * 64, "e" * 64],
        "reason_code": REASON_DUAL_REVIEWER_AUTHORIZATION_VERIFIED,
        "audit_hash": "f" * 64,
    }


def _state(**overrides) -> BranchHygieneInput:
    values = {
        "branch_name": "governance/bounded-validation-orchestration",
        "pr_number": 78,
        "pr_merged": True,
        "merge_commit_sha": SHA_MAIN,
        "branch_head_sha": SHA_BRANCH,
        "main_contains_branch_head": True,
        "merge_commit_on_main": True,
        "open_pr_references_branch": False,
        "protected_branch": False,
        "previously_deleted": False,
        "ruleset_governance": _ruleset_verified(),
        "reviewer_authorization": _reviewers_verified(),
        "merge_authorization_finalized": True,
    }
    values.update(overrides)
    return BranchHygieneInput(**values)


def test_merged_governance_branch_deleted() -> None:
    decision = evaluate_branch_hygiene(_state())

    assert decision.delete_branch is True
    assert decision.reason_code == REASON_BRANCH_ALREADY_MERGED
    assert decision.audit["deletion_decision"] == "DELETE"
    assert decision.audit["hygiene_outcome"] == OUTCOME_VERIFIED_SUCCESS
    assert decision.audit["post_merge_cleanup_verified"] is True
    assert decision.audit["github_check_conclusion"] == "success"
    assert decision.audit["audit_record_created_before_delete"] is True
    assert REASON_GOVERNANCE_FEATURE_BRANCH_ALLOWED in decision.audit["branch_protection"]["reason_codes"]


def test_restored_merged_branch_deleted_with_restored_reason() -> None:
    decision = evaluate_branch_hygiene(_state(previously_deleted=True))

    assert decision.delete_branch is True
    assert decision.reason_code == REASON_RESTORED_AFTER_MERGE
    assert decision.audit["previously_deleted"] is True


def test_unmerged_branch_blocked() -> None:
    decision = evaluate_branch_hygiene(_state(pr_merged=False))

    assert decision.delete_branch is False
    assert decision.audit["hygiene_outcome"] == OUTCOME_BLOCKED
    assert decision.audit["github_check_conclusion"] == "failure"
    assert decision.reason_code == REASON_BRANCH_NOT_MERGED_BLOCKED
    assert "pr_not_merged" in decision.blockers


def test_open_pr_branch_blocked() -> None:
    decision = evaluate_branch_hygiene(_state(open_pr_references_branch=True))

    assert decision.delete_branch is False
    assert decision.reason_code == REASON_OPEN_PR_BRANCH_BLOCKED
    assert "open_pr_references_branch" in decision.blockers


def test_protected_branch_blocked() -> None:
    decision = evaluate_branch_hygiene(_state(branch_name="main", protected_branch=True))

    assert decision.delete_branch is False
    assert decision.reason_code == REASON_PROTECTED_BRANCH_BLOCKED
    assert "main_branch_policy_required" in decision.blockers
    assert REASON_MAIN_BRANCH_POLICY_REQUIRED in decision.audit["branch_protection"]["reason_codes"]


def test_protected_feature_branch_blocked() -> None:
    decision = evaluate_branch_hygiene(
        _state(protected_branch=True, protection_reason_code=REASON_PROTECTED_BRANCH_REQUIRED)
    )

    assert decision.delete_branch is False
    assert decision.reason_code == REASON_PROTECTED_BRANCH_BLOCKED
    assert "protected_branch" in decision.blockers
    assert REASON_PROTECTED_BRANCH_REQUIRED in decision.audit["branch_protection"]["reason_codes"]


def test_non_protected_governance_feature_branch_passes_hygiene() -> None:
    decision = evaluate_branch_hygiene(
        _state(protected_branch=False, protection_reason_code=REASON_GOVERNANCE_FEATURE_BRANCH_ALLOWED)
    )

    assert decision.delete_branch is True
    assert REASON_GOVERNANCE_FEATURE_BRANCH_ALLOWED in decision.audit["branch_protection"]["reason_codes"]
    assert REASON_MAIN_RULESET_VALIDATED in decision.audit["governance_enforcement"]["reason_codes"]
    assert REASON_DUAL_REVIEWER_AUTHORIZATION_VERIFIED in decision.audit["governance_enforcement"]["reason_codes"]
    assert REASON_MERGE_AUTHORIZATION_FINALIZED in decision.audit["governance_enforcement"]["reason_codes"]


def test_ruleset_governance_missing_fails_closed() -> None:
    decision = evaluate_branch_hygiene(
        _state(ruleset_governance={"reason_code": REASON_RULESET_ENFORCEMENT_MISSING, "audit_hash": "0" * 64})
    )

    assert decision.delete_branch is False
    assert "main_ruleset_governance_unverified" in decision.blockers
    assert REASON_RULESET_ENFORCEMENT_MISSING in decision.audit["governance_enforcement"]["reason_codes"]


def test_dual_reviewer_authorization_missing_fails_closed() -> None:
    decision = evaluate_branch_hygiene(
        _state(
            reviewer_authorization={
                "reason_code": REASON_DUAL_REVIEWER_AUTHORIZATION_MISSING,
                "approved_reviewer_count": 1,
                "audit_hash": "1" * 64,
            }
        )
    )

    assert decision.delete_branch is False
    assert "dual_reviewer_authorization_missing" in decision.blockers
    assert REASON_DUAL_REVIEWER_AUTHORIZATION_MISSING in decision.audit["governance_enforcement"]["reason_codes"]


def test_merge_authorization_not_finalized_fails_closed() -> None:
    decision = evaluate_branch_hygiene(_state(merge_authorization_finalized=False))

    assert decision.delete_branch is False
    assert "merge_authorization_not_finalized" in decision.blockers
    assert REASON_MERGE_AUTHORIZATION_NOT_FINALIZED in decision.audit["governance_enforcement"]["reason_codes"]


def test_branch_protection_lookup_failure_fails_closed() -> None:
    decision = evaluate_branch_hygiene(
        _state(
            protected_branch=True,
            protection_reason_code=REASON_BRANCH_PROTECTION_LOOKUP_FAILED,
            ruleset_governance={"reason_code": REASON_RULESET_LOOKUP_FAILED, "audit_hash": "0" * 64},
        )
    )

    assert decision.delete_branch is False
    assert "branch_protection_lookup_failed" in decision.blockers
    assert REASON_BRANCH_PROTECTION_LOOKUP_FAILED in decision.audit["branch_protection"]["reason_codes"]


def test_unreachable_commit_branch_blocked() -> None:
    decision = evaluate_branch_hygiene(_state(main_contains_branch_head=False, merge_commit_on_main=False))

    assert decision.delete_branch is False
    assert decision.reason_code == REASON_LINEAGE_UNCLEAR_BLOCKED
    assert "branch_head_not_reachable_from_main" in decision.blockers


def test_unclear_lineage_fails_closed() -> None:
    decision = evaluate_branch_hygiene(_state(main_contains_branch_head=None))

    assert decision.delete_branch is False
    assert decision.reason_code == REASON_LINEAGE_UNCLEAR_BLOCKED
    assert "main_containment_proof_ambiguous" in decision.blockers


def test_audit_record_emitted_before_deletion(tmp_path: Path) -> None:
    decision = evaluate_branch_hygiene(_state())
    audit_path = tmp_path / "branch-hygiene-audit.json"

    write_audit_record(audit_path, decision.audit)

    audit = json.loads(audit_path.read_text(encoding="utf-8"))
    assert audit["branch_name"] == "governance/bounded-validation-orchestration"
    assert audit["pr_number"] == 78
    assert audit["merge_commit_sha"] == SHA_MAIN
    assert audit["branch_head_sha"] == SHA_BRANCH
    assert audit["deletion_decision"] == "DELETE"
    assert audit["reason_code"] == REASON_BRANCH_ALREADY_MERGED
    assert audit["main_containment_proof"]["branch_head_reachable_from_main"] is True
    assert audit["audit_hash"]


def test_delete_remote_branch_refuses_unsafe_names(monkeypatch) -> None:
    calls: list[list[str]] = []
    monkeypatch.setattr("scripts.governed_branch_hygiene._run_gh", lambda args: calls.append(args))

    try:
        delete_remote_branch("owner/repo", "main")
    except SystemExit as exc:
        assert "BRANCH_DELETE_REFUSED_UNSAFE_NAME" in str(exc)
    else:
        raise AssertionError("main deletion should fail closed")

    assert calls == []


def test_delete_remote_branch_uses_scoped_ref_after_audit(monkeypatch) -> None:
    calls: list[list[str]] = []
    monkeypatch.setattr("scripts.governed_branch_hygiene._run_gh", lambda args: calls.append(args))

    delete_remote_branch("owner/repo", "governance/bounded-validation-orchestration")

    assert calls == [
        [
            "api",
            "-X",
            "DELETE",
            "repos/owner/repo/git/refs/heads/governance/bounded-validation-orchestration",
        ]
    ]


def test_branch_protection_404_classifies_governance_feature_branch_as_non_protected(monkeypatch) -> None:
    class Completed:
        returncode = 1
        stdout = ""
        stderr = "HTTP 404: Not Found"

    monkeypatch.setattr("scripts.governed_branch_hygiene._run_gh_result", lambda args: Completed())

    protected, reason = _branch_protection_state("owner/repo", "governance/deterministic-pr-resolution")

    assert protected is False
    assert reason == REASON_GOVERNANCE_FEATURE_BRANCH_ALLOWED


def test_branch_protection_404_classifies_dependabot_branch_as_valid_non_protected(monkeypatch) -> None:
    class Completed:
        returncode = 1
        stdout = ""
        stderr = "HTTP 404: Not Found"

    monkeypatch.setattr("scripts.governed_branch_hygiene._run_gh_result", lambda args: Completed())

    protected, reason = _branch_protection_state("owner/repo", "dependabot/pip/cryptography-46.0.7")

    assert protected is False
    assert reason == REASON_VALID_NON_PROTECTED_BRANCH


def test_branch_protection_unknown_api_failure_fails_closed(monkeypatch) -> None:
    class Completed:
        returncode = 1
        stdout = ""
        stderr = "HTTP 500: server error"

    monkeypatch.setattr("scripts.governed_branch_hygiene._run_gh_result", lambda args: Completed())

    protected, reason = _branch_protection_state("owner/repo", "governance/deterministic-pr-resolution")

    assert protected is True
    assert reason == REASON_BRANCH_PROTECTION_LOOKUP_FAILED


def test_main_branch_policy_required_uses_legacy_fallback_when_ruleset_missing(monkeypatch) -> None:
    class Completed:
        returncode = 0
        stdout = "{}"
        stderr = ""

    calls: list[list[str]] = []

    def fake_run(args):
        calls.append(args)
        return Completed()

    monkeypatch.setattr("scripts.governed_branch_hygiene._run_gh_result", fake_run)

    protected, reason = _branch_protection_state("owner/repo", "main")

    assert protected is True
    assert reason == REASON_MAIN_BRANCH_POLICY_REQUIRED
    assert calls == [["api", "repos/owner/repo/branches/main/protection"]]


def test_main_ruleset_state_detects_active_ruleset(monkeypatch) -> None:
    class Completed:
        returncode = 0
        stdout = json.dumps(
            [
                {
                    "id": 101,
                    "name": "main governance ruleset",
                    "target": "branch",
                    "enforcement": "active",
                    "conditions": {"ref_name": {"include": ["refs/heads/main"]}},
                }
            ]
        )
        stderr = ""

    monkeypatch.setattr("scripts.governed_branch_hygiene._run_gh_result", lambda args: Completed())

    evidence = _main_ruleset_state("owner/repo")

    assert evidence["reason_code"] == REASON_RULESET_ENFORCEMENT_ACTIVE
    assert evidence["active_ruleset_count"] == 1
    assert evidence["legacy_branch_protection_fallback_only"] is True
    assert evidence["audit_hash"]
    encoded = json.dumps(evidence, sort_keys=True)
    assert "main governance ruleset" not in encoded


def test_main_ruleset_lookup_failure_fails_closed(monkeypatch) -> None:
    class Completed:
        returncode = 1
        stdout = ""
        stderr = "HTTP 403: Forbidden"

    monkeypatch.setattr("scripts.governed_branch_hygiene._run_gh_result", lambda args: Completed())

    evidence = _main_ruleset_state("owner/repo")

    assert evidence["reason_code"] == REASON_RULESET_LOOKUP_FAILED
    assert evidence["active_ruleset_count"] == 0


def test_dual_reviewer_authorization_requires_two_latest_approvals(monkeypatch) -> None:
    class Completed:
        returncode = 0
        stdout = json.dumps(
            [
                {"user": {"login": "alice"}, "state": "APPROVED", "submitted_at": "2026-05-20T00:00:00Z"},
                {"user": {"login": "bob"}, "state": "APPROVED", "submitted_at": "2026-05-20T00:01:00Z"},
                {"user": {"login": "carol"}, "state": "COMMENTED", "submitted_at": "2026-05-20T00:02:00Z"},
            ]
        )
        stderr = ""

    monkeypatch.setattr("scripts.governed_branch_hygiene._run_gh_result", lambda args: Completed())

    evidence = _reviewer_authorization_state("owner/repo", 78)

    assert evidence["reason_code"] == REASON_DUAL_REVIEWER_AUTHORIZATION_VERIFIED
    assert evidence["requirement_reason_code"] == REASON_REVIEW_AUTHORIZATION_REQUIRED
    assert evidence["approved_reviewer_count"] == 2
    encoded = json.dumps(evidence, sort_keys=True)
    assert "alice" not in encoded
    assert "bob" not in encoded


def test_dual_reviewer_authorization_latest_state_must_be_approved(monkeypatch) -> None:
    class Completed:
        returncode = 0
        stdout = json.dumps(
            [
                {"user": {"login": "alice"}, "state": "APPROVED", "submitted_at": "2026-05-20T00:00:00Z"},
                {"user": {"login": "alice"}, "state": "CHANGES_REQUESTED", "submitted_at": "2026-05-20T00:03:00Z"},
                {"user": {"login": "bob"}, "state": "APPROVED", "submitted_at": "2026-05-20T00:01:00Z"},
            ]
        )
        stderr = ""

    monkeypatch.setattr("scripts.governed_branch_hygiene._run_gh_result", lambda args: Completed())

    evidence = _reviewer_authorization_state("owner/repo", 78)

    assert evidence["reason_code"] == REASON_DUAL_REVIEWER_AUTHORIZATION_MISSING
    assert evidence["approved_reviewer_count"] == 1


def test_ruleset_authority_short_circuits_legacy_protection_for_governance_branch(monkeypatch) -> None:
    calls: list[list[str]] = []
    monkeypatch.setattr("scripts.governed_branch_hygiene._run_gh_result", lambda args: calls.append(args))

    protected, reason = _branch_protection_state(
        "owner/repo",
        "governance/ruleset-cleanup",
        {"reason_code": REASON_RULESET_ENFORCEMENT_ACTIVE, "audit_hash": "a" * 64},
    )

    assert protected is False
    assert reason == REASON_GOVERNANCE_FEATURE_BRANCH_ALLOWED
    assert calls == []


def test_ruleset_authority_classifies_main_as_protected_without_legacy_lookup(monkeypatch) -> None:
    calls: list[list[str]] = []
    monkeypatch.setattr("scripts.governed_branch_hygiene._run_gh_result", lambda args: calls.append(args))

    protected, reason = _branch_protection_state(
        "owner/repo",
        "main",
        {"reason_code": REASON_RULESET_ENFORCEMENT_ACTIVE, "audit_hash": "a" * 64},
    )

    assert protected is True
    assert reason == REASON_RULESET_ENFORCEMENT_ACTIVE
    assert calls == []


def test_ruleset_missing_falls_back_to_legacy_protection(monkeypatch) -> None:
    class Completed:
        returncode = 0
        stdout = "{}"
        stderr = ""

    monkeypatch.setattr("scripts.governed_branch_hygiene._run_gh_result", lambda args: Completed())

    protected, reason = _branch_protection_state(
        "owner/repo",
        "main",
        {"reason_code": REASON_RULESET_ENFORCEMENT_MISSING, "audit_hash": "a" * 64},
    )

    assert protected is True
    assert reason == REASON_MAIN_BRANCH_POLICY_REQUIRED


def test_ruleset_and_legacy_protection_unresolved_fails_closed(monkeypatch) -> None:
    class Completed:
        returncode = 1
        stdout = ""
        stderr = "HTTP 500: server error"

    monkeypatch.setattr("scripts.governed_branch_hygiene._run_gh_result", lambda args: Completed())

    protected, reason = _branch_protection_state(
        "owner/repo",
        "main",
        {"reason_code": REASON_RULESET_LOOKUP_FAILED, "audit_hash": "a" * 64},
    )

    assert protected is True
    assert reason == REASON_BRANCH_PROTECTION_LOOKUP_FAILED


def test_pr_view_uses_supported_github_cli_fields_only(monkeypatch) -> None:
    calls: list[list[str]] = []

    def fake_json(args):
        calls.append(args)
        return {
            "number": 78,
            "state": "MERGED",
            "mergedAt": "2026-05-19T00:00:00Z",
            "mergeCommit": {"oid": SHA_MAIN},
            "mergeStateStatus": "UNKNOWN",
            "mergedBy": {"login": "human"},
            "headRefName": "governance/bounded-validation-orchestration",
        }

    monkeypatch.setattr("scripts.governed_branch_hygiene._gh_json", fake_json)

    payload = _pr_state(78)

    assert payload["state"] == "MERGED"
    assert "--json" in calls[0]
    assert GH_PR_VIEW_FIELD_LIST in calls[0]
    assert "merged," not in GH_PR_VIEW_FIELD_LIST
    assert ",merged," not in GH_PR_VIEW_FIELD_LIST


def test_normalize_pr_merge_state_uses_supported_fields() -> None:
    normalized = normalize_pr_merge_state(
        {
            "state": "MERGED",
            "mergedAt": "2026-05-19T00:00:00Z",
            "mergeCommit": {"oid": SHA_MAIN},
            "mergeStateStatus": "CLEAN",
            "mergedBy": {"login": "human"},
        }
    )

    assert normalized["pr_merged"] is True
    assert normalized["merge_commit_sha"] == SHA_MAIN
    assert normalized["merged_by_login"] == "human"


def test_missing_merge_commit_for_merged_pr_fails_closed() -> None:
    try:
        normalize_pr_merge_state({"state": "MERGED", "mergedAt": "2026-05-19T00:00:00Z", "mergeCommit": None})
    except SystemExit as exc:
        assert "PR_MERGE_STATE_UNDETERMINED" in str(exc)
    else:
        raise AssertionError("merged PR without merge commit should fail closed")


def test_unmerged_pr_with_merge_metadata_fails_closed() -> None:
    try:
        normalize_pr_merge_state({"state": "CLOSED", "mergedAt": "", "mergeCommit": {"oid": SHA_MAIN}})
    except SystemExit as exc:
        assert "PR_MERGE_STATE_UNDETERMINED" in str(exc)
    else:
        raise AssertionError("unmerged PR with merge commit should fail closed")


def test_load_state_from_github_normalizes_merge_state(monkeypatch) -> None:
    monkeypatch.setattr(
        "scripts.governed_branch_hygiene._pr_state",
        lambda pr: {
            "number": pr,
            "state": "MERGED",
            "mergedAt": "2026-05-19T00:00:00Z",
            "mergeCommit": {"oid": SHA_MAIN},
            "mergeStateStatus": "CLEAN",
            "mergedBy": {"login": "human"},
            "headRefName": "governance/bounded-validation-orchestration",
        },
    )
    monkeypatch.setattr("scripts.governed_branch_hygiene._branch_head_state", lambda repo, branch: (SHA_BRANCH, False))
    monkeypatch.setattr("scripts.governed_branch_hygiene._branch_protection_state", lambda repo, branch, ruleset=None: (False, REASON_GOVERNANCE_FEATURE_BRANCH_ALLOWED))
    monkeypatch.setattr("scripts.governed_branch_hygiene._open_pr_references_branch", lambda branch: False)
    monkeypatch.setattr("scripts.governed_branch_hygiene._contains_ref", lambda ref: True)
    monkeypatch.setattr("scripts.governed_branch_hygiene._main_ruleset_state", lambda repo: _ruleset_verified())
    monkeypatch.setattr("scripts.governed_branch_hygiene._reviewer_authorization_state", lambda repo, pr: _reviewers_verified())

    state = load_state_from_github("owner/repo", 78, None)

    assert state.pr_merged is True
    assert state.merge_commit_sha == SHA_MAIN
    assert state.branch_head_sha == SHA_BRANCH
    assert state.toolchain_audit_evidence
    assert state.toolchain_audit_evidence["tool_name"] == "gh"
    assert state.branch_protection_reconciliation
    assert state.branch_protection_reconciliation["reason_code"] == PROTECTED_BRANCH_CLEANUP_ALLOWED


def test_branch_hygiene_uses_toolchain_guard_for_merge_normalization(monkeypatch) -> None:
    calls: list[dict] = []

    def guarded(payload):
        calls.append(payload)
        return normalize_gh_pr_merge_state(payload)

    monkeypatch.setattr("scripts.governed_branch_hygiene.normalize_gh_pr_merge_state", guarded)

    normalized = normalize_pr_merge_state(
        {
            "state": "MERGED",
            "mergedAt": "2026-05-19T00:00:00Z",
            "mergeCommit": {"oid": SHA_MAIN},
            "mergeStateStatus": "CLEAN",
            "mergedBy": {"login": "human"},
        }
    )

    assert calls
    assert normalized["pr_merged"] is True


def test_branch_hygiene_audit_includes_toolchain_compatibility_evidence() -> None:
    decision = evaluate_branch_hygiene(
        _state(
            toolchain_audit_evidence={
                "schema": "usbay.toolchain_compatibility.v1",
                "tool_name": "gh",
                "command_family": "pr view",
                "supported_field_list_hash": "a" * 64,
                "requested_field_list_hash": "b" * 64,
                "normalized_merge_state": {"pr_merged": True, "merge_commit_sha_present": True},
                "reason_code": "PR_MERGE_STATE_NORMALIZED",
                "audit_hash": "c" * 64,
            }
        )
    )

    assert decision.audit["toolchain_compatibility"]["tool_name"] == "gh"
    assert decision.audit["toolchain_compatibility"]["reason_code"] == "PR_MERGE_STATE_NORMALIZED"


def test_merged_deleted_branch_passes_without_branch_head() -> None:
    decision = evaluate_branch_hygiene(
        _state(
            branch_head_sha=None,
            main_contains_branch_head=None,
            merge_commit_on_main=True,
            branch_ref_not_found=True,
            branch_deletion_reconciliation={
                "reason_code": BRANCH_DELETED_AFTER_MERGE_VERIFIED,
                "audit_hash": "d" * 64,
                "merge_proof_hash": "e" * 64,
            },
            branch_protection_reconciliation={
                "reason_code": PROTECTED_BRANCH_CLEANUP_ALLOWED,
                "audit_hash": "f" * 64,
                "cleanup_authorization_state": "ALLOWED",
            },
        )
    )

    assert decision.delete_branch is True
    assert decision.reason_code == OUTCOME_VERIFIED_SUCCESS
    assert decision.audit["hygiene_outcome"] == OUTCOME_VERIFIED_SUCCESS
    assert decision.audit["terminal_state"]["decision"] == OUTCOME_VERIFIED_SUCCESS
    assert decision.audit["terminal_state"]["status"] == "COMPLETED"
    assert decision.audit["terminal_state"]["terminal_state_verified"] is True
    assert decision.audit["terminal_state"]["refusal_comment_allowed"] is False
    assert decision.audit["terminal_state"]["legacy_reason_code_suppressed"] is True
    assert "branch_head_sha_missing_or_invalid" not in decision.blockers
    assert decision.audit["branch_deletion_reconciliation"]["reason_code"] == BRANCH_DELETED_AFTER_MERGE_VERIFIED


def test_deleted_branch_without_verified_reconciliation_fails_closed() -> None:
    decision = evaluate_branch_hygiene(
        _state(
            branch_head_sha=None,
            main_contains_branch_head=None,
            merge_commit_on_main=True,
            branch_ref_not_found=True,
            branch_deletion_reconciliation={
                "reason_code": "BRANCH_DELETION_UNVERIFIED",
                "audit_hash": "d" * 64,
            },
        )
    )

    assert decision.delete_branch is False
    assert "branch_deletion_unverified" in decision.blockers


def test_terminal_state_report_can_be_written(tmp_path: Path) -> None:
    decision = evaluate_branch_hygiene(
        _state(
            branch_head_sha=None,
            main_contains_branch_head=None,
            merge_commit_on_main=True,
            branch_ref_not_found=True,
            branch_deletion_reconciliation={
                "reason_code": BRANCH_DELETED_AFTER_MERGE_VERIFIED,
                "audit_hash": "d" * 64,
                "merge_proof_hash": "e" * 64,
            },
            branch_protection_reconciliation={
                "reason_code": PROTECTED_BRANCH_CLEANUP_ALLOWED,
                "audit_hash": "f" * 64,
                "cleanup_authorization_state": "ALLOWED",
            },
        )
    )
    path = tmp_path / "terminal_state_report.json"

    write_terminal_state_report(path, decision.audit)

    report = json.loads(path.read_text(encoding="utf-8"))
    assert report["decision"] == OUTCOME_VERIFIED_SUCCESS
    assert report["status"] == "COMPLETED"
    assert report["terminal_state_verified"] is True


def test_branch_head_404_returns_deleted_ref_state(monkeypatch) -> None:
    class Completed:
        returncode = 1
        stdout = ""
        stderr = "HTTP 404: Not Found"

    monkeypatch.setattr("scripts.governed_branch_hygiene._run_gh_result", lambda args: Completed())

    branch_head, not_found = _branch_head_state("owner/repo", "governance/repo-production-readiness")

    assert branch_head is None
    assert not_found is True


def test_workflow_run_404_classifies_state_unverifiable_without_silent_pass() -> None:
    evidence = classify_workflow_run_retrieval(
        endpoint="repos/owner/repo/actions/runs/123",
        parameters={
            "run_id": "123",
            "workflow": "governed-branch-hygiene",
            "exclude_pull_request": True,
        },
        returncode=1,
        stdout="",
        stderr="HTTP 404: Not Found",
    )

    assert evidence["state"] == "UNVERIFIABLE"
    assert evidence["reason_code"] == REASON_GITHUB_WORKFLOW_STATE_UNVERIFIABLE
    assert evidence["failure_class"] == "STALE_OR_DELETED_WORKFLOW_RUN"
    assert evidence["fail_closed"] is True
    assert evidence["governance_integrity_impact"] is False
    assert evidence["retry_behavior"] == "NO_RETRY_FOR_404_TERMINAL_STATE"
    assert evidence["audit_hash"]


def test_workflow_run_transient_api_failure_classifies_state_unverifiable() -> None:
    evidence = classify_workflow_run_retrieval(
        endpoint="repos/owner/repo/actions/runs/123",
        parameters={"run_id": "123", "workflow": "governed-branch-hygiene"},
        returncode=1,
        stdout="",
        stderr="HTTP 502: gateway timeout",
        attempts=3,
    )

    assert evidence["state"] == "UNVERIFIABLE"
    assert evidence["reason_code"] == REASON_GITHUB_WORKFLOW_STATE_UNVERIFIABLE
    assert evidence["failure_class"] == "GITHUB_API_RETRIEVAL_FAILED"
    assert evidence["fail_closed"] is True
    assert evidence["retry_behavior"] == "CALLER_MAY_RETRY_TRANSIENT_NON_404_FAILURE"


def test_workflow_run_retrieval_success_is_deterministic() -> None:
    first = classify_workflow_run_retrieval(
        endpoint="repos/owner/repo/actions/runs/123",
        parameters={"run_id": "123", "workflow": "governed-branch-hygiene"},
        returncode=0,
        stdout='{"id":123}',
        stderr="",
    )
    second = classify_workflow_run_retrieval(
        endpoint="repos/owner/repo/actions/runs/123",
        parameters={"workflow": "governed-branch-hygiene", "run_id": "123"},
        returncode=0,
        stdout='{"id":123}',
        stderr="",
    )

    assert first == second
    assert first["state"] == "VERIFIED"
    assert first["reason_code"] == "WORKFLOW_RUN_METADATA_RETRIEVED"


def test_load_state_accepts_merged_deleted_branch_after_merge_proof(monkeypatch) -> None:
    monkeypatch.setattr(
        "scripts.governed_branch_hygiene._pr_state",
        lambda pr: {
            "number": pr,
            "state": "MERGED",
            "mergedAt": "2026-05-19T00:00:00Z",
            "mergeCommit": {"oid": SHA_MAIN},
            "mergeStateStatus": "CLEAN",
            "mergedBy": {"login": "human"},
            "headRefName": "governance/repo-production-readiness",
        },
    )
    monkeypatch.setattr("scripts.governed_branch_hygiene._branch_head_state", lambda repo, branch: (None, True))
    monkeypatch.setattr("scripts.governed_branch_hygiene._branch_protection_state", lambda repo, branch, ruleset=None: (False, REASON_GOVERNANCE_FEATURE_BRANCH_ALLOWED))
    monkeypatch.setattr("scripts.governed_branch_hygiene._open_pr_references_branch", lambda branch: False)
    monkeypatch.setattr("scripts.governed_branch_hygiene._contains_ref", lambda ref: True)
    monkeypatch.setattr("scripts.governed_branch_hygiene._main_ruleset_state", lambda repo: _ruleset_verified())
    monkeypatch.setattr("scripts.governed_branch_hygiene._reviewer_authorization_state", lambda repo, pr: _reviewers_verified())

    state = load_state_from_github("owner/repo", 78, None)
    decision = evaluate_branch_hygiene(state)

    assert state.branch_ref_not_found is True
    assert state.branch_head_sha is None
    assert state.branch_protection_reconciliation["reason_code"] == PROTECTED_BRANCH_CLEANUP_ALLOWED
    assert decision.delete_branch is True
    assert decision.reason_code == OUTCOME_VERIFIED_SUCCESS
    assert decision.audit["terminal_state"]["terminal_state_verified"] is True


def test_pb030_verified_merge_deletion_reviewer_and_checks_do_not_route_to_refusal(monkeypatch, tmp_path: Path) -> None:
    verified_state = _state(
        branch_head_sha=None,
        main_contains_branch_head=None,
        merge_commit_on_main=True,
        branch_ref_not_found=True,
        branch_deletion_reconciliation={
            "reason_code": BRANCH_DELETED_AFTER_MERGE_VERIFIED,
            "audit_hash": "d" * 64,
            "merge_proof_hash": "e" * 64,
        },
        branch_protection_reconciliation={
            "reason_code": PROTECTED_BRANCH_CLEANUP_ALLOWED,
            "audit_hash": "f" * 64,
            "cleanup_authorization_state": "ALLOWED",
        },
        ruleset_governance=_ruleset_verified(),
        reviewer_authorization=_reviewers_verified(),
        merge_authorization_finalized=True,
    )
    monkeypatch.setattr("scripts.governed_branch_hygiene.load_state_from_github", lambda repo, pr, event_path: verified_state)

    def fail_if_refusal_comment_called(pr_number, blockers, reason_code):
        raise AssertionError(f"comment_refusal called with reason_code={reason_code} blockers={blockers}")

    monkeypatch.setattr("scripts.governed_branch_hygiene.comment_refusal", fail_if_refusal_comment_called)
    audit_output = tmp_path / "branch-hygiene-audit.json"
    terminal_output = tmp_path / "terminal_state_report.json"

    exit_code = main(
        [
            "--repo",
            "owner/repo",
            "--pr",
            "78",
            "--audit-output",
            str(audit_output),
            "--terminal-state-output",
            str(terminal_output),
            "--delete",
        ]
    )

    audit = json.loads(audit_output.read_text(encoding="utf-8"))
    terminal = json.loads(terminal_output.read_text(encoding="utf-8"))
    assert exit_code == 0
    assert audit["reason_code"] == OUTCOME_VERIFIED_SUCCESS
    assert audit["deletion_decision"] == "DELETE"
    assert audit["hygiene_outcome"] == OUTCOME_VERIFIED_SUCCESS
    assert audit["post_merge_cleanup_verified"] is True
    assert audit["github_check_conclusion"] == "success"
    assert audit["blockers"] == []
    assert terminal["decision"] == OUTCOME_VERIFIED_SUCCESS
    assert terminal["terminal_state_verified"] is True
    assert terminal["refusal_comment_allowed"] is False
    assert terminal["legacy_reason_code_suppressed"] is True


def test_protected_branch_cleanup_denied_blocks_hygiene() -> None:
    decision = evaluate_branch_hygiene(
        _state(
            protected_branch=True,
            protection_reason_code=REASON_PROTECTED_BRANCH_REQUIRED,
            branch_protection_reconciliation={
                "reason_code": PROTECTED_BRANCH_CLEANUP_DENIED,
                "audit_hash": "f" * 64,
                "cleanup_authorization_state": "DENIED",
            },
        )
    )

    assert decision.delete_branch is False
    assert "protected_branch_cleanup_denied" in decision.blockers
    assert decision.audit["branch_protection_reconciliation"]["reason_code"] == PROTECTED_BRANCH_CLEANUP_DENIED


def test_protection_lookup_result_deleted_when_branch_ref_missing() -> None:
    assert (
        _protection_lookup_result(
            protected=False,
            protection_reason=REASON_GOVERNANCE_FEATURE_BRANCH_ALLOWED,
            branch_ref_not_found=True,
        )
        == "DELETED"
    )


def test_protection_lookup_result_lookup_failed_is_preserved() -> None:
    assert (
        _protection_lookup_result(
            protected=True,
            protection_reason=REASON_BRANCH_PROTECTION_LOOKUP_FAILED,
            branch_ref_not_found=False,
        )
        == "LOOKUP_FAILED"
    )
