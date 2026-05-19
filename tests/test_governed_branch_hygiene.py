from __future__ import annotations

import json
from pathlib import Path

from scripts.governed_branch_hygiene import (
    REASON_BRANCH_PROTECTION_LOOKUP_FAILED,
    REASON_BRANCH_ALREADY_MERGED,
    REASON_BRANCH_NOT_MERGED_BLOCKED,
    REASON_GOVERNANCE_FEATURE_BRANCH_ALLOWED,
    REASON_LINEAGE_UNCLEAR_BLOCKED,
    REASON_MAIN_BRANCH_POLICY_REQUIRED,
    REASON_OPEN_PR_BRANCH_BLOCKED,
    REASON_PROTECTED_BRANCH_BLOCKED,
    REASON_PROTECTED_BRANCH_REQUIRED,
    REASON_RESTORED_AFTER_MERGE,
    REASON_VALID_NON_PROTECTED_BRANCH,
    SUPPORTED_PR_VIEW_FIELDS,
    BranchHygieneInput,
    delete_remote_branch,
    evaluate_branch_hygiene,
    load_state_from_github,
    normalize_pr_merge_state,
    _branch_protection_state,
    _pr_state,
    write_audit_record,
)


SHA_MAIN = "a" * 40
SHA_BRANCH = "b" * 40


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
    }
    values.update(overrides)
    return BranchHygieneInput(**values)


def test_merged_governance_branch_deleted() -> None:
    decision = evaluate_branch_hygiene(_state())

    assert decision.delete_branch is True
    assert decision.reason_code == REASON_BRANCH_ALREADY_MERGED
    assert decision.audit["deletion_decision"] == "DELETE"
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


def test_branch_protection_lookup_failure_fails_closed() -> None:
    decision = evaluate_branch_hygiene(
        _state(protected_branch=True, protection_reason_code=REASON_BRANCH_PROTECTION_LOOKUP_FAILED)
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


def test_main_branch_policy_required_without_api_call(monkeypatch) -> None:
    calls: list[list[str]] = []
    monkeypatch.setattr("scripts.governed_branch_hygiene._run_gh_result", lambda args: calls.append(args))

    protected, reason = _branch_protection_state("owner/repo", "main")

    assert protected is True
    assert reason == REASON_MAIN_BRANCH_POLICY_REQUIRED
    assert calls == []


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
    assert SUPPORTED_PR_VIEW_FIELDS in calls[0]
    assert "merged," not in SUPPORTED_PR_VIEW_FIELDS
    assert ",merged," not in SUPPORTED_PR_VIEW_FIELDS


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
    monkeypatch.setattr("scripts.governed_branch_hygiene._branch_head_sha", lambda repo, branch: SHA_BRANCH)
    monkeypatch.setattr("scripts.governed_branch_hygiene._branch_protection_state", lambda repo, branch: (False, REASON_GOVERNANCE_FEATURE_BRANCH_ALLOWED))
    monkeypatch.setattr("scripts.governed_branch_hygiene._open_pr_references_branch", lambda branch: False)
    monkeypatch.setattr("scripts.governed_branch_hygiene._contains_ref", lambda ref: True)

    state = load_state_from_github("owner/repo", 78, None)

    assert state.pr_merged is True
    assert state.merge_commit_sha == SHA_MAIN
    assert state.branch_head_sha == SHA_BRANCH
