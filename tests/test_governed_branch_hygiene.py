from __future__ import annotations

import json
from pathlib import Path

from scripts.governed_branch_hygiene import (
    REASON_BRANCH_ALREADY_MERGED,
    REASON_BRANCH_NOT_MERGED_BLOCKED,
    REASON_LINEAGE_UNCLEAR_BLOCKED,
    REASON_OPEN_PR_BRANCH_BLOCKED,
    REASON_PROTECTED_BRANCH_BLOCKED,
    REASON_RESTORED_AFTER_MERGE,
    BranchHygieneInput,
    delete_remote_branch,
    evaluate_branch_hygiene,
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
    assert "protected_branch" in decision.blockers


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
