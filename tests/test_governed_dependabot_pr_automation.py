from __future__ import annotations

from scripts.governed_dependabot_pr_automation import (
    AUDIT_COMMENT,
    REQUIRED_CHECKS,
    DependabotPR,
    approve_comment_merge_and_delete,
    classify_dependabot_scope,
    evaluate_pr,
    lineage_recovery_audit,
)


def _checks(success: bool = True) -> tuple[dict, ...]:
    conclusion = "success" if success else "failure"
    return tuple({"name": name, "status": "completed", "conclusion": conclusion} for name in REQUIRED_CHECKS)


def _pr(**overrides) -> DependabotPR:
    values = {
        "number": 77,
        "author": "dependabot[bot]",
        "state": "OPEN",
        "base_branch": "main",
        "head_branch": "dependabot/pip/cryptography-46.0.7",
        "changed_files": ("requirements-ci.txt", ".github/workflows/production-readiness.yml"),
        "checks": _checks(),
        "url": "https://github.invalid/example/pull/77",
    }
    values.update(overrides)
    return DependabotPR(**values)


def test_eligible_dependabot_pr_is_approved_with_required_checks() -> None:
    decision = evaluate_pr(_pr())

    assert decision.approved is True
    assert decision.blockers == ()
    assert decision.audit["lineage_recovery"]["canonical_evidence_regeneration"] == "VERIFIED"


def test_non_dependabot_pr_is_blocked() -> None:
    decision = evaluate_pr(_pr(author="human-user"))

    assert decision.approved is False
    assert "author_not_dependabot" in decision.blockers


def test_governance_file_modification_is_blocked() -> None:
    decision = evaluate_pr(_pr(changed_files=("governance/policy_registry.json",)))

    assert decision.approved is False
    assert "unsafe_changed_file:governance/policy_registry.json" in decision.blockers


def test_failed_required_check_blocks_merge() -> None:
    decision = evaluate_pr(_pr(checks=_checks(success=False)))

    assert decision.approved is False
    assert "required_check_not_success:audit-artifact-guard" in decision.blockers
    assert "required_check_not_success:production-readiness" in decision.blockers


def test_skipped_required_check_blocks_merge() -> None:
    skipped = tuple({"name": name, "status": "completed", "conclusion": "skipped"} for name in REQUIRED_CHECKS)

    decision = evaluate_pr(_pr(checks=skipped))

    assert decision.approved is False
    assert "required_check_not_success:audit-artifact-guard" in decision.blockers


def test_stale_lineage_recovery_before_merge_is_audited() -> None:
    decision = evaluate_pr(
        _pr(),
        lineage_diagnostics={
            "lineage_status": "REWRITTEN_OR_ORPHANED",
            "invalidation_status": "EXPIRED_INVALID",
            "stale_refs_expired": ["pr_head:abc"],
        },
    )

    assert decision.approved is True
    assert decision.audit["lineage_recovery"]["lineage_status"] == "REWRITTEN_OR_ORPHANED"
    assert decision.audit["lineage_recovery"]["stale_lineage_invalidation"] == "EXPIRED_INVALID"
    assert decision.audit["lineage_recovery"]["audit_trace_preserved"] is True


def test_lineage_recovery_unverified_blocks_merge() -> None:
    decision = evaluate_pr(
        _pr(),
        lineage_diagnostics={"lineage_status": "REWRITTEN_OR_ORPHANED", "invalidation_status": "UNKNOWN"},
    )

    assert decision.approved is False
    assert "canonical_evidence_regeneration_unverified" in decision.blockers


def test_successful_merge_path_emits_audit_comment_and_branch_delete(monkeypatch) -> None:
    calls: list[list[str]] = []

    def fake_run_gh(args, *, input_text=None):
        calls.append(args)
        return ""

    monkeypatch.setattr("scripts.governed_dependabot_pr_automation._run_gh", fake_run_gh)

    approve_comment_merge_and_delete(77, dry_run=False)

    assert calls[0] == ["pr", "comment", "77", "--body", AUDIT_COMMENT]
    assert calls[1] == ["pr", "merge", "77", "--squash", "--delete-branch"]


def test_branch_scope_classifier_allows_dependency_and_workflow_only() -> None:
    allowed, blockers = classify_dependabot_scope(("requirements-ci.txt", ".github/workflows/codeql.yml"))

    assert allowed is True
    assert blockers == ()


def test_branch_scope_classifier_blocks_unknown_and_registry_paths() -> None:
    allowed, blockers = classify_dependabot_scope(("src/new_file.py", "audit/key_registry.json"))

    assert allowed is False
    assert "unsafe_changed_file:src/new_file.py" in blockers
    assert "unsafe_changed_file:audit/key_registry.json" in blockers


def test_audit_comment_contains_required_governance_claims_without_secrets() -> None:
    assert "No governance controls were bypassed." in AUDIT_COMMENT
    assert "No continue-on-error was introduced." in AUDIT_COMMENT
    assert "Fail-closed behavior preserved." in AUDIT_COMMENT
    assert "private_key" not in AUDIT_COMMENT.lower()
    assert "token" not in AUDIT_COMMENT.lower()


def test_lineage_recovery_audit_defaults_to_verified_current_lineage() -> None:
    audit = lineage_recovery_audit(None)

    assert audit["lineage_status"] == "CURRENT"
    assert audit["stale_lineage_invalidation"] == "NOT_REQUIRED"
    assert audit["canonical_evidence_regeneration"] == "VERIFIED"
