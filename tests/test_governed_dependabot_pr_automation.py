from __future__ import annotations

from scripts.governed_dependabot_pr_automation import (
    AUDIT_COMMENT,
    REQUIRED_CHECKS,
    DependabotPR,
    approve_comment_merge_and_delete,
    classify_dependabot_scope,
    classify_scope,
    evaluate_pr,
    lineage_recovery_audit,
    resolve_pr_identity,
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
        "head_sha": "a" * 40,
        "changed_files": ("requirements-ci.txt",),
        "checks": _checks(),
        "url": "https://github.invalid/example/pull/77",
        "file_patches": (),
    }
    values.update(overrides)
    return DependabotPR(**values)


def test_eligible_dependabot_pr_is_approved_with_required_checks() -> None:
    decision = evaluate_pr(_pr())

    assert decision.approved is True
    assert decision.blockers == ()
    assert decision.audit["classified_scope"] == "SAFE_DEPENDENCY_SCOPE"
    assert decision.audit["reason_codes"] == ("SAFE_DEPENDENCY_SCOPE_ALLOWED",)
    assert decision.audit["lineage_recovery"]["canonical_evidence_regeneration"] == "VERIFIED"


def test_non_dependabot_pr_is_blocked() -> None:
    decision = evaluate_pr(_pr(author="human-user"))

    assert decision.approved is False
    assert "author_not_dependabot" in decision.blockers
    assert "NON_DEPENDABOT_AUTHOR_BLOCKED" in decision.audit["reason_codes"]


def test_governance_file_modification_is_blocked() -> None:
    decision = evaluate_pr(_pr(changed_files=("governance/policy_registry.json",)))

    assert decision.approved is False
    assert decision.audit["classified_scope"] == "GOVERNANCE_SENSITIVE_SCOPE"
    assert "GOVERNANCE_SENSITIVE_SCOPE_BLOCKED" in decision.audit["reason_codes"]


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


def test_branch_scope_classifier_allows_dependency_only_without_patch_evidence() -> None:
    allowed, blockers = classify_dependabot_scope(("requirements-ci.txt",))

    assert allowed is True
    assert blockers == ()


def test_safe_dependency_pr_allowed() -> None:
    decision = evaluate_pr(_pr(changed_files=("requirements-ci.txt", "pyproject.toml")))

    assert decision.approved is True
    assert decision.audit["classified_scope"] == "SAFE_DEPENDENCY_SCOPE"
    assert decision.audit["risk_tier"] == "LOW"
    assert decision.audit["allow_block_decision"] == "ALLOW"
    assert decision.audit["production_readiness_status"] == "PASS"
    assert decision.audit["audit_artifact_guard_status"] == "PASS"


def test_safe_github_action_version_bump_allowed() -> None:
    patch = {
        "path": ".github/workflows/codeql.yml",
        "patch": "\n".join(
            [
                "@@",
                "-        uses: actions/checkout@v4",
                "+        uses: actions/checkout@v5",
            ]
        ),
    }

    decision = evaluate_pr(_pr(changed_files=(".github/workflows/codeql.yml",), file_patches=(patch,)))

    assert decision.approved is True
    assert decision.audit["classified_scope"] == "SAFE_WORKFLOW_VERSION_SCOPE"
    assert decision.audit["reason_codes"] == ("SAFE_WORKFLOW_VERSION_SCOPE_ALLOWED",)


def test_workflow_permission_widening_blocked() -> None:
    patch = {
        "path": ".github/workflows/codeql.yml",
        "patch": "@@\n+permissions: write-all",
    }

    decision = evaluate_pr(_pr(changed_files=(".github/workflows/codeql.yml",), file_patches=(patch,)))

    assert decision.approved is False
    assert "PERMISSION_WIDENING_BLOCKED" in decision.audit["reason_codes"]


def test_workflow_logic_change_blocked() -> None:
    patch = {
        "path": ".github/workflows/codeql.yml",
        "patch": "@@\n+      - run: echo unsafe",
    }

    decision = evaluate_pr(_pr(changed_files=(".github/workflows/codeql.yml",), file_patches=(patch,)))

    assert decision.approved is False
    assert "WORKFLOW_LOGIC_CHANGE_BLOCKED" in decision.audit["reason_codes"]


def test_runtime_file_change_blocked() -> None:
    decision = evaluate_pr(_pr(changed_files=("runtime/enforcement_gateway.py",)))

    assert decision.approved is False
    assert decision.audit["classified_scope"] == "RUNTIME_SENSITIVE_SCOPE"
    assert "RUNTIME_SENSITIVE_SCOPE_BLOCKED" in decision.audit["reason_codes"]


def test_cryptographic_file_change_blocked() -> None:
    decision = evaluate_pr(_pr(changed_files=("scripts/sign_policy.py",)))

    assert decision.approved is False
    assert decision.audit["classified_scope"] == "CRYPTOGRAPHIC_SENSITIVE_SCOPE"
    assert "CRYPTOGRAPHIC_SENSITIVE_SCOPE_BLOCKED" in decision.audit["reason_codes"]


def test_non_dependabot_branch_blocked() -> None:
    decision = evaluate_pr(_pr(head_branch="feature/human-change"))

    assert decision.approved is False
    assert "NON_DEPENDABOT_BRANCH_BLOCKED" in decision.audit["reason_codes"]


def test_unknown_file_scope_blocked() -> None:
    decision = evaluate_pr(_pr(changed_files=("src/new_file.py",)))

    assert decision.approved is False
    assert decision.audit["classified_scope"] == "UNKNOWN_SCOPE"
    assert "UNKNOWN_SCOPE_BLOCKED" in decision.audit["reason_codes"]


def test_audit_evidence_emitted_for_block_decision() -> None:
    decision = evaluate_pr(_pr(changed_files=("gateway/app.py",)))

    assert decision.audit["pr_number"] == 77
    assert decision.audit["author"] == "dependabot[bot]"
    assert decision.audit["head_branch"] == "dependabot/pip/cryptography-46.0.7"
    assert decision.audit["allow_block_decision"] == "BLOCK"
    assert decision.audit["audit_hash"]


def test_branch_scope_classifier_blocks_unknown_and_registry_paths() -> None:
    allowed, blockers = classify_dependabot_scope(("src/new_file.py", "audit/key_registry.json"))

    assert allowed is False
    assert "unknown_changed_file:src/new_file.py" in blockers
    assert "governance_sensitive_file:audit/key_registry.json" in blockers


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


def test_workflow_dispatch_explicit_pr_resolution_succeeds() -> None:
    resolution = resolve_pr_identity(
        _pr(),
        requested_pr_number=77,
        workflow_context_source="workflow_dispatch",
    )

    assert resolution.valid is True
    assert resolution.reason_codes == ()
    assert resolution.audit["valid"] is True
    assert resolution.audit["head_sha"] == "a" * 40


def test_pr_not_found_reason_code() -> None:
    resolution = resolve_pr_identity(None, requested_pr_number=404)

    assert resolution.valid is False
    assert resolution.reason_codes == ("PR_NOT_FOUND",)
    assert resolution.audit["audit_hash"]


def test_pr_branch_mismatch_reason_code() -> None:
    resolution = resolve_pr_identity(
        _pr(),
        requested_pr_number=77,
        expected_head_branch="dependabot/pip/other",
        expected_head_sha="a" * 40,
        workflow_context_source="workflow_run",
    )

    assert resolution.valid is False
    assert "PR_BRANCH_MISMATCH" in resolution.reason_codes


def test_pr_sha_mismatch_reason_code() -> None:
    resolution = resolve_pr_identity(
        _pr(),
        requested_pr_number=77,
        expected_head_branch="dependabot/pip/cryptography-46.0.7",
        expected_head_sha="b" * 40,
        workflow_context_source="workflow_run",
    )

    assert resolution.valid is False
    assert "PR_SHA_MISMATCH" in resolution.reason_codes


def test_pr_not_open_reason_code() -> None:
    resolution = resolve_pr_identity(_pr(state="MERGED"), requested_pr_number=77)

    assert resolution.valid is False
    assert "PR_NOT_OPEN" in resolution.reason_codes


def test_pr_author_invalid_reason_code() -> None:
    resolution = resolve_pr_identity(_pr(author="human"), requested_pr_number=77)

    assert resolution.valid is False
    assert "PR_AUTHOR_INVALID" in resolution.reason_codes


def test_pr_lineage_invalid_reason_code() -> None:
    resolution = resolve_pr_identity(_pr(base_branch="develop"), requested_pr_number=77)

    assert resolution.valid is False
    assert "PR_LINEAGE_INVALID" in resolution.reason_codes


def test_stale_workflow_context_rejected_without_expected_sha() -> None:
    resolution = resolve_pr_identity(
        _pr(),
        requested_pr_number=77,
        expected_head_branch="dependabot/pip/cryptography-46.0.7",
        workflow_context_source="workflow_run",
    )

    assert resolution.valid is False
    assert "WORKFLOW_CONTEXT_UNTRUSTED" in resolution.reason_codes
