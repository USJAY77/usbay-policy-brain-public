from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

from scripts.governed_dependabot_pr_automation import (
    AUDIT_COMMENT,
    GOVERNANCE_LABEL_NOT_STATUS_CHECK,
    GOVERNANCE_REVIEW_MISSING,
    GOVERNANCE_REVIEW_LABEL_APPLIED,
    GOVERNANCE_REVIEW_LABEL_MISSING,
    GOVERNANCE_REVIEW_REQUIRED,
    HEAD_SHA_MISMATCH,
    MERGE_COMMIT_MISMATCH,
    MERGE_LINEAGE_RECONCILED,
    WORKFLOW_EVENT_AMBIGUOUS,
    WORKFLOW_EVENT_STALE,
    REQUIRED_CHECKS,
    REQUIRED_CHECK_NOT_PUBLISHED,
    REVIEW_APPROVED_LABEL,
    REVIEW_LABEL,
    DependabotPR,
    approve_comment_merge_and_delete,
    classify_dependabot_scope,
    classify_scope,
    comment_and_label_blocked,
    evaluate_pr,
    lineage_recovery_audit,
    main,
    resolve_pr_identity,
    validate_required_checks,
)

ROOT = Path(__file__).resolve().parents[1]


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
        "labels": (),
        "url": "https://github.invalid/example/pull/77",
        "file_patches": (),
        "merge_sha": "",
        "repository_full_name": "example/usbay-policy-brain",
    }
    values.update(overrides)
    return DependabotPR(**values)


def test_direct_script_execution_resolves_governance_package_without_pythonpath() -> None:
    env = os.environ.copy()
    env.pop("PYTHONPATH", None)

    result = subprocess.run(
        [sys.executable, str(ROOT / "scripts" / "governed_dependabot_pr_automation.py"), "--help"],
        cwd=Path("/tmp"),
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )

    assert result.returncode == 0
    assert "ModuleNotFoundError" not in result.stderr
    assert "--lineage-diagnostics" in result.stdout


def test_eligible_dependabot_pr_is_approved_with_required_checks() -> None:
    decision = evaluate_pr(_pr())

    assert decision.approved is True
    assert decision.blockers == ()
    assert decision.audit["classified_scope"] == "SAFE_DEPENDENCY_SCOPE"
    assert decision.audit["reason_codes"] == ("SAFE_DEPENDENCY_SCOPE_ALLOWED",)
    assert decision.audit["canonical_ci_status"]["canonical_state"] == "CI_STATUS_VERIFIED"
    assert decision.audit["canonical_ci_status"]["final_merge_authority_verdict"] == "ALLOW"
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
    assert "ci_merge_authority_denied:CI_STATUS_FAIL_CLOSED" in decision.blockers


def test_missing_published_required_check_uses_explicit_reason_code() -> None:
    decision = evaluate_pr(_pr(checks=tuple(check for check in _checks() if check["name"] != "codeql-quality")))

    assert decision.approved is False
    assert f"{REQUIRED_CHECK_NOT_PUBLISHED}:codeql-quality" in decision.blockers
    assert REQUIRED_CHECK_NOT_PUBLISHED in decision.audit["reason_codes"]
    assert decision.audit["canonical_ci_status"]["canonical_state"] == "CI_STATUS_PARTIAL"


def test_governance_label_cannot_be_required_status_check() -> None:
    ok, blockers = validate_required_checks(_checks(), REQUIRED_CHECKS + (REVIEW_LABEL,))

    assert ok is False
    assert f"{GOVERNANCE_LABEL_NOT_STATUS_CHECK}:{REVIEW_LABEL}" in blockers


def test_valid_dependabot_pr_without_review_label_succeeds() -> None:
    decision = evaluate_pr(_pr(labels=()))

    assert decision.approved is True
    assert decision.audit["governance_review"]["status"] == "PASS"
    assert decision.audit["governance_review"]["review_required"] is False
    assert decision.audit["required_check_semantics"] == "github_check_runs_only"


def test_governance_review_required_label_blocks_without_approval() -> None:
    decision = evaluate_pr(_pr(labels=(REVIEW_LABEL,)))

    assert decision.approved is False
    assert "governance_review_missing" in decision.blockers
    assert GOVERNANCE_REVIEW_REQUIRED in decision.audit["reason_codes"]
    assert GOVERNANCE_REVIEW_MISSING in decision.audit["reason_codes"]
    assert decision.audit["governance_review"]["status"] == "BLOCK"


def test_governance_review_approval_label_satisfies_label_gate() -> None:
    decision = evaluate_pr(_pr(labels=(REVIEW_LABEL, REVIEW_APPROVED_LABEL)))

    assert decision.approved is True
    assert decision.audit["governance_review"]["status"] == "PASS"
    assert decision.audit["governance_review"]["review_required"] is True
    assert decision.audit["governance_review"]["review_approved"] is True


def test_audit_evidence_separates_labels_from_required_checks() -> None:
    decision = evaluate_pr(_pr(labels=(REVIEW_LABEL, REVIEW_APPROVED_LABEL)))

    assert REVIEW_LABEL in decision.audit["governance_labels"]
    assert REVIEW_LABEL not in decision.audit["required_checks"]
    assert all(status["semantic_type"] == "github_check_run" for status in decision.audit["required_check_status"])


def test_skipped_required_check_blocks_merge() -> None:
    skipped = tuple({"name": name, "status": "completed", "conclusion": "skipped"} for name in REQUIRED_CHECKS)

    decision = evaluate_pr(_pr(checks=skipped))

    assert decision.approved is False
    assert "required_check_not_success:audit-artifact-guard" in decision.blockers
    assert decision.audit["canonical_ci_status"]["canonical_state"] == "CI_STATUS_FAIL_CLOSED"


def test_stale_ci_context_blocks_dependabot_merge_authority() -> None:
    stale_checks = tuple(
        {"name": name, "status": "completed", "conclusion": "success", "headSha": "b" * 40}
        for name in REQUIRED_CHECKS
    )

    decision = evaluate_pr(_pr(checks=stale_checks))

    assert decision.approved is False
    assert "ci_merge_authority_denied:CI_STATUS_STALE" in decision.blockers
    assert "CI_STALE_CONTEXT_INVALIDATED" in decision.audit["reason_codes"]


def test_superseded_dependency_pr_blocks_dependabot_merge_authority() -> None:
    decision = evaluate_pr(_pr(superseded_by="cryptography==48.0.0"))

    assert decision.approved is False
    assert "ci_merge_authority_denied:CI_STATUS_STALE" in decision.blockers
    assert "CI_SUPERSEDED_PR_REJECTED" in decision.audit["reason_codes"]


def test_mergeable_false_blocks_dependabot_merge_authority() -> None:
    decision = evaluate_pr(_pr(mergeable=False))

    assert decision.approved is False
    assert "ci_merge_authority_denied:CI_STATUS_CONTRADICTORY" in decision.blockers
    assert "CI_MERGEABILITY_CONTRADICTORY" in decision.audit["reason_codes"]


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


def test_blocked_path_reports_missing_governance_label_deterministically(monkeypatch) -> None:
    calls: list[list[str]] = []

    def fake_run_gh(args, *, input_text=None):
        calls.append(args)
        if args[:3] == ["pr", "edit", "77"]:
            raise SystemExit("GITHUB_COMMAND_FAILED:pr edit 77 --add-label governance-review-required:'governance-review-required' not found")
        return ""

    monkeypatch.setattr("scripts.governed_dependabot_pr_automation._run_gh", fake_run_gh)

    audit = {"audit_hash": "a" * 64, "reason_codes": ("NON_DEPENDABOT_BRANCH_BLOCKED",)}
    label_audit = comment_and_label_blocked(77, ("head_branch_not_dependabot",), audit, dry_run=False)

    assert calls[0][:3] == ["pr", "comment", "77"]
    assert calls[1] == ["pr", "edit", "77", "--add-label", "governance-review-required"]
    assert label_audit["status"] == GOVERNANCE_REVIEW_LABEL_MISSING
    assert label_audit["reason_codes"] == (GOVERNANCE_REVIEW_LABEL_MISSING,)
    assert label_audit["error_hash"]
    assert "not found" not in str(label_audit)


def test_blocked_path_reports_applied_governance_label(monkeypatch) -> None:
    calls: list[list[str]] = []

    def fake_run_gh(args, *, input_text=None):
        calls.append(args)
        return ""

    monkeypatch.setattr("scripts.governed_dependabot_pr_automation._run_gh", fake_run_gh)

    audit = {"audit_hash": "a" * 64, "reason_codes": ("UNKNOWN_SCOPE_BLOCKED",)}
    label_audit = comment_and_label_blocked(77, ("unknown_changed_file:src/new_file.py",), audit, dry_run=False)

    assert calls[1] == ["pr", "edit", "77", "--add-label", "governance-review-required"]
    assert label_audit["status"] == GOVERNANCE_REVIEW_LABEL_APPLIED
    assert label_audit["reason_codes"] == (GOVERNANCE_REVIEW_LABEL_APPLIED,)
    assert label_audit["audit_hash"]


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
                "-        uses: actions/checkout@v5",
                "+        uses: actions/checkout@v6",
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


def test_blocked_main_path_rewrites_decision_output_with_label_audit(tmp_path, monkeypatch) -> None:
    def fake_run_gh(args, *, input_text=None):
        if args[:3] == ["pr", "edit", "77"]:
            raise SystemExit("GITHUB_COMMAND_FAILED:pr edit 77 --add-label governance-review-required:'governance-review-required' not found")
        return ""

    monkeypatch.setattr("scripts.governed_dependabot_pr_automation._run_gh", fake_run_gh)
    monkeypatch.setattr(
        "scripts.governed_dependabot_pr_automation.load_pr_from_github",
        lambda _number: _pr(changed_files=("gateway/app.py",)),
    )
    decision_output = tmp_path / "decision.json"
    resolution_output = tmp_path / "resolution.json"

    result = main(
        [
            "--pr",
            "77",
            "--decision-output",
            str(decision_output),
            "--resolution-output",
            str(resolution_output),
            "--merge",
        ]
    )

    assert result == 1
    decision = json.loads(decision_output.read_text(encoding="utf-8"))
    assert decision["allow_block_decision"] == "BLOCK"
    assert decision["governance_labeling"]["status"] == GOVERNANCE_REVIEW_LABEL_MISSING
    assert GOVERNANCE_REVIEW_LABEL_MISSING in decision["reason_codes"]
    assert decision["audit_hash"]


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
        event_type="pull_request",
        workflow_run_id="12345",
    )

    assert resolution.valid is True
    assert resolution.reason_codes == ()
    assert resolution.audit["valid"] is True
    assert resolution.audit["head_sha"] == "a" * 40
    assert resolution.audit["merge_provenance"]["schema_version"] == "usbay.merge_provenance_stub.v1"
    assert resolution.audit["merge_provenance"]["signature_status"] == "SIGNATURE_UNVERIFIED"
    assert resolution.audit["merge_provenance"]["reconciliation_status"] == "RECONCILED"
    assert resolution.audit["workflow_run_id_hash"]


def test_workflow_run_event_reconciles_to_pr() -> None:
    resolution = resolve_pr_identity(
        _pr(),
        requested_pr_number=77,
        expected_head_branch="dependabot/pip/cryptography-46.0.7",
        expected_head_sha="a" * 40,
        workflow_context_source="workflow_run",
        workflow_run_id="98765",
    )

    assert resolution.valid is True
    assert resolution.reason_codes == ()
    assert resolution.audit["merge_provenance"]["event_source"] == "workflow_run"


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
    assert HEAD_SHA_MISMATCH in resolution.reason_codes


def test_merge_sha_mismatch_reason_code() -> None:
    resolution = resolve_pr_identity(
        _pr(merge_sha="c" * 40),
        requested_pr_number=77,
        expected_merge_sha="d" * 40,
    )

    assert resolution.valid is False
    assert MERGE_COMMIT_MISMATCH in resolution.reason_codes


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
    assert "BASE_BRANCH_MISMATCH" in resolution.reason_codes
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
    assert WORKFLOW_EVENT_STALE in resolution.reason_codes


def test_deleted_branch_after_merge_reconciles_when_merge_provenance_verified() -> None:
    resolution = resolve_pr_identity(
        _pr(state="MERGED", head_branch="", merge_sha="e" * 40),
        requested_pr_number=77,
        expected_merge_sha="e" * 40,
        branch_deleted=True,
        merge_provenance_reconciled=True,
    )

    assert resolution.valid is True
    assert resolution.reason_codes == (MERGE_LINEAGE_RECONCILED,)
    assert resolution.audit["merge_provenance"]["reconciliation_status"] == "RECONCILED"


def test_deleted_branch_before_reconciliation_blocks() -> None:
    resolution = resolve_pr_identity(
        _pr(),
        requested_pr_number=77,
        branch_deleted=True,
    )

    assert resolution.valid is False
    assert "BRANCH_DELETED_BEFORE_RECONCILIATION" in resolution.reason_codes


def test_ambiguous_pr_lookup_blocks() -> None:
    resolution = resolve_pr_identity(None, requested_pr_number=77, candidate_pr_count=2, workflow_context_source="workflow_run")

    assert resolution.valid is False
    assert WORKFLOW_EVENT_AMBIGUOUS in resolution.reason_codes
    assert "PR_NOT_FOUND" not in resolution.reason_codes


def test_manual_dispatch_without_pr_context_blocks() -> None:
    resolution = resolve_pr_identity(_pr(), requested_pr_number=None, workflow_context_source="workflow_dispatch")

    assert resolution.valid is False
    assert "WORKFLOW_CONTEXT_UNTRUSTED" in resolution.reason_codes


def test_merge_provenance_hash_only_and_no_raw_github_body() -> None:
    resolution = resolve_pr_identity(
        _pr(repository_full_name="secret-owner/private-repo"),
        requested_pr_number=77,
        workflow_run_id="12345",
    )
    encoded = str(resolution.audit)

    assert resolution.audit["merge_provenance"]["repository_full_name_hash"]
    assert "secret-owner/private-repo" not in encoded
    assert ("raw_" + "payload") not in encoded
