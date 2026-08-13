from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

from scripts.post_merge_governance_finalizer import (
    BLOCK,
    COMMIT_ANCESTRY,
    COMMIT_ANCESTRY_VERIFIED,
    FAIL_CLOSED,
    PROTECTED_BRANCH_CLEANUP_ALLOWED,
    REVIEWED_CONTENT_EQUIVALENCE,
    REVIEWED_CONTENT_EQUIVALENCE_VERIFIED,
    MERGE_EVIDENCE_APPROVAL_MISSING,
    MERGE_EVIDENCE_APPROVAL_STALE,
    MERGE_EVIDENCE_BLOB_MISMATCH,
    MERGE_EVIDENCE_BOUNDARY_MISMATCH,
    MERGE_EVIDENCE_CHECK_FAILED,
    MERGE_EVIDENCE_CHECK_PENDING,
    MERGE_EVIDENCE_CHECK_UNPROVEN,
    MERGE_EVIDENCE_HEAD_MISMATCH,
    MERGE_EVIDENCE_INCOMPLETE,
    MERGE_EVIDENCE_STRATEGY_UNPROVEN,
    MERGE_EVIDENCE_UNEXPECTED_FILES,
    MERGE_EVIDENCE_UNEXPECTED_TREE_CHANGE,
    PASS,
    VERIFIED_SUCCESS,
    finalize_post_merge_governance,
    sample_verified_hygiene_audit,
    verify_authoritative_merge_evidence,
)


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "post_merge_governance_finalizer.py"


def test_successful_merge_and_approved_deletion_finalizes_verified_success() -> None:
    result = finalize_post_merge_governance(sample_verified_hygiene_audit())
    report = result["finalization_report"]

    assert report["decision"] == VERIFIED_SUCCESS
    assert report["final_merge_authorization_outcome"] == "APPROVED_MERGE_COMPLETION_VERIFIED"
    assert report["final_cleanup_verification_outcome"] == "APPROVED_BRANCH_DELETION_VERIFIED"
    assert report["refusal_comment_allowed"] is False
    assert report["refusal_comment_outcome"] == "REFUSAL_COMMENT_SUPPRESSED_AFTER_VERIFIED_FINALIZATION"
    assert report["false_refusal_prevented"] is True
    assert report["audit_trail_preserved"] is True
    assert report["blockers"] == []


def test_unverifiable_deletion_fails_closed() -> None:
    audit = sample_verified_hygiene_audit()
    audit["branch_deletion_reconciliation"] = {"reason_code": "BRANCH_DELETION_UNVERIFIED", "audit_hash": "e" * 64}

    result = finalize_post_merge_governance(audit)
    report = result["finalization_report"]

    assert report["decision"] == FAIL_CLOSED
    assert report["refusal_comment_allowed"] is True
    assert "branch_deletion_reconciliation_unverified" in report["blockers"]


def test_missing_merge_authorization_fails_closed() -> None:
    audit = sample_verified_hygiene_audit()
    audit["governance_enforcement"]["merge_authorization_finalized"] = False

    result = finalize_post_merge_governance(audit)

    assert result["merge_outcome"]["decision"] == FAIL_CLOSED
    assert "merge_authorization_not_finalized" in result["finalization_report"]["blockers"]


def test_protected_branch_violation_still_blocked() -> None:
    audit = sample_verified_hygiene_audit()
    audit["branch_name"] = "main"
    audit["branch_protection_reconciliation"] = {
        "reason_code": PROTECTED_BRANCH_CLEANUP_ALLOWED,
        "audit_hash": "f" * 64,
    }

    result = finalize_post_merge_governance(audit)

    assert result["cleanup_verification"]["decision"] == FAIL_CLOSED
    assert "protected_branch_cleanup_forbidden" in result["finalization_report"]["blockers"]


def test_failed_hygiene_outcome_fails_closed() -> None:
    audit = sample_verified_hygiene_audit()
    audit["hygiene_outcome"] = "BLOCKED"
    audit["post_merge_cleanup_verified"] = False
    audit["github_check_conclusion"] = "failure"

    result = finalize_post_merge_governance(audit)

    assert result["finalization_report"]["decision"] == FAIL_CLOSED
    assert "hygiene_outcome_not_verified_success" in result["finalization_report"]["blockers"]
    assert "post_merge_cleanup_not_verified" in result["finalization_report"]["blockers"]
    assert "github_check_conclusion_not_success" in result["finalization_report"]["blockers"]


def test_cli_generates_governance_evidence(tmp_path: Path) -> None:
    merge_output = tmp_path / "merge.json"
    cleanup_output = tmp_path / "cleanup.json"
    report_output = tmp_path / "report.json"

    completed = subprocess.run(
        [
            sys.executable,
            str(SCRIPT),
            "--sample-verified",
            "--merge-outcome-output",
            str(merge_output),
            "--cleanup-verification-output",
            str(cleanup_output),
            "--finalization-report-output",
            str(report_output),
        ],
        cwd=ROOT,
        text=True,
        capture_output=True,
    )

    assert completed.returncode == 0, completed.stdout + completed.stderr
    assert json.loads(merge_output.read_text(encoding="utf-8"))["decision"] == VERIFIED_SUCCESS
    assert json.loads(cleanup_output.read_text(encoding="utf-8"))["decision"] == VERIFIED_SUCCESS
    assert json.loads(report_output.read_text(encoding="utf-8"))["decision"] == VERIFIED_SUCCESS


def test_self_test_passes() -> None:
    completed = subprocess.run(
        [sys.executable, str(SCRIPT), "--self-test"],
        cwd=ROOT,
        text=True,
        capture_output=True,
    )

    assert completed.returncode == 0, completed.stdout + completed.stderr
    assert "PB024_SELF_TEST=true" in completed.stdout


def _merge_evidence(**overrides) -> dict:
    reviewed_hashes = {
        "runtime/action_token.py": "a" * 40,
        "runtime/computer_use/ai_act_live_policy_engine.py": "b" * 40,
    }
    values = {
        "authenticated_reviewed_head_sha": "1" * 40,
        "authoritative_main_sha": "3" * 40,
        "base_ref": "main",
        "human_approval_status": {
            "approved_head_sha": "1" * 40,
            "approved_reviewer_count": 2,
            "stale": False,
            "status": PASS,
        },
        "integration_commit_reachable_from_main": True,
        "integration_commit_sha": "2" * 40,
        "integration_file_boundary": tuple(reviewed_hashes),
        "integration_file_hashes": dict(reviewed_hashes),
        "merge_strategy": "MERGE_COMMIT",
        "pr_number": 340,
        "repository_identity": "USJAY77/usbay-policy-brain-public",
        "required_check_status": (
            {"name": "governance-check", "status": "completed", "conclusion": "success", "head_sha": "1" * 40},
            {"name": "policy-verification", "status": "completed", "conclusion": "success", "head_sha": "1" * 40},
        ),
        "reviewed_commit_ancestor_of_main": True,
        "reviewed_file_boundary": tuple(reviewed_hashes),
        "reviewed_file_hashes": reviewed_hashes,
        "reviewed_head_sha": "1" * 40,
        "unexpected_files": (),
        "unexpected_tree_changes": (),
        "unreviewed_post_review_mutation": False,
    }
    values.update(overrides)
    return values


def test_commit_ancestry_model_passes_with_complete_evidence() -> None:
    result = verify_authoritative_merge_evidence(_merge_evidence())

    assert result["verification_result"] == PASS
    assert result["evidence_model"] == COMMIT_ANCESTRY
    assert result["reason_code"] == COMMIT_ANCESTRY_VERIFIED
    assert result["blockers"] == []


def test_squash_reviewed_content_equivalence_model_passes_with_exact_blob_hashes() -> None:
    result = verify_authoritative_merge_evidence(
        _merge_evidence(merge_strategy="SQUASH", reviewed_commit_ancestor_of_main=False)
    )

    assert result["verification_result"] == PASS
    assert result["evidence_model"] == REVIEWED_CONTENT_EQUIVALENCE
    assert result["reason_code"] == REVIEWED_CONTENT_EQUIVALENCE_VERIFIED


def test_rebase_reviewed_content_equivalence_model_passes_when_proven() -> None:
    result = verify_authoritative_merge_evidence(
        _merge_evidence(merge_strategy="REBASE", reviewed_commit_ancestor_of_main=False)
    )

    assert result["verification_result"] == PASS
    assert result["evidence_model"] == REVIEWED_CONTENT_EQUIVALENCE
    assert result["reason_code"] == REVIEWED_CONTENT_EQUIVALENCE_VERIFIED


def test_changed_merged_blob_blocks_even_when_filenames_match() -> None:
    evidence = _merge_evidence()
    evidence["integration_file_hashes"] = {
        **evidence["integration_file_hashes"],
        "runtime/action_token.py": "c" * 40,
    }

    result = verify_authoritative_merge_evidence(evidence)

    assert result["verification_result"] == BLOCK
    assert MERGE_EVIDENCE_BLOB_MISMATCH in result["blockers"]


def test_extra_merged_file_blocks() -> None:
    evidence = _merge_evidence()
    evidence["integration_file_boundary"] = (*evidence["integration_file_boundary"], "unexpected.py")
    evidence["integration_file_hashes"] = {**evidence["integration_file_hashes"], "unexpected.py": "c" * 40}
    evidence["unexpected_files"] = ("unexpected.py",)

    result = verify_authoritative_merge_evidence(evidence)

    assert result["verification_result"] == BLOCK
    assert MERGE_EVIDENCE_BOUNDARY_MISMATCH in result["blockers"]
    assert MERGE_EVIDENCE_UNEXPECTED_FILES in result["blockers"]


def test_missing_approved_file_blocks() -> None:
    evidence = _merge_evidence()
    evidence["integration_file_boundary"] = ("runtime/action_token.py",)
    evidence["integration_file_hashes"] = {"runtime/action_token.py": "a" * 40}

    result = verify_authoritative_merge_evidence(evidence)

    assert result["verification_result"] == BLOCK
    assert MERGE_EVIDENCE_BOUNDARY_MISMATCH in result["blockers"]


def test_missing_approval_blocks() -> None:
    result = verify_authoritative_merge_evidence(_merge_evidence(human_approval_status={"status": BLOCK}))

    assert result["verification_result"] == BLOCK
    assert MERGE_EVIDENCE_APPROVAL_MISSING in result["blockers"]


def test_stale_approval_blocks() -> None:
    evidence = _merge_evidence()
    evidence["human_approval_status"] = {**evidence["human_approval_status"], "stale": True}

    result = verify_authoritative_merge_evidence(evidence)

    assert result["verification_result"] == BLOCK
    assert MERGE_EVIDENCE_APPROVAL_STALE in result["blockers"]


def test_approved_sha_mismatch_blocks() -> None:
    evidence = _merge_evidence()
    evidence["human_approval_status"] = {**evidence["human_approval_status"], "approved_head_sha": "4" * 40}

    result = verify_authoritative_merge_evidence(evidence)

    assert result["verification_result"] == BLOCK
    assert MERGE_EVIDENCE_HEAD_MISMATCH in result["blockers"]


def test_required_check_failed_blocks() -> None:
    checks = ({"name": "governance-check", "status": "completed", "conclusion": "failure", "head_sha": "1" * 40},)

    result = verify_authoritative_merge_evidence(_merge_evidence(required_check_status=checks))

    assert result["verification_result"] == BLOCK
    assert MERGE_EVIDENCE_CHECK_FAILED in result["blockers"]


def test_required_check_pending_blocks() -> None:
    checks = ({"name": "governance-check", "status": "in_progress", "conclusion": "", "head_sha": "1" * 40},)

    result = verify_authoritative_merge_evidence(_merge_evidence(required_check_status=checks))

    assert result["verification_result"] == BLOCK
    assert MERGE_EVIDENCE_CHECK_PENDING in result["blockers"]


def test_required_check_unavailable_blocks() -> None:
    result = verify_authoritative_merge_evidence(_merge_evidence(required_check_status=()))

    assert result["verification_result"] == BLOCK
    assert MERGE_EVIDENCE_CHECK_UNPROVEN in result["blockers"]


def test_unknown_merge_topology_blocks() -> None:
    result = verify_authoritative_merge_evidence(_merge_evidence(merge_strategy="OTHER"))

    assert result["verification_result"] == BLOCK
    assert result["evidence_model"] == "UNPROVEN"
    assert MERGE_EVIDENCE_STRATEGY_UNPROVEN in result["blockers"]


def test_file_boundary_mismatch_blocks() -> None:
    result = verify_authoritative_merge_evidence(_merge_evidence(reviewed_file_boundary=("runtime/action_token.py",)))

    assert result["verification_result"] == BLOCK
    assert MERGE_EVIDENCE_BOUNDARY_MISMATCH in result["blockers"]


def test_semantic_similarity_with_different_blob_blocks() -> None:
    evidence = _merge_evidence()
    evidence["integration_file_hashes"] = {
        **evidence["integration_file_hashes"],
        "runtime/computer_use/ai_act_live_policy_engine.py": "d" * 40,
    }

    result = verify_authoritative_merge_evidence(evidence)

    assert result["verification_result"] == BLOCK
    assert MERGE_EVIDENCE_BLOB_MISMATCH in result["blockers"]


def test_unexpected_tree_mutation_blocks() -> None:
    result = verify_authoritative_merge_evidence(_merge_evidence(unexpected_tree_changes=("policy/policy.json",)))

    assert result["verification_result"] == BLOCK
    assert MERGE_EVIDENCE_UNEXPECTED_TREE_CHANGE in result["blockers"]


def test_incomplete_evidence_blocks() -> None:
    result = verify_authoritative_merge_evidence({"reviewed_head_sha": "1" * 40})

    assert result["verification_result"] == BLOCK
    assert MERGE_EVIDENCE_INCOMPLETE in result["blockers"]
