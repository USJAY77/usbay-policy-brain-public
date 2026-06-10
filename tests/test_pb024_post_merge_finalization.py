from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

from scripts.post_merge_governance_finalizer import (
    FAIL_CLOSED,
    PROTECTED_BRANCH_CLEANUP_ALLOWED,
    VERIFIED_SUCCESS,
    finalize_post_merge_governance,
    sample_verified_hygiene_audit,
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
