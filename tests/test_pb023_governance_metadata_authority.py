from __future__ import annotations

import json
import subprocess
import sys
from dataclasses import replace
from pathlib import Path

import pytest

from scripts.usbay_pb_metadata_authority import (
    GeneratedMetadata,
    MetadataAuthorityBlocked,
    PBMetadata,
    generate_metadata,
    run_enforcement_verification,
    validate_generated_metadata,
    validate_pr_body,
)


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "usbay_pb_metadata_authority.py"


VALID_METADATA = PBMetadata(
    pb_number=23,
    pb_slug="governance-metadata-authority",
    pb_title="Governance Metadata Authority",
    decision="VERIFIED",
    status="READY FOR REVIEW",
)


def test_valid_pb_metadata_generates_correct_title_and_description() -> None:
    generated = generate_metadata(VALID_METADATA)

    assert generated.branch_name == "usbay/governance-metadata-authority"
    assert generated.commit_title == "PB-023 VERIFIED: Governance Metadata Authority"
    assert generated.pr_title == "PB-023 VERIFIED: Governance Metadata Authority"
    assert generated.decision == "VERIFIED"
    assert generated.status == "READY FOR REVIEW"
    assert "## RISK" in generated.pr_body
    assert "## MECHANISM" in generated.pr_body
    assert "## GAP" in generated.pr_body
    assert "## AUDIT" in generated.pr_body
    assert "## IMPACT" in generated.pr_body
    assert "## Decision\nVERIFIED" in generated.pr_body
    assert "## Status\nREADY FOR REVIEW" in generated.pr_body


def test_review_required_title_format_is_supported() -> None:
    metadata = replace(VALID_METADATA, decision="REVIEW_REQUIRED", status="AWAITING_APPROVAL")

    generated = generate_metadata(metadata)

    assert generated.pr_title == "PB-023 REVIEW_REQUIRED: Governance Metadata Authority"


def test_blocked_title_format_is_supported() -> None:
    metadata = replace(VALID_METADATA, decision="BLOCKED", status="FAIL_CLOSED")

    generated = generate_metadata(metadata)

    assert generated.pr_title == "PB-023 BLOCKED: Governance Metadata Authority"


def test_invalid_title_fails_closed() -> None:
    generated = generate_metadata(VALID_METADATA)
    tampered = replace(generated, pr_title="Governance Metadata Authority")

    with pytest.raises(MetadataAuthorityBlocked, match="MANUAL_METADATA_OVERRIDE_BLOCKED:pr_title"):
        validate_generated_metadata(VALID_METADATA, tampered)


def test_malformed_pr_title_fails_closed_even_with_override() -> None:
    generated = generate_metadata(VALID_METADATA)
    tampered = replace(generated, pr_title="Governance Metadata Authority")

    with pytest.raises(MetadataAuthorityBlocked, match="PR_TITLE_MALFORMED"):
        validate_generated_metadata(VALID_METADATA, tampered, allow_governance_override=True)


def test_missing_body_fails_closed() -> None:
    with pytest.raises(MetadataAuthorityBlocked, match="PR_BODY_MISSING"):
        validate_pr_body("")


def test_decision_status_mismatch_fails_closed() -> None:
    metadata = replace(VALID_METADATA, decision="VERIFIED", status="AWAITING_APPROVAL")

    with pytest.raises(MetadataAuthorityBlocked, match="DECISION_STATUS_MISMATCH"):
        generate_metadata(metadata)


def test_generated_commit_title_matches_pr_title() -> None:
    generated = generate_metadata(VALID_METADATA)

    assert generated.commit_title == generated.pr_title


def test_commit_title_mismatch_fails_closed() -> None:
    generated = generate_metadata(VALID_METADATA)
    tampered = replace(generated, commit_title="PB-023 VERIFIED: Different")

    with pytest.raises(MetadataAuthorityBlocked, match="MANUAL_METADATA_OVERRIDE_BLOCKED:commit_title"):
        validate_generated_metadata(VALID_METADATA, tampered)


def test_pb_number_mismatch_fails_closed() -> None:
    generated = generate_metadata(VALID_METADATA)
    tampered = replace(generated, pb_number=24)

    with pytest.raises(MetadataAuthorityBlocked, match="PB_NUMBER_MISMATCH"):
        validate_generated_metadata(VALID_METADATA, tampered, allow_governance_override=True)


def test_manual_override_blocked_unless_governance_override_flag_present() -> None:
    generated = generate_metadata(VALID_METADATA)
    override = GeneratedMetadata(
        **{
            **generated.__dict__,
            "branch_name": "usbay/manual-branch",
        }
    )

    with pytest.raises(MetadataAuthorityBlocked, match="MANUAL_METADATA_OVERRIDE_BLOCKED:branch_name"):
        validate_generated_metadata(VALID_METADATA, override)

    validate_generated_metadata(VALID_METADATA, override, allow_governance_override=True)


def test_pr_body_requires_all_governance_sections() -> None:
    with pytest.raises(MetadataAuthorityBlocked, match="PR_BODY_REQUIRED_SECTIONS_MISSING"):
        validate_pr_body("## RISK\nOnly risk.\n")


def test_cli_generates_evidence_outputs(tmp_path: Path) -> None:
    report = tmp_path / "report.json"
    pr_body = tmp_path / "body.md"
    commit_title = tmp_path / "commit.txt"
    pr_title = tmp_path / "title.txt"

    completed = subprocess.run(
        [
            sys.executable,
            str(SCRIPT),
            "--pb-number",
            "23",
            "--pb-slug",
            "governance-metadata-authority",
            "--pb-title",
            "Governance Metadata Authority",
            "--decision",
            "VERIFIED",
            "--status",
            "READY FOR REVIEW",
            "--report-json",
            str(report),
            "--pr-body-output",
            str(pr_body),
            "--commit-title-output",
            str(commit_title),
            "--pr-title-output",
            str(pr_title),
        ],
        cwd=ROOT,
        text=True,
        capture_output=True,
    )

    assert completed.returncode == 0, completed.stdout + completed.stderr
    payload = json.loads(report.read_text(encoding="utf-8"))
    assert payload["decision"] == "VERIFIED"
    assert payload["generated_metadata"]["pr_title"] == "PB-023 VERIFIED: Governance Metadata Authority"
    assert pr_title.read_text(encoding="utf-8").strip() == "PB-023 VERIFIED: Governance Metadata Authority"
    assert commit_title.read_text(encoding="utf-8").strip() == "PB-023 VERIFIED: Governance Metadata Authority"
    assert "## Decision\nVERIFIED" in pr_body.read_text(encoding="utf-8")


def test_enforcement_verification_blocks_all_required_negative_tests() -> None:
    report = run_enforcement_verification(VALID_METADATA)

    assert report["decision"] == "VERIFIED"
    assert report["enforcement_capable"] is True
    assert report["summary"] == {"total": 10, "fail_closed": 10, "not_blocked": 0}
    results = {result["test"]: result for result in report["negative_tests"]}
    assert set(results) == {
        "invalid_pr_title",
        "invalid_commit_title",
        "missing_pr_body",
        "missing_risk_section",
        "missing_mechanism_section",
        "missing_gap_section",
        "missing_audit_section",
        "missing_impact_section",
        "decision_mismatch",
        "status_mismatch",
    }
    for result in results.values():
        assert result["expected"] == "FAIL_CLOSED"
        assert result["outcome"] == "FAIL_CLOSED"


def test_cli_generates_enforcement_report(tmp_path: Path) -> None:
    report = tmp_path / "enforcement.json"

    completed = subprocess.run(
        [
            sys.executable,
            str(SCRIPT),
            "--pb-number",
            "23",
            "--pb-slug",
            "governance-metadata-authority",
            "--pb-title",
            "Governance Metadata Authority",
            "--decision",
            "VERIFIED",
            "--status",
            "READY FOR REVIEW",
            "--enforcement-report-json",
            str(report),
        ],
        cwd=ROOT,
        text=True,
        capture_output=True,
    )

    assert completed.returncode == 0, completed.stdout + completed.stderr
    payload = json.loads(report.read_text(encoding="utf-8"))
    assert payload["decision"] == "VERIFIED"
    assert payload["summary"]["fail_closed"] == 10
    assert payload["summary"]["not_blocked"] == 0


def test_cli_missing_metadata_fails_closed() -> None:
    completed = subprocess.run(
        [
            sys.executable,
            str(SCRIPT),
            "--pb-number",
            "23",
            "--pb-slug",
            "governance-metadata-authority",
        ],
        cwd=ROOT,
        text=True,
        capture_output=True,
    )

    assert completed.returncode == 1
    assert "Decision: BLOCKED" in completed.stdout
    assert "METADATA_REQUIRED_FIELDS_MISSING" in completed.stdout
