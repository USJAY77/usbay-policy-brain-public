from __future__ import annotations

import json
import subprocess
import sys
from dataclasses import replace
from pathlib import Path

import pytest

from scripts.governance_pr_template_validator import (
    FORBIDDEN_PLACEHOLDERS,
    REQUIRED_SECTIONS,
    TemplateValidationBlocked,
    generate_pr_body,
    pb025_metadata,
    validate_metadata,
    validate_pr_body,
)


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "governance_pr_template_validator.py"


def test_generated_pr_body_is_fully_populated() -> None:
    body = generate_pr_body(pb025_metadata())
    validation = validate_pr_body(body)

    for section in REQUIRED_SECTIONS:
        assert f"## {section}" in body
        assert validation["required_sections"][section] == "POPULATED"
    for placeholder in FORBIDDEN_PLACEHOLDERS:
        assert placeholder not in body
        assert validation["forbidden_placeholders"][placeholder] == "ABSENT"


@pytest.mark.parametrize("placeholder", FORBIDDEN_PLACEHOLDERS)
def test_unresolved_template_placeholders_fail_closed(placeholder: str) -> None:
    with pytest.raises(TemplateValidationBlocked, match="UNRESOLVED_TEMPLATE_PLACEHOLDER"):
        validate_pr_body(f"## PURPOSE\n{placeholder}\n")


@pytest.mark.parametrize("section", REQUIRED_SECTIONS)
def test_missing_required_section_fails_closed(section: str) -> None:
    body = generate_pr_body(pb025_metadata()).replace(f"## {section}\n", f"## {section} REMOVED\n", 1)

    with pytest.raises(TemplateValidationBlocked, match="REQUIRED_SECTION_MISSING"):
        validate_pr_body(body)


def test_empty_sections_fail_closed() -> None:
    body = generate_pr_body(pb025_metadata()).replace("## PURPOSE\nEliminate unresolved governance template placeholders from generated PB pull request bodies before PR creation.", "## PURPOSE\n")

    with pytest.raises(TemplateValidationBlocked, match="SECTION_EMPTY"):
        validate_pr_body(body)


def test_required_field_empty_blocks_generation() -> None:
    metadata = replace(pb025_metadata(), purpose="")

    with pytest.raises(TemplateValidationBlocked, match="FIELD_EMPTY:purpose"):
        validate_metadata(metadata)


def test_required_approvals_empty_blocks_generation() -> None:
    metadata = replace(pb025_metadata(), required_approvals=())

    with pytest.raises(TemplateValidationBlocked, match="REQUIRED_APPROVALS_EMPTY"):
        generate_pr_body(metadata)


def test_decision_status_mismatch_blocks_generation() -> None:
    metadata = replace(pb025_metadata(), status="FAIL_CLOSED")

    with pytest.raises(TemplateValidationBlocked, match="DECISION_STATUS_MISMATCH"):
        generate_pr_body(metadata)


def test_cli_generates_body_and_validation_report(tmp_path: Path) -> None:
    body_path = tmp_path / "body.md"
    report_path = tmp_path / "report.json"

    completed = subprocess.run(
        [
            sys.executable,
            str(SCRIPT),
            "--pb025",
            "--body-output",
            str(body_path),
            "--report-output",
            str(report_path),
        ],
        cwd=ROOT,
        text=True,
        capture_output=True,
    )

    assert completed.returncode == 0, completed.stdout + completed.stderr
    body = body_path.read_text(encoding="utf-8")
    report = json.loads(report_path.read_text(encoding="utf-8"))
    assert report["decision"] == "VERIFIED"
    assert report["status"] == "READY FOR REVIEW"
    assert report["governance_controls"]["pr_creation_blocked_on_invalid_body"] is True
    assert "USBAY-AUDIT" in body
    assert "USBAY-GLOBAL23" in body


def test_cli_validation_fails_closed_for_placeholder(tmp_path: Path) -> None:
    body_path = tmp_path / "body.md"
    body_path.write_text("## PURPOSE\nDescribe what is changing and why.\n", encoding="utf-8")

    completed = subprocess.run(
        [sys.executable, str(SCRIPT), "--validate-body", str(body_path)],
        cwd=ROOT,
        text=True,
        capture_output=True,
    )

    assert completed.returncode == 1
    assert "Decision: FAIL_CLOSED" in completed.stdout
    assert "UNRESOLVED_TEMPLATE_PLACEHOLDER" in completed.stdout
