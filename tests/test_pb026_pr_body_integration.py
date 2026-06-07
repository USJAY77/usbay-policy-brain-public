from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

from scripts.governance_pr_body_integration import (
    FORBIDDEN_PLACEHOLDERS,
    OpenPRRepairInput,
    PRBodyIntegrationBlocked,
    build_open_pr_repair_report,
    generate_pr_body,
    pb026_metadata,
    placeholder_count,
    validate_pr_body,
    validate_pr_create_command,
    validate_repository_template,
)


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "governance_pr_body_integration.py"


def test_generated_pr_body_contains_no_placeholders_and_required_sections() -> None:
    body = generate_pr_body(pb026_metadata())
    validation = validate_pr_body(body)

    assert validation["required_sections"]["PURPOSE"] == "POPULATED"
    assert validation["required_sections"]["RISK"] == "POPULATED"
    assert validation["required_sections"]["POLICY LINK"] == "POPULATED"
    assert validation["required_sections"]["REQUIRED APPROVALS"] == "POPULATED"
    assert validation["required_sections"]["AUDIT"] == "POPULATED"
    assert validation["required_sections"]["IMPACT"] == "POPULATED"
    for placeholder in FORBIDDEN_PLACEHOLDERS:
        assert placeholder not in body


def test_legacy_template_placeholders_fail_closed() -> None:
    legacy = """# USBAY GOVERNANCE PR
## PURPOSE
Describe what is changing and why.
"""

    with pytest.raises(PRBodyIntegrationBlocked, match="UNRESOLVED_TEMPLATE_PLACEHOLDER"):
        validate_pr_body(legacy)


def test_repository_template_is_fallback_guard_without_legacy_placeholders() -> None:
    template = (ROOT / ".github" / "pull_request_template.md").read_text(encoding="utf-8")
    validation = validate_repository_template(template)

    assert validation["template_mode"] == "FAIL_CLOSED_FALLBACK_GUARD"
    assert validation["legacy_template"] == "REMOVED"


def test_missing_generated_body_in_pr_create_command_fails_closed() -> None:
    with pytest.raises(PRBodyIntegrationBlocked, match="GENERATED_PR_BODY_NOT_USED"):
        validate_pr_create_command(
            ["gh", "pr", "create", "--base", "main", "--head", "branch", "--title", "PB-026 VERIFIED: Governance PR Body Integration"],
            "governance/evidence/pb026_generated_pr_body.md",
            generate_pr_body(pb026_metadata()),
        )


def test_wrong_body_file_fails_closed() -> None:
    with pytest.raises(PRBodyIntegrationBlocked, match="GENERATED_BODY_FILE_NOT_USED"):
        validate_pr_create_command(
            ["gh", "pr", "create", "--body-file", ".github/pull_request_template.md"],
            "governance/evidence/pb026_generated_pr_body.md",
            generate_pr_body(pb026_metadata()),
        )


def test_generated_body_file_is_accepted() -> None:
    result = validate_pr_create_command(
        ["gh", "pr", "create", "--body-file", "governance/evidence/pb026_generated_pr_body.md"],
        "governance/evidence/pb026_generated_pr_body.md",
        generate_pr_body(pb026_metadata()),
    )

    assert result["generated_body_used"] is True
    assert result["mode"] == "BODY_FILE"


def test_body_text_must_match_generated_body() -> None:
    with pytest.raises(PRBodyIntegrationBlocked, match="GENERATED_BODY_TEXT_NOT_USED"):
        validate_pr_create_command(
            ["gh", "pr", "create", "--body", "manual body"],
            "governance/evidence/pb026_generated_pr_body.md",
            generate_pr_body(pb026_metadata()),
        )


def test_cli_generates_body_and_report(tmp_path: Path) -> None:
    body_path = tmp_path / "body.md"
    report_path = tmp_path / "report.json"

    completed = subprocess.run(
        [
            sys.executable,
            str(SCRIPT),
            "--body-output",
            str(body_path),
            "--report-output",
            str(report_path),
            "--template-path",
            str(ROOT / ".github" / "pull_request_template.md"),
        ],
        cwd=ROOT,
        text=True,
        capture_output=True,
    )

    assert completed.returncode == 0, completed.stdout + completed.stderr
    body = body_path.read_text(encoding="utf-8")
    report = json.loads(report_path.read_text(encoding="utf-8"))
    assert report["decision"] == "VERIFIED"
    assert report["pr_create_command_validation"]["generated_body_used"] is True
    assert "Describe what is changing and why." not in body
    assert "## PURPOSE" in body


def test_placeholder_count_detects_legacy_template_markers() -> None:
    body = "\n".join(FORBIDDEN_PLACEHOLDERS)

    assert placeholder_count(body) == len(FORBIDDEN_PLACEHOLDERS)


def test_open_pr_repair_report_verifies_successful_repairs_without_raw_body() -> None:
    report = build_open_pr_repair_report(
        [
            OpenPRRepairInput(
                pr_number=191,
                pb_number=24,
                pb_title="Post-Merge Governance Finalization",
                original_body="\n".join(FORBIDDEN_PLACEHOLDERS),
                update_attempted=True,
                update_succeeded=True,
            )
        ],
        open_pr_enumeration_status="VERIFIED",
    )

    assert report["decision"] == "VERIFIED"
    assert report["scanned_prs"][0]["placeholder_count_before"] == 6
    assert report["scanned_prs"][0]["placeholder_count_after"] == 0
    assert report["scanned_prs"][0]["pr_body_updated"] is True
    assert "original_body" not in report["scanned_prs"][0]


def test_open_pr_repair_report_fails_closed_when_update_is_forbidden() -> None:
    report = build_open_pr_repair_report(
        [
            OpenPRRepairInput(
                pr_number=192,
                pb_number=25,
                pb_title="Governance PR Template Completion",
                original_body="\n".join(FORBIDDEN_PLACEHOLDERS),
                update_attempted=True,
                update_succeeded=False,
                update_error="GITHUB_UPDATE_FORBIDDEN",
            )
        ],
        open_pr_enumeration_status="PARTIAL_GH_LIST_BLOCKED",
    )

    assert report["decision"] == "FAIL_CLOSED"
    assert report["status"] == "AUTHORIZATION_BLOCKED"
    assert report["scanned_prs"][0]["placeholder_count_before"] == 6
    assert report["scanned_prs"][0]["placeholder_count_after"] == 6
    assert report["scanned_prs"][0]["pr_body_updated"] is False
    assert report["scanned_prs"][0]["update_error"] == "GITHUB_UPDATE_FORBIDDEN"
