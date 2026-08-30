from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

from scripts.usbay_cross_system_orchestrator import (
    ActionRequest,
    OrchestrationBlocked,
    connector_registry,
    contains_sensitive_data,
    cross_system_action_log,
    evaluate_action,
    generated_pr_body,
    generated_title,
    governance_metadata_validation,
    pb028_metadata,
    redact_sensitive,
    run_orchestration,
    validate_generated_pr_body,
    validate_registry,
)


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "usbay_cross_system_orchestrator.py"


def test_missing_connector_blocks_execution() -> None:
    registry = connector_registry()
    registry.pop("notion")

    with pytest.raises(OrchestrationBlocked, match="CONNECTOR_MISSING:notion"):
        validate_registry(registry)


def test_failed_connector_blocks_execution() -> None:
    result = evaluate_action(
        ActionRequest(system="github", action_type="sync_pr_metadata", dry_run=True),
        connector_registry(),
        connector_failed=True,
    )

    assert result["decision"] == "BLOCKED"
    assert result["status"] == "FAIL_CLOSED"
    assert "connector_failed" in result["blockers"]


def test_human_approval_required_for_external_actions() -> None:
    result = evaluate_action(
        ActionRequest(system="linkedin", action_type="post", dry_run=True, human_approved=False),
        connector_registry(),
    )

    assert result["decision"] == "BLOCKED"
    assert "human_approval_required" in result["blockers"]


def test_linkedin_public_action_never_runs_automatically() -> None:
    result = evaluate_action(
        ActionRequest(system="linkedin", action_type="post", dry_run=False, human_approved=True),
        connector_registry(),
    )

    assert result["decision"] == "BLOCKED"
    assert "external_action_not_allowed_without_explicit_release" in result["blockers"]


def test_github_notion_euria_sync_can_run_in_dry_run_mode() -> None:
    report = run_orchestration(
        [
            ActionRequest(system="github", action_type="sync_pr_metadata", dry_run=True),
            ActionRequest(system="notion", action_type="sync_evidence_page", dry_run=True),
            ActionRequest(system="euria", action_type="sync_project_context", dry_run=True),
        ],
        connector_registry(),
    )

    assert report["decision"] == "VERIFIED"
    assert {action["system"] for action in report["actions"]} == {"github", "notion", "euria"}
    assert all(action["decision"] == "APPROVED_DRY_RUN" for action in report["actions"])


def test_sensitive_data_is_redacted_and_not_logged() -> None:
    payload = {"token": "example-sensitive-value", "nested": {"api_key": "example-sensitive-value"}}

    assert contains_sensitive_data(payload) is True
    redacted = redact_sensitive(payload)
    assert "example-sensitive-value" not in json.dumps(redacted)
    result = evaluate_action(
        ActionRequest(system="github", action_type="sync_pr_metadata", dry_run=True, payload=payload),
        connector_registry(),
    )
    assert result["sensitive_data_logged"] is False
    assert "payload" not in result


def test_cross_system_action_log_contains_no_raw_payloads() -> None:
    report = run_orchestration(
        [ActionRequest(system="github", action_type="sync_pr_metadata", dry_run=True, payload={"secret": "value"})],
        connector_registry(),
    )
    log = cross_system_action_log(report)

    assert log["raw_payloads_logged"] is False
    assert log["sensitive_data_logged"] is False
    assert "secret" not in json.dumps(log).lower()


def test_cli_generates_audit_evidence(tmp_path: Path) -> None:
    completed = subprocess.run(
        [sys.executable, str(SCRIPT), "--output-dir", str(tmp_path)],
        cwd=ROOT,
        text=True,
        capture_output=True,
    )

    assert completed.returncode == 0, completed.stdout + completed.stderr
    assert (tmp_path / "automation_orchestrator_report.json").is_file()
    assert (tmp_path / "connector_health_report.json").is_file()
    assert (tmp_path / "cross_system_action_log.json").is_file()
    assert (tmp_path / "governance_metadata_validation.json").is_file()
    assert (tmp_path / "generated_pr_body.md").is_file()
    report = json.loads((tmp_path / "automation_orchestrator_report.json").read_text(encoding="utf-8"))
    assert report["decision"] == "VERIFIED"
    assert report["external_public_action_performed"] is False


def test_metadata_validation_verifies_commit_pr_title_and_body() -> None:
    metadata = pb028_metadata()
    title = generated_title(metadata)
    body = generated_pr_body(metadata)

    report = governance_metadata_validation(commit_title=title, pr_title=title, pr_body=body, metadata=metadata)

    assert report["decision"] == "VERIFIED"
    assert report["comparisons"]["commit_title_matches_generated"] is True
    assert report["comparisons"]["pr_title_matches_generated"] is True
    assert report["comparisons"]["pr_body_matches_generated"] is True


def test_metadata_validation_blocks_commit_title_mismatch() -> None:
    metadata = pb028_metadata()
    title = generated_title(metadata)
    body = generated_pr_body(metadata)

    report = governance_metadata_validation(commit_title="manual title", pr_title=title, pr_body=body, metadata=metadata)

    assert report["decision"] == "BLOCKED"
    assert report["status"] == "FAIL_CLOSED"
    assert report["comparisons"]["commit_title_matches_generated"] is False


def test_generated_pr_body_blocks_placeholders() -> None:
    body = generated_pr_body(pb028_metadata()) + "Describe what is changing and why."

    try:
        validate_generated_pr_body(body)
    except OrchestrationBlocked as exc:
        assert "PR_BODY_PLACEHOLDER_PRESENT" in str(exc)
    else:
        raise AssertionError("placeholder body was not blocked")
