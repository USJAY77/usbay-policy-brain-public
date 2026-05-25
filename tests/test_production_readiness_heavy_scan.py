from __future__ import annotations

from pathlib import Path

import pytest

from scripts import verify_production_readiness as readiness


ROOT = Path(__file__).resolve().parents[1]
HEAVY_WORKFLOW = ROOT / ".github" / "workflows" / "production-readiness-heavy-scan.yml"

pytestmark = pytest.mark.heavy


def test_heavy_scan_lane_is_explicit_and_non_default(capsys: pytest.CaptureFixture[str]) -> None:
    result = readiness.main(["--lane", "heavy-scan", "--event", "manual", "--root", str(ROOT)])
    output = capsys.readouterr().out

    assert result == 0
    assert "selected_lane=heavy-scan" in output
    assert "lane_pr_blocking=false" in output
    assert "PRODUCTION_READINESS_HEAVY_SCAN=true" in output
    assert "PRODUCTION_READINESS=true" in output


def test_heavy_scan_pull_request_is_blocked_without_success_marker(capsys: pytest.CaptureFixture[str]) -> None:
    result = readiness.main(["--lane", "heavy-scan", "--event", "pull_request", "--root", str(ROOT)])
    output = capsys.readouterr().out

    assert result == 1
    assert "selected_lane=heavy-scan" in output
    assert "lane_pr_blocking=false" in output
    assert "allowed_trigger=false" in output
    assert "PRODUCTION_READINESS_LANE_TRIGGER_BLOCKED" in output
    assert "PRODUCTION_READINESS_HEAVY_SCAN=true" not in output


def test_heavy_scan_policy_allows_manual_and_scheduled_contexts() -> None:
    for event in ("manual", "workflow_dispatch", "scheduled", "schedule", "nightly"):
        _policy, _policy_hash, evidence = readiness.validate_lane_policy(ROOT, "heavy-scan", event)
        assert evidence["selected_lane"] == "heavy-scan"
        assert evidence["lane_pr_blocking"] is False
        assert evidence["allowed_trigger"] is True


def test_heavy_scan_workflow_is_non_pr_and_least_privilege() -> None:
    text = HEAVY_WORKFLOW.read_text(encoding="utf-8")

    assert "workflow_dispatch:" in text
    assert "schedule:" in text
    assert "pull_request:" not in text
    assert "push:" not in text
    assert "permissions:\n  contents: read" in text
    assert "contents: write" not in text
    assert "pull-requests: write" not in text
    assert "issues: write" not in text
    assert "continue-on-error" not in text


def test_heavy_scan_workflow_writes_required_evidence_path() -> None:
    text = HEAVY_WORKFLOW.read_text(encoding="utf-8")

    assert "python3 scripts/verify_production_readiness.py" in text
    assert "--lane heavy-scan" in text
    assert "--event \"${event_context}\"" in text
    assert "event_context=\"manual\"" in text
    assert "event_context=\"scheduled\"" in text
    assert "evidence/production-readiness-heavy-scan-output.txt" in text
    assert "selected_lane=heavy-scan" in text
    assert "lane_pr_blocking=false" in text
    assert "allowed_trigger=true" in text
    assert "lane_policy_hash=" in text
    assert "PRODUCTION_READINESS_HEAVY_SCAN=true" in text


def test_heavy_scan_workflow_is_required_by_orchestration_lane() -> None:
    assert readiness.check_heavy_scan_workflow(ROOT) == []
