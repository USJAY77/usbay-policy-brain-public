from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "pb017_governance_action_tracking.py"


def _write_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _run(input_dir: Path, output_dir: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(SCRIPT), str(input_dir), str(output_dir)],
        cwd=ROOT,
        text=True,
        capture_output=True,
    )


def _write_pb016(input_dir: Path, actions: list[dict] | None = None) -> None:
    actions = actions or [
        {
            "action_id": "ACTION-001",
            "priority_id": "PB016-001",
            "title": "Collect PB-015 maturity report",
            "severity": "CRITICAL",
            "status": "OPEN",
            "owner": "Information not provided",
            "required_evidence": "PB-015 maturity report",
        },
        {
            "action_id": "ACTION-002",
            "priority_id": "PB016-002",
            "title": "Verify capability matrix",
            "severity": "HIGH",
            "status": "COMPLETED",
            "owner": "Governance",
            "required_evidence": "Capability matrix",
        },
    ]
    _write_json(
        input_dir / "pb016_governance_improvement_plan.json",
        {
            "schema": "usbay.pb016.governance_improvement_plan.v1",
            "decision": "VERIFIED",
            "fail_closed": False,
            "errors": [],
        },
    )
    _write_json(
        input_dir / "pb016_governance_roadmap.json",
        {
            "schema": "usbay.pb016.governance_roadmap.v1",
            "decision": "VERIFIED",
            "fail_closed": False,
            "errors": [],
            "roadmap": [
                {"phase_id": "PHASE-1", "priority_items": ["PB016-001"]},
                {"phase_id": "PHASE-2", "priority_items": ["PB016-002"]},
            ],
        },
    )
    _write_json(
        input_dir / "pb016_governance_action_register.json",
        {
            "schema": "usbay.pb016.governance_action_register.v1",
            "decision": "VERIFIED",
            "fail_closed": False,
            "errors": [],
            "actions": actions,
        },
    )
    _write_json(
        input_dir / "pb016_governance_priority_matrix.json",
        {
            "schema": "usbay.pb016.governance_priority_matrix.v1",
            "decision": "VERIFIED",
            "fail_closed": False,
            "errors": [],
        },
    )


def test_action_tracker_progress_completion_and_dashboard_generated(tmp_path: Path) -> None:
    input_dir = tmp_path / "pb016"
    output_dir = tmp_path / "pb017"
    _write_pb016(input_dir)

    completed = _run(input_dir, output_dir)

    assert completed.returncode == 0, completed.stdout + completed.stderr
    tracker = json.loads((output_dir / "pb017_governance_action_tracker.json").read_text(encoding="utf-8"))
    progress = json.loads((output_dir / "pb017_governance_progress_report.json").read_text(encoding="utf-8"))
    completion = json.loads((output_dir / "pb017_governance_completion_report.json").read_text(encoding="utf-8"))
    dashboard = json.loads((output_dir / "pb017_governance_status_dashboard.json").read_text(encoding="utf-8"))
    assert tracker["open_actions"] == 1
    assert tracker["completed_actions"] == 1
    assert progress["governance_progress_percentage"] == 50
    assert progress["roadmap_completion_percentage"] == 50
    assert completion["completed_action_count"] == 1
    assert dashboard["status"] == "ON_TRACK"


def test_missing_action_register_fails_closed(tmp_path: Path) -> None:
    input_dir = tmp_path / "pb016"
    output_dir = tmp_path / "pb017"
    _write_pb016(input_dir)
    (input_dir / "pb016_governance_action_register.json").unlink()

    completed = _run(input_dir, output_dir)

    assert completed.returncode == 1
    assert "PB017_ACTION_REGISTER_MISSING" in completed.stdout
    dashboard = json.loads((output_dir / "pb017_governance_status_dashboard.json").read_text(encoding="utf-8"))
    assert dashboard["decision"] == "BLOCKED"


def test_overdue_critical_action_fails_closed(tmp_path: Path) -> None:
    input_dir = tmp_path / "pb016"
    output_dir = tmp_path / "pb017"
    _write_pb016(
        input_dir,
        [
            {
                "action_id": "ACTION-001",
                "priority_id": "PB016-001",
                "title": "Overdue critical",
                "severity": "CRITICAL",
                "status": "OPEN",
                "due_date": "2000-01-01",
            }
        ],
    )

    completed = _run(input_dir, output_dir)

    assert completed.returncode == 1
    assert "PB017_OVERDUE_CRITICAL_ACTION:ACTION-001" in completed.stdout
    dashboard = json.loads((output_dir / "pb017_governance_status_dashboard.json").read_text(encoding="utf-8"))
    assert dashboard["overdue_critical_action_detected"] is True


def test_invalid_action_status_fails_closed(tmp_path: Path) -> None:
    input_dir = tmp_path / "pb016"
    output_dir = tmp_path / "pb017"
    _write_pb016(input_dir, [{"action_id": "ACTION-001", "status": "DONE", "severity": "LOW"}])

    completed = _run(input_dir, output_dir)

    assert completed.returncode == 1
    assert "PB017_INVALID_ACTION_STATUS:ACTION-001:DONE" in completed.stdout


def test_unsupported_governance_artifact_fails_closed(tmp_path: Path) -> None:
    input_dir = tmp_path / "pb016"
    output_dir = tmp_path / "pb017"
    _write_pb016(input_dir)
    _write_json(input_dir / "unsupported.json", {"unsupported": True})

    completed = _run(input_dir, output_dir)

    assert completed.returncode == 1
    assert "PB017_UNSUPPORTED_GOVERNANCE_ARTIFACT:unsupported.json" in completed.stdout


def test_completed_actions_can_reach_full_progress(tmp_path: Path) -> None:
    input_dir = tmp_path / "pb016"
    output_dir = tmp_path / "pb017"
    _write_pb016(
        input_dir,
        [
            {"action_id": "ACTION-001", "priority_id": "PB016-001", "status": "COMPLETED", "severity": "CRITICAL"},
            {"action_id": "ACTION-002", "priority_id": "PB016-002", "status": "COMPLETED", "severity": "HIGH"},
        ],
    )

    completed = _run(input_dir, output_dir)

    assert completed.returncode == 0
    progress = json.loads((output_dir / "pb017_governance_progress_report.json").read_text(encoding="utf-8"))
    assert progress["governance_progress_percentage"] == 100
    assert progress["roadmap_completion_percentage"] == 100
