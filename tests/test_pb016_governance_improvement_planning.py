from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "pb016_governance_improvement_planning.py"


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


def _write_pb015(input_dir: Path) -> None:
    controls = {f"PB-{index:03d}": {"status": "VERIFIED"} for index in range(5, 16)}
    _write_json(
        input_dir / "pb015_maturity_report.json",
        {
            "schema": "usbay.pb015.governance_maturity_report.v1",
            "decision": "VERIFIED",
            "fail_closed": False,
            "maturity_score": 82,
            "controls": controls,
            "governance_weaknesses": ["Evidence owner delegation not complete"],
            "recovery_readiness": "VERIFIED",
            "monitoring_readiness": "VERIFIED",
        },
    )
    _write_json(
        input_dir / "pb015_capability_matrix.json",
        {
            "schema": "usbay.pb015.capability_matrix.v1",
            "decision": "VERIFIED",
            "fail_closed": False,
            "controls": controls,
            "capability_gaps": [
                {
                    "gap_id": "GAP-001",
                    "capability": "External WORM provider evidence",
                    "severity": "CRITICAL",
                    "control": "PB-006",
                    "evidence_required": "Provider retention and legal hold receipts",
                }
            ],
        },
    )
    _write_json(
        input_dir / "pb015_governance_scorecard.json",
        {
            "schema": "usbay.pb015.governance_scorecard.v1",
            "decision": "VERIFIED",
            "fail_closed": False,
            "governance_score": 88,
        },
    )


def test_improvement_plan_priority_matrix_roadmap_and_action_register_generated(tmp_path: Path) -> None:
    input_dir = tmp_path / "pb015"
    output_dir = tmp_path / "pb016"
    _write_pb015(input_dir)

    completed = _run(input_dir, output_dir)

    assert completed.returncode == 0, completed.stdout + completed.stderr
    plan = json.loads((output_dir / "pb016_governance_improvement_plan.json").read_text(encoding="utf-8"))
    priority = json.loads((output_dir / "pb016_governance_priority_matrix.json").read_text(encoding="utf-8"))
    roadmap = json.loads((output_dir / "pb016_governance_roadmap.json").read_text(encoding="utf-8"))
    actions = json.loads((output_dir / "pb016_governance_action_register.json").read_text(encoding="utf-8"))
    assert plan["decision"] == "VERIFIED"
    assert plan["governance_score"] == 88
    assert priority["priority_count"] == 2
    assert roadmap["roadmap"][0]["phase_id"] == "PHASE-1"
    assert actions["action_count"] == 2
    assert plan["external_network_access_performed"] is False


def test_missing_maturity_report_fails_closed(tmp_path: Path) -> None:
    input_dir = tmp_path / "pb015"
    output_dir = tmp_path / "pb016"
    _write_pb015(input_dir)
    (input_dir / "pb015_maturity_report.json").unlink()

    completed = _run(input_dir, output_dir)

    assert completed.returncode == 1
    assert "PB016_MATURITY_REPORT_MISSING" in completed.stdout
    plan = json.loads((output_dir / "pb016_governance_improvement_plan.json").read_text(encoding="utf-8"))
    assert plan["decision"] == "BLOCKED"


def test_missing_capability_matrix_fails_closed(tmp_path: Path) -> None:
    input_dir = tmp_path / "pb015"
    output_dir = tmp_path / "pb016"
    _write_pb015(input_dir)
    (input_dir / "pb015_capability_matrix.json").unlink()

    completed = _run(input_dir, output_dir)

    assert completed.returncode == 1
    assert "PB016_CAPABILITY_MATRIX_MISSING" in completed.stdout
    priority = json.loads((output_dir / "pb016_governance_priority_matrix.json").read_text(encoding="utf-8"))
    assert priority["decision"] == "BLOCKED"


def test_invalid_governance_score_fails_closed(tmp_path: Path) -> None:
    input_dir = tmp_path / "pb015"
    output_dir = tmp_path / "pb016"
    _write_pb015(input_dir)
    scorecard = json.loads((input_dir / "pb015_governance_scorecard.json").read_text(encoding="utf-8"))
    scorecard["governance_score"] = "invalid"
    _write_json(input_dir / "pb015_governance_scorecard.json", scorecard)

    completed = _run(input_dir, output_dir)

    assert completed.returncode == 1
    assert "PB016_GOVERNANCE_SCORE_INVALID" in completed.stdout


def test_missing_governance_control_fails_closed(tmp_path: Path) -> None:
    input_dir = tmp_path / "pb015"
    output_dir = tmp_path / "pb016"
    _write_pb015(input_dir)
    report = json.loads((input_dir / "pb015_maturity_report.json").read_text(encoding="utf-8"))
    matrix = json.loads((input_dir / "pb015_capability_matrix.json").read_text(encoding="utf-8"))
    report["controls"].pop("PB-014")
    matrix["controls"].pop("PB-014")
    _write_json(input_dir / "pb015_maturity_report.json", report)
    _write_json(input_dir / "pb015_capability_matrix.json", matrix)

    completed = _run(input_dir, output_dir)

    assert completed.returncode == 1
    assert "PB016_GOVERNANCE_CONTROL_MISSING:PB-014" in completed.stdout


def test_unsupported_governance_artifact_fails_closed(tmp_path: Path) -> None:
    input_dir = tmp_path / "pb015"
    output_dir = tmp_path / "pb016"
    _write_pb015(input_dir)
    _write_json(input_dir / "unsupported.json", {"unsupported": True})

    completed = _run(input_dir, output_dir)

    assert completed.returncode == 1
    assert "PB016_UNSUPPORTED_GOVERNANCE_ARTIFACT:unsupported.json" in completed.stdout
