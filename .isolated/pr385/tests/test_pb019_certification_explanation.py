from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "pb019_certification_explanation.py"


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


def _write_pb018(input_dir: Path, decision: str = "BLOCKED") -> None:
    errors = ["PB018_GOVERNANCE_MATURITY_INCOMPLETE"] if decision == "BLOCKED" else []
    fail_closed = decision == "BLOCKED"
    _write_json(
        input_dir / "pb018_agent_governance_certificate.json",
        {
            "schema": "usbay.pb018.agent_governance_certificate.v1",
            "agent_id": "TEST-AGENT",
            "decision": decision,
            "certificate_status": decision,
            "fail_closed": fail_closed,
            "errors": errors,
            "governance_score": 85.71,
        },
    )
    _write_json(
        input_dir / "pb018_agent_risk_assessment.json",
        {
            "schema": "usbay.pb018.agent_risk_assessment.v1",
            "agent_id": "TEST-AGENT",
            "decision": decision,
            "fail_closed": fail_closed,
            "errors": errors,
            "risk_level": "HIGH" if decision == "BLOCKED" else "LOW",
        },
    )
    _write_json(
        input_dir / "pb018_agent_scorecard.json",
        {
            "schema": "usbay.pb018.agent_scorecard.v1",
            "agent_id": "TEST-AGENT",
            "decision": decision,
            "fail_closed": fail_closed,
            "errors": errors,
            "score": 85.71 if decision == "BLOCKED" else 100,
            "score_areas": {
                "Governance Maturity": {
                    "status": "BLOCKED" if decision == "BLOCKED" else "VERIFIED",
                    "evidence": [
                        "governance/evidence/pb017_action_tracking/pb017_governance_action_tracker.json"
                    ],
                    "gaps": [
                        "PB-016 decision=BLOCKED",
                        "open_actions=15",
                        "overdue_actions=0",
                    ]
                    if decision == "BLOCKED"
                    else [],
                }
            },
        },
    )
    _write_json(
        input_dir / "pb018_agent_attestation.json",
        {
            "schema": "usbay.pb018.agent_attestation.v1",
            "agent_id": "TEST-AGENT",
            "decision": decision,
            "attestation_status": decision,
            "fail_closed": fail_closed,
            "errors": errors,
            "pb016_decision": "BLOCKED" if decision == "BLOCKED" else "VERIFIED",
            "open_governance_actions": 15 if decision == "BLOCKED" else 0,
            "overdue_governance_actions": 0,
        },
    )


def test_pb019_explains_pb018_blocked_certification(tmp_path: Path) -> None:
    input_dir = tmp_path / "pb018"
    output_dir = tmp_path / "pb019"
    _write_pb018(input_dir)

    completed = _run(input_dir, output_dir)

    assert completed.returncode == 0, completed.stdout + completed.stderr
    explanation = json.loads((output_dir / "pb019_certification_explanation.json").read_text(encoding="utf-8"))
    failure = json.loads((output_dir / "pb019_certification_failure_report.json").read_text(encoding="utf-8"))
    gaps = json.loads((output_dir / "pb019_certification_gap_report.json").read_text(encoding="utf-8"))
    actions = json.loads((output_dir / "pb019_required_actions.json").read_text(encoding="utf-8"))
    assert explanation["decision"] == "VERIFIED"
    assert explanation["certification_granted"] is False
    assert failure["pb018_decision"] == "BLOCKED"
    assert gaps["gap_count"] == 1
    assert actions["required_action_count"] == 2
    assert actions["required_actions"][0]["status"] == "OPEN"


def test_missing_pb018_input_fails_closed(tmp_path: Path) -> None:
    input_dir = tmp_path / "pb018"
    output_dir = tmp_path / "pb019"
    _write_pb018(input_dir)
    (input_dir / "pb018_agent_attestation.json").unlink()

    completed = _run(input_dir, output_dir)

    assert completed.returncode == 1
    assert "PB019_REQUIRED_INPUT_MISSING:pb018_agent_attestation.json" in completed.stdout
    explanation = json.loads((output_dir / "pb019_certification_explanation.json").read_text(encoding="utf-8"))
    assert explanation["decision"] == "BLOCKED"


def test_unsupported_pb018_artifact_fails_closed(tmp_path: Path) -> None:
    input_dir = tmp_path / "pb018"
    output_dir = tmp_path / "pb019"
    _write_pb018(input_dir)
    _write_json(input_dir / "unsupported.json", {"unsupported": True})

    completed = _run(input_dir, output_dir)

    assert completed.returncode == 1
    assert "PB019_UNSUPPORTED_GOVERNANCE_ARTIFACT:unsupported.json" in completed.stdout


def test_invalid_pb018_schema_fails_closed(tmp_path: Path) -> None:
    input_dir = tmp_path / "pb018"
    output_dir = tmp_path / "pb019"
    _write_pb018(input_dir)
    payload = json.loads((input_dir / "pb018_agent_scorecard.json").read_text(encoding="utf-8"))
    payload["schema"] = "invalid"
    _write_json(input_dir / "pb018_agent_scorecard.json", payload)

    completed = _run(input_dir, output_dir)

    assert completed.returncode == 1
    assert "PB019_SCORECARD_SCHEMA_INVALID" in completed.stdout


def test_verified_pb018_has_no_failure_to_explain(tmp_path: Path) -> None:
    input_dir = tmp_path / "pb018"
    output_dir = tmp_path / "pb019"
    _write_pb018(input_dir, decision="VERIFIED")

    completed = _run(input_dir, output_dir)

    assert completed.returncode == 1
    assert "PB019_NO_FAILURE_TO_EXPLAIN" in completed.stdout
    explanation = json.loads((output_dir / "pb019_certification_explanation.json").read_text(encoding="utf-8"))
    assert explanation["fail_closed"] is True
