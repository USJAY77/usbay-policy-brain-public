from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "pb018_agent_governance_certification.py"


def _write_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _run(
    pb010: Path,
    pb013: Path,
    pb014: Path,
    pb017: Path,
    output: Path,
    profile: Path | None = None,
) -> subprocess.CompletedProcess[str]:
    command = [
        sys.executable,
        str(SCRIPT),
        str(pb010),
        str(pb013),
        str(pb014),
        str(pb017),
        str(output),
    ]
    if profile is not None:
        command.extend(["--agent-profile", str(profile)])
    return subprocess.run(command, cwd=ROOT, text=True, capture_output=True)


def _verified_report(schema: str) -> dict:
    return {
        "schema": schema,
        "decision": "VERIFIED",
        "fail_closed": False,
        "errors": [],
    }


def _write_inputs(root: Path, pb016_decision: str = "VERIFIED", open_actions: int = 0) -> tuple[Path, Path, Path, Path]:
    pb010 = root / "pb010"
    pb013 = root / "pb013"
    pb014 = root / "pb014"
    pb017 = root / "pb017"
    _write_json(
        pb010 / "pb010_chain_verification_report.json",
        _verified_report("usbay.pb010.chain_verification_report.v1"),
    )
    _write_json(
        pb010 / "pb010_chain_certificate.json",
        _verified_report("usbay.pb010.chain_certificate.v1"),
    )
    _write_json(
        pb010 / "pb010_governance_scorecard.json",
        _verified_report("usbay.pb010.governance_scorecard.v1"),
    )
    _write_json(
        pb013 / "pb013_governance_status_summary.json",
        {
            **_verified_report("usbay.pb013.governance_status_summary.v1"),
            "health_score": 100,
        },
    )
    _write_json(
        pb013 / "pb013_governance_health_report.json",
        _verified_report("usbay.pb013.governance_health_report.v1"),
    )
    _write_json(
        pb013 / "pb013_governance_risk_score.json",
        _verified_report("usbay.pb013.governance_risk_score.v1"),
    )
    _write_json(
        pb013 / "pb013_governance_monitor_report.json",
        _verified_report("usbay.pb013.governance_monitor_report.v1"),
    )
    _write_json(
        pb014 / "pb014_recovery_scorecard.json",
        _verified_report("usbay.pb014.recovery_scorecard.v1"),
    )
    _write_json(
        pb014 / "pb014_recovery_backup_manifest.json",
        _verified_report("usbay.pb014.recovery_backup_manifest.v1"),
    )
    _write_json(
        pb014 / "pb014_recovery_simulation_report.json",
        _verified_report("usbay.pb014.recovery_simulation_report.v1"),
    )
    _write_json(
        pb014 / "pb014_recovery_verification_report.json",
        _verified_report("usbay.pb014.recovery_verification_report.v1"),
    )
    _write_json(
        pb017 / "pb017_governance_action_tracker.json",
        {
            **_verified_report("usbay.pb017.governance_action_tracker.v1"),
            "open_actions": open_actions,
            "overdue_actions": 0,
        },
    )
    _write_json(
        pb017 / "pb017_governance_status_dashboard.json",
        {
            **_verified_report("usbay.pb017.governance_status_dashboard.v1"),
            "pb016_decision": pb016_decision,
        },
    )
    _write_json(
        pb017 / "pb017_governance_progress_report.json",
        _verified_report("usbay.pb017.governance_progress_report.v1"),
    )
    _write_json(
        pb017 / "pb017_governance_completion_report.json",
        _verified_report("usbay.pb017.governance_completion_report.v1"),
    )
    return pb010, pb013, pb014, pb017


def _profile(path: Path, **overrides: object) -> Path:
    payload = {
        "agent_id": "TEST-AGENT",
        "agent_name": "Test Agent",
        "agent_mode": "LOCAL_GOVERNANCE_VALIDATION_ONLY",
        "policy_compliance_mode": "USBAY_GOVERNED",
        "execution_authority": "NONE",
        "execution_verifiability": "LOCAL_ARTIFACTS_ONLY",
        "audit_trail_available": True,
        "human_approval_path": "MANDATORY",
        "fail_closed_default": True,
        "recovery_capability_required": True,
        "policy_bypass_capability": False,
        "unsupported_capabilities": [],
    }
    payload.update(overrides)
    _write_json(path, payload)
    return path


def test_agent_governance_certificate_generated_for_verified_controls(tmp_path: Path) -> None:
    pb010, pb013, pb014, pb017 = _write_inputs(tmp_path / "inputs")
    output = tmp_path / "pb018"

    completed = _run(pb010, pb013, pb014, pb017, output)

    assert completed.returncode == 0, completed.stdout + completed.stderr
    certificate = json.loads((output / "pb018_agent_governance_certificate.json").read_text(encoding="utf-8"))
    risk = json.loads((output / "pb018_agent_risk_assessment.json").read_text(encoding="utf-8"))
    scorecard = json.loads((output / "pb018_agent_scorecard.json").read_text(encoding="utf-8"))
    attestation = json.loads((output / "pb018_agent_attestation.json").read_text(encoding="utf-8"))
    assert certificate["decision"] == "VERIFIED"
    assert certificate["governance_score"] == 100
    assert risk["risk_level"] == "LOW"
    assert scorecard["score_areas"]["Human Oversight"]["status"] == "VERIFIED"
    assert attestation["human_final_authority_required"] is True


def test_missing_audit_trail_fails_closed(tmp_path: Path) -> None:
    pb010, pb013, pb014, pb017 = _write_inputs(tmp_path / "inputs")
    profile = _profile(tmp_path / "agent.json", audit_trail_available=False)
    output = tmp_path / "pb018"

    completed = _run(pb010, pb013, pb014, pb017, output, profile)

    assert completed.returncode == 1
    assert "PB018_AUDIT_TRAIL_MISSING" in completed.stdout
    risk = json.loads((output / "pb018_agent_risk_assessment.json").read_text(encoding="utf-8"))
    assert risk["missing_audit_trail_detected"] is True


def test_policy_bypass_detected_fails_closed(tmp_path: Path) -> None:
    pb010, pb013, pb014, pb017 = _write_inputs(tmp_path / "inputs")
    profile = _profile(tmp_path / "agent.json", policy_bypass_capability=True)
    output = tmp_path / "pb018"

    completed = _run(pb010, pb013, pb014, pb017, output, profile)

    assert completed.returncode == 1
    assert "PB018_POLICY_BYPASS_DETECTED" in completed.stdout
    risk = json.loads((output / "pb018_agent_risk_assessment.json").read_text(encoding="utf-8"))
    assert risk["policy_bypass_detected"] is True


def test_missing_human_oversight_fails_closed(tmp_path: Path) -> None:
    pb010, pb013, pb014, pb017 = _write_inputs(tmp_path / "inputs")
    profile = _profile(tmp_path / "agent.json", human_approval_path="OPTIONAL")
    output = tmp_path / "pb018"

    completed = _run(pb010, pb013, pb014, pb017, output, profile)

    assert completed.returncode == 1
    assert "PB018_HUMAN_APPROVAL_PATH_MISSING" in completed.stdout
    scorecard = json.loads((output / "pb018_agent_scorecard.json").read_text(encoding="utf-8"))
    assert scorecard["score_areas"]["Human Oversight"]["status"] == "BLOCKED"


def test_unsupported_capability_fails_closed(tmp_path: Path) -> None:
    pb010, pb013, pb014, pb017 = _write_inputs(tmp_path / "inputs")
    profile = _profile(tmp_path / "agent.json", unsupported_capabilities=["DIRECT_EXTERNAL_EXECUTION"])
    output = tmp_path / "pb018"

    completed = _run(pb010, pb013, pb014, pb017, output, profile)

    assert completed.returncode == 1
    assert "PB018_UNSUPPORTED_CAPABILITY" in completed.stdout
    risk = json.loads((output / "pb018_agent_risk_assessment.json").read_text(encoding="utf-8"))
    assert risk["unsupported_capability_detected"] is True


def test_incomplete_governance_maturity_fails_closed(tmp_path: Path) -> None:
    pb010, pb013, pb014, pb017 = _write_inputs(tmp_path / "inputs", pb016_decision="BLOCKED", open_actions=2)
    output = tmp_path / "pb018"

    completed = _run(pb010, pb013, pb014, pb017, output)

    assert completed.returncode == 1
    assert "PB018_GOVERNANCE_MATURITY_INCOMPLETE" in completed.stdout
    attestation = json.loads((output / "pb018_agent_attestation.json").read_text(encoding="utf-8"))
    assert attestation["pb016_decision"] == "BLOCKED"
    assert attestation["open_governance_actions"] == 2
