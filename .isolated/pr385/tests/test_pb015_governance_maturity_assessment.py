from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "pb015_governance_maturity_assessment.py"


def _write_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _verified(schema: str | None = None) -> dict:
    payload = {
        "decision": "VERIFIED",
        "fail_closed": False,
        "generated_at": "2026-06-16T00:00:00Z",
    }
    if schema:
        payload["schema"] = schema
    return payload


def _run(evidence_root: Path, output_dir: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(SCRIPT), str(evidence_root), str(output_dir)],
        cwd=ROOT,
        text=True,
        capture_output=True,
    )


def _write_upstream_evidence(root: Path) -> None:
    files = {
        "pb005/pb005_final_execution_report.json": None,
        "pb005/pb005_evidence_manifest.json": None,
        "pb005/pb006_integrity_report.json": None,
        "pb005/pb007_verification_report.json": None,
        "pb005/pb008_non_repudiation_report.json": None,
        "pb005/pb008_timestamp_receipt.json": None,
        "pb009_archive/pb009_archive_manifest.json": None,
        "pb010_chain/pb010_chain_certificate.json": "usbay.pb010.chain_certificate.v1",
        "pb010_chain/pb010_chain_verification_report.json": "usbay.pb010.chain_verification_report.v1",
        "pb010_chain/pb010_governance_scorecard.json": "usbay.pb010.governance_scorecard.v1",
        "pb011_baseline/pb011_baseline_manifest.json": None,
        "pb011_baseline/pb011_drift_report.json": "usbay.pb011.drift_report.v1",
        "pb011_baseline/pb011_drift_scorecard.json": "usbay.pb011.drift_scorecard.v1",
        "pb012_control_registry/governance_control_registry.json": "usbay.pb012.governance_control_registry.v1",
        "pb012_control_registry/governance_control_manifest.json": "usbay.pb012.governance_control_manifest.v1",
        "pb012_control_registry/governance_self_attestation.json": "usbay.pb012.governance_self_attestation.v1",
        "pb013_monitor/pb013_governance_health_report.json": "usbay.pb013.governance_health_report.v1",
        "pb013_monitor/pb013_governance_monitor_report.json": "usbay.pb013.governance_monitor_report.v1",
        "pb013_monitor/pb013_governance_risk_score.json": "usbay.pb013.governance_risk_score.v1",
        "pb013_monitor/pb013_governance_status_summary.json": "usbay.pb013.governance_status_summary.v1",
        "pb014_recovery/pb014_recovery_backup_manifest.json": "usbay.pb014.recovery_backup_manifest.v1",
        "pb014_recovery/pb014_recovery_simulation_report.json": "usbay.pb014.recovery_simulation_report.v1",
        "pb014_recovery/pb014_recovery_verification_report.json": "usbay.pb014.recovery_verification_report.v1",
        "pb014_recovery/pb014_recovery_scorecard.json": "usbay.pb014.recovery_scorecard.v1",
    }
    for relative_path, schema in files.items():
        _write_json(root / relative_path, _verified(schema))


def test_pb015_generates_canonical_maturity_outputs_for_verified_lineage(tmp_path: Path) -> None:
    evidence_root = tmp_path / "evidence"
    output_dir = tmp_path / "pb015_maturity"
    _write_upstream_evidence(evidence_root)

    completed = _run(evidence_root, output_dir)

    assert completed.returncode == 0, completed.stdout + completed.stderr
    maturity = json.loads((output_dir / "pb015_maturity_report.json").read_text(encoding="utf-8"))
    matrix = json.loads((output_dir / "pb015_capability_matrix.json").read_text(encoding="utf-8"))
    scorecard = json.loads((output_dir / "pb015_governance_scorecard.json").read_text(encoding="utf-8"))
    assert maturity["schema"] == "usbay.pb015.governance_maturity_report.v1"
    assert matrix["schema"] == "usbay.pb015.capability_matrix.v1"
    assert scorecard["schema"] == "usbay.pb015.governance_scorecard.v1"
    assert maturity["decision"] == "VERIFIED"
    assert maturity["fail_closed"] is False
    assert maturity["maturity_score"] == 100
    assert scorecard["governance_score"] == 100
    assert "PB-015" in maturity["controls"]
    assert set(scorecard["verified_controls"]) == {f"PB-{index:03d}" for index in range(5, 16)}
    assert maturity["external_network_access_performed"] is False
    assert maturity["no_production_readiness_claim"] is True


def test_missing_upstream_evidence_fails_closed(tmp_path: Path) -> None:
    evidence_root = tmp_path / "evidence"
    output_dir = tmp_path / "pb015_maturity"
    _write_upstream_evidence(evidence_root)
    (evidence_root / "pb010_chain" / "pb010_chain_certificate.json").unlink()

    completed = _run(evidence_root, output_dir)

    assert completed.returncode == 1
    assert "PB015_REQUIRED_EVIDENCE_MISSING:PB-010:pb010_chain/pb010_chain_certificate.json" in completed.stdout
    maturity = json.loads((output_dir / "pb015_maturity_report.json").read_text(encoding="utf-8"))
    assert maturity["decision"] == "BLOCKED"
    assert maturity["fail_closed"] is True
    assert "PB-010" in maturity["blocked_controls"]


def test_unverified_upstream_evidence_fails_closed(tmp_path: Path) -> None:
    evidence_root = tmp_path / "evidence"
    output_dir = tmp_path / "pb015_maturity"
    _write_upstream_evidence(evidence_root)
    payload = _verified("usbay.pb013.governance_status_summary.v1")
    payload["decision"] = "BLOCKED"
    payload["fail_closed"] = True
    _write_json(evidence_root / "pb013_monitor" / "pb013_governance_status_summary.json", payload)

    completed = _run(evidence_root, output_dir)

    assert completed.returncode == 1
    assert "PB015_REQUIRED_EVIDENCE_NOT_VERIFIED:PB-013:pb013_monitor/pb013_governance_status_summary.json" in completed.stdout
    scorecard = json.loads((output_dir / "pb015_governance_scorecard.json").read_text(encoding="utf-8"))
    assert "PB-013" in scorecard["blocked_controls"]


def test_invalid_upstream_schema_fails_closed(tmp_path: Path) -> None:
    evidence_root = tmp_path / "evidence"
    output_dir = tmp_path / "pb015_maturity"
    _write_upstream_evidence(evidence_root)
    payload = _verified("usbay.pb012.governance_control_registry.v2")
    _write_json(evidence_root / "pb012_control_registry" / "governance_control_registry.json", payload)

    completed = _run(evidence_root, output_dir)

    assert completed.returncode == 1
    assert "PB015_REQUIRED_EVIDENCE_SCHEMA_INVALID:PB-012:pb012_control_registry/governance_control_registry.json" in completed.stdout


def test_unsupported_output_artifact_fails_closed(tmp_path: Path) -> None:
    evidence_root = tmp_path / "evidence"
    output_dir = tmp_path / "pb015_maturity"
    _write_upstream_evidence(evidence_root)
    _write_json(output_dir / "unexpected.json", {"unsupported": True})

    completed = _run(evidence_root, output_dir)

    assert completed.returncode == 1
    assert "PB015_UNSUPPORTED_GOVERNANCE_ARTIFACT:unexpected.json" in completed.stdout


def test_pb016_accepts_pb015_verified_outputs(tmp_path: Path) -> None:
    evidence_root = tmp_path / "evidence"
    pb015_output = tmp_path / "pb015_maturity"
    pb016_output = tmp_path / "pb016"
    _write_upstream_evidence(evidence_root)

    pb015 = _run(evidence_root, pb015_output)
    assert pb015.returncode == 0, pb015.stdout + pb015.stderr
    pb016 = subprocess.run(
        [sys.executable, str(ROOT / "scripts" / "pb016_governance_improvement_planning.py"), str(pb015_output), str(pb016_output)],
        cwd=ROOT,
        text=True,
        capture_output=True,
    )

    assert pb016.returncode == 0, pb016.stdout + pb016.stderr
    plan = json.loads((pb016_output / "pb016_governance_improvement_plan.json").read_text(encoding="utf-8"))
    assert plan["decision"] == "VERIFIED"
    assert plan["maturity_score"] == 100
