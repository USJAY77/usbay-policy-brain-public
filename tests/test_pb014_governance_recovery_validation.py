from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "pb014_governance_recovery_validation.py"


def _write_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _run(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(SCRIPT), *args],
        cwd=ROOT,
        text=True,
        capture_output=True,
    )


def _verified(schema: str) -> dict:
    return {"schema": schema, "decision": "VERIFIED", "fail_closed": False, "errors": []}


def _write_project(root: Path) -> None:
    controls = []
    for number in range(5, 12):
        control_id = f"PB-{number:03d}"
        definition_paths = [
            f"controls/{control_id}/definition.json",
            f"controls/{control_id}/test.json",
        ]
        controls.append(
            {
                "control_id": control_id,
                "title": f"{control_id} Control",
                "version": "v1",
                "definition_paths": definition_paths,
            }
        )
        for path in definition_paths:
            _write_json(root / path, {"control_id": control_id, "path": path})

    _write_json(
        root / "governance/evidence/pb012_control_registry/governance_control_registry.json",
        {
            "schema": "usbay.pb012.governance_control_registry.v1",
            "control_count": 7,
            "controls": controls,
        },
    )
    _write_json(root / "governance/evidence/pb012_control_registry/governance_control_manifest.json", _verified("usbay.pb012.governance_control_manifest.v1"))
    _write_json(
        root / "governance/evidence/pb012_control_registry/governance_self_attestation.json",
        {
            **_verified("usbay.pb012.governance_self_attestation.v1"),
            "registry_hash_mismatch_detected": False,
            "control_manifest_mismatch_detected": False,
        },
    )
    _write_json(root / "governance/evidence/pb010_chain/pb010_chain_verification_report.json", _verified("usbay.pb010.chain_verification_report.v1"))
    _write_json(root / "governance/evidence/pb011_baseline/pb011_drift_report.json", _verified("usbay.pb011.drift_report.v1"))
    _write_json(
        root / "governance/evidence/pb013_monitor/pb013_governance_health_report.json",
        {**_verified("usbay.pb013.governance_health_report.v1"), "health_score": 100},
    )
    for path, schema in {
        "governance/evidence/pb013_monitor/pb013_governance_risk_score.json": "usbay.pb013.governance_risk_score.v1",
        "governance/evidence/pb013_monitor/pb013_governance_monitor_report.json": "usbay.pb013.governance_monitor_report.v1",
        "governance/evidence/pb013_monitor/pb013_governance_status_summary.json": "usbay.pb013.governance_status_summary.v1",
    }.items():
        _write_json(root / path, _verified(schema))


def test_recovery_backup_simulation_verification_and_scorecard_succeed(tmp_path: Path) -> None:
    project = tmp_path / "project"
    output = tmp_path / "pb014"
    _write_project(project)

    completed = _run("run", str(project), str(output))

    assert completed.returncode == 0, completed.stdout + completed.stderr
    backup = json.loads((output / "pb014_recovery_backup_manifest.json").read_text(encoding="utf-8"))
    simulation = json.loads((output / "pb014_recovery_simulation_report.json").read_text(encoding="utf-8"))
    verification = json.loads((output / "pb014_recovery_verification_report.json").read_text(encoding="utf-8"))
    scorecard = json.loads((output / "pb014_recovery_scorecard.json").read_text(encoding="utf-8"))
    assert backup["decision"] == "VERIFIED"
    assert simulation["missing_artifact_recovered"] is True
    assert simulation["corrupted_artifact_recovered"] is True
    assert verification["decision"] == "VERIFIED"
    assert scorecard["score"] == 100


def test_missing_backup_fails_closed(tmp_path: Path) -> None:
    output = tmp_path / "pb014"

    completed = _run("verify", str(output))

    assert completed.returncode == 1
    assert "PB014_RECOVERY_BASELINE_MISSING:pb014_recovery_backup_manifest.json" in completed.stdout
    scorecard = json.loads((output / "pb014_recovery_scorecard.json").read_text(encoding="utf-8"))
    assert scorecard["missing_backup_detected"] is True


def test_corrupted_backup_artifact_fails_hash_verification(tmp_path: Path) -> None:
    project = tmp_path / "project"
    output = tmp_path / "pb014"
    _write_project(project)
    assert _run("run", str(project), str(output)).returncode == 0
    backup_file = next((output / "backup_artifacts").rglob("definition.json"))
    backup_file.write_text("tampered\n", encoding="utf-8")

    completed = _run("verify", str(output))

    assert completed.returncode == 1
    assert "PB014_RESTORED_ARTIFACT_HASH_MISMATCH" in completed.stdout
    scorecard = json.loads((output / "pb014_recovery_scorecard.json").read_text(encoding="utf-8"))
    assert scorecard["hash_mismatch_detected"] is True


def test_registry_mismatch_after_recovery_fails_closed(tmp_path: Path) -> None:
    project = tmp_path / "project"
    output = tmp_path / "pb014"
    _write_project(project)
    _write_json(
        project / "governance/evidence/pb012_control_registry/governance_self_attestation.json",
        {
            **_verified("usbay.pb012.governance_self_attestation.v1"),
            "registry_hash_mismatch_detected": True,
        },
    )

    completed = _run("run", str(project), str(output))

    assert completed.returncode == 1
    assert "PB014_REGISTRY_MISMATCH_AFTER_RECOVERY" in completed.stdout


def test_pb010_and_pb011_mismatch_after_recovery_fail_closed(tmp_path: Path) -> None:
    project = tmp_path / "project"
    output = tmp_path / "pb014"
    _write_project(project)
    _write_json(project / "governance/evidence/pb010_chain/pb010_chain_verification_report.json", {**_verified("usbay.pb010.chain_verification_report.v1"), "decision": "BLOCKED"})
    _write_json(project / "governance/evidence/pb011_baseline/pb011_drift_report.json", {**_verified("usbay.pb011.drift_report.v1"), "fail_closed": True})

    completed = _run("run", str(project), str(output))

    assert completed.returncode == 1
    assert "PB014_PB010_CERTIFICATION_MISMATCH_AFTER_RECOVERY" in completed.stdout
    assert "PB014_PB011_DRIFT_MISMATCH_AFTER_RECOVERY" in completed.stdout


def test_pb013_health_below_threshold_fails_closed(tmp_path: Path) -> None:
    project = tmp_path / "project"
    output = tmp_path / "pb014"
    _write_project(project)
    _write_json(project / "governance/evidence/pb013_monitor/pb013_governance_health_report.json", {**_verified("usbay.pb013.governance_health_report.v1"), "health_score": 99})

    completed = _run("run", str(project), str(output))

    assert completed.returncode == 1
    assert "PB014_PB013_HEALTH_SCORE_BELOW_THRESHOLD" in completed.stdout


def test_unsupported_recovery_artifact_fails_closed(tmp_path: Path) -> None:
    project = tmp_path / "project"
    output = tmp_path / "pb014"
    _write_project(project)
    assert _run("run", str(project), str(output)).returncode == 0
    _write_json(output / "backup_artifacts/unsupported.json", {"unsupported": True})

    completed = _run("verify", str(output))

    assert completed.returncode == 1
    assert "PB014_UNSUPPORTED_RECOVERY_ARTIFACT:unsupported.json" in completed.stdout
