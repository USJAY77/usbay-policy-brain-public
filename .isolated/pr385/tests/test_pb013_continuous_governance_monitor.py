from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "pb013_continuous_governance_monitor.py"


PB005_FILES = {
    "pb005_endpoint_evidence.json",
    "pb005_schema_evidence.json",
    "pb005_write_receipt.json",
    "pb005_read_receipt.json",
    "pb005_persistence_evidence.json",
    "pb005_evidence_manifest.json",
    "pb005_final_execution_report.json",
    "pb006_signed_evidence_manifest.json",
    "pb006_integrity_report.json",
    "pb007_verification_report.json",
    "pb008_timestamp_receipt.json",
    "pb008_non_repudiation_report.json",
}
PB009_ROOT = {
    "pb009_archive_manifest.json",
    "pb009_retention_report.json",
    "pb009_restore_verification_report.json",
    "pb009_archive_integrity_report.json",
}
PB010_FILES = {
    "pb010_chain_certificate.json",
    "pb010_chain_verification_report.json",
    "pb010_governance_scorecard.json",
}
PB011_FILES = {
    "pb011_baseline_manifest.json",
    "pb011_drift_report.json",
    "pb011_drift_scorecard.json",
}
PB012_FILES = {
    "governance_control_registry.json",
    "governance_control_manifest.json",
    "governance_self_attestation.json",
}


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


def _verified_report(schema: str) -> dict:
    return {"schema": schema, "decision": "VERIFIED", "fail_closed": False, "errors": []}


def _write_fixture(root: Path) -> tuple[Path, Path, Path, Path, Path, Path]:
    pb005 = root / "pb005"
    pb009 = root / "pb009_archive"
    pb010 = root / "pb010_chain"
    pb011 = root / "pb011_baseline"
    pb012 = root / "pb012_control_registry"
    output = root / "pb013_monitor"

    for filename in PB005_FILES:
        _write_json(pb005 / filename, {"schema": filename, "decision": "VERIFIED", "fail_closed": False, "errors": []})
    _write_json(
        pb005 / "pb006_integrity_report.json",
        {"control_id": "PB-006", "decision": "VERIFIED", "fail_closed": False, "errors": []},
    )
    _write_json(
        pb005 / "pb007_verification_report.json",
        {"control_id": "PB-007", "decision": "VERIFIED", "fail_closed": False, "errors": []},
    )
    _write_json(
        pb005 / "pb008_non_repudiation_report.json",
        _verified_report("usbay.pb008.non_repudiation_report.v1"),
    )

    for filename in PB009_ROOT:
        _write_json(pb009 / filename, _verified_report(filename))
    _write_json(
        pb009 / "pb009_archive_integrity_report.json",
        _verified_report("usbay.pb009.archive_integrity_report.v1"),
    )
    for filename in PB005_FILES:
        _write_json(pb009 / "artifacts" / filename, {"schema": filename})

    for filename in PB010_FILES:
        _write_json(pb010 / filename, _verified_report(filename))
    _write_json(
        pb010 / "pb010_chain_verification_report.json",
        _verified_report("usbay.pb010.chain_verification_report.v1"),
    )

    for filename in PB011_FILES:
        _write_json(pb011 / filename, _verified_report(filename))
    _write_json(
        pb011 / "pb011_drift_report.json",
        _verified_report("usbay.pb011.drift_report.v1"),
    )

    for filename in PB012_FILES:
        _write_json(pb012 / filename, _verified_report(filename))
    _write_json(
        pb012 / "governance_self_attestation.json",
        _verified_report("usbay.pb012.governance_self_attestation.v1"),
    )
    return pb005, pb009, pb010, pb011, pb012, output


def _run_monitor(paths: tuple[Path, Path, Path, Path, Path, Path]) -> subprocess.CompletedProcess[str]:
    return _run(*(str(path) for path in paths))


def test_monitor_generates_health_risk_monitor_and_summary_reports(tmp_path: Path) -> None:
    paths = _write_fixture(tmp_path)

    completed = _run_monitor(paths)

    assert completed.returncode == 0, completed.stdout + completed.stderr
    output = paths[-1]
    health = json.loads((output / "pb013_governance_health_report.json").read_text(encoding="utf-8"))
    risk = json.loads((output / "pb013_governance_risk_score.json").read_text(encoding="utf-8"))
    monitor = json.loads((output / "pb013_governance_monitor_report.json").read_text(encoding="utf-8"))
    summary = json.loads((output / "pb013_governance_status_summary.json").read_text(encoding="utf-8"))
    assert health["decision"] == "VERIFIED"
    assert health["health_score"] == 100
    assert risk["risk_score"] == 0
    assert monitor["decision"] == "VERIFIED"
    assert summary["status"] == "HEALTHY"


def test_missing_control_fails_closed(tmp_path: Path) -> None:
    paths = _write_fixture(tmp_path)
    (paths[0] / "pb005_read_receipt.json").unlink()

    completed = _run_monitor(paths)

    assert completed.returncode == 1
    assert "PB013_REQUIRED_CONTROL_MISSING:pb005/pb005_read_receipt.json" in completed.stdout
    health = json.loads((paths[-1] / "pb013_governance_health_report.json").read_text(encoding="utf-8"))
    assert health["decision"] == "BLOCKED"


def test_drift_failure_fails_closed(tmp_path: Path) -> None:
    paths = _write_fixture(tmp_path)
    _write_json(
        paths[3] / "pb011_drift_report.json",
        {"schema": "usbay.pb011.drift_report.v1", "decision": "BLOCKED", "fail_closed": True, "errors": ["drift"]},
    )

    completed = _run_monitor(paths)

    assert completed.returncode == 1
    assert "PB013_DRIFT_REPORT_FAILED" in completed.stdout
    report = json.loads((paths[-1] / "pb013_governance_monitor_report.json").read_text(encoding="utf-8"))
    assert report["drift_report_failed"] is True


def test_certification_failure_fails_closed(tmp_path: Path) -> None:
    paths = _write_fixture(tmp_path)
    _write_json(
        paths[2] / "pb010_chain_verification_report.json",
        {"schema": "usbay.pb010.chain_verification_report.v1", "decision": "BLOCKED", "fail_closed": True, "errors": ["cert"]},
    )

    completed = _run_monitor(paths)

    assert completed.returncode == 1
    assert "PB013_CERTIFICATION_REPORT_FAILED" in completed.stdout
    report = json.loads((paths[-1] / "pb013_governance_monitor_report.json").read_text(encoding="utf-8"))
    assert report["certification_report_failed"] is True


def test_control_registry_mismatch_fails_closed(tmp_path: Path) -> None:
    paths = _write_fixture(tmp_path)
    _write_json(
        paths[4] / "governance_self_attestation.json",
        {
            "schema": "usbay.pb012.governance_self_attestation.v1",
            "decision": "VERIFIED",
            "fail_closed": False,
            "errors": [],
            "registry_hash_mismatch_detected": True,
        },
    )

    completed = _run_monitor(paths)

    assert completed.returncode == 1
    assert "PB013_CONTROL_REGISTRY_MISMATCH" in completed.stdout
    report = json.loads((paths[-1] / "pb013_governance_monitor_report.json").read_text(encoding="utf-8"))
    assert report["control_registry_mismatch"] is True


def test_unsupported_governance_artifact_fails_closed(tmp_path: Path) -> None:
    paths = _write_fixture(tmp_path)
    _write_json(paths[2] / "unsupported.json", {"unsupported": True})

    completed = _run_monitor(paths)

    assert completed.returncode == 1
    assert "PB013_UNSUPPORTED_GOVERNANCE_ARTIFACT:pb010_chain/unsupported.json" in completed.stdout
    report = json.loads((paths[-1] / "pb013_governance_monitor_report.json").read_text(encoding="utf-8"))
    assert report["unsupported_governance_artifact_detected"] is True
