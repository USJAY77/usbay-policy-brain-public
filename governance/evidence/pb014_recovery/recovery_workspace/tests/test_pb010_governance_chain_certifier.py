from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
PB006 = ROOT / "scripts" / "pb006_evidence_integrity.py"
PB007 = ROOT / "scripts" / "pb007_independent_verifier.py"
PB008 = ROOT / "scripts" / "pb008_timestamp_verifier.py"
PB009 = ROOT / "scripts" / "pb009_immutable_archive.py"
PB010 = ROOT / "scripts" / "pb010_governance_chain_certifier.py"


def _write_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _run(script: Path, *args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(script), *args],
        cwd=ROOT,
        text=True,
        capture_output=True,
    )


def _write_chain(root: Path) -> tuple[Path, Path, Path]:
    pb005 = root / "pb005"
    archive = root / "pb009_archive"
    output = root / "pb010_chain"
    pb005.mkdir()
    pb005_artifacts = {
        "pb005_endpoint_evidence.json": {"classification": "VERIFIED", "schema": "endpoint"},
        "pb005_schema_evidence.json": {"classification": "VERIFIED", "schema": "schema"},
        "pb005_write_receipt.json": {"classification": "VERIFIED", "schema": "write"},
        "pb005_read_receipt.json": {"classification": "VERIFIED", "schema": "read"},
        "pb005_persistence_evidence.json": {"classification": "VERIFIED", "schema": "persistence"},
    }
    for filename, payload in pb005_artifacts.items():
        _write_json(pb005 / filename, payload)
    hashes = {
        filename: hashlib.sha256((pb005 / filename).read_bytes()).hexdigest()
        for filename in pb005_artifacts
    }
    aggregate_hash = hashlib.sha256(
        json.dumps(hashes, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    _write_json(
        pb005 / "pb005_evidence_manifest.json",
        {
            "aggregate_hash": aggregate_hash,
            "artifact_hashes": hashes,
            "classification": "VERIFIED",
            "schema": "usbay.pb005.evidence_manifest.v1",
        },
    )
    _write_json(
        pb005 / "pb005_final_execution_report.json",
        {"final_classification": "VERIFIED", "schema": "final"},
    )
    assert _run(PB006, "generate", str(pb005)).returncode == 0
    assert _run(PB007, str(pb005)).returncode == 0
    assert _run(PB008, "generate", str(pb005)).returncode == 0
    assert _run(PB009, "archive", str(pb005), str(archive)).returncode == 0
    return pb005, archive, output


def test_governance_chain_certificate_generated_for_valid_chain(tmp_path: Path) -> None:
    pb005, archive, output = _write_chain(tmp_path)

    completed = _run(PB010, str(pb005), str(archive), str(output))

    assert completed.returncode == 0, completed.stdout + completed.stderr
    assert "Decision: VERIFIED" in completed.stdout
    certificate = json.loads((output / "pb010_chain_certificate.json").read_text(encoding="utf-8"))
    report = json.loads((output / "pb010_chain_verification_report.json").read_text(encoding="utf-8"))
    scorecard = json.loads((output / "pb010_governance_scorecard.json").read_text(encoding="utf-8"))
    assert certificate["decision"] == "VERIFIED"
    assert certificate["local_governance_validation_only"] is True
    assert certificate["no_external_certification_claim"] is True
    assert report["decision"] == "VERIFIED"
    assert scorecard["controls_verified"] == 5
    assert scorecard["controls_total"] == 5


def test_missing_pb_control_fails_closed(tmp_path: Path) -> None:
    pb005, archive, output = _write_chain(tmp_path)
    (pb005 / "pb008_non_repudiation_report.json").unlink()

    completed = _run(PB010, str(pb005), str(archive), str(output))

    assert completed.returncode == 1
    assert "Decision: BLOCKED" in completed.stdout
    assert "PB010_REQUIRED_ARTIFACT_MISSING:pb008_non_repudiation_report.json" in completed.stdout
    report = json.loads((output / "pb010_chain_verification_report.json").read_text(encoding="utf-8"))
    assert report["decision"] == "BLOCKED"
    assert report["missing_artifact_detected"] is True


def test_tampered_report_schema_fails_closed(tmp_path: Path) -> None:
    pb005, archive, output = _write_chain(tmp_path)
    report_path = pb005 / "pb007_verification_report.json"
    report = json.loads(report_path.read_text(encoding="utf-8"))
    report["schema"] = "tampered.schema"
    _write_json(report_path, report)

    completed = _run(PB010, str(pb005), str(archive), str(output))

    assert completed.returncode == 1
    assert "PB010_PB007_VERIFICATION_REPORT_SCHEMA_INVALID" in completed.stdout
    chain_report = json.loads((output / "pb010_chain_verification_report.json").read_text(encoding="utf-8"))
    assert chain_report["report_schema_invalid"] is True
    assert chain_report["fail_closed"] is True


def test_unsupported_artifact_fails_closed(tmp_path: Path) -> None:
    pb005, archive, output = _write_chain(tmp_path)
    _write_json(pb005 / "unsupported.json", {"unsupported": True})

    completed = _run(PB010, str(pb005), str(archive), str(output))

    assert completed.returncode == 1
    assert "PB010_UNSUPPORTED_ARTIFACT:unsupported.json" in completed.stdout
    report = json.loads((output / "pb010_chain_verification_report.json").read_text(encoding="utf-8"))
    assert report["unsupported_artifact_detected"] is True
