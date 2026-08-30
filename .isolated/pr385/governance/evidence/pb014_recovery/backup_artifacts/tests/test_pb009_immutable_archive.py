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


def _write_json(path: Path, payload: dict) -> None:
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _run(script: Path, *args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(script), *args],
        cwd=ROOT,
        text=True,
        capture_output=True,
    )


def _write_pb005_to_pb008_bundle(root: Path) -> None:
    pb005_artifacts = {
        "pb005_endpoint_evidence.json": {"classification": "VERIFIED", "schema": "endpoint"},
        "pb005_schema_evidence.json": {"classification": "VERIFIED", "schema": "schema"},
        "pb005_write_receipt.json": {"classification": "VERIFIED", "schema": "write"},
        "pb005_read_receipt.json": {"classification": "VERIFIED", "schema": "read"},
        "pb005_persistence_evidence.json": {"classification": "VERIFIED", "schema": "persistence"},
    }
    for filename, payload in pb005_artifacts.items():
        _write_json(root / filename, payload)

    hashes = {
        filename: hashlib.sha256((root / filename).read_bytes()).hexdigest()
        for filename in pb005_artifacts
    }
    aggregate_hash = hashlib.sha256(
        json.dumps(hashes, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    _write_json(
        root / "pb005_evidence_manifest.json",
        {
            "aggregate_hash": aggregate_hash,
            "artifact_hashes": hashes,
            "classification": "VERIFIED",
            "schema": "usbay.pb005.evidence_manifest.v1",
        },
    )
    _write_json(
        root / "pb005_final_execution_report.json",
        {"final_classification": "VERIFIED", "schema": "final"},
    )

    assert _run(PB006, "generate", str(root)).returncode == 0
    assert _run(PB007, str(root)).returncode == 0
    assert _run(PB008, "generate", str(root)).returncode == 0


def test_archive_manifest_retention_and_restore_reports_are_generated(tmp_path: Path) -> None:
    source = tmp_path / "source"
    archive = tmp_path / "archive"
    source.mkdir()
    _write_pb005_to_pb008_bundle(source)

    completed = _run(PB009, "archive", str(source), str(archive), "--retention-days", "30")

    assert completed.returncode == 0, completed.stdout + completed.stderr
    assert "Decision: VERIFIED" in completed.stdout
    manifest = json.loads((archive / "pb009_archive_manifest.json").read_text(encoding="utf-8"))
    retention = json.loads((archive / "pb009_retention_report.json").read_text(encoding="utf-8"))
    restore = json.loads((archive / "pb009_restore_verification_report.json").read_text(encoding="utf-8"))
    integrity = json.loads((archive / "pb009_archive_integrity_report.json").read_text(encoding="utf-8"))
    assert manifest["artifact_count"] == 12
    assert retention["decision"] == "VERIFIED"
    assert restore["restore_verification_succeeded"] is True
    assert integrity["archive_integrity_verified"] is True

    verification = _run(PB009, "verify", str(archive))

    assert verification.returncode == 0, verification.stdout + verification.stderr
    assert "PB009_ARCHIVE_VERIFICATION_VERIFIED" in verification.stdout


def test_missing_archive_artifact_fails_closed(tmp_path: Path) -> None:
    source = tmp_path / "source"
    archive = tmp_path / "archive"
    source.mkdir()
    _write_pb005_to_pb008_bundle(source)
    assert _run(PB009, "archive", str(source), str(archive)).returncode == 0
    (archive / "artifacts" / "pb008_timestamp_receipt.json").unlink()

    completed = _run(PB009, "verify", str(archive))

    assert completed.returncode == 1
    assert "PB009_ARCHIVED_ARTIFACT_MISSING:pb008_timestamp_receipt.json" in completed.stdout
    restore = json.loads((archive / "pb009_restore_verification_report.json").read_text(encoding="utf-8"))
    assert restore["decision"] == "BLOCKED"
    assert restore["restore_verification_succeeded"] is False


def test_manifest_mismatch_fails_closed(tmp_path: Path) -> None:
    source = tmp_path / "source"
    archive = tmp_path / "archive"
    source.mkdir()
    _write_pb005_to_pb008_bundle(source)
    assert _run(PB009, "archive", str(source), str(archive)).returncode == 0
    manifest_path = archive / "pb009_archive_manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["artifact_count"] = 0
    _write_json(manifest_path, manifest)

    completed = _run(PB009, "verify", str(archive))

    assert completed.returncode == 1
    assert "PB009_ARCHIVE_MANIFEST_SIGNATURE_MISMATCH" in completed.stdout
    integrity = json.loads((archive / "pb009_archive_integrity_report.json").read_text(encoding="utf-8"))
    assert integrity["manifest_mismatch_detected"] is True


def test_retention_violation_fails_closed(tmp_path: Path) -> None:
    source = tmp_path / "source"
    archive = tmp_path / "archive"
    source.mkdir()
    _write_pb005_to_pb008_bundle(source)

    completed = _run(PB009, "archive", str(source), str(archive), "--retention-days", "0")

    assert completed.returncode == 1
    assert "PB009_RETENTION_DAYS_INVALID" in completed.stdout
    retention = json.loads((archive / "pb009_retention_report.json").read_text(encoding="utf-8"))
    assert retention["decision"] == "BLOCKED"
    assert retention["fail_closed"] is True
