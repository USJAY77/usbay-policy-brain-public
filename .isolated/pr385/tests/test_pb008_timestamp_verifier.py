from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
PB006 = ROOT / "scripts" / "pb006_evidence_integrity.py"
PB008 = ROOT / "scripts" / "pb008_timestamp_verifier.py"


def _write_json(path: Path, payload: dict) -> None:
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _run(script: Path, *args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(script), *args],
        cwd=ROOT,
        text=True,
        capture_output=True,
    )


def _write_pb005_bundle(root: Path) -> None:
    artifacts = {
        "pb005_endpoint_evidence.json": {"classification": "VERIFIED", "schema": "endpoint"},
        "pb005_schema_evidence.json": {"classification": "VERIFIED", "schema": "schema"},
        "pb005_write_receipt.json": {"classification": "VERIFIED", "schema": "write"},
        "pb005_read_receipt.json": {"classification": "VERIFIED", "schema": "read"},
        "pb005_persistence_evidence.json": {"classification": "VERIFIED", "schema": "persistence"},
    }
    for filename, payload in artifacts.items():
        _write_json(root / filename, payload)

    hashes = {
        filename: hashlib.sha256((root / filename).read_bytes()).hexdigest()
        for filename in artifacts
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


def test_timestamp_receipt_generated_and_verified(tmp_path: Path) -> None:
    _write_pb005_bundle(tmp_path)

    completed = _run(PB008, "generate", str(tmp_path))

    assert completed.returncode == 0, completed.stdout + completed.stderr
    assert "Decision: VERIFIED" in completed.stdout
    receipt = json.loads((tmp_path / "pb008_timestamp_receipt.json").read_text(encoding="utf-8"))
    report = json.loads((tmp_path / "pb008_non_repudiation_report.json").read_text(encoding="utf-8"))
    assert receipt["receipt_type"] == "RFC3161_COMPATIBLE_TIMESTAMP_RECEIPT"
    assert receipt["timestamped_artifact"] == "pb006_signed_evidence_manifest.json"
    assert report["decision"] == "VERIFIED"
    assert report["timestamp_valid"] is True

    verification = _run(PB008, "verify", str(tmp_path))

    assert verification.returncode == 0, verification.stdout + verification.stderr
    assert "PB008_TIMESTAMP_VERIFICATION_VERIFIED" in verification.stdout


def test_tampered_manifest_fails_timestamp_verification(tmp_path: Path) -> None:
    _write_pb005_bundle(tmp_path)
    assert _run(PB008, "generate", str(tmp_path)).returncode == 0
    manifest = json.loads((tmp_path / "pb006_signed_evidence_manifest.json").read_text(encoding="utf-8"))
    manifest["artifact_count"] = 999
    _write_json(tmp_path / "pb006_signed_evidence_manifest.json", manifest)

    completed = _run(PB008, "verify", str(tmp_path))

    assert completed.returncode == 1
    assert "Decision: BLOCKED" in completed.stdout
    assert "PB008_MANIFEST_HASH_MISMATCH" in completed.stdout
    report = json.loads((tmp_path / "pb008_non_repudiation_report.json").read_text(encoding="utf-8"))
    assert report["decision"] == "BLOCKED"
    assert report["fail_closed"] is True


def test_missing_timestamp_fails_closed(tmp_path: Path) -> None:
    _write_pb005_bundle(tmp_path)

    completed = _run(PB008, "verify", str(tmp_path))

    assert completed.returncode == 1
    assert "PB008_TIMESTAMP_MISSING" in completed.stdout
    report = json.loads((tmp_path / "pb008_non_repudiation_report.json").read_text(encoding="utf-8"))
    assert report["decision"] == "BLOCKED"
    assert report["timestamp_receipt_present"] is False


def test_invalid_tsa_response_fails_closed(tmp_path: Path) -> None:
    _write_pb005_bundle(tmp_path)
    assert _run(PB008, "generate", str(tmp_path)).returncode == 0
    receipt = json.loads((tmp_path / "pb008_timestamp_receipt.json").read_text(encoding="utf-8"))
    receipt["tsa_response"]["signature_hash"] = "0" * 64
    _write_json(tmp_path / "pb008_timestamp_receipt.json", receipt)

    completed = _run(PB008, "verify", str(tmp_path))

    assert completed.returncode == 1
    assert "PB008_TSA_VERIFICATION_FAILED" in completed.stdout
    report = json.loads((tmp_path / "pb008_non_repudiation_report.json").read_text(encoding="utf-8"))
    assert report["tsa_response_verified"] is False


def test_unsupported_timestamp_artifact_fails_closed(tmp_path: Path) -> None:
    _write_pb005_bundle(tmp_path)
    assert _run(PB008, "generate", str(tmp_path)).returncode == 0
    receipt = json.loads((tmp_path / "pb008_timestamp_receipt.json").read_text(encoding="utf-8"))
    receipt["timestamped_artifact"] = "unsupported.json"
    _write_json(tmp_path / "pb008_timestamp_receipt.json", receipt)

    completed = _run(PB008, "verify", str(tmp_path))

    assert completed.returncode == 1
    assert "PB008_UNSUPPORTED_ARTIFACT:unsupported.json" in completed.stdout
