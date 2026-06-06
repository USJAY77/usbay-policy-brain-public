from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
PB006 = ROOT / "scripts" / "pb006_evidence_integrity.py"
PB007 = ROOT / "scripts" / "pb007_independent_verifier.py"


def _write_json(path: Path, payload: dict) -> None:
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _write_pb005_bundle(root: Path) -> None:
    for filename, payload in {
        "pb005_endpoint_evidence.json": {"classification": "VERIFIED", "schema": "endpoint"},
        "pb005_schema_evidence.json": {"classification": "VERIFIED", "schema": "schema"},
        "pb005_write_receipt.json": {"classification": "VERIFIED", "schema": "write"},
        "pb005_read_receipt.json": {"classification": "VERIFIED", "schema": "read"},
        "pb005_persistence_evidence.json": {"classification": "VERIFIED", "schema": "persistence"},
    }.items():
        _write_json(root / filename, payload)
    assert _run(PB006, "generate", str(root)).returncode == 0
    # PB-006 does not require the final execution report, so add it and then
    # regenerate to bind it into the PB-006 manifest.
    _write_json(
        root / "pb005_final_execution_report.json",
        {"final_classification": "VERIFIED", "schema": "final"},
    )
    # PB-005 manifest must include the core PB-005 hashes, not PB-006 outputs.
    core_hashes = {}
    for artifact in (
        "pb005_endpoint_evidence.json",
        "pb005_schema_evidence.json",
        "pb005_write_receipt.json",
        "pb005_read_receipt.json",
        "pb005_persistence_evidence.json",
    ):
        import hashlib

        core_hashes[artifact] = hashlib.sha256((root / artifact).read_bytes()).hexdigest()
    aggregate = hashlib.sha256(
        json.dumps(core_hashes, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    _write_json(
        root / "pb005_evidence_manifest.json",
        {
            "aggregate_hash": aggregate,
            "artifact_hashes": core_hashes,
            "classification": "VERIFIED",
            "missing_required_artifacts": [],
            "non_verified_artifacts": [],
            "schema": "usbay.pb005.evidence_manifest.v1",
        },
    )
    assert _run(PB006, "generate", str(root)).returncode == 0


def _run(script: Path, *args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(script), *args],
        cwd=ROOT,
        text=True,
        capture_output=True,
    )


def test_independent_verifier_succeeds_on_valid_pb005_pb006_bundle(tmp_path: Path) -> None:
    _write_pb005_bundle(tmp_path)

    completed = _run(PB007, str(tmp_path))

    assert completed.returncode == 0, completed.stdout + completed.stderr
    assert "Decision: VERIFIED" in completed.stdout
    report = json.loads((tmp_path / "pb007_verification_report.json").read_text(encoding="utf-8"))
    assert report["decision"] == "VERIFIED"
    assert report["aws_access_performed"] is False
    assert report["postgresql_access_performed"] is False


def test_independent_verifier_blocks_tampered_bundle(tmp_path: Path) -> None:
    _write_pb005_bundle(tmp_path)
    _write_json(tmp_path / "pb005_read_receipt.json", {"classification": "VERIFIED", "tampered": True})

    completed = _run(PB007, str(tmp_path))

    assert completed.returncode == 1
    assert "Decision: BLOCKED" in completed.stdout
    assert "PB007_PB005_HASH_MISMATCH:pb005_read_receipt.json" in completed.stdout
    report = json.loads((tmp_path / "pb007_verification_report.json").read_text(encoding="utf-8"))
    assert report["decision"] == "BLOCKED"
    assert report["artifact_modification_detected"] is True


def test_independent_verifier_blocks_missing_artifact(tmp_path: Path) -> None:
    _write_pb005_bundle(tmp_path)
    (tmp_path / "pb005_write_receipt.json").unlink()

    completed = _run(PB007, str(tmp_path))

    assert completed.returncode == 1
    assert "PB007_ARTIFACT_MISSING:pb005_write_receipt.json" in completed.stdout
    report = json.loads((tmp_path / "pb007_verification_report.json").read_text(encoding="utf-8"))
    assert report["missing_artifact_detected"] is True


def test_independent_verifier_blocks_unsupported_artifact(tmp_path: Path) -> None:
    _write_pb005_bundle(tmp_path)
    _write_json(tmp_path / "unsupported.json", {"unsupported": True})

    completed = _run(PB007, str(tmp_path))

    assert completed.returncode == 1
    assert "PB007_UNSUPPORTED_ARTIFACT:unsupported.json" in completed.stdout
    report = json.loads((tmp_path / "pb007_verification_report.json").read_text(encoding="utf-8"))
    assert report["unsupported_artifact_detected"] is True
