from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "pb006_evidence_integrity.py"


def _write_pb005_artifacts(root: Path) -> None:
    artifacts = {
        "pb005_endpoint_evidence.json": {"classification": "VERIFIED", "schema": "endpoint"},
        "pb005_schema_evidence.json": {"classification": "VERIFIED", "schema": "schema"},
        "pb005_write_receipt.json": {"classification": "VERIFIED", "schema": "write"},
        "pb005_read_receipt.json": {"classification": "VERIFIED", "schema": "read"},
        "pb005_persistence_evidence.json": {"classification": "VERIFIED", "schema": "persistence"},
        "pb005_evidence_manifest.json": {"classification": "VERIFIED", "schema": "manifest"},
    }
    for filename, payload in artifacts.items():
        (root / filename).write_text(json.dumps(payload, sort_keys=True) + "\n", encoding="utf-8")


def _run(*args: str, cwd: Path = ROOT) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(SCRIPT), *args],
        cwd=cwd,
        text=True,
        capture_output=True,
    )


def test_generate_manifest_hashes_every_pb005_artifact_and_reports_verified(tmp_path: Path) -> None:
    _write_pb005_artifacts(tmp_path)

    completed = _run("generate", str(tmp_path))

    assert completed.returncode == 0, completed.stdout + completed.stderr
    assert "Decision: VERIFIED" in completed.stdout
    manifest = json.loads((tmp_path / "pb006_signed_evidence_manifest.json").read_text(encoding="utf-8"))
    report = json.loads((tmp_path / "pb006_integrity_report.json").read_text(encoding="utf-8"))
    assert manifest["pb005_compatible"] is True
    assert set(manifest["artifact_hashes"]) == {
        "pb005_endpoint_evidence.json",
        "pb005_schema_evidence.json",
        "pb005_write_receipt.json",
        "pb005_read_receipt.json",
        "pb005_persistence_evidence.json",
        "pb005_evidence_manifest.json",
    }
    assert manifest["signature"]["signature_hash"]
    assert report["decision"] == "VERIFIED"
    assert report["fail_closed"] is False


def test_artifact_modification_is_detected_and_fails_closed(tmp_path: Path) -> None:
    _write_pb005_artifacts(tmp_path)
    assert _run("generate", str(tmp_path)).returncode == 0

    (tmp_path / "pb005_write_receipt.json").write_text(
        json.dumps({"classification": "VERIFIED", "tampered": True}) + "\n",
        encoding="utf-8",
    )
    completed = _run("verify", str(tmp_path))

    assert completed.returncode == 1
    assert "Decision: BLOCKED" in completed.stdout
    assert "PB006_ARTIFACT_HASH_MISMATCH:pb005_write_receipt.json" in completed.stdout
    report = json.loads((tmp_path / "pb006_integrity_report.json").read_text(encoding="utf-8"))
    assert report["decision"] == "BLOCKED"
    assert report["fail_closed"] is True
    assert report["artifact_modification_detected"] is True


def test_missing_manifest_fails_closed(tmp_path: Path) -> None:
    _write_pb005_artifacts(tmp_path)

    completed = _run("verify", str(tmp_path))

    assert completed.returncode == 1
    assert "PB006_SIGNED_MANIFEST_MISSING" in completed.stdout
    report = json.loads((tmp_path / "pb006_integrity_report.json").read_text(encoding="utf-8"))
    assert report["decision"] == "BLOCKED"
    assert report["fail_closed"] is True


def test_unmanifested_artifact_fails_closed(tmp_path: Path) -> None:
    _write_pb005_artifacts(tmp_path)
    assert _run("generate", str(tmp_path)).returncode == 0

    (tmp_path / "extra.json").write_text('{"unexpected": true}\n', encoding="utf-8")
    completed = _run("verify", str(tmp_path))

    assert completed.returncode == 1
    assert "PB006_UNMANIFESTED_ARTIFACT:extra.json" in completed.stdout
