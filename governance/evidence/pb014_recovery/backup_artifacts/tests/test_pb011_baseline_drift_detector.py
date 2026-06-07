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
PB011 = ROOT / "scripts" / "pb011_baseline_drift_detector.py"


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


def _write_certified_chain(root: Path) -> tuple[Path, Path, Path, Path]:
    pb005 = root / "pb005"
    archive = root / "pb009_archive"
    pb010 = root / "pb010_chain"
    pb011 = root / "pb011_baseline"
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
    _write_json(pb005 / "pb005_final_execution_report.json", {"final_classification": "VERIFIED"})
    assert _run(PB006, "generate", str(pb005)).returncode == 0
    assert _run(PB007, str(pb005)).returncode == 0
    assert _run(PB008, "generate", str(pb005)).returncode == 0
    assert _run(PB009, "archive", str(pb005), str(archive)).returncode == 0
    assert _run(PB010, str(pb005), str(archive), str(pb010)).returncode == 0
    return pb005, archive, pb010, pb011


def test_baseline_snapshot_and_drift_report_verify_clean_chain(tmp_path: Path) -> None:
    pb005, archive, pb010, pb011 = _write_certified_chain(tmp_path)

    baseline = _run(PB011, "baseline", str(pb005), str(archive), str(pb010), str(pb011))
    verify = _run(PB011, "verify", str(pb005), str(archive), str(pb010), str(pb011))

    assert baseline.returncode == 0, baseline.stdout + baseline.stderr
    assert verify.returncode == 0, verify.stdout + verify.stderr
    manifest = json.loads((pb011 / "pb011_baseline_manifest.json").read_text(encoding="utf-8"))
    report = json.loads((pb011 / "pb011_drift_report.json").read_text(encoding="utf-8"))
    scorecard = json.loads((pb011 / "pb011_drift_scorecard.json").read_text(encoding="utf-8"))
    assert manifest["decision"] == "VERIFIED"
    assert report["decision"] == "VERIFIED"
    assert report["artifact_hash_changed"] is False
    assert scorecard["decision"] == "VERIFIED"


def test_modified_artifact_detected_and_fails_closed(tmp_path: Path) -> None:
    pb005, archive, pb010, pb011 = _write_certified_chain(tmp_path)
    assert _run(PB011, "baseline", str(pb005), str(archive), str(pb010), str(pb011)).returncode == 0
    _write_json(pb005 / "pb005_read_receipt.json", {"classification": "VERIFIED", "tampered": True})

    completed = _run(PB011, "verify", str(pb005), str(archive), str(pb010), str(pb011))

    assert completed.returncode == 1
    assert "PB011_ARTIFACT_HASH_CHANGED:pb005/pb005_read_receipt.json" in completed.stdout
    report = json.loads((pb011 / "pb011_drift_report.json").read_text(encoding="utf-8"))
    assert report["decision"] == "BLOCKED"
    assert report["artifact_hash_changed"] is True


def test_missing_artifact_detected_and_fails_closed(tmp_path: Path) -> None:
    pb005, archive, pb010, pb011 = _write_certified_chain(tmp_path)
    assert _run(PB011, "baseline", str(pb005), str(archive), str(pb010), str(pb011)).returncode == 0
    (archive / "artifacts" / "pb008_timestamp_receipt.json").unlink()

    completed = _run(PB011, "verify", str(pb005), str(archive), str(pb010), str(pb011))

    assert completed.returncode == 1
    assert "PB011_CERTIFIED_ARTIFACT_MISSING:pb009_archive/artifacts/pb008_timestamp_receipt.json" in completed.stdout
    report = json.loads((pb011 / "pb011_drift_report.json").read_text(encoding="utf-8"))
    assert report["certified_artifact_missing"] is True


def test_unsupported_artifact_detected_and_fails_closed(tmp_path: Path) -> None:
    pb005, archive, pb010, pb011 = _write_certified_chain(tmp_path)
    assert _run(PB011, "baseline", str(pb005), str(archive), str(pb010), str(pb011)).returncode == 0
    _write_json(pb010 / "unsupported.json", {"unsupported": True})

    completed = _run(PB011, "verify", str(pb005), str(archive), str(pb010), str(pb011))

    assert completed.returncode == 1
    assert "PB011_UNSUPPORTED_ARTIFACT:pb010_chain/unsupported.json" in completed.stdout
    report = json.loads((pb011 / "pb011_drift_report.json").read_text(encoding="utf-8"))
    assert report["unsupported_artifact_detected"] is True


def test_certification_report_change_detected_and_fails_closed(tmp_path: Path) -> None:
    pb005, archive, pb010, pb011 = _write_certified_chain(tmp_path)
    assert _run(PB011, "baseline", str(pb005), str(archive), str(pb010), str(pb011)).returncode == 0
    report_path = pb010 / "pb010_chain_verification_report.json"
    report = json.loads(report_path.read_text(encoding="utf-8"))
    report["generated_at"] = "tampered"
    _write_json(report_path, report)

    completed = _run(PB011, "verify", str(pb005), str(archive), str(pb010), str(pb011))

    assert completed.returncode == 1
    assert "PB011_ARTIFACT_HASH_CHANGED:pb010_chain/pb010_chain_verification_report.json" in completed.stdout
    drift = json.loads((pb011 / "pb011_drift_report.json").read_text(encoding="utf-8"))
    assert drift["certification_report_changed"] is True


def test_governance_score_degradation_detected_and_fails_closed(tmp_path: Path) -> None:
    pb005, archive, pb010, pb011 = _write_certified_chain(tmp_path)
    assert _run(PB011, "baseline", str(pb005), str(archive), str(pb010), str(pb011)).returncode == 0
    scorecard_path = pb010 / "pb010_governance_scorecard.json"
    scorecard = json.loads(scorecard_path.read_text(encoding="utf-8"))
    scorecard["score"] = scorecard["score"] - 1
    _write_json(scorecard_path, scorecard)

    completed = _run(PB011, "verify", str(pb005), str(archive), str(pb010), str(pb011))

    assert completed.returncode == 1
    assert "PB011_GOVERNANCE_SCORE_DECREASED" in completed.stdout
    drift = json.loads((pb011 / "pb011_drift_report.json").read_text(encoding="utf-8"))
    score = json.loads((pb011 / "pb011_drift_scorecard.json").read_text(encoding="utf-8"))
    assert drift["governance_score_decreased"] is True
    assert score["governance_score_decreased"] is True


def test_baseline_manifest_mismatch_detected_and_fails_closed(tmp_path: Path) -> None:
    pb005, archive, pb010, pb011 = _write_certified_chain(tmp_path)
    assert _run(PB011, "baseline", str(pb005), str(archive), str(pb010), str(pb011)).returncode == 0
    manifest_path = pb011 / "pb011_baseline_manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["artifact_count"] = 0
    _write_json(manifest_path, manifest)

    completed = _run(PB011, "verify", str(pb005), str(archive), str(pb010), str(pb011))

    assert completed.returncode == 1
    assert "PB011_BASELINE_MANIFEST_MISMATCH" in completed.stdout
    drift = json.loads((pb011 / "pb011_drift_report.json").read_text(encoding="utf-8"))
    assert drift["baseline_manifest_mismatch"] is True
