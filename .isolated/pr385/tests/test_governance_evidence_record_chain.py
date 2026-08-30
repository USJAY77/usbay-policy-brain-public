from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

from governance.evidence_record_chain import (
    EVIDENCE_RECORD_CHAIN_ERROR_CODES,
    create_evidence_record,
    evidence_record_summary,
    explain_evidence_record_failure,
    load_evidence_record_chain_error_registry,
    renew_evidence_record,
    verify_evidence_record,
)
from tests.test_governance_sealed_audit_archive import _archive


ROOT = Path(__file__).resolve().parents[1]


def _record() -> tuple[dict, dict]:
    archive, _artifacts = _archive()
    record = create_evidence_record(
        archive,
        renewal_timestamp_utc="2026-05-12T00:10:00Z",
        renewal_reason="initial_archive_timestamp",
    )
    return record, archive


def _renewed_record() -> tuple[dict, dict]:
    record, archive = _record()
    renewed = renew_evidence_record(
        record,
        archive,
        renewal_timestamp_utc="2026-05-12T00:11:00Z",
        renewal_reason="scheduled_hash_renewal",
    )
    return renewed, archive


def test_valid_evidence_record_verification() -> None:
    record, archive = _record()

    result = verify_evidence_record(record, sealed_archive=archive)

    assert result.valid is True
    assert result.errors == ()
    assert result.renewal_round == 0
    assert evidence_record_summary(record)["evidence_record_id"] == result.evidence_record_id


def test_valid_renewal_verification() -> None:
    record, archive = _renewed_record()

    result = verify_evidence_record(record, sealed_archive=archive)

    assert result.valid is True
    assert result.errors == ()
    assert result.renewal_round == 1
    assert result.append_only_position == 1


def test_broken_chronology_rejection() -> None:
    record, archive = _renewed_record()
    record["evidence_records"][1]["previous_evidence_record_hash"] = "f" * 64

    result = verify_evidence_record(record, sealed_archive=archive)

    assert result.valid is False
    assert "EVIDENCE_RECORD_CHAIN_MISMATCH" in result.errors


def test_replay_rejection() -> None:
    record, archive = _record()

    result = verify_evidence_record(record, sealed_archive=archive, existing_evidence_records=[record])

    assert result.valid is False
    assert "EVIDENCE_RECORD_REPLAY_DETECTED" in result.errors


def test_append_only_violation_rejection() -> None:
    record, archive = _renewed_record()
    record["renewal_manifest"][1]["prior_chain_hash"] = "0" * 64

    result = verify_evidence_record(record, sealed_archive=archive)

    assert result.valid is False
    assert "EVIDENCE_RECORD_APPEND_ONLY_VIOLATION" in result.errors


def test_invalid_renewal_round_rejection() -> None:
    record, archive = _renewed_record()
    record["evidence_records"][1]["renewal_round"] = 7

    result = verify_evidence_record(record, sealed_archive=archive)

    assert result.valid is False
    assert "EVIDENCE_RECORD_RENEWAL_INVALID" in result.errors


def test_invalid_hash_algorithm_rejection() -> None:
    record, archive = _record()
    record["evidence_records"][0]["hash_algorithm"] = "SHA1"

    result = verify_evidence_record(record, sealed_archive=archive)

    assert result.valid is False
    assert "EVIDENCE_RECORD_HASH_ALGORITHM_INVALID" in result.errors


def test_reordered_renewal_rejection() -> None:
    record, archive = _renewed_record()
    record["evidence_records"] = [record["evidence_records"][1], record["evidence_records"][0]]

    result = verify_evidence_record(record, sealed_archive=archive)

    assert result.valid is False
    assert "EVIDENCE_RECORD_RENEWAL_INVALID" in result.errors


def test_unsafe_diagnostics_rejection() -> None:
    record, archive = _record()
    record["diagnostics"] = {"approval_contents": "do-not-export"}

    result = verify_evidence_record(record, sealed_archive=archive)

    assert result.valid is False
    assert "EVIDENCE_RECORD_DIAGNOSTICS_UNSAFE" in result.errors


def test_evidence_record_error_registry_complete() -> None:
    registry = load_evidence_record_chain_error_registry(ROOT)

    assert set(EVIDENCE_RECORD_CHAIN_ERROR_CODES).issubset(registry)
    assert explain_evidence_record_failure(ROOT, "EVIDENCE_RECORD_CHAIN_MISMATCH")["fail_closed_reason"]


def test_create_renew_and_verify_cli_redacts_output(tmp_path: Path) -> None:
    archive, _artifacts = _archive()
    archive_path = tmp_path / "sealed-audit-archive.json"
    record_path = tmp_path / "evidence-record.json"
    renewed_path = tmp_path / "evidence-record-renewed.json"
    archive_path.write_text(json.dumps(archive, sort_keys=True), encoding="utf-8")

    created = subprocess.run(
        [
            sys.executable,
            "scripts/governance_diagnostics.py",
            "create-evidence-record",
            "--sealed-audit-archive",
            str(archive_path),
            "--validation-timestamp",
            "2026-05-12T00:10:00Z",
            "--renewal-reason",
            "initial_archive_timestamp",
            "--output",
            str(record_path),
        ],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
    )

    assert created.returncode == 0
    assert record_path.is_file()
    assert "approval_contents" not in created.stdout
    assert "PRIVATE KEY" not in created.stdout

    renewed = subprocess.run(
        [
            sys.executable,
            "scripts/governance_diagnostics.py",
            "renew-evidence-record",
            "--evidence-record",
            str(record_path),
            "--sealed-audit-archive",
            str(archive_path),
            "--validation-timestamp",
            "2026-05-12T00:11:00Z",
            "--renewal-reason",
            "scheduled_hash_renewal",
            "--output",
            str(renewed_path),
        ],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
    )

    assert renewed.returncode == 0
    assert renewed_path.is_file()
    assert "approval_contents" not in renewed.stdout
    assert "PRIVATE KEY" not in renewed_path.read_text(encoding="utf-8")

    verified = subprocess.run(
        [
            sys.executable,
            "scripts/governance_diagnostics.py",
            "verify-evidence-record",
            "--evidence-record",
            str(renewed_path),
            "--sealed-audit-archive",
            str(archive_path),
        ],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
    )

    assert verified.returncode == 0
    assert '"valid":true' in verified.stdout
