from __future__ import annotations

import copy
import json
import subprocess
import sys
from functools import cache
from pathlib import Path

from governance.evidence_renewal_runtime import (
    EVIDENCE_RENEWAL_RUNTIME_ERROR_CODES,
    explain_evidence_renewal_runtime_failure,
    load_evidence_renewal_runtime_error_registry,
    prepare_evidence_renewal_runtime_record,
    verify_evidence_renewal_runtime_record,
)
from tests.test_governance_regulator_export_profile import _profile

ROOT = Path(__file__).resolve().parents[1]


@cache
def _runtime_record_source() -> tuple[dict, dict, dict, dict, dict, dict, dict]:
    profile, archive, evidence_record, worm, tsa, policy_metadata = _profile()
    record = prepare_evidence_renewal_runtime_record(
        evidence_record_chain=evidence_record,
        sealed_archive=archive,
        worm_immutable_storage=worm,
        tsa_live_verification=tsa,
        regulator_export_profile=profile,
        policy_decision_metadata=policy_metadata,
        created_at_utc="2026-05-12T00:15:00Z",
    )
    return record, profile, archive, evidence_record, worm, tsa, policy_metadata


def _runtime_record() -> tuple[dict, dict, dict, dict, dict, dict, dict]:
    return copy.deepcopy(_runtime_record_source())


def test_valid_evidence_renewal_runtime_record() -> None:
    record, profile, archive, evidence_record, worm, tsa, policy_metadata = _runtime_record()

    result = verify_evidence_renewal_runtime_record(
        record,
        evidence_record_chain=evidence_record,
        sealed_archive=archive,
        worm_immutable_storage=worm,
        tsa_live_verification=tsa,
        regulator_export_profile=profile,
        policy_decision_metadata=policy_metadata,
    )

    assert result.valid is True
    assert result.errors == ()
    assert result.runtime_mode == "LOCAL_ONLY"
    assert result.worm_manifest_hash == worm["immutable_storage_manifest_hash"]
    assert result.tsa_timestamp_token_hash == tsa["timestamp_token_hash"]
    assert result.regulator_export_profile_hash == profile["export_profile_hash"]
    assert record["runtime_output_path"].startswith("evidence-renewal-runtime://local-only/sha256/")


def test_missing_evidence_chain_fails_closed() -> None:
    record, profile, archive, _evidence_record, worm, tsa, policy_metadata = _runtime_record()
    record["evidence_record_id"] = ""

    result = verify_evidence_renewal_runtime_record(record, sealed_archive=archive, worm_immutable_storage=worm, tsa_live_verification=tsa, regulator_export_profile=profile, policy_decision_metadata=policy_metadata)

    assert result.valid is False
    assert "EVIDENCE_RENEWAL_RUNTIME_EVIDENCE_CHAIN_MISSING" in result.errors


def test_missing_sealed_archive_fails_closed() -> None:
    record, profile, _archive, evidence_record, worm, tsa, policy_metadata = _runtime_record()
    record["sealed_archive_root_hash"] = ""

    result = verify_evidence_renewal_runtime_record(record, evidence_record_chain=evidence_record, worm_immutable_storage=worm, tsa_live_verification=tsa, regulator_export_profile=profile, policy_decision_metadata=policy_metadata)

    assert result.valid is False
    assert "EVIDENCE_RENEWAL_RUNTIME_SEALED_ARCHIVE_MISSING" in result.errors


def test_missing_worm_manifest_fails_closed() -> None:
    record, profile, archive, evidence_record, _worm, tsa, policy_metadata = _runtime_record()
    record["worm_manifest_hash"] = ""

    result = verify_evidence_renewal_runtime_record(record, evidence_record_chain=evidence_record, sealed_archive=archive, tsa_live_verification=tsa, regulator_export_profile=profile, policy_decision_metadata=policy_metadata)

    assert result.valid is False
    assert "EVIDENCE_RENEWAL_RUNTIME_WORM_MANIFEST_MISSING" in result.errors


def test_missing_tsa_metadata_fails_closed() -> None:
    record, profile, archive, evidence_record, worm, _tsa, policy_metadata = _runtime_record()
    record["tsa_timestamp_token_hash"] = ""

    result = verify_evidence_renewal_runtime_record(record, evidence_record_chain=evidence_record, sealed_archive=archive, worm_immutable_storage=worm, regulator_export_profile=profile, policy_decision_metadata=policy_metadata)

    assert result.valid is False
    assert "EVIDENCE_RENEWAL_RUNTIME_TSA_METADATA_MISSING" in result.errors


def test_missing_regulator_profile_fails_closed() -> None:
    record, _profile_payload, archive, evidence_record, worm, tsa, policy_metadata = _runtime_record()
    record["regulator_export_profile_hash"] = ""

    result = verify_evidence_renewal_runtime_record(record, evidence_record_chain=evidence_record, sealed_archive=archive, worm_immutable_storage=worm, tsa_live_verification=tsa, policy_decision_metadata=policy_metadata)

    assert result.valid is False
    assert "EVIDENCE_RENEWAL_RUNTIME_REGULATOR_PROFILE_MISSING" in result.errors


def test_reordered_renewal_entries_fail_closed() -> None:
    record, profile, archive, evidence_record, worm, tsa, policy_metadata = _runtime_record()
    record["renewal_runtime_entries"][0]["append_only_position"] = 1

    result = verify_evidence_renewal_runtime_record(record, evidence_record_chain=evidence_record, sealed_archive=archive, worm_immutable_storage=worm, tsa_live_verification=tsa, regulator_export_profile=profile, policy_decision_metadata=policy_metadata)

    assert result.valid is False
    assert "EVIDENCE_RENEWAL_RUNTIME_ENTRY_ORDER_INVALID" in result.errors


def test_duplicate_renewal_id_fails_closed() -> None:
    record, profile, archive, evidence_record, worm, tsa, policy_metadata = _runtime_record()

    result = verify_evidence_renewal_runtime_record(
        record,
        evidence_record_chain=evidence_record,
        sealed_archive=archive,
        worm_immutable_storage=worm,
        tsa_live_verification=tsa,
        regulator_export_profile=profile,
        policy_decision_metadata=policy_metadata,
        existing_records=[dict(record)],
    )

    assert result.valid is False
    assert "EVIDENCE_RENEWAL_RUNTIME_DUPLICATE_RENEWAL_ID" in result.errors


def test_stale_policy_metadata_fails_closed() -> None:
    record, profile, archive, evidence_record, worm, tsa, policy_metadata = _runtime_record()
    policy_metadata = dict(policy_metadata)
    policy_metadata["decision_timestamp_utc"] = "2026-05-10T00:15:00Z"

    result = verify_evidence_renewal_runtime_record(record, evidence_record_chain=evidence_record, sealed_archive=archive, worm_immutable_storage=worm, tsa_live_verification=tsa, regulator_export_profile=profile, policy_decision_metadata=policy_metadata)

    assert result.valid is False
    assert "EVIDENCE_RENEWAL_RUNTIME_POLICY_DECISION_STALE" in result.errors


def test_mutable_runtime_path_fails_closed() -> None:
    record, profile, archive, evidence_record, worm, tsa, policy_metadata = _runtime_record()
    record["runtime_output_path"] = "/tmp/renewal-runtime.json"

    result = verify_evidence_renewal_runtime_record(record, evidence_record_chain=evidence_record, sealed_archive=archive, worm_immutable_storage=worm, tsa_live_verification=tsa, regulator_export_profile=profile, policy_decision_metadata=policy_metadata)

    assert result.valid is False
    assert "EVIDENCE_RENEWAL_RUNTIME_PATH_MUTABLE" in result.errors


def test_raw_payload_leakage_fails_closed() -> None:
    record, profile, archive, evidence_record, worm, tsa, policy_metadata = _runtime_record()
    record["raw_runtime_renewal"] = "do-not-export"

    result = verify_evidence_renewal_runtime_record(record, evidence_record_chain=evidence_record, sealed_archive=archive, worm_immutable_storage=worm, tsa_live_verification=tsa, regulator_export_profile=profile, policy_decision_metadata=policy_metadata)

    assert result.valid is False
    assert "EVIDENCE_RENEWAL_RUNTIME_RAW_PAYLOAD_LEAKAGE" in result.errors


def test_unsafe_diagnostics_fails_closed() -> None:
    record, profile, archive, evidence_record, worm, tsa, policy_metadata = _runtime_record()
    record["diagnostics"] = {"debug": "approval_contents"}

    result = verify_evidence_renewal_runtime_record(record, evidence_record_chain=evidence_record, sealed_archive=archive, worm_immutable_storage=worm, tsa_live_verification=tsa, regulator_export_profile=profile, policy_decision_metadata=policy_metadata)

    assert result.valid is False
    assert "EVIDENCE_RENEWAL_RUNTIME_DIAGNOSTICS_UNSAFE" in result.errors


def test_evidence_renewal_runtime_registry_complete() -> None:
    registry = load_evidence_renewal_runtime_error_registry(ROOT)

    assert set(EVIDENCE_RENEWAL_RUNTIME_ERROR_CODES).issubset(registry)
    assert explain_evidence_renewal_runtime_failure(ROOT, "EVIDENCE_RENEWAL_RUNTIME_PATH_MUTABLE")["fail_closed_reason"]


def test_create_and_verify_cli_redacts_output(tmp_path: Path) -> None:
    _record, profile, archive, evidence_record, worm, tsa, policy_metadata = _runtime_record()
    paths = {
        "archive": tmp_path / "sealed-audit-archive.json",
        "evidence_record": tmp_path / "evidence-record.json",
        "worm": tmp_path / "worm-immutable-storage.json",
        "tsa": tmp_path / "tsa-live-verification.json",
        "profile": tmp_path / "regulator-export-profile.json",
        "policy": tmp_path / "policy-decision-metadata.json",
    }
    paths["archive"].write_text(json.dumps(archive, sort_keys=True), encoding="utf-8")
    paths["evidence_record"].write_text(json.dumps(evidence_record, sort_keys=True), encoding="utf-8")
    paths["worm"].write_text(json.dumps(worm, sort_keys=True), encoding="utf-8")
    paths["tsa"].write_text(json.dumps(tsa, sort_keys=True), encoding="utf-8")
    paths["profile"].write_text(json.dumps(profile, sort_keys=True), encoding="utf-8")
    paths["policy"].write_text(json.dumps(policy_metadata, sort_keys=True), encoding="utf-8")
    runtime_path = tmp_path / "evidence-renewal-runtime.json"

    created = subprocess.run(
        [
            sys.executable,
            "scripts/governance_diagnostics.py",
            "prepare-evidence-renewal-runtime",
            "--sealed-audit-archive",
            str(paths["archive"]),
            "--evidence-record",
            str(paths["evidence_record"]),
            "--worm-immutable-storage",
            str(paths["worm"]),
            "--tsa-live-verification",
            str(paths["tsa"]),
            "--regulator-export-profile",
            str(paths["profile"]),
            "--policy-decision-metadata",
            str(paths["policy"]),
            "--validation-timestamp",
            "2026-05-12T00:15:00Z",
            "--output",
            str(runtime_path),
        ],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
    )

    assert created.returncode == 0
    assert runtime_path.is_file()
    assert "approval_contents" not in created.stdout
    assert "PRIVATE KEY" not in created.stdout

    verified = subprocess.run(
        [
            sys.executable,
            "scripts/governance_diagnostics.py",
            "verify-evidence-renewal-runtime",
            "--evidence-renewal-runtime",
            str(runtime_path),
            "--sealed-audit-archive",
            str(paths["archive"]),
            "--evidence-record",
            str(paths["evidence_record"]),
            "--worm-immutable-storage",
            str(paths["worm"]),
            "--tsa-live-verification",
            str(paths["tsa"]),
            "--regulator-export-profile",
            str(paths["profile"]),
            "--policy-decision-metadata",
            str(paths["policy"]),
        ],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
    )

    assert verified.returncode == 0
    assert "evidence_renewal_runtime_verification" in verified.stdout
    assert "approval_contents" not in verified.stdout
