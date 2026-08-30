from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

from governance.evidence_renewal_runtime import (
    EVIDENCE_RENEWAL_RUNTIME_ERROR_CODES,
    EvidenceRenewalRuntimeError,
    assert_evidence_renewal_runtime_safe,
    explain_evidence_renewal_runtime_failure,
    load_evidence_renewal_runtime_error_registry,
    redacted_evidence_renewal_runtime_payload,
    verify_evidence_renewal_runtime_record,
)
from governance.policy_pack import (
    ValidationSnapshot,
    _VALIDATION_SNAPSHOT_CACHE,
    _validation_snapshot_hash,
    assert_cached_validation_safe,
    clear_validation_snapshot_cache,
    validation_snapshot_cache_stats,
)
from tests.governance_test_builders import EvidenceBuilder

ROOT = Path(__file__).resolve().parents[1]
_EVIDENCE_BUILDER = EvidenceBuilder()


def _runtime_record() -> tuple[dict, dict, dict, dict, dict, dict, dict]:
    return _EVIDENCE_BUILDER.evidence_renewal_runtime_record()


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


def test_validation_snapshot_reuses_identical_renewal_runtime_evidence() -> None:
    record, *_rest = _runtime_record()
    payload = redacted_evidence_renewal_runtime_payload(record)
    clear_validation_snapshot_cache()

    assert_evidence_renewal_runtime_safe(payload)
    first_stats = validation_snapshot_cache_stats()
    assert_evidence_renewal_runtime_safe(payload)
    second_stats = validation_snapshot_cache_stats()

    assert first_stats["misses"] > 0
    assert second_stats["hits"] > first_stats["hits"]


def test_validation_snapshot_does_not_cache_invalid_renewal_runtime_evidence() -> None:
    record, *_rest = _runtime_record()
    payload = redacted_evidence_renewal_runtime_payload(record)
    payload["diagnostics"] = {"approval_contents": "do-not-cache"}
    clear_validation_snapshot_cache()

    for _index in range(2):
        try:
            assert_evidence_renewal_runtime_safe(payload)
        except EvidenceRenewalRuntimeError as exc:
            assert str(exc) == "EVIDENCE_RENEWAL_RUNTIME_DIAGNOSTICS_UNSAFE"
        else:
            raise AssertionError("invalid renewal runtime evidence was allowed")

    stats = validation_snapshot_cache_stats()
    assert stats["hits"] == 0
    assert stats["entries"] == 0


def test_validation_snapshot_invalidates_schema_policy_tenant_and_evidence_changes() -> None:
    clear_validation_snapshot_cache()
    calls: list[dict] = []

    def validator(payload: dict) -> None:
        calls.append(dict(payload))

    base = {
        "schema": "usbay.test.validation.v1",
        "policy_version": "policy.v1",
        "tenant_id": "tenant-a",
        "evidence_hash": "a" * 64,
    }

    assert_cached_validation_safe("test.validation", base, validator)
    assert_cached_validation_safe("test.validation", dict(base), validator)
    assert_cached_validation_safe("test.validation", {**base, "schema": "usbay.test.validation.v2"}, validator)
    assert_cached_validation_safe("test.validation", {**base, "policy_version": "policy.v2"}, validator)
    assert_cached_validation_safe("test.validation", {**base, "tenant_id": "tenant-b"}, validator)
    assert_cached_validation_safe("test.validation", {**base, "evidence_hash": "b" * 64}, validator)

    stats = validation_snapshot_cache_stats()
    assert len(calls) == 5
    assert stats["hits"] == 1
    assert stats["misses"] == 5


def test_validation_snapshot_namespace_isolation() -> None:
    clear_validation_snapshot_cache()
    calls: list[str] = []
    payload = {"schema": "usbay.test.validation.v1", "tenant_id": "tenant-a", "evidence_hash": "a" * 64}

    def first_validator(_payload: dict) -> None:
        calls.append("first")

    def second_validator(_payload: dict) -> None:
        calls.append("second")

    assert_cached_validation_safe("test.validation.first", payload, first_validator)
    assert_cached_validation_safe("test.validation.second", payload, second_validator)
    assert_cached_validation_safe("test.validation.first", dict(payload), first_validator)

    stats = validation_snapshot_cache_stats()
    assert calls == ["first", "second"]
    assert stats["hits"] == 1
    assert stats["misses"] == 2


def test_validation_snapshot_corruption_revalidates_before_reuse() -> None:
    clear_validation_snapshot_cache()
    calls: list[str] = []
    payload = {"schema": "usbay.test.validation.v1", "tenant_id": "tenant-a", "evidence_hash": "a" * 64}
    payload_hash = _validation_snapshot_hash(payload)
    _VALIDATION_SNAPSHOT_CACHE[("test.validation", payload_hash)] = ValidationSnapshot(
        namespace="wrong.namespace",
        payload_hash=payload_hash,
    )

    def validator(_payload: dict) -> None:
        calls.append("validated")

    assert_cached_validation_safe("test.validation", payload, validator)
    stats = validation_snapshot_cache_stats()

    assert calls == ["validated"]
    assert stats["corruptions"] == 1
    assert stats["hits"] == 0
    assert stats["misses"] == 1


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
