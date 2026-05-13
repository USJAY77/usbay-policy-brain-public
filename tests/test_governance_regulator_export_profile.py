from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

from governance.regulator_export_profile import (
    EXPORT_PROFILE_TYPES,
    REGULATOR_EXPORT_PROFILE_ERROR_CODES,
    explain_regulator_export_profile_failure,
    load_regulator_export_profile_error_registry,
    prepare_regulator_export_profile,
    verify_regulator_export_profile,
)
from governance.tsa_live_verification import prepare_tsa_live_verification_plan
from governance.worm_immutable_storage import prepare_worm_immutable_storage_plan
from tests.test_governance_evidence_record_chain import _record
from tests.test_governance_signed_bundle_timestamp import _attachment


ROOT = Path(__file__).resolve().parents[1]


def _policy_metadata() -> dict:
    return {
        "actor_hash": "a" * 64,
        "decision_timestamp_utc": "2026-05-12T00:13:00Z",
        "policy_decision": "ALLOW",
        "policy_decision_id": "b" * 64,
        "policy_hash": "c" * 64,
        "policy_version_hash": "d" * 64,
    }


def _profile(profile_type: str = "EU_AI_ACT_AUDIT") -> tuple[dict, dict, dict, dict, dict, dict]:
    evidence_record, archive = _record()
    worm = prepare_worm_immutable_storage_plan(
        sealed_archive=archive,
        evidence_record_chain=evidence_record,
        created_at_utc="2026-05-12T00:12:00Z",
    )
    attachment, _envelope, _policy = _attachment()
    tsa = prepare_tsa_live_verification_plan(
        attachment,
        verification_checked_at_utc="2026-05-12T00:07:00Z",
    )
    policy_metadata = _policy_metadata()
    profile = prepare_regulator_export_profile(
        sealed_archive=archive,
        evidence_record_chain=evidence_record,
        worm_immutable_storage=worm,
        tsa_live_verification=tsa,
        policy_decision_metadata=policy_metadata,
        export_profile_type=profile_type,
        created_at_utc="2026-05-12T00:14:00Z",
    )
    return profile, archive, evidence_record, worm, tsa, policy_metadata


def test_valid_regulator_export_profile_types() -> None:
    for profile_type in EXPORT_PROFILE_TYPES:
        profile, archive, evidence_record, worm, tsa, policy_metadata = _profile(profile_type)

        result = verify_regulator_export_profile(
            profile,
            sealed_archive=archive,
            evidence_record_chain=evidence_record,
            worm_immutable_storage=worm,
            tsa_live_verification=tsa,
            policy_decision_metadata=policy_metadata,
        )

        assert result.valid is True
        assert result.errors == ()
        assert result.export_profile_type == profile_type
        assert profile["export_output_path"].startswith(f"regulator-export://local-only/sha256/{profile_type}/")


def test_missing_evidence_chain_rejection() -> None:
    profile, archive, _evidence_record, worm, tsa, policy_metadata = _profile()
    profile["evidence_record_id"] = ""

    result = verify_regulator_export_profile(profile, sealed_archive=archive, worm_immutable_storage=worm, tsa_live_verification=tsa, policy_decision_metadata=policy_metadata)

    assert result.valid is False
    assert "REGULATOR_EXPORT_EVIDENCE_CHAIN_MISSING" in result.errors


def test_missing_sealed_archive_rejection() -> None:
    profile, _archive, evidence_record, worm, tsa, policy_metadata = _profile()
    profile["sealed_archive_id"] = ""

    result = verify_regulator_export_profile(profile, evidence_record_chain=evidence_record, worm_immutable_storage=worm, tsa_live_verification=tsa, policy_decision_metadata=policy_metadata)

    assert result.valid is False
    assert "REGULATOR_EXPORT_SEALED_ARCHIVE_MISSING" in result.errors


def test_missing_worm_manifest_rejection() -> None:
    profile, archive, evidence_record, _worm, tsa, policy_metadata = _profile()
    profile["worm_storage_plan_id"] = ""

    result = verify_regulator_export_profile(profile, sealed_archive=archive, evidence_record_chain=evidence_record, tsa_live_verification=tsa, policy_decision_metadata=policy_metadata)

    assert result.valid is False
    assert "REGULATOR_EXPORT_WORM_MANIFEST_MISSING" in result.errors


def test_missing_tsa_metadata_rejection() -> None:
    profile, archive, evidence_record, worm, _tsa, policy_metadata = _profile()
    profile["tsa_live_verification_id"] = ""

    result = verify_regulator_export_profile(profile, sealed_archive=archive, evidence_record_chain=evidence_record, worm_immutable_storage=worm, policy_decision_metadata=policy_metadata)

    assert result.valid is False
    assert "REGULATOR_EXPORT_TSA_METADATA_MISSING" in result.errors


def test_missing_policy_decision_metadata_rejection() -> None:
    profile, archive, evidence_record, worm, tsa, _policy_metadata = _profile()
    profile["policy_decision_metadata_hash"] = ""

    result = verify_regulator_export_profile(profile, sealed_archive=archive, evidence_record_chain=evidence_record, worm_immutable_storage=worm, tsa_live_verification=tsa)

    assert result.valid is False
    assert "REGULATOR_EXPORT_POLICY_DECISION_MISSING" in result.errors


def test_mutable_export_path_rejection() -> None:
    profile, archive, evidence_record, worm, tsa, policy_metadata = _profile()
    profile["export_output_path"] = "/tmp/regulator-export.json"

    result = verify_regulator_export_profile(profile, sealed_archive=archive, evidence_record_chain=evidence_record, worm_immutable_storage=worm, tsa_live_verification=tsa, policy_decision_metadata=policy_metadata)

    assert result.valid is False
    assert "REGULATOR_EXPORT_OUTPUT_PATH_MUTABLE" in result.errors


def test_duplicate_evidence_reference_rejection() -> None:
    profile, archive, evidence_record, worm, tsa, policy_metadata = _profile()
    profile["evidence_references"][1]["evidence_hash"] = profile["evidence_references"][0]["evidence_hash"]

    result = verify_regulator_export_profile(profile, sealed_archive=archive, evidence_record_chain=evidence_record, worm_immutable_storage=worm, tsa_live_verification=tsa, policy_decision_metadata=policy_metadata)

    assert result.valid is False
    assert "REGULATOR_EXPORT_DUPLICATE_EVIDENCE_REFERENCE" in result.errors


def test_reordered_evidence_entries_rejection() -> None:
    profile, archive, evidence_record, worm, tsa, policy_metadata = _profile()
    profile["evidence_references"] = [profile["evidence_references"][1], profile["evidence_references"][0], *profile["evidence_references"][2:]]

    result = verify_regulator_export_profile(profile, sealed_archive=archive, evidence_record_chain=evidence_record, worm_immutable_storage=worm, tsa_live_verification=tsa, policy_decision_metadata=policy_metadata)

    assert result.valid is False
    assert "REGULATOR_EXPORT_ENTRY_ORDER_INVALID" in result.errors


def test_raw_payload_leakage_rejection() -> None:
    profile, archive, evidence_record, worm, tsa, policy_metadata = _profile()
    profile["raw_governance_payload"] = "do-not-export"

    result = verify_regulator_export_profile(profile, sealed_archive=archive, evidence_record_chain=evidence_record, worm_immutable_storage=worm, tsa_live_verification=tsa, policy_decision_metadata=policy_metadata)

    assert result.valid is False
    assert "REGULATOR_EXPORT_RAW_PAYLOAD_LEAKAGE" in result.errors


def test_unsafe_diagnostics_rejection() -> None:
    profile, archive, evidence_record, worm, tsa, policy_metadata = _profile()
    profile["diagnostics"] = {"debug": "approval_contents"}

    result = verify_regulator_export_profile(profile, sealed_archive=archive, evidence_record_chain=evidence_record, worm_immutable_storage=worm, tsa_live_verification=tsa, policy_decision_metadata=policy_metadata)

    assert result.valid is False
    assert "REGULATOR_EXPORT_DIAGNOSTICS_UNSAFE" in result.errors


def test_regulator_export_error_registry_complete() -> None:
    registry = load_regulator_export_profile_error_registry(ROOT)

    assert set(REGULATOR_EXPORT_PROFILE_ERROR_CODES).issubset(registry)
    assert explain_regulator_export_profile_failure(ROOT, "REGULATOR_EXPORT_OUTPUT_PATH_MUTABLE")["fail_closed_reason"]


def test_create_and_verify_cli_redacts_output(tmp_path: Path) -> None:
    profile, archive, evidence_record, worm, tsa, policy_metadata = _profile()
    paths = {
        "archive": tmp_path / "sealed-audit-archive.json",
        "evidence_record": tmp_path / "evidence-record.json",
        "worm": tmp_path / "worm-immutable-storage.json",
        "tsa": tmp_path / "tsa-live-verification.json",
        "policy": tmp_path / "policy-decision-metadata.json",
    }
    paths["archive"].write_text(json.dumps(archive, sort_keys=True), encoding="utf-8")
    paths["evidence_record"].write_text(json.dumps(evidence_record, sort_keys=True), encoding="utf-8")
    paths["worm"].write_text(json.dumps(worm, sort_keys=True), encoding="utf-8")
    paths["tsa"].write_text(json.dumps(tsa, sort_keys=True), encoding="utf-8")
    paths["policy"].write_text(json.dumps(policy_metadata, sort_keys=True), encoding="utf-8")
    profile_path = tmp_path / "regulator-export-profile.json"

    created = subprocess.run(
        [
            sys.executable,
            "scripts/governance_diagnostics.py",
            "prepare-regulator-export-profile",
            "--sealed-audit-archive",
            str(paths["archive"]),
            "--evidence-record",
            str(paths["evidence_record"]),
            "--worm-immutable-storage",
            str(paths["worm"]),
            "--tsa-live-verification",
            str(paths["tsa"]),
            "--policy-decision-metadata",
            str(paths["policy"]),
            "--export-profile-type",
            profile["export_profile_type"],
            "--validation-timestamp",
            "2026-05-12T00:14:00Z",
            "--output",
            str(profile_path),
        ],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
    )

    assert created.returncode == 0
    assert profile_path.is_file()
    assert "approval_contents" not in created.stdout
    assert "PRIVATE KEY" not in created.stdout

    verified = subprocess.run(
        [
            sys.executable,
            "scripts/governance_diagnostics.py",
            "verify-regulator-export-profile",
            "--regulator-export-profile",
            str(profile_path),
            "--sealed-audit-archive",
            str(paths["archive"]),
            "--evidence-record",
            str(paths["evidence_record"]),
            "--worm-immutable-storage",
            str(paths["worm"]),
            "--tsa-live-verification",
            str(paths["tsa"]),
            "--policy-decision-metadata",
            str(paths["policy"]),
        ],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
    )

    assert verified.returncode == 0
    assert '"valid":true' in verified.stdout
    assert "approval_contents" not in verified.stdout
