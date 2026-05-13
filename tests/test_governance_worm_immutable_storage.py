from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

from governance.worm_immutable_storage import (
    WORM_IMMUTABLE_STORAGE_ERROR_CODES,
    explain_worm_immutable_storage_failure,
    load_worm_immutable_storage_error_registry,
    prepare_worm_immutable_storage_plan,
    verify_worm_immutable_storage_plan,
)
from tests.test_governance_evidence_record_chain import _record


ROOT = Path(__file__).resolve().parents[1]


def _worm_plan() -> tuple[dict, dict, dict]:
    evidence_record, archive = _record()
    plan = prepare_worm_immutable_storage_plan(
        sealed_archive=archive,
        evidence_record_chain=evidence_record,
        created_at_utc="2026-05-12T00:12:00Z",
    )
    return plan, archive, evidence_record


def test_valid_worm_immutable_storage_plan_verification() -> None:
    plan, archive, evidence_record = _worm_plan()

    result = verify_worm_immutable_storage_plan(plan, sealed_archive=archive, evidence_record_chain=evidence_record)

    assert result.valid is True
    assert result.errors == ()
    assert result.storage_mode == "LOCAL_ONLY"
    assert result.archive_root_hash == archive["archive_root_hash"]
    assert all(entry["storage_object_path"].startswith("worm://local-only/sha256/") for entry in plan["immutable_storage_manifest"])


def test_missing_archive_root_hash_rejection() -> None:
    plan, archive, evidence_record = _worm_plan()
    plan["archive_root_hash"] = ""

    result = verify_worm_immutable_storage_plan(plan, sealed_archive=archive, evidence_record_chain=evidence_record)

    assert result.valid is False
    assert "WORM_IMMUTABLE_ARCHIVE_ROOT_HASH_MISSING" in result.errors


def test_missing_evidence_record_chain_rejection() -> None:
    plan, archive, _evidence_record = _worm_plan()
    plan["evidence_record_id"] = ""

    result = verify_worm_immutable_storage_plan(plan, sealed_archive=archive)

    assert result.valid is False
    assert "WORM_IMMUTABLE_EVIDENCE_RECORD_CHAIN_MISSING" in result.errors


def test_reordered_entries_rejection() -> None:
    plan, archive, evidence_record = _worm_plan()
    plan["immutable_storage_manifest"] = [plan["immutable_storage_manifest"][1], plan["immutable_storage_manifest"][0]]

    result = verify_worm_immutable_storage_plan(plan, sealed_archive=archive, evidence_record_chain=evidence_record)

    assert result.valid is False
    assert "WORM_IMMUTABLE_ENTRY_ORDER_INVALID" in result.errors


def test_duplicate_archive_id_rejection() -> None:
    plan, archive, evidence_record = _worm_plan()

    result = verify_worm_immutable_storage_plan(plan, sealed_archive=archive, evidence_record_chain=evidence_record, existing_plans=[plan])

    assert result.valid is False
    assert "WORM_IMMUTABLE_DUPLICATE_ARCHIVE_ID" in result.errors


def test_mutable_output_path_rejection() -> None:
    plan, archive, evidence_record = _worm_plan()
    plan["immutable_storage_manifest"][0]["storage_object_path"] = "/tmp/mutable/archive.json"

    result = verify_worm_immutable_storage_plan(plan, sealed_archive=archive, evidence_record_chain=evidence_record)

    assert result.valid is False
    assert "WORM_IMMUTABLE_OUTPUT_PATH_MUTABLE" in result.errors


def test_manifest_hash_mismatch_rejection() -> None:
    plan, archive, evidence_record = _worm_plan()
    plan["immutable_storage_manifest_hash"] = "0" * 64

    result = verify_worm_immutable_storage_plan(plan, sealed_archive=archive, evidence_record_chain=evidence_record)

    assert result.valid is False
    assert "WORM_IMMUTABLE_MANIFEST_INVALID" in result.errors


def test_unsafe_diagnostics_rejection() -> None:
    plan, archive, evidence_record = _worm_plan()
    plan["diagnostics"] = {"approval_contents": "do-not-export"}

    result = verify_worm_immutable_storage_plan(plan, sealed_archive=archive, evidence_record_chain=evidence_record)

    assert result.valid is False
    assert "WORM_IMMUTABLE_DIAGNOSTICS_UNSAFE" in result.errors


def test_worm_immutable_storage_error_registry_complete() -> None:
    registry = load_worm_immutable_storage_error_registry(ROOT)

    assert set(WORM_IMMUTABLE_STORAGE_ERROR_CODES).issubset(registry)
    assert explain_worm_immutable_storage_failure(ROOT, "WORM_IMMUTABLE_OUTPUT_PATH_MUTABLE")["fail_closed_reason"]


def test_create_and_verify_cli_redacts_output(tmp_path: Path) -> None:
    plan_path = tmp_path / "worm-immutable-storage.json"
    evidence_record, archive = _record()
    archive_path = tmp_path / "sealed-audit-archive.json"
    evidence_record_path = tmp_path / "evidence-record.json"
    archive_path.write_text(json.dumps(archive, sort_keys=True), encoding="utf-8")
    evidence_record_path.write_text(json.dumps(evidence_record, sort_keys=True), encoding="utf-8")

    created = subprocess.run(
        [
            sys.executable,
            "scripts/governance_diagnostics.py",
            "prepare-worm-immutable-storage",
            "--sealed-audit-archive",
            str(archive_path),
            "--evidence-record",
            str(evidence_record_path),
            "--validation-timestamp",
            "2026-05-12T00:12:00Z",
            "--output",
            str(plan_path),
        ],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
    )

    assert created.returncode == 0
    assert plan_path.is_file()
    assert "approval_contents" not in created.stdout
    assert "PRIVATE KEY" not in created.stdout
    assert "PRIVATE KEY" not in plan_path.read_text(encoding="utf-8")

    verified = subprocess.run(
        [
            sys.executable,
            "scripts/governance_diagnostics.py",
            "verify-worm-immutable-storage",
            "--worm-immutable-storage",
            str(plan_path),
            "--sealed-audit-archive",
            str(archive_path),
            "--evidence-record",
            str(evidence_record_path),
        ],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
    )

    assert verified.returncode == 0
    assert '"valid":true' in verified.stdout
    assert "approval_contents" not in verified.stdout
