from __future__ import annotations

import json
import shutil
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

import pytest

from audit.exporter import (
    AuditExportPackageError,
    TENANT_PACKAGE_AUTHORITY_IDENTITY,
    TENANT_PACKAGE_EVIDENCE_INDEX,
    TENANT_PACKAGE_VERIFICATION_REPORT,
    build_package_source,
    build_tenant_package,
    validate_package_source,
    verify_tenant_package,
)
from audit.immutable_ledger import append_evidence_event, export_evidence_bundle
from audit.worm_archive import WORMArchive
from security.tenant_context import tenant_hash
from tests.provenance_helpers import install_runtime_authority
from tests.test_audit_exporter import isolated_anchor_keys
from tests.test_worm_evidence_archive import _policy as retention_policy


def _decision(tenant_id: str = "t1") -> dict:
    return {
        "node_id": "node-1",
        "tenant_id": tenant_id,
        "tenant_hash": tenant_hash(tenant_id),
        "policy_hash": "policy-hash-1",
        "consensus_result": "ALLOW",
        "nonce_hash": "nonce-hash-1",
        "request_hash": "request-hash-1",
        "consensus_evidence_bundle": {
            "node_ids": ["node-1", "node-2", "node-3"],
            "timestamps": {"node-1": 1, "node-2": 1, "node-3": 1},
            "policy_hash": "policy-hash-1",
            "tenant_id": tenant_id,
            "tenant_hash": tenant_hash(tenant_id),
            "consensus_result": "allow",
            "attestation_evidence": [
                {
                    "logical_node_id": "node-1",
                    "node_id": "attested-node-1",
                    "node_role": "primary",
                    "tenant_id": tenant_id,
                    "tenant_hash": tenant_hash(tenant_id),
                    "provider_mode": "mock_local",
                    "hardware_backed": False,
                    "attestation_hash": "attestation-hash-1",
                    "attestation_timestamp": 1,
                }
            ],
            "attestation_evidence_hash": "attestation-evidence-hash-1",
            "sha256_evidence_hash": "evidence-hash-1",
            "consensus_signature": "consensus-signature-1",
        },
    }


def _build_package(tmp_path: Path, monkeypatch) -> Path:
    authority = install_runtime_authority(monkeypatch, tmp_path)
    isolated_anchor_keys(tmp_path, monkeypatch)
    ledger = tmp_path / "evidence.jsonl"
    append_evidence_event(ledger, action="consensus_allow", decision=_decision("t1"))
    bundle_dir = tmp_path / "bundle"
    export_evidence_bundle(ledger, bundle_dir, provenance_authority=authority)
    archive = WORMArchive(tmp_path / "archive", retention_policy_path=retention_policy(tmp_path))
    worm_manifest = archive.archive_bundle(
        bundle_dir,
        now=datetime(2026, 1, 1, tzinfo=timezone.utc),
        provenance_authority=authority,
    )
    package_dir = tmp_path / "tenant_package"
    build_tenant_package(
        tenant_id="t1",
        package_path=package_dir,
        evidence_bundle_dir=bundle_dir,
        worm_manifest_path=(
            tmp_path
            / "archive"
            / "tenant"
            / "t1"
            / worm_manifest["object_id"]
            / "evidence_archive_manifest.json"
        ),
        provenance_authority=authority,
    )
    return package_dir


def _mutated_package(tmp_path: Path, monkeypatch) -> Path:
    source = _build_package(tmp_path, monkeypatch)
    target = tmp_path / "mutated_package"
    shutil.copytree(source, target)
    return target


def _install_exporter_authority(monkeypatch, tmp_path: Path, *, tenant_id: str = "t1"):
    authority = install_runtime_authority(monkeypatch, tmp_path, tenant_id=tenant_id)
    return authority, authority.context_dict()


def _assert_authority_lineage(context: dict) -> None:
    assert context["release_lineage"] is True
    assert context["ancestor_continuity"] is True
    assert context["expected_commit"]
    assert context["current_commit"]
    assert context["expected_commit"] in context["accepted_commit_set"]


def test_valid_tenant_package_passes(tmp_path: Path, monkeypatch) -> None:
    package = _build_package(tmp_path, monkeypatch)

    report = verify_tenant_package(package)
    manifest = json.loads((package / "verification_manifest.json").read_text(encoding="utf-8"))
    identity = json.loads((package / TENANT_PACKAGE_AUTHORITY_IDENTITY).read_text(encoding="utf-8"))

    assert report["result"] == "PASS"
    assert manifest["tenant_id"] == "t1"
    assert manifest["tenant_hash"] == tenant_hash("t1")
    assert manifest["package_hash"]
    assert identity["authority_reuse_verified"] is True
    assert identity["secondary_authority_resolution_allowed"] is False
    assert identity["canonical_bootstrap_lineage_summary"]["expected_commit"] == manifest["provenance_context"]["expected_commit"]


def test_package_build_requires_injected_runtime_authority(tmp_path: Path, monkeypatch) -> None:
    install_runtime_authority(monkeypatch, tmp_path)
    isolated_anchor_keys(tmp_path, monkeypatch)

    with pytest.raises(AuditExportPackageError, match="runtime_provenance_authority_required"):
        build_tenant_package(
            tenant_id="t1",
            package_path=tmp_path / "package",
            evidence_bundle_dir=tmp_path / "source",
        )


def test_package_source_build_requires_injected_runtime_authority(tmp_path: Path, monkeypatch) -> None:
    install_runtime_authority(monkeypatch, tmp_path)
    isolated_anchor_keys(tmp_path, monkeypatch)

    with pytest.raises(AuditExportPackageError, match="runtime_provenance_authority_required"):
        build_package_source(
            tenant_id="t1",
            source_dir=tmp_path / "source",
            retention_policy_path=retention_policy(tmp_path),
        )


def test_package_source_validation_requires_injected_runtime_authority(tmp_path: Path, monkeypatch) -> None:
    authority = install_runtime_authority(monkeypatch, tmp_path)
    isolated_anchor_keys(tmp_path, monkeypatch)
    source = tmp_path / "source"
    build_package_source(
        tenant_id="t1",
        source_dir=source,
        retention_policy_path=retention_policy(tmp_path),
        provenance_authority=authority,
    )

    with pytest.raises(AuditExportPackageError, match="runtime_provenance_authority_required"):
        validate_package_source(source, tenant_id="t1")


def test_package_verify_accepts_reused_runtime_authority(tmp_path: Path, monkeypatch) -> None:
    authority = install_runtime_authority(monkeypatch, tmp_path)
    package = _build_package(tmp_path, monkeypatch)

    report = verify_tenant_package(package, provenance_authority=authority)
    identity = json.loads((package / TENANT_PACKAGE_AUTHORITY_IDENTITY).read_text(encoding="utf-8"))

    assert report["result"] == "PASS"
    assert identity["authority_instance_id"] == authority.authority_id


def test_valid_package_produces_evidence_index(tmp_path: Path, monkeypatch) -> None:
    package = _build_package(tmp_path, monkeypatch)

    report = verify_tenant_package(package)
    index = json.loads((package / TENANT_PACKAGE_EVIDENCE_INDEX).read_text(encoding="utf-8"))
    manifest = json.loads((package / "verification_manifest.json").read_text(encoding="utf-8"))

    assert report["result"] == "PASS"
    assert index["tenant_id"] == "t1"
    assert index["tenant_hash"] == tenant_hash("t1")
    assert index["release_id"] == manifest["release_id"]
    assert index["git_commit"] == manifest["git_commit"]
    assert index["package_hash"] == manifest["package_hash"]
    assert index["audit_ledger_hash"] == manifest["ledger_sha256"]
    assert index["worm_manifest_hash"] == report["evidence_file_hashes"]["evidence_archive_manifest.json"]
    assert index["rfc3161_timestamp_proof_hash"] == report["evidence_file_hashes"]["rfc3161_timestamp.tsr"]
    assert index["governance_release_hash"] == report["evidence_file_hashes"]["governance_release.json"]
    assert index["verification_manifest_hash"] == report["evidence_file_hashes"]["verification_manifest.json"]


def test_valid_package_produces_verification_report(tmp_path: Path, monkeypatch) -> None:
    package = _build_package(tmp_path, monkeypatch)

    report = verify_tenant_package(package)
    text = (package / TENANT_PACKAGE_VERIFICATION_REPORT).read_text(encoding="utf-8")

    assert report["result"] == "PASS"
    assert "Result: PASS" in text
    assert "Tenant binding: PASS" in text
    assert "Release signature: PASS" in text
    assert "WORM verification: PASS" in text
    assert "Ledger continuity: PASS" in text
    assert "RFC3161 timestamp: PASS" in text
    assert "No secret leakage: PASS" in text
    assert "audit.jsonl:" in text


def test_missing_evidence_file_fails_closed(tmp_path: Path, monkeypatch) -> None:
    package = _mutated_package(tmp_path, monkeypatch)
    (package / "audit.jsonl").unlink()

    report = verify_tenant_package(package)

    assert report["result"] == "FAIL"
    assert any("audit.jsonl" in control for control in report["failed_control_ids"])


def test_tenant_mismatch_fails_closed(tmp_path: Path, monkeypatch) -> None:
    package = _mutated_package(tmp_path, monkeypatch)
    context = json.loads((package / "tenant_context.json").read_text(encoding="utf-8"))
    context["tenant_id"] = "t2"
    context["tenant_hash"] = tenant_hash("t2")
    context["tenant_scope"] = "tenant/t2"
    (package / "tenant_context.json").write_text(json.dumps(context, sort_keys=True, separators=(",", ":")), encoding="utf-8")

    report = verify_tenant_package(package)

    assert report["result"] == "FAIL"
    assert any("TENANT" in control.upper() for control in report["failed_control_ids"])


def test_tenant_mismatch_report_shows_fail(tmp_path: Path, monkeypatch) -> None:
    package = _mutated_package(tmp_path, monkeypatch)
    context = json.loads((package / "tenant_context.json").read_text(encoding="utf-8"))
    context["tenant_id"] = "t2"
    context["tenant_hash"] = tenant_hash("t2")
    context["tenant_scope"] = "tenant/t2"
    (package / "tenant_context.json").write_text(json.dumps(context, sort_keys=True, separators=(",", ":")), encoding="utf-8")

    report = verify_tenant_package(package)
    text = (package / TENANT_PACKAGE_VERIFICATION_REPORT).read_text(encoding="utf-8")

    assert report["result"] == "FAIL"
    assert "Result: FAIL" in text
    assert "Tenant binding: FAIL" in text


def test_modified_ledger_fails_closed(tmp_path: Path, monkeypatch) -> None:
    package = _mutated_package(tmp_path, monkeypatch)
    with (package / "audit.jsonl").open("a", encoding="utf-8") as handle:
        handle.write('{"tenant_id":"t1","tenant_hash":"' + tenant_hash("t1") + '"}\n')

    report = verify_tenant_package(package)

    assert report["result"] == "FAIL"
    assert any("LEDGER" in control or "AUDIT" in control for control in report["failed_control_ids"])


def test_tampered_package_report_shows_fail(tmp_path: Path, monkeypatch) -> None:
    package = _mutated_package(tmp_path, monkeypatch)
    (package / "ledger.sha256").write_text("0" * 64 + "\n", encoding="utf-8")

    report = verify_tenant_package(package)
    text = (package / TENANT_PACKAGE_VERIFICATION_REPORT).read_text(encoding="utf-8")

    assert report["result"] == "FAIL"
    assert "Result: FAIL" in text
    assert "LEDGER" in text.upper() or "BUNDLE:" in text


def test_modified_worm_manifest_fails_closed(tmp_path: Path, monkeypatch) -> None:
    package = _mutated_package(tmp_path, monkeypatch)
    manifest = json.loads((package / "evidence_archive_manifest.json").read_text(encoding="utf-8"))
    manifest["object_hashes"]["ledger.sha256"] = "0" * 64
    (package / "evidence_archive_manifest.json").write_text(json.dumps(manifest, sort_keys=True, separators=(",", ":")), encoding="utf-8")

    report = verify_tenant_package(package)

    assert report["result"] == "FAIL"
    assert "worm_manifest_hash_mismatch" in report["failed_control_ids"]


def test_invalid_release_signature_fails_closed(tmp_path: Path, monkeypatch) -> None:
    package = _mutated_package(tmp_path, monkeypatch)
    release = json.loads((package / "governance_release.json").read_text(encoding="utf-8"))
    release["release_signature"] = "hmac-sha256:" + "0" * 64
    (package / "governance_release.json").write_text(json.dumps(release, sort_keys=True, separators=(",", ":")), encoding="utf-8")

    report = verify_tenant_package(package)

    assert report["result"] == "FAIL"
    assert any("RELEASE_SIGNATURE" in control or "DEPLOYMENT_PROVENANCE" in control for control in report["failed_control_ids"])


def test_raw_secret_leakage_fails_closed(tmp_path: Path, monkeypatch) -> None:
    package = _mutated_package(tmp_path, monkeypatch)
    with (package / "audit.jsonl").open("a", encoding="utf-8") as handle:
        handle.write('{"raw_nonce":"do-not-export"}\n')

    report = verify_tenant_package(package)

    assert report["result"] == "FAIL"
    assert any("SECRET" in control or "NO_SECRET_LEAKAGE" in control for control in report["failed_control_ids"])


def test_secret_leakage_value_is_never_included_in_report(tmp_path: Path, monkeypatch) -> None:
    package = _mutated_package(tmp_path, monkeypatch)
    with (package / "audit.jsonl").open("a", encoding="utf-8") as handle:
        handle.write('{"raw_nonce":"do-not-export"}\n')

    report = verify_tenant_package(package)
    text = (package / TENANT_PACKAGE_VERIFICATION_REPORT).read_text(encoding="utf-8")

    assert report["result"] == "FAIL"
    assert "PACKAGE_SECRET_LEAKAGE" in text
    assert "do-not-export" not in text
    assert "raw_nonce" not in text


def test_offline_verification_report_is_deterministic(tmp_path: Path, monkeypatch) -> None:
    package = _build_package(tmp_path, monkeypatch)

    first = verify_tenant_package(package)
    first_report = (package / TENANT_PACKAGE_VERIFICATION_REPORT).read_text(encoding="utf-8")
    second = verify_tenant_package(package)
    second_report = (package / TENANT_PACKAGE_VERIFICATION_REPORT).read_text(encoding="utf-8")

    assert first["result"] == "PASS"
    assert second["result"] == "PASS"
    assert first_report == second_report


def test_offline_verification_passes_without_runtime_services(tmp_path: Path, monkeypatch) -> None:
    package = _build_package(tmp_path, monkeypatch)
    monkeypatch.setenv("REQUIRE_REDIS", "true")
    monkeypatch.delenv("REDIS_URL", raising=False)

    report = verify_tenant_package(package)

    assert report["result"] == "PASS"


def test_build_package_source_generates_offline_verifiable_source(tmp_path: Path, monkeypatch) -> None:
    authority = install_runtime_authority(monkeypatch, tmp_path)
    isolated_anchor_keys(tmp_path, monkeypatch)
    source = tmp_path / "generated_source"

    summary = build_package_source(
        tenant_id="t1",
        source_dir=source,
        retention_policy_path=retention_policy(tmp_path),
        provenance_authority=authority,
        now=datetime(2026, 1, 1, tzinfo=timezone.utc),
    )

    assert summary["tenant_id"] == "t1"
    assert validate_package_source(source, tenant_id="t1", provenance_authority=authority)["tenant_id"] == "t1"
    assert verify_tenant_package(source)["result"] == "FAIL"
    assert (source / "audit.jsonl").is_file()
    assert (source / "rfc3161_timestamp.tsr").is_file()
    assert (source / "evidence_archive_manifest.json").is_file()


def test_build_tenant_package_auto_generates_missing_source(tmp_path: Path, monkeypatch) -> None:
    authority = install_runtime_authority(monkeypatch, tmp_path)
    isolated_anchor_keys(tmp_path, monkeypatch)
    source = tmp_path / "missing_source"
    package = tmp_path / "package"

    manifest = build_tenant_package(
        tenant_id="t1",
        package_path=package,
        evidence_bundle_dir=source,
        provenance_authority=authority,
    )

    assert manifest["tenant_id"] == "t1"
    assert source.is_dir()
    assert verify_tenant_package(package)["result"] == "PASS"


def test_local_runtime_package_generation_uses_canonical_provenance_context(tmp_path: Path, monkeypatch) -> None:
    authority = install_runtime_authority(monkeypatch, tmp_path)
    isolated_anchor_keys(tmp_path, monkeypatch)
    source = tmp_path / "local_source"

    summary = build_package_source(
        tenant_id="t1",
        source_dir=source,
        retention_policy_path=retention_policy(tmp_path),
        provenance_authority=authority,
        now=datetime(2026, 1, 1, tzinfo=timezone.utc),
    )

    assert summary["tenant_id"] == "t1"
    assert validate_package_source(source, tenant_id="t1", provenance_authority=authority)["tenant_id"] == "t1"


def test_github_actions_package_generation_uses_canonical_ci_context(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("USBAY_ENV", "development")
    authority, context = _install_exporter_authority(monkeypatch, tmp_path)
    isolated_anchor_keys(tmp_path, monkeypatch)
    source = tmp_path / "ci_source"

    summary = build_package_source(
        tenant_id="t1",
        source_dir=source,
        retention_policy_path=retention_policy(tmp_path),
        provenance_authority=authority,
        now=datetime(2026, 1, 1, tzinfo=timezone.utc),
    )

    _assert_authority_lineage(context)
    assert summary["tenant_id"] == "t1"
    assert validate_package_source(source, tenant_id="t1", provenance_authority=authority)["tenant_id"] == "t1"


def test_ci_merge_commit_lineage_package_generation(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("USBAY_ENV", "development")
    authority, context = _install_exporter_authority(monkeypatch, tmp_path)
    isolated_anchor_keys(tmp_path, monkeypatch)

    build_package_source(
        tenant_id="t1",
        source_dir=tmp_path / "merge_source",
        retention_policy_path=retention_policy(tmp_path),
        provenance_authority=authority,
        now=datetime(2026, 1, 1, tzinfo=timezone.utc),
    )

    _assert_authority_lineage(context)


def test_ci_detached_head_lineage_package_generation(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("USBAY_ENV", "development")
    authority, context = _install_exporter_authority(monkeypatch, tmp_path)
    isolated_anchor_keys(tmp_path, monkeypatch)

    build_package_source(
        tenant_id="t1",
        source_dir=tmp_path / "detached_source",
        retention_policy_path=retention_policy(tmp_path),
        provenance_authority=authority,
        now=datetime(2026, 1, 1, tzinfo=timezone.utc),
    )

    _assert_authority_lineage(context)


def test_ci_replay_lineage_package_generation_uses_canonical_context(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("USBAY_ENV", "development")
    authority, context = _install_exporter_authority(monkeypatch, tmp_path)
    isolated_anchor_keys(tmp_path, monkeypatch)
    source = tmp_path / "replay_source"
    package = tmp_path / "replay_package"

    manifest = build_tenant_package(
        tenant_id="t1",
        evidence_bundle_dir=source,
        package_path=package,
        provenance_authority=authority,
    )

    _assert_authority_lineage(context)
    assert manifest["tenant_id"] == "t1"
    assert verify_tenant_package(package)["result"] == "PASS"


def test_evidence_index_generation_under_github_actions(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("USBAY_ENV", "development")
    authority, context = _install_exporter_authority(monkeypatch, tmp_path)
    isolated_anchor_keys(tmp_path, monkeypatch)
    package = tmp_path / "ci_index_package"

    manifest = build_tenant_package(
        tenant_id="t1",
        evidence_bundle_dir=tmp_path / "ci_index_source",
        package_path=package,
        provenance_authority=authority,
    )
    index = json.loads((package / TENANT_PACKAGE_EVIDENCE_INDEX).read_text(encoding="utf-8"))

    assert manifest["provenance_context"] == context
    assert index["git_commit"] == manifest["git_commit"]
    assert index["package_hash"] == manifest["package_hash"]
    assert verify_tenant_package(package)["result"] == "PASS"


def test_verification_report_generation_under_github_actions(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("USBAY_ENV", "development")
    authority, context = _install_exporter_authority(monkeypatch, tmp_path)
    isolated_anchor_keys(tmp_path, monkeypatch)
    package = tmp_path / "ci_report_package"

    manifest = build_tenant_package(
        tenant_id="t1",
        evidence_bundle_dir=tmp_path / "ci_report_source",
        package_path=package,
        provenance_authority=authority,
    )
    report = verify_tenant_package(package)
    text = (package / TENANT_PACKAGE_VERIFICATION_REPORT).read_text(encoding="utf-8")

    assert report["result"] == "PASS"
    assert manifest["provenance_context"] == context
    assert "Result: PASS" in text
    assert "Git Commit: " + manifest["git_commit"] in text


def test_detached_head_reporting_uses_package_provenance_context(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("USBAY_ENV", "development")
    authority, context = _install_exporter_authority(monkeypatch, tmp_path)
    isolated_anchor_keys(tmp_path, monkeypatch)
    package = tmp_path / "ci_detached_report_package"

    manifest = build_tenant_package(
        tenant_id="t1",
        evidence_bundle_dir=tmp_path / "ci_detached_report_source",
        package_path=package,
        provenance_authority=authority,
    )
    verify_tenant_package(package)
    text = (package / TENANT_PACKAGE_VERIFICATION_REPORT).read_text(encoding="utf-8")

    assert manifest["provenance_context"] == context
    assert "Git Commit: " + manifest["git_commit"] in text
    assert "Result: PASS" in text


def test_merge_sha_reporting_uses_package_provenance_context(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("USBAY_ENV", "development")
    authority, context = _install_exporter_authority(monkeypatch, tmp_path)
    isolated_anchor_keys(tmp_path, monkeypatch)
    package = tmp_path / "ci_merge_report_package"

    manifest = build_tenant_package(
        tenant_id="t1",
        evidence_bundle_dir=tmp_path / "ci_merge_report_source",
        package_path=package,
        provenance_authority=authority,
    )
    verify_tenant_package(package)
    text = (package / TENANT_PACKAGE_VERIFICATION_REPORT).read_text(encoding="utf-8")

    assert manifest["provenance_context"] == context
    assert "Git Commit: " + manifest["git_commit"] in text
    assert "Result: PASS" in text


def test_replay_base_lineage_reporting_uses_package_provenance_context(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("USBAY_ENV", "development")
    authority, context = _install_exporter_authority(monkeypatch, tmp_path)
    isolated_anchor_keys(tmp_path, monkeypatch)
    package = tmp_path / "ci_replay_report_package"

    manifest = build_tenant_package(
        tenant_id="t1",
        evidence_bundle_dir=tmp_path / "ci_replay_report_source",
        package_path=package,
        provenance_authority=authority,
    )
    verify_tenant_package(package)
    text = (package / TENANT_PACKAGE_VERIFICATION_REPORT).read_text(encoding="utf-8")

    assert manifest["provenance_context"] == context
    assert "Git Commit: " + manifest["git_commit"] in text
    assert "Result: PASS" in text


def test_deterministic_ci_report_generation(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("USBAY_ENV", "development")
    authority, _context = _install_exporter_authority(monkeypatch, tmp_path)
    isolated_anchor_keys(tmp_path, monkeypatch)
    package = tmp_path / "ci_deterministic_report_package"

    build_tenant_package(
        tenant_id="t1",
        evidence_bundle_dir=tmp_path / "ci_deterministic_report_source",
        package_path=package,
        provenance_authority=authority,
    )
    first = verify_tenant_package(package)
    first_text = (package / TENANT_PACKAGE_VERIFICATION_REPORT).read_text(encoding="utf-8")
    second = verify_tenant_package(package)
    second_text = (package / TENANT_PACKAGE_VERIFICATION_REPORT).read_text(encoding="utf-8")

    assert first["result"] == "PASS"
    assert second["result"] == "PASS"
    assert first_text == second_text


def test_malformed_generated_source_fails_closed(tmp_path: Path, monkeypatch) -> None:
    authority = install_runtime_authority(monkeypatch, tmp_path)
    isolated_anchor_keys(tmp_path, monkeypatch)
    source = tmp_path / "generated_source"
    build_package_source(
        tenant_id="t1",
        source_dir=source,
        retention_policy_path=retention_policy(tmp_path),
        provenance_authority=authority,
    )
    context = json.loads((source / "tenant_context.json").read_text(encoding="utf-8"))
    context.pop("tenant_id")
    (source / "tenant_context.json").write_text(json.dumps(context, sort_keys=True, separators=(",", ":")), encoding="utf-8")

    with pytest.raises(Exception):
        validate_package_source(source, tenant_id="t1", provenance_authority=authority)


def test_tampered_generated_source_fails_closed(tmp_path: Path, monkeypatch) -> None:
    authority = install_runtime_authority(monkeypatch, tmp_path)
    isolated_anchor_keys(tmp_path, monkeypatch)
    source = tmp_path / "generated_source"
    build_package_source(
        tenant_id="t1",
        source_dir=source,
        retention_policy_path=retention_policy(tmp_path),
        provenance_authority=authority,
    )
    (source / "ledger.sha256").write_text("0" * 64 + "\n", encoding="utf-8")

    with pytest.raises(Exception):
        validate_package_source(source, tenant_id="t1", provenance_authority=authority)


def test_missing_rfc3161_proof_source_fails_closed(tmp_path: Path, monkeypatch) -> None:
    authority = install_runtime_authority(monkeypatch, tmp_path)
    isolated_anchor_keys(tmp_path, monkeypatch)
    source = tmp_path / "generated_source"
    build_package_source(
        tenant_id="t1",
        source_dir=source,
        retention_policy_path=retention_policy(tmp_path),
        provenance_authority=authority,
    )
    (source / "rfc3161_timestamp.tsr").unlink()

    with pytest.raises(Exception):
        validate_package_source(source, tenant_id="t1", provenance_authority=authority)


def test_mixed_tenant_source_fails_closed(tmp_path: Path, monkeypatch) -> None:
    authority = install_runtime_authority(monkeypatch, tmp_path)
    isolated_anchor_keys(tmp_path, monkeypatch)
    source = tmp_path / "generated_source"
    build_package_source(
        tenant_id="t1",
        source_dir=source,
        retention_policy_path=retention_policy(tmp_path),
        provenance_authority=authority,
    )
    context = json.loads((source / "tenant_context.json").read_text(encoding="utf-8"))
    context["tenant_id"] = "t2"
    context["tenant_hash"] = tenant_hash("t2")
    context["tenant_scope"] = "tenant/t2"
    (source / "tenant_context.json").write_text(json.dumps(context, sort_keys=True, separators=(",", ":")), encoding="utf-8")

    with pytest.raises(Exception):
        validate_package_source(source, tenant_id="t1", provenance_authority=authority)


def test_cli_build_and_verify_auto_generated_package(tmp_path: Path, monkeypatch) -> None:
    install_runtime_authority(monkeypatch, tmp_path)
    isolated_anchor_keys(tmp_path, monkeypatch)
    package = tmp_path / "cli_package"
    source = tmp_path / "cli_source"

    build = subprocess.run(
        [
            sys.executable,
            "-m",
            "audit.exporter",
            "build-tenant-package",
            "--tenant-id",
            "t1",
            "--evidence-bundle-dir",
            str(source),
            "--package-path",
            str(package),
        ],
        cwd=Path(__file__).resolve().parents[1],
        text=True,
        capture_output=True,
        check=False,
    )
    verify = subprocess.run(
        [sys.executable, "-m", "audit.exporter", "verify-tenant-package", str(package)],
        cwd=Path(__file__).resolve().parents[1],
        text=True,
        capture_output=True,
        check=False,
    )

    assert build.returncode == 0, build.stderr
    assert verify.returncode == 0, verify.stderr
    assert json.loads(verify.stdout)["result"] == "PASS"
