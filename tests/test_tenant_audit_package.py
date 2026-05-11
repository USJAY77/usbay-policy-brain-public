from __future__ import annotations

import json
import shutil
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

import pytest

from audit.exporter import build_package_source, build_tenant_package, validate_package_source, verify_tenant_package
from audit.immutable_ledger import append_evidence_event, export_evidence_bundle
from audit.worm_archive import WORMArchive
from security.tenant_context import tenant_hash
from tests.provenance_helpers import install_valid_test_provenance
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
    provenance_context = install_valid_test_provenance(monkeypatch, tmp_path)
    isolated_anchor_keys(tmp_path, monkeypatch)
    ledger = tmp_path / "evidence.jsonl"
    append_evidence_event(ledger, action="consensus_allow", decision=_decision("t1"))
    bundle_dir = tmp_path / "bundle"
    export_evidence_bundle(ledger, bundle_dir, provenance_context=provenance_context)
    archive = WORMArchive(tmp_path / "archive", retention_policy_path=retention_policy(tmp_path))
    worm_manifest = archive.archive_bundle(bundle_dir, now=datetime(2026, 1, 1, tzinfo=timezone.utc))
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
    )
    return package_dir


def _mutated_package(tmp_path: Path, monkeypatch) -> Path:
    source = _build_package(tmp_path, monkeypatch)
    target = tmp_path / "mutated_package"
    shutil.copytree(source, target)
    return target


def test_valid_tenant_package_passes(tmp_path: Path, monkeypatch) -> None:
    package = _build_package(tmp_path, monkeypatch)

    report = verify_tenant_package(package)
    manifest = json.loads((package / "verification_manifest.json").read_text(encoding="utf-8"))

    assert report["result"] == "PASS"
    assert manifest["tenant_id"] == "t1"
    assert manifest["tenant_hash"] == tenant_hash("t1")
    assert manifest["package_hash"]


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


def test_modified_ledger_fails_closed(tmp_path: Path, monkeypatch) -> None:
    package = _mutated_package(tmp_path, monkeypatch)
    with (package / "audit.jsonl").open("a", encoding="utf-8") as handle:
        handle.write('{"tenant_id":"t1","tenant_hash":"' + tenant_hash("t1") + '"}\n')

    report = verify_tenant_package(package)

    assert report["result"] == "FAIL"
    assert any("LEDGER" in control or "AUDIT" in control for control in report["failed_control_ids"])


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


def test_offline_verification_passes_without_runtime_services(tmp_path: Path, monkeypatch) -> None:
    package = _build_package(tmp_path, monkeypatch)
    monkeypatch.setenv("REQUIRE_REDIS", "true")
    monkeypatch.delenv("REDIS_URL", raising=False)

    report = verify_tenant_package(package)

    assert report["result"] == "PASS"


def test_build_package_source_generates_offline_verifiable_source(tmp_path: Path, monkeypatch) -> None:
    install_valid_test_provenance(monkeypatch, tmp_path)
    isolated_anchor_keys(tmp_path, monkeypatch)
    source = tmp_path / "generated_source"

    summary = build_package_source(
        tenant_id="t1",
        source_dir=source,
        retention_policy_path=retention_policy(tmp_path),
        now=datetime(2026, 1, 1, tzinfo=timezone.utc),
    )

    assert summary["tenant_id"] == "t1"
    assert validate_package_source(source, tenant_id="t1")["tenant_id"] == "t1"
    assert verify_tenant_package(source)["result"] == "FAIL"
    assert (source / "audit.jsonl").is_file()
    assert (source / "rfc3161_timestamp.tsr").is_file()
    assert (source / "evidence_archive_manifest.json").is_file()


def test_build_tenant_package_auto_generates_missing_source(tmp_path: Path, monkeypatch) -> None:
    install_valid_test_provenance(monkeypatch, tmp_path)
    isolated_anchor_keys(tmp_path, monkeypatch)
    source = tmp_path / "missing_source"
    package = tmp_path / "package"

    manifest = build_tenant_package(
        tenant_id="t1",
        package_path=package,
        evidence_bundle_dir=source,
    )

    assert manifest["tenant_id"] == "t1"
    assert source.is_dir()
    assert verify_tenant_package(package)["result"] == "PASS"


def test_malformed_generated_source_fails_closed(tmp_path: Path, monkeypatch) -> None:
    install_valid_test_provenance(monkeypatch, tmp_path)
    isolated_anchor_keys(tmp_path, monkeypatch)
    source = tmp_path / "generated_source"
    build_package_source(tenant_id="t1", source_dir=source, retention_policy_path=retention_policy(tmp_path))
    context = json.loads((source / "tenant_context.json").read_text(encoding="utf-8"))
    context.pop("tenant_id")
    (source / "tenant_context.json").write_text(json.dumps(context, sort_keys=True, separators=(",", ":")), encoding="utf-8")

    with pytest.raises(Exception):
        validate_package_source(source, tenant_id="t1")


def test_tampered_generated_source_fails_closed(tmp_path: Path, monkeypatch) -> None:
    install_valid_test_provenance(monkeypatch, tmp_path)
    isolated_anchor_keys(tmp_path, monkeypatch)
    source = tmp_path / "generated_source"
    build_package_source(tenant_id="t1", source_dir=source, retention_policy_path=retention_policy(tmp_path))
    (source / "ledger.sha256").write_text("0" * 64 + "\n", encoding="utf-8")

    with pytest.raises(Exception):
        validate_package_source(source, tenant_id="t1")


def test_missing_rfc3161_proof_source_fails_closed(tmp_path: Path, monkeypatch) -> None:
    install_valid_test_provenance(monkeypatch, tmp_path)
    isolated_anchor_keys(tmp_path, monkeypatch)
    source = tmp_path / "generated_source"
    build_package_source(tenant_id="t1", source_dir=source, retention_policy_path=retention_policy(tmp_path))
    (source / "rfc3161_timestamp.tsr").unlink()

    with pytest.raises(Exception):
        validate_package_source(source, tenant_id="t1")


def test_mixed_tenant_source_fails_closed(tmp_path: Path, monkeypatch) -> None:
    install_valid_test_provenance(monkeypatch, tmp_path)
    isolated_anchor_keys(tmp_path, monkeypatch)
    source = tmp_path / "generated_source"
    build_package_source(tenant_id="t1", source_dir=source, retention_policy_path=retention_policy(tmp_path))
    context = json.loads((source / "tenant_context.json").read_text(encoding="utf-8"))
    context["tenant_id"] = "t2"
    context["tenant_hash"] = tenant_hash("t2")
    context["tenant_scope"] = "tenant/t2"
    (source / "tenant_context.json").write_text(json.dumps(context, sort_keys=True, separators=(",", ":")), encoding="utf-8")

    with pytest.raises(Exception):
        validate_package_source(source, tenant_id="t1")


def test_cli_build_and_verify_auto_generated_package(tmp_path: Path, monkeypatch) -> None:
    install_valid_test_provenance(monkeypatch, tmp_path)
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
