from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

import pytest

from audit.immutable_ledger import append_evidence_event, export_evidence_bundle
from audit.worm_archive import WORMArchive, WORMArchiveError, load_retention_policy
from security.deployment_attestation import sign_release_manifest
from tests.provenance_helpers import install_valid_test_provenance
from tests.test_audit_exporter import isolated_anchor_keys


def _decision():
    return {
        "node_id": "node-1",
        "tenant_id": "t1",
        "tenant_hash": __import__("hashlib").sha256(b"t1").hexdigest(),
        "policy_hash": "policy-hash-1",
        "consensus_result": "ALLOW",
        "nonce_hash": "nonce-hash-1",
        "request_hash": "request-hash-1",
        "consensus_evidence_bundle": {
            "node_ids": ["node-1", "node-2", "node-3"],
            "timestamps": {"node-1": 1, "node-2": 1, "node-3": 1},
            "policy_hash": "policy-hash-1",
            "tenant_id": "t1",
            "tenant_hash": __import__("hashlib").sha256(b"t1").hexdigest(),
            "consensus_result": "allow",
            "attestation_evidence": [
                {
                    "logical_node_id": "node-1",
                    "node_id": "attested-node-1",
                    "node_role": "primary",
                    "tenant_id": "t1",
                    "tenant_hash": __import__("hashlib").sha256(b"t1").hexdigest(),
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


def _policy(tmp_path: Path, **overrides) -> Path:
    payload = {
        "default_retention_days": 30,
        "legal_hold": False,
        "delete_prohibited_before": "2030-01-01T00:00:00Z",
        "export_retention_class": "governance_evidence_worm",
    }
    payload.update(overrides)
    path = tmp_path / "retention_policy.json"
    path.write_text(json.dumps(payload, sort_keys=True), encoding="utf-8")
    return path


def _bundle(tmp_path: Path, monkeypatch) -> Path:
    provenance_context = install_valid_test_provenance(monkeypatch, tmp_path)
    isolated_anchor_keys(tmp_path, monkeypatch)
    ledger = tmp_path / "evidence.jsonl"
    append_evidence_event(ledger, action="consensus_allow", decision=_decision())
    bundle_dir = tmp_path / "bundle"
    export_evidence_bundle(ledger, bundle_dir, provenance_context=provenance_context)
    return bundle_dir


def _archive(tmp_path: Path, monkeypatch, **policy_overrides):
    bundle = _bundle(tmp_path, monkeypatch)
    policy = _policy(tmp_path, **policy_overrides)
    archive = WORMArchive(tmp_path / "archive", retention_policy_path=policy)
    manifest = archive.archive_bundle(bundle, now=datetime(2026, 1, 1, tzinfo=timezone.utc))
    return archive, manifest, bundle


def test_valid_worm_archive_passes(tmp_path, monkeypatch) -> None:
    archive, manifest, _bundle_dir = _archive(tmp_path, monkeypatch)

    assert manifest["primary_region"] == "usbay-primary"
    assert manifest["secondary_region"] == "usbay-secondary"
    assert manifest["replication_status"] == "verified"
    assert manifest["archive_mode"] == "local_mock"
    assert manifest["tenant_id"] == "t1"
    assert manifest["attestation_evidence_hash"]
    assert archive.validate_archive(manifest["object_id"]) is True


def test_worm_archive_path_uses_canonical_ci_validator(tmp_path, monkeypatch) -> None:
    monkeypatch.delenv("USBAY_ENV", raising=False)
    monkeypatch.setenv("GITHUB_ACTIONS", "true")
    monkeypatch.setenv("GITHUB_REPOSITORY", "owner/repo")
    monkeypatch.setenv("GITHUB_SHA", "d" * 40)
    bundle = _bundle(tmp_path, monkeypatch)
    release_path = bundle / "governance_release.json"
    release = json.loads(release_path.read_text(encoding="utf-8"))
    release["git_commit"] = "d" * 40
    release["release_signature"] = sign_release_manifest(release)
    release_path.write_text(json.dumps(release, sort_keys=True, separators=(",", ":")), encoding="utf-8")
    archive = WORMArchive(tmp_path / "archive", retention_policy_path=_policy(tmp_path))

    manifest = archive.archive_bundle(bundle)

    assert manifest["tenant_id"] == "t1"
    context = manifest["deployment_provenance_context"]
    assert context["ci_mode"] is True
    assert "d" * 40 in context["accepted_commit_set"]


def test_worm_archive_rejects_unrelated_ci_commit(tmp_path, monkeypatch) -> None:
    monkeypatch.delenv("USBAY_ENV", raising=False)
    monkeypatch.setenv("GITHUB_ACTIONS", "true")
    monkeypatch.setenv("GITHUB_REPOSITORY", "owner/repo")
    monkeypatch.setenv("GITHUB_SHA", "d" * 40)
    bundle = _bundle(tmp_path, monkeypatch)
    release_path = bundle / "governance_release.json"
    release = json.loads(release_path.read_text(encoding="utf-8"))
    release["git_commit"] = "e" * 40
    release["release_signature"] = sign_release_manifest(release)
    release_path.write_text(json.dumps(release, sort_keys=True, separators=(",", ":")), encoding="utf-8")
    archive = WORMArchive(tmp_path / "archive", retention_policy_path=_policy(tmp_path))

    with pytest.raises(WORMArchiveError, match="git_commit_mismatch"):
        archive.archive_bundle(bundle)


def test_overwrite_attempt_rejected(tmp_path, monkeypatch) -> None:
    archive, manifest, bundle = _archive(tmp_path, monkeypatch)

    with pytest.raises(WORMArchiveError, match="worm_overwrite_rejected"):
        archive.archive_bundle(bundle)

    assert archive.validate_archive(manifest["object_id"]) is True


def test_delete_during_retention_rejected(tmp_path, monkeypatch) -> None:
    archive, manifest, _bundle_dir = _archive(tmp_path, monkeypatch)

    with pytest.raises(WORMArchiveError, match="retention_window_active"):
        archive.delete_archive(manifest["object_id"], now=datetime(2026, 1, 2, tzinfo=timezone.utc))


def test_legal_hold_blocks_deletion(tmp_path, monkeypatch) -> None:
    archive, manifest, _bundle_dir = _archive(tmp_path, monkeypatch, legal_hold=True)

    with pytest.raises(WORMArchiveError, match="legal_hold_active"):
        archive.delete_archive(manifest["object_id"], now=datetime(2040, 1, 1, tzinfo=timezone.utc))


def test_replica_mismatch_fails_closed(tmp_path, monkeypatch) -> None:
    archive, manifest, _bundle_dir = _archive(tmp_path, monkeypatch)
    replica_file = (
        tmp_path
        / "archive"
        / "tenant"
        / manifest["tenant_id"]
        / manifest["secondary_region"]
        / manifest["object_id"]
        / "ledger.sha256"
    )
    replica_file.write_text("0" * 64 + "\n", encoding="utf-8")

    with pytest.raises(WORMArchiveError, match="replica_hash_mismatch"):
        archive.validate_archive(manifest["object_id"])


def test_missing_manifest_fails_closed(tmp_path, monkeypatch) -> None:
    archive, manifest, _bundle_dir = _archive(tmp_path, monkeypatch)
    (
        tmp_path
        / "archive"
        / "tenant"
        / manifest["tenant_id"]
        / manifest["object_id"]
        / "evidence_archive_manifest.json"
    ).unlink()

    with pytest.raises(WORMArchiveError, match="archive_manifest_missing"):
        archive.validate_archive(manifest["object_id"])


def test_invalid_retention_policy_fails_closed(tmp_path) -> None:
    policy = _policy(tmp_path, default_retention_days=0)

    with pytest.raises(WORMArchiveError, match="invalid_retention_policy"):
        load_retention_policy(policy)


def test_secret_leakage_fails_closed(tmp_path, monkeypatch) -> None:
    bundle = _bundle(tmp_path, monkeypatch)
    with (bundle / "audit.jsonl").open("a", encoding="utf-8") as handle:
        handle.write('{"raw_nonce":"do-not-archive"}\n')
    archive = WORMArchive(tmp_path / "archive", retention_policy_path=_policy(tmp_path))

    with pytest.raises(WORMArchiveError, match="archive_secret_leakage_detected"):
        archive.archive_bundle(bundle)


def test_local_mock_allowed_only_in_non_production_mode(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("USBAY_ENV", "production")

    with pytest.raises(WORMArchiveError, match="worm_archive_unavailable_in_production"):
        WORMArchive(tmp_path / "archive", archive_mode="local_mock", retention_policy_path=_policy(tmp_path))


def test_external_worm_mode_constructs_in_production(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("USBAY_ENV", "production")

    archive = WORMArchive(tmp_path / "archive", archive_mode="external_worm", retention_policy_path=_policy(tmp_path))

    assert archive.archive_mode == "external_worm"
