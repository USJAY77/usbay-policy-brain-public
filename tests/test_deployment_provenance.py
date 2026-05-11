from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

import pytest

import gateway.app as gateway_app
from audit.immutable_ledger import append_evidence_event, export_evidence_bundle
from audit.worm_archive import WORMArchive
from security.deployment_attestation import (
    DeploymentAttestationError,
    canonical_json,
    commit_continuity_valid,
    release_hash,
    sign_release_manifest,
    validate_release_manifest,
)
from security.hydra_consensus import HydraNodeDecision, evaluate_consensus, replay_registry_hash
from tests.provenance_helpers import install_valid_test_provenance
from tests.test_audit_exporter import isolated_anchor_keys
from tests.test_worm_evidence_archive import _policy as retention_policy


def _node_policy(tmp_path: Path) -> tuple[Path, str]:
    activating_node_id = "usbay-node-activation-test"
    policy = {
        "required_attestation_mode": "mock_local",
        "allowed_node_roles": ["gateway", "primary", "secondary", "offline_backup"],
        "attestation_ttl_seconds": 30,
        "require_hardware_backing": False,
        "production_rejects_mock": True,
        "enrolled_nodes": {
            "gateway-1": {
                "role": "gateway",
                "public_identity": {
                    "vendor": "USBAY",
                    "node_label": "gateway-1",
                    "public_key_id": "activation-test",
                },
            }
        },
    }
    path = tmp_path / "node_attestation_policy.json"
    path.write_text(canonical_json(policy), encoding="utf-8")
    from security.node_identity import load_node_attestation_policy

    node_id = load_node_attestation_policy(path)["enrolled_nodes"]["gateway-1"]["node_id"]
    assert node_id != activating_node_id
    return path, node_id


def _manifest(
    *,
    node_id: str,
    policy_bundle_hash: str = "b" * 64,
    git_commit: str = "c" * 40,
    previous_release_hash: str = "GENESIS",
    release_history=None,
    timestamp: str = "2026-05-11T00:00:00Z",
    tenant_id: str = "t1",
) -> dict:
    manifest = {
        "release_id": "release-test-1",
        "git_commit": git_commit,
        "policy_bundle_hash": policy_bundle_hash,
        "deployment_timestamp": timestamp,
        "activating_node_id": node_id,
        "tenant_id": tenant_id,
        "previous_release_hash": previous_release_hash,
    }
    if release_history is not None:
        manifest["release_history"] = release_history
    manifest["release_signature"] = sign_release_manifest(manifest)
    return manifest


def _write_manifest(path: Path, manifest: dict) -> Path:
    path.write_text(canonical_json(manifest), encoding="utf-8")
    return path


def test_valid_signed_release_passes(tmp_path: Path) -> None:
    node_policy, node_id = _node_policy(tmp_path)
    path = _write_manifest(tmp_path / "governance_release.json", _manifest(node_id=node_id))

    result = validate_release_manifest(
        path,
        expected_git_commit="c" * 40,
        expected_policy_bundle_hash="b" * 64,
        node_policy_path=node_policy,
        now=datetime(2026, 5, 12, tzinfo=timezone.utc),
    )

    assert result["release_signature_valid"] is True
    assert result["activating_node_id"] == node_id
    assert result["provenance_context"] == {
        "expected_commit": "c" * 40,
        "current_commit": result["provenance_context"]["current_commit"],
        "ci_mode": False,
        "accepted_commit_set": ["c" * 40],
        "ancestor_continuity": True,
        "release_lineage": True,
    }


def test_production_exact_commit_enforcement(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("USBAY_ENV", "production")
    monkeypatch.setenv("GITHUB_ACTIONS", "true")
    monkeypatch.setenv("GITHUB_REPOSITORY", "owner/repo")
    monkeypatch.setenv("GITHUB_SHA", "d" * 40)
    node_policy, node_id = _node_policy(tmp_path)
    path = _write_manifest(tmp_path / "governance_release.json", _manifest(node_id=node_id, git_commit="c" * 40))

    with pytest.raises(DeploymentAttestationError, match="git_commit_mismatch"):
        validate_release_manifest(
            path,
            expected_git_commit="d" * 40,
            expected_policy_bundle_hash="b" * 64,
            node_policy_path=node_policy,
            now=datetime(2026, 5, 12, tzinfo=timezone.utc),
        )


def test_ci_merge_sha_accepted(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.delenv("USBAY_ENV", raising=False)
    monkeypatch.setenv("GITHUB_ACTIONS", "true")
    monkeypatch.setenv("GITHUB_REPOSITORY", "owner/repo")
    monkeypatch.setenv("GITHUB_SHA", "d" * 40)
    node_policy, node_id = _node_policy(tmp_path)
    path = _write_manifest(tmp_path / "governance_release.json", _manifest(node_id=node_id, git_commit="d" * 40))

    result = validate_release_manifest(
        path,
        expected_git_commit="c" * 40,
        expected_policy_bundle_hash="b" * 64,
        node_policy_path=node_policy,
        now=datetime(2026, 5, 12, tzinfo=timezone.utc),
    )

    assert result["git_commit"] == "d" * 40


def test_detached_head_accepted_in_ci(monkeypatch) -> None:
    monkeypatch.delenv("USBAY_ENV", raising=False)
    monkeypatch.setenv("GITHUB_ACTIONS", "true")
    monkeypatch.setenv("GITHUB_REPOSITORY", "owner/repo")
    monkeypatch.setenv("GITHUB_SHA", "a" * 40)
    monkeypatch.setenv("GITHUB_HEAD_SHA", "c" * 40)

    assert commit_continuity_valid("c" * 40, "a" * 40) is True


def test_synthetic_pr_merge_commit_parent_accepted_in_ci(monkeypatch) -> None:
    monkeypatch.delenv("USBAY_ENV", raising=False)
    monkeypatch.setenv("GITHUB_ACTIONS", "true")
    monkeypatch.setenv("GITHUB_REPOSITORY", "owner/repo")
    monkeypatch.setenv("GITHUB_SHA", "a" * 40)
    monkeypatch.setenv("GITHUB_HEAD_SHA", "b" * 40)
    monkeypatch.setenv("GITHUB_BASE_SHA", "c" * 40)

    assert commit_continuity_valid("b" * 40, "a" * 40) is True


def test_invalid_unrelated_commit_rejected(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.delenv("USBAY_ENV", raising=False)
    monkeypatch.setenv("GITHUB_ACTIONS", "true")
    monkeypatch.setenv("GITHUB_REPOSITORY", "owner/repo")
    monkeypatch.setenv("GITHUB_SHA", "d" * 40)
    node_policy, node_id = _node_policy(tmp_path)
    path = _write_manifest(tmp_path / "governance_release.json", _manifest(node_id=node_id, git_commit="e" * 40))

    with pytest.raises(DeploymentAttestationError, match="git_commit_mismatch"):
        validate_release_manifest(
            path,
            expected_git_commit="c" * 40,
            expected_policy_bundle_hash="b" * 64,
            node_policy_path=node_policy,
            now=datetime(2026, 5, 12, tzinfo=timezone.utc),
        )


def test_unsigned_release_rejected(tmp_path: Path) -> None:
    node_policy, node_id = _node_policy(tmp_path)
    manifest = _manifest(node_id=node_id)
    manifest.pop("release_signature")
    path = _write_manifest(tmp_path / "governance_release.json", manifest)

    with pytest.raises(DeploymentAttestationError, match="release_manifest_invalid"):
        validate_release_manifest(path, expected_git_commit="c" * 40, expected_policy_bundle_hash="b" * 64, node_policy_path=node_policy)


def test_tampered_policy_hash_rejected(tmp_path: Path) -> None:
    node_policy, node_id = _node_policy(tmp_path)
    path = _write_manifest(tmp_path / "governance_release.json", _manifest(node_id=node_id, policy_bundle_hash="d" * 64))

    with pytest.raises(DeploymentAttestationError, match="policy_bundle_hash_mismatch"):
        validate_release_manifest(path, expected_git_commit="c" * 40, expected_policy_bundle_hash="b" * 64, node_policy_path=node_policy)


def test_rollback_chain_mismatch_rejected(tmp_path: Path) -> None:
    node_policy, node_id = _node_policy(tmp_path)
    previous = _manifest(node_id=node_id, timestamp="2026-05-10T00:00:00Z")
    current = _manifest(
        node_id=node_id,
        previous_release_hash="0" * 64,
        release_history=[previous],
    )
    path = _write_manifest(tmp_path / "governance_release.json", current)

    assert release_hash(previous) != current["previous_release_hash"]
    with pytest.raises(DeploymentAttestationError, match="previous_release_hash_mismatch"):
        validate_release_manifest(path, expected_git_commit="c" * 40, expected_policy_bundle_hash="b" * 64, node_policy_path=node_policy)


def test_wrong_activating_node_rejected(tmp_path: Path) -> None:
    node_policy, _node_id = _node_policy(tmp_path)
    path = _write_manifest(tmp_path / "governance_release.json", _manifest(node_id="unknown-node"))

    with pytest.raises(DeploymentAttestationError, match="activating_node_unknown"):
        validate_release_manifest(path, expected_git_commit="c" * 40, expected_policy_bundle_hash="b" * 64, node_policy_path=node_policy)


def test_missing_release_manifest_rejected(tmp_path: Path) -> None:
    node_policy, _node_id = _node_policy(tmp_path)

    with pytest.raises(DeploymentAttestationError, match="release_manifest_missing"):
        validate_release_manifest(tmp_path / "missing.json", expected_git_commit="c" * 40, expected_policy_bundle_hash="b" * 64, node_policy_path=node_policy)


def test_startup_provenance_validation_rejected_on_ambiguity(tmp_path: Path, monkeypatch) -> None:
    install_valid_test_provenance(monkeypatch, tmp_path)

    def _fail_closed(**_kwargs):
        raise DeploymentAttestationError("startup_provenance_ambiguity")

    monkeypatch.setattr(gateway_app, "assert_startup_release_integrity", _fail_closed)

    with pytest.raises(DeploymentAttestationError, match="startup_provenance_ambiguity"):
        gateway_app.validate_policy_registry_startup()


def _decision(node_id: str, now: float) -> HydraNodeDecision:
    policy_hash = "policy-hash-1"
    nonce_hash = "nonce-hash-1"
    return HydraNodeDecision(
        node_id=node_id,
        node_role={"node-1": "primary", "node-2": "secondary", "node-3": "offline_backup"}[node_id],
        request_hash="request-hash-1",
        policy_version="policy-v1",
        policy_hash=policy_hash,
        nonce_hash=nonce_hash,
        replay_registry_hash=replay_registry_hash(policy_hash, nonce_hash),
        nonce_state="unused",
        tenant_id="t1",
        tenant_hash=__import__("hashlib").sha256(b"t1").hexdigest(),
        attestation_timestamp=now,
        attestation_hash=f"attestation-{node_id}",
        attestation_node_id=f"attested-{node_id}",
        attestation_provider_mode="mock_local",
        decision="allow",
        reason="allow",
        timestamp=now,
    )


def test_deployment_provenance_bound_into_consensus_export_and_archive(tmp_path: Path, monkeypatch) -> None:
    provenance_context = install_valid_test_provenance(monkeypatch, tmp_path)
    isolated_anchor_keys(tmp_path, monkeypatch)
    consensus = evaluate_consensus(
        [
            _decision("node-1", datetime.now(timezone.utc).timestamp()),
            _decision("node-2", datetime.now(timezone.utc).timestamp()),
            _decision("node-3", datetime.now(timezone.utc).timestamp()),
        ],
        provenance_context=provenance_context,
    )
    assert consensus.evidence_bundle["deployment_provenance"]["provenance_context"] == provenance_context

    ledger = tmp_path / "evidence.jsonl"
    append_evidence_event(
        ledger,
        action="consensus_allow",
        decision={
            "node_id": "node-1",
            "tenant_id": "t1",
            "tenant_hash": __import__("hashlib").sha256(b"t1").hexdigest(),
            "policy_hash": "policy-hash-1",
            "consensus_result": "ALLOW",
            "consensus_evidence_bundle": consensus.evidence_bundle,
        },
    )
    bundle_dir = tmp_path / "bundle"
    export_evidence_bundle(ledger, bundle_dir, provenance_context=provenance_context)
    assert (bundle_dir / "governance_release.json").is_file()
    verification = json.loads((bundle_dir / "timestamp_verification.json").read_text(encoding="utf-8"))
    assert verification["message_imprint_valid"] is True

    archive = WORMArchive(tmp_path / "archive", retention_policy_path=retention_policy(tmp_path))
    manifest = archive.archive_bundle(bundle_dir, now=datetime(2026, 5, 11, tzinfo=timezone.utc))
    assert "governance_release.json" in manifest["object_hashes"]
    assert "deployment_provenance_context" in manifest


def test_no_secret_leakage_regression(tmp_path: Path) -> None:
    node_policy, node_id = _node_policy(tmp_path)
    path = _write_manifest(tmp_path / "governance_release.json", _manifest(node_id=node_id))
    result = validate_release_manifest(path, expected_git_commit="c" * 40, expected_policy_bundle_hash="b" * 64, node_policy_path=node_policy)
    text = json.dumps(result, sort_keys=True).lower()

    assert "raw_nonce" not in text
    assert "approval" not in text
    assert "private" + "_" + "key" not in text
    assert "secret" not in text
