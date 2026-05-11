from __future__ import annotations

import json
from dataclasses import FrozenInstanceError
from datetime import datetime, timezone
from pathlib import Path

import pytest

import gateway.app as gateway_app
from audit.immutable_ledger import append_evidence_event, export_evidence_bundle
from audit.worm_archive import WORMArchive
from security.deployment_attestation import (
    DeploymentAttestationError,
    build_release_manifest,
    canonical_json,
    commit_continuity_valid,
    environment_mode,
    github_actions_ci,
    normalized_provenance_context,
    policy_bundle_hash,
    release_hash,
    resolve_runtime_provenance_authority,
    assert_runtime_provenance_authority,
    runtime_provenance_bootstrap_diagnostics,
    sign_release_manifest,
    validate_release_manifest,
    verify_release_signature,
    write_runtime_provenance_bootstrap_diagnostics,
    write_release_manifest,
)
from security.hydra_consensus import HydraNodeDecision, evaluate_consensus, replay_registry_hash
from tests.provenance_helpers import install_runtime_authority
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


def _default_signed_manifest(git_commit: str, tenant_id: str = "t1") -> dict:
    manifest = build_release_manifest(tenant_id=tenant_id, previous_manifest=None)
    manifest["git_commit"] = git_commit
    manifest["tenant_id"] = tenant_id
    manifest["release_signature"] = sign_release_manifest(manifest)
    return manifest


def _expected_ci_mode() -> bool:
    return environment_mode() != "production" and github_actions_ci()


def _assert_canonical_provenance_context(
    context: dict,
    *,
    expected_commit: str,
    current_commit: str | None = None,
    ci_mode: bool,
    ancestor_continuity: bool,
    release_lineage: bool,
    trusted_commits: set[str] | None = None,
) -> None:
    assert context["expected_commit"] == expected_commit
    if current_commit is not None:
        assert context["current_commit"] == current_commit
    else:
        assert isinstance(context["current_commit"], str)
        assert len(context["current_commit"]) == 40
    assert context["ci_mode"] is ci_mode
    assert context["ancestor_continuity"] is ancestor_continuity
    assert context["release_lineage"] is release_lineage
    accepted = context["accepted_commit_set"]
    assert isinstance(accepted, list)
    assert accepted == sorted(set(accepted))
    assert expected_commit in accepted
    for commit in trusted_commits or set():
        assert commit in accepted


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
    _assert_canonical_provenance_context(
        result["provenance_context"],
        expected_commit="c" * 40,
        ci_mode=_expected_ci_mode(),
        ancestor_continuity=True,
        release_lineage=True,
        trusted_commits={"c" * 40},
    )


def test_build_release_manifest_is_reproducible_and_canonical(tmp_path: Path) -> None:
    node_policy, node_id = _node_policy(tmp_path)
    timestamp = "2026-05-11T00:00:00Z"

    first = build_release_manifest(
        release_id="release-test-canonical",
        deployment_timestamp=timestamp,
        activating_node_id=node_id,
        tenant_id="t1",
        node_policy_path=node_policy,
    )
    second = build_release_manifest(
        release_id="release-test-canonical",
        deployment_timestamp=timestamp,
        activating_node_id=node_id,
        tenant_id="t1",
        node_policy_path=node_policy,
    )

    assert first == second
    assert first["git_commit"]
    assert first["policy_bundle_hash"] == policy_bundle_hash()
    assert first["activating_node_id"] == node_id
    assert first["previous_release_hash"] == "GENESIS"
    assert verify_release_signature(first) is True


def test_write_release_manifest_validates_written_manifest(tmp_path: Path) -> None:
    node_policy, node_id = _node_policy(tmp_path)
    path = tmp_path / "governance_release.json"

    manifest = write_release_manifest(
        path,
        release_id="release-test-write",
        deployment_timestamp="2026-05-11T00:00:00Z",
        activating_node_id=node_id,
        tenant_id="t1",
        preserve_existing_lineage=False,
        node_policy_path=node_policy,
    )
    written = json.loads(path.read_text(encoding="utf-8"))
    summary = validate_release_manifest(
        path,
        expected_git_commit=manifest["git_commit"],
        expected_policy_bundle_hash=manifest["policy_bundle_hash"],
        node_policy_path=node_policy,
        now=datetime(2026, 5, 12, tzinfo=timezone.utc),
    )

    assert written == manifest
    assert summary["release_signature_valid"] is True
    assert summary["policy_bundle_hash"] == policy_bundle_hash()


def test_write_release_manifest_preserves_rollback_lineage(tmp_path: Path) -> None:
    node_policy, node_id = _node_policy(tmp_path)
    path = tmp_path / "governance_release.json"
    previous = write_release_manifest(
        path,
        release_id="release-test-previous",
        deployment_timestamp="2026-05-10T00:00:00Z",
        activating_node_id=node_id,
        tenant_id="t1",
        preserve_existing_lineage=False,
        node_policy_path=node_policy,
    )

    current = write_release_manifest(
        path,
        release_id="release-test-current",
        deployment_timestamp="2026-05-11T00:00:00Z",
        activating_node_id=node_id,
        tenant_id="t1",
        preserve_existing_lineage=True,
        node_policy_path=node_policy,
    )

    assert current["previous_release_hash"] == release_hash(previous)
    assert current["release_history"][-1] == previous
    validate_release_manifest(
        path,
        expected_git_commit=current["git_commit"],
        expected_policy_bundle_hash=current["policy_bundle_hash"],
        node_policy_path=node_policy,
        now=datetime(2026, 5, 12, tzinfo=timezone.utc),
    )


def test_build_release_manifest_rejects_unknown_activating_node(tmp_path: Path) -> None:
    node_policy, _node_id = _node_policy(tmp_path)

    with pytest.raises(DeploymentAttestationError, match="activating_node_unknown"):
        build_release_manifest(
            release_id="release-test-bad-node",
            deployment_timestamp="2026-05-11T00:00:00Z",
            activating_node_id="unknown-node",
            tenant_id="t1",
            node_policy_path=node_policy,
        )


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


def test_github_actions_merge_sha_normalization(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.delenv("USBAY_ENV", raising=False)
    monkeypatch.setenv("GITHUB_ACTIONS", "true")
    monkeypatch.setenv("GITHUB_REPOSITORY", "owner/repo")
    monkeypatch.setenv("GITHUB_SHA", "d" * 40)
    path = _write_manifest(tmp_path / "governance_release.json", _default_signed_manifest("d" * 40))

    context = normalized_provenance_context(path)

    _assert_canonical_provenance_context(
        context,
        expected_commit="d" * 40,
        ci_mode=True,
        ancestor_continuity=True,
        release_lineage=True,
        trusted_commits={"d" * 40},
    )


def test_runtime_provenance_authority_is_immutable_and_reused(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.delenv("USBAY_ENV", raising=False)
    monkeypatch.delenv("GITHUB_ACTIONS", raising=False)
    path = _write_manifest(tmp_path / "governance_release.json", _default_signed_manifest(current_commit := __import__("subprocess").check_output(["git", "rev-parse", "HEAD"], text=True).strip()))

    authority = resolve_runtime_provenance_authority(path)

    assert authority.context_dict() == normalized_provenance_context(path)
    assert assert_runtime_provenance_authority(authority, path) is authority
    with pytest.raises(FrozenInstanceError):
        authority.authority_id = "mutated"


def test_runtime_provenance_authority_rejects_cross_manifest_reuse(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.delenv("USBAY_ENV", raising=False)
    monkeypatch.setenv("GITHUB_ACTIONS", "true")
    monkeypatch.setenv("GITHUB_REPOSITORY", "owner/repo")
    monkeypatch.setenv("GITHUB_SHA", "1" * 40)
    first = _write_manifest(tmp_path / "first_release.json", _default_signed_manifest("1" * 40))
    second = _write_manifest(tmp_path / "second_release.json", _default_signed_manifest("2" * 40))
    authority = resolve_runtime_provenance_authority(first)

    with pytest.raises(DeploymentAttestationError, match="git_commit_mismatch|runtime_provenance_authority_mismatch"):
        assert_runtime_provenance_authority(authority, second)


def test_detached_head_normalization_from_github_head_sha(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.delenv("USBAY_ENV", raising=False)
    monkeypatch.setenv("GITHUB_ACTIONS", "true")
    monkeypatch.setenv("GITHUB_REPOSITORY", "owner/repo")
    monkeypatch.setenv("GITHUB_SHA", "a" * 40)
    monkeypatch.setenv("GITHUB_HEAD_SHA", "b" * 40)
    path = _write_manifest(tmp_path / "governance_release.json", _default_signed_manifest("b" * 40))

    context = normalized_provenance_context(path)

    _assert_canonical_provenance_context(
        context,
        expected_commit="a" * 40,
        ci_mode=True,
        ancestor_continuity=True,
        release_lineage=True,
        trusted_commits={"a" * 40, "b" * 40},
    )


def test_replay_lineage_normalization_from_github_base_sha(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.delenv("USBAY_ENV", raising=False)
    monkeypatch.setenv("GITHUB_ACTIONS", "true")
    monkeypatch.setenv("GITHUB_REPOSITORY", "owner/repo")
    monkeypatch.setenv("GITHUB_SHA", "a" * 40)
    monkeypatch.setenv("GITHUB_BASE_SHA", "c" * 40)
    path = _write_manifest(tmp_path / "governance_release.json", _default_signed_manifest("c" * 40))

    context = normalized_provenance_context(path)

    _assert_canonical_provenance_context(
        context,
        expected_commit="a" * 40,
        ci_mode=True,
        ancestor_continuity=True,
        release_lineage=True,
        trusted_commits={"a" * 40, "c" * 40},
    )


def test_github_event_payload_head_sha_normalization(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.delenv("USBAY_ENV", raising=False)
    monkeypatch.setenv("GITHUB_ACTIONS", "true")
    monkeypatch.setenv("GITHUB_REPOSITORY", "owner/repo")
    monkeypatch.setenv("GITHUB_SHA", "a" * 40)
    event_path = tmp_path / "event.json"
    event_path.write_text(
        canonical_json({"pull_request": {"head": {"sha": "e" * 40}, "base": {"sha": "f" * 40}}}),
        encoding="utf-8",
    )
    monkeypatch.setenv("GITHUB_EVENT_PATH", str(event_path))
    path = _write_manifest(tmp_path / "governance_release.json", _default_signed_manifest("e" * 40))

    context = normalized_provenance_context(path)

    _assert_canonical_provenance_context(
        context,
        expected_commit="a" * 40,
        ci_mode=True,
        ancestor_continuity=True,
        release_lineage=True,
        trusted_commits={"a" * 40, "e" * 40, "f" * 40},
    )


def test_detached_head_authority_bootstrap(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.delenv("USBAY_ENV", raising=False)
    monkeypatch.setenv("GITHUB_ACTIONS", "true")
    monkeypatch.setenv("GITHUB_REPOSITORY", "owner/repo")
    monkeypatch.setenv("GITHUB_SHA", "1" * 40)
    monkeypatch.setenv("GITHUB_HEAD_SHA", "2" * 40)
    path = _write_manifest(tmp_path / "governance_release.json", _default_signed_manifest("2" * 40))

    authority = resolve_runtime_provenance_authority(path)

    assert authority.provenance_context.ci_mode is True
    assert authority.provenance_context.ancestor_continuity is True
    assert "2" * 40 in authority.provenance_context.accepted_commit_set


def test_merge_sha_authority_bootstrap(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.delenv("USBAY_ENV", raising=False)
    monkeypatch.setenv("GITHUB_ACTIONS", "true")
    monkeypatch.setenv("GITHUB_REPOSITORY", "owner/repo")
    monkeypatch.setenv("GITHUB_SHA", "3" * 40)
    path = _write_manifest(tmp_path / "governance_release.json", _default_signed_manifest("3" * 40))

    authority = resolve_runtime_provenance_authority(path)

    assert authority.provenance_context.expected_commit == "3" * 40
    assert authority.provenance_context.ancestor_continuity is True


def test_pr_merge_runtime_authority_bootstrap_from_event_payload(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.delenv("USBAY_ENV", raising=False)
    monkeypatch.setenv("GITHUB_ACTIONS", "true")
    monkeypatch.setenv("GITHUB_REPOSITORY", "owner/repo")
    monkeypatch.setenv("GITHUB_EVENT_NAME", "pull_request")
    monkeypatch.setenv("GITHUB_SHA", "4" * 40)
    event_path = tmp_path / "event.json"
    event_path.write_text(canonical_json({"pull_request": {"head": {"sha": "5" * 40}, "merge_commit_sha": "4" * 40}}), encoding="utf-8")
    monkeypatch.setenv("GITHUB_EVENT_PATH", str(event_path))
    path = _write_manifest(tmp_path / "governance_release.json", _default_signed_manifest("5" * 40))

    authority = resolve_runtime_provenance_authority(path)

    assert authority.provenance_context.ancestor_continuity is True
    assert "5" * 40 in authority.provenance_context.accepted_commit_set


def test_replay_base_lineage_authority_bootstrap(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.delenv("USBAY_ENV", raising=False)
    monkeypatch.setenv("GITHUB_ACTIONS", "true")
    monkeypatch.setenv("GITHUB_REPOSITORY", "owner/repo")
    monkeypatch.setenv("GITHUB_SHA", "6" * 40)
    monkeypatch.setenv("GITHUB_BASE_SHA", "7" * 40)
    path = _write_manifest(tmp_path / "governance_release.json", _default_signed_manifest("7" * 40))

    authority = resolve_runtime_provenance_authority(path)

    assert authority.provenance_context.ancestor_continuity is True
    assert "7" * 40 in authority.provenance_context.accepted_commit_set


def test_workflow_dispatch_authority_bootstrap(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.delenv("USBAY_ENV", raising=False)
    monkeypatch.setenv("GITHUB_ACTIONS", "true")
    monkeypatch.setenv("GITHUB_REPOSITORY", "owner/repo")
    monkeypatch.setenv("GITHUB_EVENT_NAME", "workflow_dispatch")
    monkeypatch.setenv("GITHUB_SHA", "8" * 40)
    path = _write_manifest(tmp_path / "governance_release.json", _default_signed_manifest("8" * 40))

    authority = resolve_runtime_provenance_authority(path)

    assert authority.provenance_context.ancestor_continuity is True
    assert authority.provenance_context.expected_commit == "8" * 40


def test_merge_queue_authority_bootstrap(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.delenv("USBAY_ENV", raising=False)
    monkeypatch.setenv("GITHUB_ACTIONS", "true")
    monkeypatch.setenv("GITHUB_REPOSITORY", "owner/repo")
    monkeypatch.setenv("GITHUB_EVENT_NAME", "merge_group")
    monkeypatch.setenv("GITHUB_SHA", "9" * 40)
    event_path = tmp_path / "merge_group_event.json"
    event_path.write_text(canonical_json({"merge_group": {"head_sha": "a" * 40, "base_sha": "b" * 40}}), encoding="utf-8")
    monkeypatch.setenv("GITHUB_EVENT_PATH", str(event_path))
    path = _write_manifest(tmp_path / "governance_release.json", _default_signed_manifest("a" * 40))

    authority = resolve_runtime_provenance_authority(path)

    assert authority.provenance_context.ancestor_continuity is True
    assert "a" * 40 in authority.provenance_context.accepted_commit_set
    assert "b" * 40 in authority.provenance_context.accepted_commit_set


def test_runtime_provenance_bootstrap_diagnostics_are_deterministic(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.delenv("USBAY_ENV", raising=False)
    monkeypatch.setenv("GITHUB_ACTIONS", "true")
    monkeypatch.setenv("GITHUB_REPOSITORY", "owner/repo")
    monkeypatch.setenv("GITHUB_SHA", "c" * 40)
    path = _write_manifest(tmp_path / "governance_release.json", _default_signed_manifest("c" * 40))
    diagnostics_path = tmp_path / "runtime_provenance_bootstrap.json"

    first = write_runtime_provenance_bootstrap_diagnostics(path, diagnostics_path)
    second = runtime_provenance_bootstrap_diagnostics(path)

    assert first == second
    assert diagnostics_path.is_file()
    assert first["ancestor_continuity"] is True
    assert first["accepted_commit_candidates"] == sorted(first["accepted_commit_candidates"])
    assert "secret" not in diagnostics_path.read_text(encoding="utf-8").lower()


def test_mixed_ci_lineage_normalization_rejected(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.delenv("USBAY_ENV", raising=False)
    monkeypatch.setenv("GITHUB_ACTIONS", "true")
    monkeypatch.setenv("GITHUB_REPOSITORY", "owner/repo")
    monkeypatch.setenv("GITHUB_SHA", "a" * 40)
    monkeypatch.setenv("GITHUB_HEAD_SHA", "b" * 40)
    monkeypatch.setenv("GITHUB_BASE_SHA", "c" * 40)
    path = _write_manifest(tmp_path / "governance_release.json", _default_signed_manifest("e" * 40))

    with pytest.raises(DeploymentAttestationError, match="git_commit_mismatch"):
        normalized_provenance_context(path)


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
    install_runtime_authority(monkeypatch, tmp_path)

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
    authority = install_runtime_authority(monkeypatch, tmp_path)
    provenance_context = authority.context_dict()
    isolated_anchor_keys(tmp_path, monkeypatch)
    consensus = evaluate_consensus(
        [
            _decision("node-1", datetime.now(timezone.utc).timestamp()),
            _decision("node-2", datetime.now(timezone.utc).timestamp()),
            _decision("node-3", datetime.now(timezone.utc).timestamp()),
        ],
        provenance_authority=authority,
    )
    _assert_canonical_provenance_context(
        consensus.evidence_bundle["deployment_provenance"]["provenance_context"],
        expected_commit=provenance_context["expected_commit"],
        current_commit=provenance_context["current_commit"],
        ci_mode=provenance_context["ci_mode"],
        ancestor_continuity=provenance_context["ancestor_continuity"],
        release_lineage=provenance_context["release_lineage"],
        trusted_commits=set(provenance_context["accepted_commit_set"]),
    )

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
    export_evidence_bundle(ledger, bundle_dir, provenance_authority=authority)
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
