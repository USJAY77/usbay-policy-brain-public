from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import audit.immutable_ledger as immutable_ledger
import gateway.app as gateway_app
from security.deployment_attestation import (
    RuntimeProvenanceAuthority,
    canonical_json,
    current_git_commit,
    policy_bundle_hash,
    resolve_runtime_provenance_authority,
    sign_release_manifest,
    validate_release_manifest,
)


def current_authority_lineage_snapshot(authority: RuntimeProvenanceAuthority) -> dict[str, Any]:
    lineage = authority.context_dict()
    return {
        "authority_id": authority.authority_id,
        "authority_release_path": authority.release_path,
        "release_hash": authority.release_hash,
        "policy_bundle_hash": authority.policy_bundle_hash,
        "tenant_id": authority.tenant_id,
        "expected_commit": lineage["expected_commit"],
        "current_commit": lineage["current_commit"],
        "accepted_commit_set": lineage["accepted_commit_set"],
        "ancestor_continuity": lineage["ancestor_continuity"],
        "ci_mode": lineage["ci_mode"],
        "release_lineage": lineage["release_lineage"],
        "lineage_source": "RuntimeProvenanceAuthority",
    }


def write_authority_lineage_diagnostics(
    tmp_path: Path,
    authority: RuntimeProvenanceAuthority,
    manifest: dict[str, Any],
) -> None:
    diagnostics_dir = tmp_path / "runtime_authority_diagnostics"
    diagnostics_dir.mkdir(parents=True, exist_ok=True)
    identity = authority.to_dict()
    lineage = authority.context_dict()
    lineage_sync = current_authority_lineage_snapshot(authority)
    expected_vs_actual = {
        "authority_expected_commit": lineage["expected_commit"],
        "authority_current_commit": lineage["current_commit"],
        "release_git_commit": manifest["git_commit"],
        "accepted_commit_set": lineage["accepted_commit_set"],
        "ancestor_continuity": lineage["ancestor_continuity"],
        "ci_mode": lineage["ci_mode"],
        "source": "RuntimeProvenanceAuthority",
    }
    (diagnostics_dir / "test_runtime_authority_identity.json").write_text(
        canonical_json(identity) + "\n",
        encoding="utf-8",
    )
    (diagnostics_dir / "test_authority_lineage_summary.json").write_text(
        canonical_json(lineage) + "\n",
        encoding="utf-8",
    )
    (diagnostics_dir / "test_lineage_sync_report.json").write_text(
        canonical_json(lineage_sync) + "\n",
        encoding="utf-8",
    )
    (diagnostics_dir / "expected_vs_actual_commit.json").write_text(
        canonical_json(expected_vs_actual) + "\n",
        encoding="utf-8",
    )
    (diagnostics_dir / "authority_lineage_resolution.json").write_text(
        canonical_json(lineage_sync) + "\n",
        encoding="utf-8",
    )


def valid_test_release_manifest(tenant_id: str = "t1") -> dict[str, Any]:
    manifest = json.loads(Path("governance_release.json").read_text(encoding="utf-8"))
    manifest["git_commit"] = current_git_commit()
    manifest["policy_bundle_hash"] = policy_bundle_hash()
    manifest["tenant_id"] = tenant_id
    manifest["release_signature"] = sign_release_manifest(manifest)
    return manifest


def install_runtime_authority(monkeypatch, tmp_path: Path, tenant_id: str = "t1") -> RuntimeProvenanceAuthority:
    manifest = valid_test_release_manifest(tenant_id=tenant_id)
    release_path = tmp_path / f"valid_governance_release_{tenant_id}.json"
    release_path.write_text(canonical_json(manifest), encoding="utf-8")
    authority = resolve_runtime_provenance_authority(release_path)
    missing = object()

    def _validate_release_manifest(path=missing, *args, **kwargs):
        if path is missing:
            return validate_release_manifest(release_path, *args, **kwargs)
        return validate_release_manifest(path, *args, **kwargs)

    import audit.exporter as audit_exporter

    write_authority_lineage_diagnostics(tmp_path, authority, manifest)

    monkeypatch.setattr(gateway_app, "runtime_provenance_authority", lambda: authority)
    monkeypatch.setattr(immutable_ledger, "load_release_manifest", lambda: manifest)
    monkeypatch.setattr(immutable_ledger, "validate_release_manifest", _validate_release_manifest)
    monkeypatch.setattr(audit_exporter, "resolve_runtime_provenance_authority", lambda path=release_path: authority)
    monkeypatch.setattr(audit_exporter, "validate_release_manifest", _validate_release_manifest)
    return authority
