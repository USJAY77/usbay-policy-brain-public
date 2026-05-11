from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import audit.immutable_ledger as immutable_ledger
import gateway.app as gateway_app
from security.deployment_attestation import (
    canonical_json,
    current_git_commit,
    policy_bundle_hash,
    sign_release_manifest,
    validate_release_manifest,
)


def valid_test_release_manifest(tenant_id: str = "t1") -> dict[str, Any]:
    manifest = json.loads(Path("governance_release.json").read_text(encoding="utf-8"))
    manifest["git_commit"] = current_git_commit()
    manifest["policy_bundle_hash"] = policy_bundle_hash()
    manifest["tenant_id"] = tenant_id
    manifest["release_signature"] = sign_release_manifest(manifest)
    return manifest


def install_valid_test_provenance(monkeypatch, tmp_path: Path, tenant_id: str = "t1") -> dict[str, Any]:
    manifest = valid_test_release_manifest(tenant_id=tenant_id)
    release_path = tmp_path / f"valid_governance_release_{tenant_id}.json"
    release_path.write_text(canonical_json(manifest), encoding="utf-8")
    summary = validate_release_manifest(release_path, expected_tenant_id=tenant_id)
    context = summary["provenance_context"]
    missing = object()

    def _validate_release_manifest(path=missing, *args, **kwargs):
        if path is missing:
            return validate_release_manifest(release_path, *args, **kwargs)
        return validate_release_manifest(path, *args, **kwargs)

    import audit.exporter as audit_exporter

    monkeypatch.setattr(gateway_app, "runtime_provenance_context", lambda: context)
    monkeypatch.setattr(immutable_ledger, "load_release_manifest", lambda: manifest)
    monkeypatch.setattr(immutable_ledger, "validate_release_manifest", _validate_release_manifest)
    monkeypatch.setattr(audit_exporter, "normalized_provenance_context", lambda path=release_path: context)
    monkeypatch.setattr(audit_exporter, "validate_release_manifest", _validate_release_manifest)
    return context


def valid_test_provenance_context() -> dict[str, Any]:
    manifest = valid_test_release_manifest()
    release_path = Path("/tmp") / "usbay_valid_test_release_manifest.json"
    release_path.write_text(canonical_json(manifest), encoding="utf-8")
    return validate_release_manifest(release_path)["provenance_context"]
