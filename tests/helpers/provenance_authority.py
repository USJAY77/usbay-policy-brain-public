from __future__ import annotations

import json
from pathlib import Path

import audit.immutable_ledger as immutable_ledger
import gateway.app as gateway_app
from security.deployment_attestation import (
    RuntimeProvenanceAuthority,
    resolve_runtime_provenance_authority,
    validate_release_manifest,
)
from tests.helpers.provenance_bootstrap import write_authority_lineage_diagnostics
from tests.helpers.provenance_manifest import ensure_test_release_manifest
from tests.helpers.provenance_tenant import DEFAULT_TEST_TENANT_ID

# Purpose: install immutable RuntimeProvenanceAuthority into governance test paths.
# Governance scope: runtime startup, ledger export, package export, and gateway validation.
# Fail-closed expectation: all monkeypatched validators delegate to canonical validation.
# Sensitive-data handling: only signed manifests and authority metadata are loaded.


def install_runtime_authority(
    monkeypatch,
    tmp_path: Path,
    tenant_id: str = DEFAULT_TEST_TENANT_ID,
) -> RuntimeProvenanceAuthority:
    release_path = ensure_test_release_manifest(monkeypatch, tmp_path, tenant_id=tenant_id)
    manifest = json.loads(release_path.read_text(encoding="utf-8"))
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
