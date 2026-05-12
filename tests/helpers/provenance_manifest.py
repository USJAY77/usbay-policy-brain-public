from __future__ import annotations

from pathlib import Path
from typing import Any

from security.deployment_attestation import (
    build_release_manifest,
    current_git_commit,
    ensure_runtime_release_manifest,
    policy_bundle_hash,
    sign_release_manifest,
)
from tests.helpers.provenance_generation import write_manifest_generation_audit
from tests.helpers.provenance_tenant import DEFAULT_TEST_TENANT_ID

# Purpose: generate canonical temporary governance release manifests for tests.
# Governance scope: release signature, policy bundle hash, git commit continuity.
# Fail-closed expectation: generation uses runtime writer/validators, not static fixtures.
# Sensitive-data handling: no private keys, approval material, or raw secrets are emitted.


def valid_test_release_manifest(tenant_id: str = DEFAULT_TEST_TENANT_ID) -> dict[str, Any]:
    manifest = build_release_manifest(tenant_id=tenant_id, previous_manifest=None)
    manifest["git_commit"] = current_git_commit()
    manifest["policy_bundle_hash"] = policy_bundle_hash()
    manifest["tenant_id"] = tenant_id
    manifest["release_signature"] = sign_release_manifest(manifest)
    return manifest


def ensure_test_release_manifest(monkeypatch, tmp_path: Path, tenant_id: str = DEFAULT_TEST_TENANT_ID) -> Path:
    release_path = tmp_path / f"generated_governance_release_{tenant_id}.json"
    ensure_runtime_release_manifest(release_path, tenant_id=tenant_id, force=True)
    write_manifest_generation_audit(tmp_path, release_path, tenant_id)
    monkeypatch.setenv("USBAY_GOVERNANCE_RELEASE_PATH", str(release_path))
    return release_path
