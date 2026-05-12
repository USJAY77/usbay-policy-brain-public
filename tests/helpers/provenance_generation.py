from __future__ import annotations

from pathlib import Path
from typing import Any

from security.deployment_attestation import canonical_json

# Purpose: write deterministic diagnostics for generated test release manifests.
# Governance scope: proves tests used generated manifests outside source control.
# Fail-closed expectation: this module does not validate manifests; runtime validators do.
# Sensitive-data handling: diagnostics contain paths, tenant IDs, and hashes only.


def diagnostics_dir(tmp_path: Path) -> Path:
    path = tmp_path / "runtime_authority_diagnostics"
    path.mkdir(parents=True, exist_ok=True)
    return path


def write_json_diagnostic(tmp_path: Path, name: str, payload: dict[str, Any]) -> None:
    (diagnostics_dir(tmp_path) / name).write_text(
        canonical_json(payload) + "\n",
        encoding="utf-8",
    )


def write_manifest_generation_audit(tmp_path: Path, release_path: Path, tenant_id: str) -> None:
    write_json_diagnostic(
        tmp_path,
        "generated_manifest_path.json",
        {"generated_manifest_path": str(release_path), "tracked_repo_manifest_required": False},
    )
    write_json_diagnostic(
        tmp_path,
        "manifest_generation_audit.json",
        {
            "generated_manifest_path": str(release_path),
            "tenant_id": tenant_id,
            "source": "canonical_runtime_writer",
            "tracked_repo_manifest_required": False,
        },
    )
