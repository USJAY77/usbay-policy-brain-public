from __future__ import annotations

from typing import Any

from security.deployment_attestation import RuntimeProvenanceAuthority

# Purpose: expose authority-derived CI/runtime lineage snapshots.
# Governance scope: immutable RuntimeProvenanceAuthority continuity evidence.
# Fail-closed expectation: no synthetic commit hashes or fallback lineage are created here.
# Sensitive-data handling: snapshots include commit and authority hashes only, never secrets.


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
