from __future__ import annotations

from pathlib import Path
from typing import Any

from security.deployment_attestation import RuntimeProvenanceAuthority
from tests.helpers.provenance_ci import current_authority_lineage_snapshot
from tests.helpers.provenance_generation import write_json_diagnostic

# Purpose: capture deterministic RuntimeProvenanceAuthority bootstrap diagnostics.
# Governance scope: authority identity, accepted lineage, current/expected commit evidence.
# Fail-closed expectation: diagnostics are derived from an already validated authority only.
# Sensitive-data handling: no secrets, private keys, raw nonces, or approval contents.


def write_authority_lineage_diagnostics(
    tmp_path: Path,
    authority: RuntimeProvenanceAuthority,
    manifest: dict[str, Any],
) -> None:
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
    write_json_diagnostic(tmp_path, "test_runtime_authority_identity.json", identity)
    write_json_diagnostic(tmp_path, "test_authority_lineage_summary.json", lineage)
    write_json_diagnostic(tmp_path, "test_lineage_sync_report.json", lineage_sync)
    write_json_diagnostic(tmp_path, "expected_vs_actual_commit.json", expected_vs_actual)
    write_json_diagnostic(tmp_path, "authority_lineage_resolution.json", lineage_sync)
