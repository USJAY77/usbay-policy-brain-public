"""Hash-only staging manifest generation for approved publication scope."""

from __future__ import annotations

import json
from typing import Any

from publication.commit_scope_validator import validate_commit_scope
from publication.models import CommitScopeResult, hash_payload


def generate_staging_manifest(candidate_files: list[str] | tuple[str, ...] | None) -> dict[str, Any]:
    scope_result = validate_commit_scope(candidate_files)
    return manifest_from_scope_result(scope_result)


def manifest_from_scope_result(scope_result: CommitScopeResult) -> dict[str, Any]:
    manifest = {
        "approved": scope_result.approved,
        "policy_version": scope_result.policy_version,
        "reason": scope_result.reason,
        "staged_files": scope_result.staged_files if scope_result.approved else (),
        "rejected_files": scope_result.rejected_files,
        "scope_evidence_hash": scope_result.evidence_hash,
        "raw_file_content_stored": False,
    }
    return {
        **manifest,
        "manifest_hash": hash_payload(manifest),
    }


def staging_manifest_json(candidate_files: list[str] | tuple[str, ...] | None) -> str:
    return json.dumps(generate_staging_manifest(candidate_files), sort_keys=True, indent=2)
