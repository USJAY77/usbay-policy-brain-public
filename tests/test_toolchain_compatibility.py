from __future__ import annotations

import json

from governance.toolchain_compatibility import (
    GH_PR_VIEW_FIELD_LIST,
    PR_MERGE_STATE_NORMALIZED,
    PR_MERGE_STATE_UNDETERMINED,
    TOOLCHAIN_SCHEMA_UNSUPPORTED_FIELD,
    ToolchainCompatibilityError,
    normalize_gh_pr_merge_state,
    toolchain_audit_evidence,
    validate_gh_pr_view_fields,
)


SHA_MAIN = "a" * 40


def test_supported_fields_pass_validation() -> None:
    evidence = validate_gh_pr_view_fields(GH_PR_VIEW_FIELD_LIST)

    assert evidence["tool_name"] == "gh"
    assert evidence["command_family"] == "pr view"
    assert evidence["reason_code"] == "TOOLCHAIN_SCHEMA_VALIDATED"
    assert evidence["supported_field_list_hash"]
    assert evidence["requested_field_list_hash"]


def test_unsupported_merged_field_rejected_before_gh_execution() -> None:
    try:
        validate_gh_pr_view_fields("number,merged,mergeCommit")
    except ToolchainCompatibilityError as exc:
        assert exc.reason_code == TOOLCHAIN_SCHEMA_UNSUPPORTED_FIELD
        assert exc.audit_evidence["reason_code"] == TOOLCHAIN_SCHEMA_UNSUPPORTED_FIELD
    else:
        raise AssertionError("unsupported gh field was accepted")


def test_missing_merge_commit_fails_closed() -> None:
    try:
        normalize_gh_pr_merge_state(
            {
                "state": "MERGED",
                "mergedAt": "2026-05-19T00:00:00Z",
                "mergeCommit": None,
            }
        )
    except ToolchainCompatibilityError as exc:
        assert exc.reason_code == PR_MERGE_STATE_UNDETERMINED
    else:
        raise AssertionError("merged PR without merge commit should fail closed")


def test_merged_state_with_merged_at_and_merge_commit_passes() -> None:
    normalized = normalize_gh_pr_merge_state(
        {
            "state": "MERGED",
            "mergedAt": "2026-05-19T00:00:00Z",
            "mergeCommit": {"oid": SHA_MAIN},
            "mergeStateStatus": "CLEAN",
            "mergedBy": {"login": "human"},
        }
    )

    assert normalized["pr_merged"] is True
    assert normalized["merge_commit_sha"] == SHA_MAIN
    assert normalized["reason_code"] == PR_MERGE_STATE_NORMALIZED
    assert normalized["audit_evidence"]["reason_code"] == PR_MERGE_STATE_NORMALIZED


def test_contradictory_state_fails_closed() -> None:
    try:
        normalize_gh_pr_merge_state(
            {
                "state": "CLOSED",
                "mergedAt": "2026-05-19T00:00:00Z",
                "mergeCommit": {"oid": SHA_MAIN},
            }
        )
    except ToolchainCompatibilityError as exc:
        assert exc.reason_code == PR_MERGE_STATE_UNDETERMINED
    else:
        raise AssertionError("contradictory merge state should fail closed")


def test_audit_evidence_is_bounded_and_redacted() -> None:
    evidence = toolchain_audit_evidence(
        requested_fields=GH_PR_VIEW_FIELD_LIST,
        normalized_merge_state={"pr_merged": True, "merge_commit_sha": SHA_MAIN, "state": "MERGED"},
        reason_code=PR_MERGE_STATE_NORMALIZED,
    )
    encoded = json.dumps(evidence, sort_keys=True)

    assert evidence["audit_hash"]
    assert SHA_MAIN not in encoded
    assert "PRIVATE KEY" not in encoded
    assert "token" not in encoded.lower()
    assert "raw" not in encoded.lower()
