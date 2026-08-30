from __future__ import annotations

import json
from pathlib import Path

from governance.canonical_governance_state import (
    CANONICAL_GOVERNANCE_STATE_REASON_CODES,
    GOVERNANCE_BLOCKED,
    GOVERNANCE_REVIEW_REQUIRED,
    GOVERNANCE_VALIDATED,
    build_canonical_governance_state,
    load_canonical_governance_state_error_registry,
    sha256_text,
)


ROOT = Path(__file__).resolve().parents[1]
POLICY_HASH = "a" * 64
RUNTIME_HASH = "b" * 64
HEAD_SHA = "c" * 40
MERGE_SHA = "d" * 40


def _state(**overrides):
    values = {
        "pr_number": 77,
        "repository_full_name": "usbay/policy-brain",
        "base_branch": "main",
        "head_branch": "dependabot/pip/cryptography",
        "head_sha": HEAD_SHA,
        "merge_sha": "",
        "actor": "dependabot[bot]",
        "event_type": "pull_request",
        "workflow_run_id": "",
        "workflow_name": "production-readiness",
        "branch_deleted": False,
        "checks_status": "PENDING",
        "runtime_evidence_hash": RUNTIME_HASH,
        "policy_version_hash": POLICY_HASH,
        "timestamp_utc": "2026-05-18T00:00:00Z",
    }
    values.update(overrides)
    return build_canonical_governance_state(**values)


def test_valid_pr_event_produces_validated_state() -> None:
    state = _state()

    assert state["canonical_state"] == GOVERNANCE_VALIDATED
    assert state["event_sequence_state"] == "PR_OPEN"
    assert "EVENT_SEQUENCE_RECONCILED" in state["reason_codes"]


def test_valid_workflow_run_reconciles_to_same_pr_identity() -> None:
    state = _state(event_type="workflow_run", workflow_run_id="123", checks_status={"production-readiness": "PASS"})

    assert state["canonical_state"] == GOVERNANCE_VALIDATED
    assert state["event_sequence_state"] == "CHECKS_COMPLETE"


def test_valid_push_to_main_after_merge_reconciles() -> None:
    state = _state(event_type="push", merge_sha=MERGE_SHA, head_branch="", actor="github-actions[bot]")

    assert state["canonical_state"] == GOVERNANCE_VALIDATED
    assert state["event_sequence_state"] == "MERGE_COMMITTED"


def test_branch_deletion_after_reconciled_merge_does_not_block() -> None:
    state = _state(event_type="delete", merge_sha=MERGE_SHA, branch_deleted=True, actor="github-actions[bot]")

    assert state["canonical_state"] == GOVERNANCE_VALIDATED
    assert state["event_sequence_state"] == "BRANCH_DELETED"


def test_branch_deletion_before_reconciliation_blocks() -> None:
    state = _state(event_type="delete", merge_sha="", branch_deleted=True)

    assert state["canonical_state"] == GOVERNANCE_BLOCKED
    assert "EVENT_SEQUENCE_CONFLICT" in state["reason_codes"]


def test_stale_workflow_run_blocks() -> None:
    state = _state(event_type="workflow_run", workflow_run_id="", checks_status="PASS")

    assert state["canonical_state"] == GOVERNANCE_BLOCKED
    assert "EVENT_SEQUENCE_CONFLICT" in state["reason_codes"]


def test_missing_pr_context_blocks() -> None:
    state = _state(pr_number=None)

    assert state["canonical_state"] == GOVERNANCE_BLOCKED
    assert "EVENT_SEQUENCE_CONFLICT" in state["reason_codes"]


def test_ambiguous_pr_context_blocks() -> None:
    state = _state(candidate_pr_count=2)

    assert state["canonical_state"] == GOVERNANCE_BLOCKED
    assert "AUTHORITY_SOURCE_AMBIGUOUS" in state["reason_codes"]


def test_head_sha_mismatch_blocks() -> None:
    state = _state(expected_head_sha="e" * 40)

    assert state["canonical_state"] == GOVERNANCE_BLOCKED
    assert "EVENT_SEQUENCE_CONFLICT" in state["reason_codes"]


def test_merge_sha_mismatch_blocks() -> None:
    state = _state(merge_sha=MERGE_SHA, expected_merge_sha="e" * 40)

    assert state["canonical_state"] == GOVERNANCE_BLOCKED
    assert "EVENT_SEQUENCE_CONFLICT" in state["reason_codes"]


def test_base_branch_mismatch_blocks() -> None:
    state = _state(base_branch="develop")

    assert state["canonical_state"] == GOVERNANCE_BLOCKED
    assert "EVENT_SEQUENCE_CONFLICT" in state["reason_codes"]


def test_untrusted_authority_source_blocks() -> None:
    state = _state(actor="human-user")

    assert state["canonical_state"] == GOVERNANCE_BLOCKED
    assert "AUTHORITY_SOURCE_UNTRUSTED" in state["reason_codes"]


def test_missing_policy_hash_blocks() -> None:
    state = _state(policy_version_hash="")

    assert state["canonical_state"] == GOVERNANCE_BLOCKED
    assert "POLICY_HASH_MISSING" in state["reason_codes"]


def test_runtime_evidence_missing_requires_review_not_green() -> None:
    state = _state(runtime_evidence_hash="")

    assert state["canonical_state"] == GOVERNANCE_REVIEW_REQUIRED
    assert "RUNTIME_EVIDENCE_MISSING" in state["reason_codes"]


def test_event_and_reconciliation_hashes_are_deterministic() -> None:
    first = _state()
    second = _state()

    assert first["event_fingerprint"] == second["event_fingerprint"]
    assert first["reconciliation_hash"] == second["reconciliation_hash"]
    assert first["audit_hash"] == second["audit_hash"]


def test_audit_hash_contains_no_secrets_payloads_paths_or_stack_traces() -> None:
    state = _state(repository_full_name="secret-owner/private-repo", workflow_name="production-readiness")
    encoded = json.dumps(state, sort_keys=True)

    assert "secret-owner/private-repo" not in encoded
    assert ("raw_" + "payload") not in encoded
    assert "Traceback" not in encoded
    assert "/Users/" not in encoded
    assert state["signature_status"] == "SIGNATURE_UNVERIFIED"


def test_error_registry_complete() -> None:
    registry = load_canonical_governance_state_error_registry(ROOT)

    assert set(CANONICAL_GOVERNANCE_STATE_REASON_CODES).issubset(registry)
    assert registry["POLICY_HASH_MISSING"]["fail_closed_reason"]
