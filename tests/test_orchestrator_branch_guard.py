from __future__ import annotations

import pytest

from governance.orchestrator_branch_guard import (
    BRANCH_GUARD_VERSION,
    branch_guard_contract,
    evaluate_branch_operation,
)


pytestmark = pytest.mark.governance


def _audit() -> dict[str, str]:
    return {
        "actor": "codex",
        "device": "local",
        "decision": "ALLOW",
        "timestamp": "2026-06-14T00:00:00Z",
        "policy_version": BRANCH_GUARD_VERSION,
    }


def test_branch_guard_contract_declares_allowed_and_blocked_operations() -> None:
    contract = branch_guard_contract()

    assert contract["policy_version"] == BRANCH_GUARD_VERSION
    assert "branch_from_origin_main" in contract["allowed"]
    assert "force_push" in contract["blocked"]
    assert "branch_mutation_without_audit_record" in contract["blocked"]


def test_allows_single_pb_branch_from_origin_main_with_tracked_files_and_audit() -> None:
    decision = evaluate_branch_operation(
        branch_name="usbay/pb-336-branch-guard-contract",
        base_ref="origin/main",
        changed_files=("governance/orchestrator_branch_guard.py",),
        operation="create_branch",
        audit=_audit(),
    )

    assert decision.decision == "ALLOW"
    assert decision.reason_codes == ()


def test_blocks_force_push_and_direct_main_edits() -> None:
    decision = evaluate_branch_operation(
        branch_name="main",
        base_ref="origin/main",
        changed_files=("governance/orchestrator_branch_guard.py",),
        operation="force_push",
        audit=_audit(),
    )

    assert decision.decision == "BLOCK"
    assert "FORCE_PUSH_BLOCKED" in decision.reason_codes
    assert "DIRECT_MAIN_EDIT_BLOCKED" in decision.reason_codes


def test_blocks_non_origin_main_base_and_missing_audit() -> None:
    decision = evaluate_branch_operation(
        branch_name="usbay/pb-336-branch-guard-contract",
        base_ref="feature/local",
        changed_files=("governance/orchestrator_branch_guard.py",),
        operation="create_branch",
        audit=None,
    )

    assert decision.decision == "BLOCK"
    assert "BASE_REF_NOT_ORIGIN_MAIN" in decision.reason_codes
    assert "BRANCH_AUDIT_RECORD_MISSING" in decision.reason_codes


def test_blocks_multi_pb_branch_and_evidence_scope_without_explicit_authority() -> None:
    decision = evaluate_branch_operation(
        branch_name="usbay/pb-336-pb337-combined",
        base_ref="origin/main",
        changed_files=("governance/evidence/pb336/report.json",),
        operation="create_branch",
        audit=_audit(),
    )

    assert decision.decision == "BLOCK"
    assert "MULTI_PB_BRANCH_BLOCKED" in decision.reason_codes
    assert "EVIDENCE_PATH_REQUIRES_EXPLICIT_SCOPE" in decision.reason_codes
