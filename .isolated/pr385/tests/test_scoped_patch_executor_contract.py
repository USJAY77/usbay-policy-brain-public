from __future__ import annotations

import pytest

from governance.scoped_patch_executor_contract import (
    SCOPED_PATCH_EXECUTOR_VERSION,
    evaluate_patch_scope,
    scoped_patch_executor_contract,
)


pytestmark = pytest.mark.governance


def test_scoped_patch_contract_declares_fail_closed_scope_rules() -> None:
    contract = scoped_patch_executor_contract()

    assert contract["policy_version"] == SCOPED_PATCH_EXECUTOR_VERSION
    assert contract["explicit_file_allowlist_required"] is True
    assert contract["outside_scope_decision"] == "BLOCK"
    assert contract["evidence_paths_immutable_by_default"] is True
    assert contract["uncertainty_decision"] == "BLOCK"


def test_allows_patch_inside_explicit_file_allowlist() -> None:
    decision = evaluate_patch_scope(
        changed_files=("governance/scoped_patch_executor_contract.py",),
        file_allowlist=("governance/scoped_patch_executor_contract.py", "tests/test_scoped_patch_executor_contract.py"),
    )

    assert decision.decision == "ALLOW"
    assert decision.reason_codes == ()


def test_blocks_missing_allowlist_and_missing_changed_files() -> None:
    decision = evaluate_patch_scope(changed_files=(), file_allowlist=())

    assert decision.decision == "BLOCK"
    assert "PATCH_ALLOWLIST_MISSING" in decision.reason_codes
    assert "PATCH_CHANGED_FILES_MISSING" in decision.reason_codes


def test_blocks_patch_outside_scope() -> None:
    decision = evaluate_patch_scope(
        changed_files=("gateway/app.py",),
        file_allowlist=("governance/scoped_patch_executor_contract.py",),
    )

    assert decision.decision == "BLOCK"
    assert "PATCH_OUTSIDE_SCOPE" in decision.reason_codes


def test_evidence_paths_are_immutable_unless_explicitly_scoped() -> None:
    blocked = evaluate_patch_scope(
        changed_files=("governance/evidence/pb337/report.json",),
        file_allowlist=("governance/evidence/pb337/report.json",),
    )
    allowed = evaluate_patch_scope(
        changed_files=("governance/evidence/pb337/report.json",),
        file_allowlist=("governance/evidence/pb337/report.json",),
        evidence_mutation_explicitly_scoped=True,
    )

    assert blocked.decision == "BLOCK"
    assert "EVIDENCE_PATH_IMMUTABLE" in blocked.reason_codes
    assert allowed.decision == "ALLOW"


def test_path_traversal_is_blocked_as_uncertain() -> None:
    decision = evaluate_patch_scope(
        changed_files=("../secrets.txt",),
        file_allowlist=("governance/",),
    )

    assert decision.decision == "BLOCK"
    assert "PATCH_PATH_UNSAFE" in decision.reason_codes
