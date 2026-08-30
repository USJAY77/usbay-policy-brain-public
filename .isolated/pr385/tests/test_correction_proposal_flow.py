from __future__ import annotations

from terminal.correction_proposal import correction_proposal_flow_json, propose_correction


def test_correction_proposal_generates_required_fields_without_modification() -> None:
    proposal = propose_correction(reason="formatting-only correction", files_affected=["tests/example.py"])
    for field in ("proposal_id", "reason", "files_affected", "risk_level", "approval_required", "policy_hash", "decision"):
        assert field in proposal
    assert proposal["approval_required"] is True
    assert proposal["automatic_file_modification_allowed"] is False


def test_correction_proposal_blocks_critical_risk() -> None:
    proposal = propose_correction(reason="unsafe deletion", files_affected=["file.py"], risk_level="CRITICAL")
    assert proposal["decision"] == "BLOCKED"
    assert proposal["network_allowed"] is False


def test_correction_proposal_flow_blocks_git_and_network_execution() -> None:
    flow = correction_proposal_flow_json()
    assert flow["generate_patch_proposals_only"] is True
    assert flow["git_add_allowed"] is False
    assert flow["git_commit_allowed"] is False
    assert flow["git_push_allowed"] is False
    assert flow["git_merge_allowed"] is False
    assert flow["delete_allowed"] is False
    assert flow["install_allowed"] is False
    assert flow["network_allowed"] is False
