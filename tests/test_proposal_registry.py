import json

import pytest

from governance.correction_proposals import (
    APPROVAL_APPROVED,
    APPROVAL_REJECTED,
    detect_governance_issue,
    generate_correction_proposal,
)
from governance.proposal_registry import (
    GENESIS_HASH,
    REASON_EXECUTION_BLOCKED,
    REASON_PROPOSAL_EXPIRED,
    REASON_REGISTRY_CORRUPTED,
    REASON_REGISTRY_UNAVAILABLE,
    REASON_UNKNOWN_STATE,
    STATE_APPROVED,
    STATE_EXPIRED,
    STATE_PENDING_APPROVAL,
    STATE_REJECTED,
    ProposalRegistry,
    ProposalRegistryError,
    initialize_proposal_registry,
    verify_proposal_registry,
)


CREATED_AT = "2026-06-12T00:00:00Z"
FUTURE_EXPIRY = "2026-06-13T00:00:00Z"
PAST_EXPIRY = "2026-06-11T00:00:00Z"


def _proposal(*, issue_type: str = "CI_FAILURE", observed_failure: str = "pytest failed", expires_at: str = ""):
    issue = detect_governance_issue(
        issue_type,
        observed_failure=observed_failure,
        source="pb297_local_validation",
    )
    return generate_correction_proposal(issue, timestamp=CREATED_AT, expires_at=expires_at)


def _registry(tmp_path):
    path = tmp_path / "proposal_registry.json"
    initialize_proposal_registry(path)
    return ProposalRegistry(path), path


def test_create_proposal_records_pending_lifecycle_and_append_only_history(tmp_path):
    registry, path = _registry(tmp_path)
    proposal = _proposal()

    record = registry.create(proposal, timestamp=CREATED_AT)

    assert record["proposal_id"] == proposal["proposal_id"]
    assert record["proposal_hash"] == proposal["proposal_hash"]
    assert record["proposal_type"] == "CI_FAILURE"
    assert record["risk_level"] == "MEDIUM"
    assert record["proposal_payload_hash"]
    assert record["approval_status"] == "PENDING"
    assert record["execution_status"] == "BLOCKED"
    assert record["lifecycle_state"] == STATE_PENDING_APPROVAL
    assert record["created_at"] == CREATED_AT
    assert record["audit_hash"]
    data = json.loads(path.read_text(encoding="utf-8"))
    assert [event["lifecycle_state"] for event in data["history"]] == ["CREATED", STATE_PENDING_APPROVAL]
    assert data["history"][0]["previous_hash"] == GENESIS_HASH
    assert data["history"][1]["previous_hash"] == data["history"][0]["event_hash"]
    assert verify_proposal_registry(path) is True
    assert proposal["proposed_action"] not in path.read_text(encoding="utf-8")


def test_registry_survives_restart_and_approves_proposal(tmp_path):
    registry, path = _registry(tmp_path)
    proposal = _proposal(expires_at=FUTURE_EXPIRY)
    registry.create(proposal, timestamp=CREATED_AT)

    restarted = ProposalRegistry(path)
    approved = restarted.transition(proposal["proposal_id"], lifecycle_state=STATE_APPROVED, timestamp=CREATED_AT)

    assert approved["approval_status"] == APPROVAL_APPROVED
    assert approved["execution_status"] == "NOT_EXECUTED"
    assert restarted.assert_execution_allowed(proposal["proposal_id"], now=CREATED_AT)["lifecycle_state"] == STATE_APPROVED
    assert verify_proposal_registry(path) is True


def test_reject_proposal_blocks_execution(tmp_path):
    registry, _path = _registry(tmp_path)
    proposal = _proposal()
    registry.create(proposal, timestamp=CREATED_AT)

    rejected = registry.transition(proposal["proposal_id"], lifecycle_state=STATE_REJECTED, timestamp=CREATED_AT)

    assert rejected["approval_status"] == APPROVAL_REJECTED
    assert rejected["execution_status"] == "BLOCKED"
    with pytest.raises(ProposalRegistryError, match=REASON_EXECUTION_BLOCKED):
        registry.assert_execution_allowed(proposal["proposal_id"], now=CREATED_AT)


def test_expire_proposal_and_execution_blocked_after_expiry(tmp_path):
    registry, path = _registry(tmp_path)
    proposal = _proposal(expires_at=PAST_EXPIRY)
    registry.create(proposal, timestamp=CREATED_AT)
    registry.transition(proposal["proposal_id"], lifecycle_state=STATE_APPROVED, timestamp=CREATED_AT)

    expired = registry.expire_if_needed(proposal["proposal_id"], now=CREATED_AT)

    assert expired["lifecycle_state"] == STATE_EXPIRED
    assert expired["execution_status"] == "BLOCKED"
    with pytest.raises(ProposalRegistryError, match=REASON_PROPOSAL_EXPIRED):
        registry.assert_execution_allowed(proposal["proposal_id"], now=CREATED_AT)
    assert verify_proposal_registry(path) is True


def test_registry_unavailable_and_corrupted_fail_closed(tmp_path):
    missing = tmp_path / "missing.json"
    with pytest.raises(ProposalRegistryError, match=REASON_REGISTRY_UNAVAILABLE):
        ProposalRegistry(missing).load()

    corrupted = tmp_path / "corrupted.json"
    corrupted.write_text("{not-json", encoding="utf-8")
    with pytest.raises(ProposalRegistryError, match=REASON_REGISTRY_CORRUPTED):
        ProposalRegistry(corrupted).load()
    assert verify_proposal_registry(corrupted) is False


def test_unknown_lifecycle_state_denied(tmp_path):
    registry, path = _registry(tmp_path)
    proposal = _proposal()
    registry.create(proposal, timestamp=CREATED_AT)
    data = json.loads(path.read_text(encoding="utf-8"))
    data["proposals"][proposal["proposal_id"]]["lifecycle_state"] = "MAYBE"
    path.write_text(json.dumps(data), encoding="utf-8")

    with pytest.raises(ProposalRegistryError, match=REASON_UNKNOWN_STATE):
        registry.load()


def test_chain_tampering_detected(tmp_path):
    registry, path = _registry(tmp_path)
    proposal = _proposal()
    registry.create(proposal, timestamp=CREATED_AT)
    data = json.loads(path.read_text(encoding="utf-8"))
    data["history"][1]["previous_hash"] = "bad"
    path.write_text(json.dumps(data), encoding="utf-8")

    with pytest.raises(ProposalRegistryError, match=REASON_REGISTRY_CORRUPTED):
        registry.load()


def test_registry_does_not_store_raw_sensitive_proposal_payload(tmp_path):
    registry, path = _registry(tmp_path)
    raw_sensitive_failure = "failure contains token=redacted-test-value"
    proposal = _proposal(observed_failure=raw_sensitive_failure)

    registry.create(proposal, timestamp=CREATED_AT)

    serialized = path.read_text(encoding="utf-8")
    assert raw_sensitive_failure not in serialized
    assert proposal["observed_failure_hash"] not in serialized
    assert "redacted-test-value" not in serialized
