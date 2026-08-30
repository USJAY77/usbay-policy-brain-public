import json

from governance.correction_proposals import detect_governance_issue, generate_correction_proposal
from governance.proposal_execution_adapter import (
    DECISION_DENY,
    DECISION_EXECUTION_ELIGIBLE,
    REASON_NONCE_DENY,
    REASON_OK,
    REASON_POLICY_SIGNATURE_INVALID,
    REASON_PROPOSAL_EXPIRED,
    REASON_PROPOSAL_HASH_MISMATCH,
    REASON_PROPOSAL_NOT_FOUND,
    REASON_REGISTRY_UNAVAILABLE,
    STATE_BLOCKED,
    STATE_EXECUTION_ELIGIBLE,
    STATE_EXPIRED,
    ProposalExecutionAdapter,
)
from governance.proposal_registry import (
    STATE_APPROVED,
    STATE_REJECTED,
    ProposalRegistry,
    initialize_proposal_registry,
)
from security.persistent_nonce_store import LocalPersistentNonceStore, initialize_persistent_nonce_store


CREATED_AT = "2026-06-12T00:00:00Z"
FUTURE_EXPIRY = "2026-06-13T00:00:00Z"
PAST_EXPIRY = "2026-06-11T00:00:00Z"


def _proposal(*, expires_at: str = ""):
    issue = detect_governance_issue(
        "CI_FAILURE",
        observed_failure="governed validation failed",
        source="pb298_local_validation",
    )
    return generate_correction_proposal(issue, timestamp=CREATED_AT, expires_at=expires_at)


def _revocation_registry(path, *, revoked_runtime_ids=None):
    path.write_text(
        json.dumps(
            {
                "schema_version": "usbay.runtime_revocation_registry.v1",
                "registry_state": "ACTIVE",
                "revoked_runtime_ids": revoked_runtime_ids or [],
                "revoked_device_ids": [],
                "revoked_attestation_ids": [],
                "revoked_operator_ids": [],
            },
            sort_keys=True,
        ),
        encoding="utf-8",
    )


def _adapter(tmp_path, *, policy_loader=None, revoked_runtime_ids=None, initialize_registry=True):
    proposal_registry_path = tmp_path / "proposal_registry.json"
    if initialize_registry:
        initialize_proposal_registry(proposal_registry_path)
    nonce_path = tmp_path / "nonce_store.json"
    initialize_persistent_nonce_store(nonce_path)
    revocation_path = tmp_path / "runtime_revocation_registry.json"
    _revocation_registry(revocation_path, revoked_runtime_ids=revoked_runtime_ids)
    return ProposalExecutionAdapter(
        proposal_registry=ProposalRegistry(proposal_registry_path),
        nonce_store=LocalPersistentNonceStore(nonce_path, ttl_seconds=300, now_fn=lambda: 1000),
        revocation_registry_path=revocation_path,
        policy_loader=policy_loader or (lambda: {"policy_signature_valid": True, "policy_hash": "policy-hash"}),
    )


def _approved_proposal(adapter):
    proposal = _proposal(expires_at=FUTURE_EXPIRY)
    adapter.proposal_registry.create(proposal, timestamp=CREATED_AT)
    adapter.proposal_registry.transition(proposal["proposal_id"], lifecycle_state=STATE_APPROVED, timestamp=CREATED_AT)
    return proposal


def _request(proposal, *, nonce="nonce-1", runtime_id="runtime-1"):
    return {
        "proposal_id": proposal["proposal_id"],
        "proposal_hash": proposal["proposal_hash"],
        "approval_id": "approval-1",
        "execution_id": "execution-1",
        "actor": "operator@example.invalid",
        "runtime_id": runtime_id,
        "device_id": "device-1",
        "attestation_id": "attestation-1",
        "operator_id": "operator-1",
        "nonce": nonce,
    }


def test_approved_proposal_becomes_execution_eligible(tmp_path):
    adapter = _adapter(tmp_path)
    proposal = _approved_proposal(adapter)

    result = adapter.evaluate(_request(proposal), timestamp=CREATED_AT)

    assert result["decision"] == DECISION_EXECUTION_ELIGIBLE
    assert result["execution_state"] == STATE_EXECUTION_ELIGIBLE
    assert result["reason_code"] == REASON_OK
    audit = result["audit_evidence"]
    assert audit["proposal_id"] == proposal["proposal_id"]
    assert audit["proposal_hash"] == proposal["proposal_hash"]
    assert audit["approval_id"] == "approval-1"
    assert audit["execution_id"] == "execution-1"
    assert audit["decision_hash"]
    assert audit["actor_hash"]


def test_rejected_proposal_denies_execution(tmp_path):
    adapter = _adapter(tmp_path)
    proposal = _proposal(expires_at=FUTURE_EXPIRY)
    adapter.proposal_registry.create(proposal, timestamp=CREATED_AT)
    adapter.proposal_registry.transition(proposal["proposal_id"], lifecycle_state=STATE_REJECTED, timestamp=CREATED_AT)

    result = adapter.evaluate(_request(proposal), timestamp=CREATED_AT)

    assert result["decision"] == DECISION_DENY
    assert result["execution_state"] == STATE_BLOCKED


def test_expired_proposal_denies_execution(tmp_path):
    adapter = _adapter(tmp_path)
    proposal = _proposal(expires_at=PAST_EXPIRY)
    adapter.proposal_registry.create(proposal, timestamp=CREATED_AT)
    adapter.proposal_registry.transition(proposal["proposal_id"], lifecycle_state=STATE_APPROVED, timestamp=CREATED_AT)

    result = adapter.evaluate(_request(proposal), timestamp=CREATED_AT)

    assert result["decision"] == DECISION_DENY
    assert result["execution_state"] == STATE_EXPIRED
    assert result["reason_code"] == REASON_PROPOSAL_EXPIRED


def test_missing_proposal_denies_execution(tmp_path):
    adapter = _adapter(tmp_path)
    proposal = _proposal(expires_at=FUTURE_EXPIRY)

    result = adapter.evaluate(_request(proposal), timestamp=CREATED_AT)

    assert result["decision"] == DECISION_DENY
    assert result["reason_code"] == REASON_PROPOSAL_NOT_FOUND


def test_hash_mismatch_denies_execution(tmp_path):
    adapter = _adapter(tmp_path)
    proposal = _approved_proposal(adapter)
    request = _request(proposal)
    request["proposal_hash"] = "0" * 64

    result = adapter.evaluate(request, timestamp=CREATED_AT)

    assert result["decision"] == DECISION_DENY
    assert result["reason_code"] == REASON_PROPOSAL_HASH_MISMATCH


def test_revoked_runtime_denies_execution(tmp_path):
    adapter = _adapter(tmp_path, revoked_runtime_ids=["runtime-1"])
    proposal = _approved_proposal(adapter)

    result = adapter.evaluate(_request(proposal, runtime_id="runtime-1"), timestamp=CREATED_AT)

    assert result["decision"] == DECISION_DENY
    assert result["execution_state"] == STATE_BLOCKED
    assert result["reason_code"] == "runtime_id_revoked"


def test_nonce_replay_denies_second_execution(tmp_path):
    adapter = _adapter(tmp_path)
    proposal = _approved_proposal(adapter)

    first = adapter.evaluate(_request(proposal, nonce="nonce-replay"), timestamp=CREATED_AT)
    second = adapter.evaluate(_request(proposal, nonce="nonce-replay"), timestamp=CREATED_AT)

    assert first["decision"] == DECISION_EXECUTION_ELIGIBLE
    assert second["decision"] == DECISION_DENY
    assert second["reason_code"] == REASON_NONCE_DENY


def test_registry_unavailable_denies_execution(tmp_path):
    adapter = _adapter(tmp_path, initialize_registry=False)
    proposal = _proposal(expires_at=FUTURE_EXPIRY)

    result = adapter.evaluate(_request(proposal), timestamp=CREATED_AT)

    assert result["decision"] == DECISION_DENY
    assert result["reason_code"] == REASON_REGISTRY_UNAVAILABLE


def test_invalid_policy_signature_denies_execution(tmp_path):
    adapter = _adapter(tmp_path, policy_loader=lambda: {"policy_signature_valid": False})
    proposal = _approved_proposal(adapter)

    result = adapter.evaluate(_request(proposal), timestamp=CREATED_AT)

    assert result["decision"] == DECISION_DENY
    assert result["reason_code"] == REASON_POLICY_SIGNATURE_INVALID
