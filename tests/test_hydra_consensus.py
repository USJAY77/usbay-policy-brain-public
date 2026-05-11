from __future__ import annotations

import time

from security.hydra_consensus import (
    HydraNodeDecision,
    consensus_evidence_hash,
    decide_consensus,
    evaluate_consensus as _evaluate_consensus,
    replay_registry_hash,
)
from security.deployment_attestation import resolve_runtime_provenance_authority


def node_decision(
    node_id: str,
    decision: str,
    *,
    request_hash: str = "request-hash-1",
    policy_version: str = "policy-v1",
    policy_hash: str = "policy-hash-1",
    nonce_hash: str = "nonce-hash-1",
    replay_hash: str | None = None,
    nonce_state: str = "unused",
    timestamp: float | None = None,
    reason: str | None = None,
) -> HydraNodeDecision:
    now = time.time() if timestamp is None else timestamp
    return HydraNodeDecision(
        node_id=node_id,
        node_role={"node-1": "primary", "node-2": "secondary", "node-3": "offline_backup"}.get(node_id, ""),
        request_hash=request_hash,
        policy_version=policy_version,
        policy_hash=policy_hash,
        nonce_hash=nonce_hash,
        replay_registry_hash=replay_hash or replay_registry_hash(policy_hash, nonce_hash),
        nonce_state=nonce_state,
        tenant_id="t1",
        tenant_hash=__import__("hashlib").sha256(b"t1").hexdigest(),
        decision=decision,
        reason=reason or f"{node_id}-{decision}",
        timestamp=now,
        attestation_timestamp=now,
        attestation_hash=f"attestation-hash-{node_id}",
        attestation_node_id=f"attested-{node_id}",
        attestation_provider_mode="mock_local",
    )


def evaluate_consensus(decisions, **kwargs):
    kwargs.setdefault("provenance_authority", resolve_runtime_provenance_authority())
    return _evaluate_consensus(decisions, **kwargs)


def test_two_allow_one_deny_fails_closed_on_node_disagreement() -> None:
    result = evaluate_consensus(
        [
            node_decision("node-1", "allow"),
            node_decision("node-2", "allow"),
            node_decision("node-3", "deny"),
        ]
    )

    assert result.final_decision == "deny"
    assert result.consensus_reached is False
    assert result.votes_allow == 2
    assert result.votes_deny == 1
    assert result.required_votes == 2
    assert result.reason == "node_disagreement"


def test_two_allow_one_offline_allows_with_signed_evidence() -> None:
    result = evaluate_consensus(
        [
            node_decision("node-1", "allow"),
            node_decision("node-2", "allow"),
            node_decision("node-3", "deny", nonce_state="", replay_hash="", reason="node_unavailable"),
        ]
    )

    assert result.final_decision == "allow"
    assert result.consensus_reached is True
    assert result.votes_allow == 2
    assert result.evidence_bundle is not None
    assert result.evidence_bundle["sha256_evidence_hash"] == consensus_evidence_hash(result.evidence_bundle)
    assert result.evidence_bundle["consensus_signature"]


def test_two_deny_one_allow_fails_closed_on_disagreement() -> None:
    result = evaluate_consensus(
        [
            node_decision("node-1", "deny"),
            node_decision("node-2", "deny"),
            node_decision("node-3", "allow"),
        ]
    )

    assert result.final_decision == "deny"
    assert result.consensus_reached is False
    assert result.votes_allow == 1
    assert result.votes_deny == 2
    assert result.reason == "node_disagreement"


def test_invalid_decision_fails_closed_without_consensus() -> None:
    result = evaluate_consensus(
        [
            node_decision("node-1", "allow"),
            node_decision("node-2", "deny"),
            node_decision("node-3", "invalid"),
        ]
    )

    assert result.final_decision == "deny"
    assert result.consensus_reached is False
    assert result.votes_allow == 0
    assert result.votes_deny == 0
    assert result.reason == "invalid_decision"


def test_empty_node_id_fails_closed() -> None:
    result = evaluate_consensus(
        [
            node_decision("node-1", "allow"),
            node_decision("", "allow"),
            node_decision("node-3", "deny"),
        ]
    )

    assert result.final_decision == "deny"
    assert result.consensus_reached is False
    assert result.reason == "empty_node_id"


def test_mismatched_request_hash_fails_closed() -> None:
    result = evaluate_consensus(
        [
            node_decision("node-1", "allow"),
            node_decision("node-2", "allow", request_hash="other-hash"),
            node_decision("node-3", "allow"),
        ]
    )

    assert result.final_decision == "deny"
    assert result.consensus_reached is False
    assert result.reason == "request_hash_mismatch"


def test_mismatched_policy_version_fails_closed() -> None:
    result = evaluate_consensus(
        [
            node_decision("node-1", "allow"),
            node_decision("node-2", "allow", policy_version="policy-v2"),
            node_decision("node-3", "allow"),
        ]
    )

    assert result.final_decision == "deny"
    assert result.consensus_reached is False
    assert result.reason == "policy_version_mismatch"


def test_mismatched_policy_hash_fails_closed() -> None:
    result = evaluate_consensus(
        [
            node_decision("node-1", "allow"),
            node_decision("node-2", "allow", policy_hash="policy-hash-2"),
            node_decision("node-3", "allow"),
        ],
        expected_policy_hash="policy-hash-1",
    )

    assert result.final_decision == "deny"
    assert result.consensus_reached is False
    assert result.reason == "policy_hash_mismatch"


def test_replay_registry_divergence_fails_closed() -> None:
    result = evaluate_consensus(
        [
            node_decision("node-1", "allow"),
            node_decision("node-2", "allow", replay_hash="divergent"),
            node_decision("node-3", "allow"),
        ]
    )

    assert result.final_decision == "deny"
    assert result.consensus_reached is False
    assert result.reason == "replay_registry_divergence"


def test_stale_node_fails_closed() -> None:
    stale = time.time() - 120
    result = evaluate_consensus(
        [
            node_decision("node-1", "allow"),
            node_decision("node-2", "allow", timestamp=stale),
            node_decision("node-3", "allow"),
        ],
        freshness_seconds=30,
    )

    assert result.final_decision == "deny"
    assert result.consensus_reached is False
    assert result.reason == "node_stale"


def test_fewer_than_three_decisions_fails_closed() -> None:
    result = evaluate_consensus(
        [
            node_decision("node-1", "allow"),
            node_decision("node-2", "allow"),
        ]
    )

    assert result.final_decision == "deny"
    assert result.consensus_reached is False
    assert result.reason == "fewer_than_3_decisions"


def test_no_majority_with_malformed_input_fails_closed() -> None:
    result = evaluate_consensus(
        [
            node_decision("node-1", "allow"),
            node_decision("node-2", "deny"),
            node_decision("node-3", "invalid"),
        ]
    )

    assert result.final_decision == "deny"
    assert result.consensus_reached is False
    assert result.reason == "invalid_decision"


def test_decide_consensus_two_allow_one_deny_allows() -> None:
    votes = [
        {"node": "node1", "decision": "ALLOW", "valid": True},
        {"node": "node2", "decision": "ALLOW", "valid": True},
        {"node": "node3", "decision": "DENY", "valid": True},
    ]

    assert decide_consensus(votes) == "ALLOW"


def test_decide_consensus_one_allow_two_invalid_denies() -> None:
    votes = [
        {"node": "node1", "decision": "ALLOW", "valid": False},
        {"node": "node2", "decision": "ALLOW", "valid": False},
        {"node": "node3", "decision": "ALLOW", "valid": True},
    ]

    assert decide_consensus(votes) == "DENY"


def test_decide_consensus_malformed_input_denies() -> None:
    assert decide_consensus({"node": "node1", "decision": "ALLOW", "valid": True}) == "DENY"
    assert decide_consensus([{"node": "node1", "decision": "MAYBE", "valid": True}]) == "DENY"
    assert decide_consensus([object()]) == "DENY"


def test_decide_consensus_empty_list_denies() -> None:
    assert decide_consensus([]) == "DENY"


def test_decide_consensus_missing_valid_field_denies() -> None:
    votes = [
        {"node": "node1", "decision": "ALLOW", "valid": True},
        {"node": "node2", "decision": "ALLOW"},
        {"node": "node3", "decision": "ALLOW"},
    ]

    assert decide_consensus(votes) == "DENY"
