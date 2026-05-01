from __future__ import annotations

from security.hydra_consensus import HydraNodeDecision, decide_consensus, evaluate_consensus


def node_decision(
    node_id: str,
    decision: str,
    *,
    request_hash: str = "request-hash-1",
    policy_version: str = "policy-v1",
) -> HydraNodeDecision:
    return HydraNodeDecision(
        node_id=node_id,
        request_hash=request_hash,
        policy_version=policy_version,
        decision=decision,
        reason=f"{node_id}-{decision}",
        timestamp=1777248000.0,
    )


def test_two_allow_one_deny_allows() -> None:
    result = evaluate_consensus(
        [
            node_decision("node-1", "allow"),
            node_decision("node-2", "allow"),
            node_decision("node-3", "deny"),
        ]
    )

    assert result.final_decision == "allow"
    assert result.consensus_reached is True
    assert result.votes_allow == 2
    assert result.votes_deny == 1
    assert result.required_votes == 2


def test_two_deny_one_allow_denies() -> None:
    result = evaluate_consensus(
        [
            node_decision("node-1", "deny"),
            node_decision("node-2", "deny"),
            node_decision("node-3", "allow"),
        ]
    )

    assert result.final_decision == "deny"
    assert result.consensus_reached is True
    assert result.votes_allow == 1
    assert result.votes_deny == 2


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
