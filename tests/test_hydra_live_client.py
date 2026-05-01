from __future__ import annotations

import json

from security.hydra_consensus import decide_consensus
from security.hydra_live_client import (
    collect_live_votes,
    decide_live_consensus,
    default_live_node_clients,
    invalid_vote,
    validate_vote_response,
)
from security.hydra_node_service import build_vote_response


def signed_vote(
    node_id: str,
    decision: str,
    *,
    request_hash: str = "request-hash",
    policy_version: str = "policy-v1",
) -> dict:
    return build_vote_response(
        node_id=node_id,
        decision=decision,
        request_hash=request_hash,
        policy_version=policy_version,
    )


class StaticClient:
    def __init__(self, node_id: str, vote: dict | None = None, raises: Exception | None = None) -> None:
        self.node_id = node_id
        self._vote = vote
        self._raises = raises

    def vote(self, request_hash, policy_version, action="", context=None):
        if self._raises is not None:
            raise self._raises
        return validate_vote_response(
            self._vote,
            expected_node_id=self.node_id,
            request_hash=request_hash,
            policy_version=policy_version,
        )


def test_live_consensus_two_allow_one_deny_allows() -> None:
    clients = [
        StaticClient("node1", signed_vote("node1", "ALLOW")),
        StaticClient("node2", signed_vote("node2", "ALLOW")),
        StaticClient("node3", signed_vote("node3", "DENY")),
    ]

    assert decide_live_consensus("request-hash", "policy-v1", clients=clients) == "ALLOW"


def test_live_consensus_three_allow_allows() -> None:
    clients = [
        StaticClient("node1", signed_vote("node1", "ALLOW")),
        StaticClient("node2", signed_vote("node2", "ALLOW")),
        StaticClient("node3", signed_vote("node3", "ALLOW")),
    ]

    assert decide_live_consensus("request-hash", "policy-v1", clients=clients) == "ALLOW"


def test_one_node_down_still_allows_with_two_valid_allow_votes() -> None:
    clients = [
        StaticClient("node1", signed_vote("node1", "ALLOW")),
        StaticClient("node2", signed_vote("node2", "ALLOW")),
        StaticClient("node3", raises=TimeoutError("timeout")),
    ]

    votes = collect_live_votes("request-hash", "policy-v1", clients=clients)

    assert votes[2] == invalid_vote("node3")
    assert decide_consensus(votes) == "ALLOW"


def test_two_nodes_down_denies() -> None:
    clients = [
        StaticClient("node1", signed_vote("node1", "ALLOW")),
        StaticClient("node2", raises=TimeoutError("timeout")),
        StaticClient("node3", raises=TimeoutError("timeout")),
    ]

    assert decide_live_consensus("request-hash", "policy-v1", clients=clients) == "DENY"


def test_one_allow_two_deny_denies() -> None:
    clients = [
        StaticClient("node1", signed_vote("node1", "ALLOW")),
        StaticClient("node2", signed_vote("node2", "DENY")),
        StaticClient("node3", signed_vote("node3", "DENY")),
    ]

    assert decide_live_consensus("request-hash", "policy-v1", clients=clients) == "DENY"


def test_all_nodes_unavailable_denies() -> None:
    clients = [
        StaticClient("node1", raises=TimeoutError("timeout")),
        StaticClient("node2", raises=TimeoutError("timeout")),
        StaticClient("node3", raises=TimeoutError("timeout")),
    ]

    assert decide_live_consensus("request-hash", "policy-v1", clients=clients) == "DENY"


def test_bad_signature_is_invalid_and_denies_without_majority() -> None:
    bad = signed_vote("node1", "ALLOW")
    bad["signature"] = "bad"
    clients = [
        StaticClient("node1", bad),
        StaticClient("node2", raises=TimeoutError("timeout")),
        StaticClient("node3", raises=TimeoutError("timeout")),
    ]

    assert decide_live_consensus("request-hash", "policy-v1", clients=clients) == "DENY"


def test_mismatched_request_hash_denies() -> None:
    clients = [
        StaticClient("node1", signed_vote("node1", "ALLOW", request_hash="other-hash")),
        StaticClient("node2", signed_vote("node2", "ALLOW", request_hash="other-hash")),
        StaticClient("node3", signed_vote("node3", "ALLOW", request_hash="other-hash")),
    ]

    assert decide_live_consensus("request-hash", "policy-v1", clients=clients) == "DENY"


def test_mismatched_policy_version_denies() -> None:
    clients = [
        StaticClient("node1", signed_vote("node1", "ALLOW", policy_version="policy-v2")),
        StaticClient("node2", signed_vote("node2", "ALLOW", policy_version="policy-v2")),
        StaticClient("node3", signed_vote("node3", "ALLOW", policy_version="policy-v2")),
    ]

    assert decide_live_consensus("request-hash", "policy-v1", clients=clients) == "DENY"


def test_malformed_response_denies() -> None:
    vote = validate_vote_response(
        "not-a-dict",
        expected_node_id="node1",
        request_hash="request-hash",
        policy_version="policy-v1",
    )

    assert vote == invalid_vote("node1")
    assert decide_consensus([vote]) == "DENY"


def test_hydra_node_urls_and_timeout_ms_config(monkeypatch) -> None:
    monkeypatch.setenv("HYDRA_NODE_URLS", "http://h1/vote,http://h2/vote,http://h3/vote")
    monkeypatch.setenv("USBAY_HYDRA_NODE_TIMEOUT_MS", "250")

    clients = default_live_node_clients()

    assert [client.url for client in clients] == [
        "http://h1/vote",
        "http://h2/vote",
        "http://h3/vote",
    ]
    assert all(client.timeout_seconds == 0.25 for client in clients)


def test_signed_response_contains_no_raw_payload() -> None:
    vote = signed_vote("node1", "ALLOW")

    encoded = json.dumps(vote)
    assert "payload" not in vote
    assert "secret_context" not in encoded
