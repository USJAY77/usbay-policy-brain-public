from __future__ import annotations

import json

import pytest

from security.hydra_consensus import decide_consensus
from security.hydra_live_client import (
    HydraLiveNodeClient,
    authorize_hydra_remote_transport,
    collect_live_votes,
    decide_live_consensus,
    default_live_node_clients,
    hydra_endpoint_url_hash,
    invalid_vote,
    validate_vote_response,
)
from security.hydra_nodes import RemoteHydraNode
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


def remote_authorization(
    *,
    node_id: str = "node1",
    url: str = "https://hydra.example.test/vote",
    request_hash: str = "request-hash",
    policy_version: str = "policy-v1",
    decision: str = "ALLOW",
    issued_at: float = 1_700_000_000.0,
    expires_at: float = 1_700_000_060.0,
    evidence_verified: bool = True,
    trust_material_available: bool = True,
) -> dict:
    return {
        "authorization_id": "auth-1",
        "decision": decision,
        "node_id": node_id,
        "request_hash": request_hash,
        "policy_version": policy_version,
        "endpoint_url_hash": hydra_endpoint_url_hash(url),
        "issued_at": issued_at,
        "expires_at": expires_at,
        "evidence_verified": evidence_verified,
        "trust_material_available": trust_material_available,
        "revoked": False,
        "replayed": False,
    }


def authorized_context(**overrides) -> dict:
    authorization = remote_authorization(**overrides)
    return {
        "hydra_remote_transport_authorization": authorization,
        "hydra_remote_transport_authorization_freshness_seconds": 120.0,
    }


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


def test_authorization_contract_returns_hash_only_evidence() -> None:
    evidence = authorize_hydra_remote_transport(
        node_id="node1",
        url="https://hydra.example.test/vote",
        request_hash="request-hash",
        policy_version="policy-v1",
        context=authorized_context(),
        now=1_700_000_010.0,
    )

    encoded = json.dumps(evidence)
    assert evidence["decision"] == "ALLOW"
    assert "https://hydra.example.test/vote" not in encoded
    assert "auth-1" not in encoded


def test_hydra_live_vote_blocks_missing_authorization_before_transport(monkeypatch) -> None:
    calls = []

    def transport(*_args, **_kwargs):
        calls.append("transport")
        raise AssertionError("transport must not be reached")

    monkeypatch.setattr("security.hydra_live_client.request.urlopen", transport)

    client = HydraLiveNodeClient("node1", url="https://hydra.example.test/vote")

    try:
        client.vote("request-hash", "policy-v1")
    except ValueError as exc:
        assert str(exc) == "hydra_remote_transport_authorization_missing"
    else:
        raise AssertionError("missing authorization must fail closed")

    assert calls == []


def test_hydra_live_collect_votes_blocks_missing_authorization_before_transport(monkeypatch) -> None:
    calls = []

    def transport(*_args, **_kwargs):
        calls.append("transport")
        raise AssertionError("transport must not be reached")

    monkeypatch.setattr("security.hydra_live_client.request.urlopen", transport)

    votes = collect_live_votes(
        "request-hash",
        "policy-v1",
        clients=[HydraLiveNodeClient("node1", url="https://hydra.example.test/vote")],
    )

    assert votes[0] == invalid_vote("node1")
    assert calls == []


def test_remote_hydra_node_blocks_missing_authorization_before_transport(monkeypatch) -> None:
    calls = []

    def transport(*_args, **_kwargs):
        calls.append("transport")
        raise AssertionError("transport must not be reached")

    monkeypatch.setattr("security.hydra_nodes.request.urlopen", transport)

    node = RemoteHydraNode(node_id="node-3", url="https://hydra.example.test/evaluate")

    try:
        node.evaluate("request-hash", "policy-v1")
    except ValueError as exc:
        assert str(exc) == "hydra_remote_transport_authorization_missing"
    else:
        raise AssertionError("missing authorization must fail closed")

    assert calls == []


def test_hydra_live_vote_allows_transport_after_authorization(monkeypatch) -> None:
    calls = []
    response = signed_vote("node1", "ALLOW")

    class FakeResponse:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return None

        def read(self):
            return json.dumps(response).encode("utf-8")

    def transport(*_args, **_kwargs):
        calls.append("transport")
        return FakeResponse()

    monkeypatch.setattr("security.hydra_live_client.request.urlopen", transport)
    monkeypatch.setattr("security.hydra_live_client.time.time", lambda: 1_700_000_010.0)

    client = HydraLiveNodeClient("node1", url="https://hydra.example.test/vote")
    vote = client.vote("request-hash", "policy-v1", context=authorized_context())

    assert vote == {"node": "node1", "decision": "ALLOW", "valid": True}
    assert calls == ["transport"]


def test_hydra_live_vote_authorizes_before_transport(monkeypatch) -> None:
    order = []
    response = signed_vote("node1", "ALLOW")

    class FakeResponse:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return None

        def read(self):
            return json.dumps(response).encode("utf-8")

    def authorize(**_kwargs):
        order.append("authorize")
        return {"decision": "ALLOW"}

    def transport(*_args, **_kwargs):
        order.append("transport")
        return FakeResponse()

    monkeypatch.setattr("security.hydra_live_client.authorize_hydra_remote_transport", authorize)
    monkeypatch.setattr("security.hydra_live_client.request.urlopen", transport)

    client = HydraLiveNodeClient("node1", url="https://hydra.example.test/vote")
    vote = client.vote("request-hash", "policy-v1", context={"hydra_remote_transport_authorization": {}})

    assert vote == {"node": "node1", "decision": "ALLOW", "valid": True}
    assert order == ["authorize", "transport"]


def test_remote_hydra_node_allows_transport_after_authorization(monkeypatch) -> None:
    calls = []
    response = {
        "node_id": "node-3",
        "node_role": "offline_backup",
        "request_hash": "request-hash",
        "policy_version": "policy-v1",
        "decision": "allow",
        "reason": "remote_policy_allow",
        "timestamp": 1_700_000_010.0,
    }

    class FakeResponse:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return None

        def read(self):
            return json.dumps(response).encode("utf-8")

    def transport(*_args, **_kwargs):
        calls.append("transport")
        return FakeResponse()

    monkeypatch.setattr("security.hydra_nodes.request.urlopen", transport)
    monkeypatch.setattr("security.hydra_live_client.time.time", lambda: 1_700_000_010.0)

    node = RemoteHydraNode(node_id="node-3", url="https://hydra.example.test/evaluate")
    decision = node.evaluate(
        "request-hash",
        "policy-v1",
        context=authorized_context(node_id="node-3", url="https://hydra.example.test/evaluate"),
    )

    assert decision.node_id == "node-3"
    assert decision.decision == "allow"
    assert calls == ["transport"]


def test_hydra_live_consensus_behavior_remains_unchanged_with_authorized_static_clients() -> None:
    clients = [
        StaticClient("node1", signed_vote("node1", "ALLOW")),
        StaticClient("node2", signed_vote("node2", "ALLOW")),
        StaticClient("node3", signed_vote("node3", "DENY")),
    ]

    assert decide_live_consensus("request-hash", "policy-v1", clients=clients) == "ALLOW"


def test_blocked_hydra_transport_emits_non_sensitive_evidence() -> None:
    try:
        authorize_hydra_remote_transport(
            node_id="node1",
            url="https://hydra.example.test/vote",
            request_hash="request-hash",
            policy_version="policy-v1",
            context={},
            now=1_700_000_010.0,
        )
    except ValueError as exc:
        encoded = str(exc)
    else:
        raise AssertionError("missing authorization must fail closed")

    assert encoded == "hydra_remote_transport_authorization_missing"
    assert "https://hydra.example.test/vote" not in encoded
    assert "auth-1" not in encoded


def test_no_fail_open_fallback_for_unknown_authorization_state(monkeypatch) -> None:
    calls = []

    def transport(*_args, **_kwargs):
        calls.append("transport")
        raise AssertionError("transport must not be reached")

    monkeypatch.setattr("security.hydra_live_client.request.urlopen", transport)

    context = authorized_context(decision="REVIEW_REQUIRED")
    client = HydraLiveNodeClient("node1", url="https://hydra.example.test/vote")

    try:
        client.vote("request-hash", "policy-v1", context=context)
    except ValueError as exc:
        assert str(exc) == "hydra_remote_transport_authorization_not_allowed"
    else:
        raise AssertionError("unknown authorization must fail closed")

    assert calls == []


def test_post_transport_vote_validation_remains_intact() -> None:
    response = signed_vote("node1", "ALLOW")
    response["signature"] = "invalid"

    assert (
        validate_vote_response(
            response,
            expected_node_id="node1",
            request_hash="request-hash",
            policy_version="policy-v1",
        )
        == invalid_vote("node1")
    )


def test_transport_blocked_when_authorization_evidence_unverified(monkeypatch) -> None:
    calls = []

    def transport(*_args, **_kwargs):
        calls.append("transport")
        raise AssertionError("transport must not be reached")

    monkeypatch.setattr("security.hydra_live_client.request.urlopen", transport)
    monkeypatch.setattr("security.hydra_live_client.time.time", lambda: 1_700_000_010.0)

    client = HydraLiveNodeClient("node1", url="https://hydra.example.test/vote")
    context = authorized_context(evidence_verified=False)

    try:
        client.vote("request-hash", "policy-v1", context=context)
    except ValueError as exc:
        assert str(exc) == "hydra_remote_transport_authorization_evidence_unverified"
    else:
        raise AssertionError("unverified evidence must fail closed")

    assert calls == []


def test_transport_blocked_when_required_trust_material_unavailable(monkeypatch) -> None:
    calls = []

    def transport(*_args, **_kwargs):
        calls.append("transport")
        raise AssertionError("transport must not be reached")

    monkeypatch.setattr("security.hydra_live_client.request.urlopen", transport)
    monkeypatch.setattr("security.hydra_live_client.time.time", lambda: 1_700_000_010.0)

    client = HydraLiveNodeClient("node1", url="https://hydra.example.test/vote")
    context = authorized_context(trust_material_available=False)

    try:
        client.vote("request-hash", "policy-v1", context=context)
    except ValueError as exc:
        assert str(exc) == "hydra_remote_transport_authorization_trust_unavailable"
    else:
        raise AssertionError("unavailable trust material must fail closed")

    assert calls == []


@pytest.mark.parametrize(
    ("context", "expected_reason"),
    [
        ({}, "hydra_remote_transport_authorization_missing"),
        (
            {"hydra_remote_transport_authorization": "malformed"},
            "hydra_remote_transport_authorization_missing",
        ),
        (
            authorized_context(decision="DENY"),
            "hydra_remote_transport_authorization_not_allowed",
        ),
        (
            authorized_context(expires_at=1_700_000_001.0),
            "hydra_remote_transport_authorization_expired",
        ),
        (
            authorized_context(issued_at=1_699_999_000.0, expires_at=1_700_000_060.0),
            "hydra_remote_transport_authorization_stale",
        ),
        (
            authorized_context(node_id="node2"),
            "hydra_remote_transport_authorization_node_mismatch",
        ),
        (
            authorized_context(url="https://other-hydra.example.test/vote"),
            "hydra_remote_transport_authorization_endpoint_mismatch",
        ),
        (
            authorized_context(request_hash="other-request-hash"),
            "hydra_remote_transport_authorization_request_mismatch",
        ),
        (
            authorized_context(policy_version="policy-v2"),
            "hydra_remote_transport_authorization_policy_mismatch",
        ),
    ],
)
def test_hydra_transport_authorization_failures_block_before_urlopen(
    monkeypatch,
    context,
    expected_reason,
) -> None:
    calls = []

    def transport(*_args, **_kwargs):
        calls.append("transport")
        raise AssertionError("transport must not be reached")

    monkeypatch.setattr("security.hydra_live_client.request.urlopen", transport)
    monkeypatch.setattr("security.hydra_live_client.time.time", lambda: 1_700_000_010.0)

    client = HydraLiveNodeClient("node1", url="https://hydra.example.test/vote")

    try:
        client.vote("request-hash", "policy-v1", context=context)
    except ValueError as exc:
        assert str(exc) == expected_reason
    else:
        raise AssertionError("authorization failure must fail closed")

    assert calls == []
