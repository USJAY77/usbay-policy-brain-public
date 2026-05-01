from __future__ import annotations

from fastapi.testclient import TestClient

from security import hydra_node_service
from security.hydra_node_service import (
    build_vote_response,
    evaluate_node_vote,
    verify_vote_signature,
)


def test_vote_endpoint_returns_signed_allow(monkeypatch) -> None:
    monkeypatch.setenv("USBAY_HYDRA_NODE_ID", "node1")
    monkeypatch.setenv("USBAY_HYDRA_NODE_1_KEY", "node-1-test-secret")
    client = TestClient(hydra_node_service.app)

    response = client.post(
        "/vote",
        json={
            "request_hash": "request-hash",
            "policy_version": "policy-v1",
            "action": "execute",
            "context": {},
        },
    )

    assert response.status_code == 200
    vote = response.json()
    assert vote["node_id"] == "node1"
    assert vote["decision"] == "ALLOW"
    assert vote["request_hash"] == "request-hash"
    assert vote["policy_version"] == "policy-v1"
    assert vote["valid"] is True
    assert verify_vote_signature(vote, "node-1-test-secret") is True


def test_vote_endpoint_supports_per_node_metadata_decision(monkeypatch) -> None:
    monkeypatch.setenv("USBAY_HYDRA_NODE_ID", "node3")
    client = TestClient(hydra_node_service.app)

    response = client.post(
        "/vote",
        json={
            "request_hash": "request-hash",
            "policy_version": "policy-v1",
            "action": "execute",
            "context": {"node_decisions": {"node3": "DENY"}},
        },
    )

    assert response.status_code == 200
    assert response.json()["node_id"] == "node3"
    assert response.json()["decision"] == "DENY"


def test_vote_endpoint_denies_missing_hash_fail_closed(monkeypatch) -> None:
    monkeypatch.setenv("USBAY_HYDRA_NODE_ID", "node2")
    client = TestClient(hydra_node_service.app)

    response = client.post(
        "/vote",
        json={
            "request_hash": "",
            "policy_version": "policy-v1",
            "action": "execute",
            "context": {},
        },
    )

    assert response.status_code == 200
    assert response.json()["node_id"] == "node2"
    assert response.json()["decision"] == "DENY"
    assert response.json()["valid"] is True


def test_vote_signature_detection_fails_for_tampering(monkeypatch) -> None:
    monkeypatch.setenv("USBAY_HYDRA_NODE_1_KEY", "node-1-test-secret")
    vote = build_vote_response(
        node_id="node1",
        decision="ALLOW",
        request_hash="request-hash",
        policy_version="policy-v1",
    )

    vote["decision"] = "DENY"

    assert verify_vote_signature(vote, "node-1-test-secret") is False


def test_evaluate_node_vote_never_returns_raw_context() -> None:
    vote = evaluate_node_vote(
        {
            "request_hash": "request-hash",
            "policy_version": "policy-v1",
            "action": "execute",
            "context": {"payload": "secret"},
        },
        node_id="node1",
    )

    assert "context" not in vote
    assert "payload" not in vote
