from __future__ import annotations

import time
from pathlib import Path

from fastapi.testclient import TestClient

import gateway.app as gateway_app
from audit.hash_chain import AuditHashChain
from security.decision_store import DecisionStoreTestDouble
from security.hydra_consensus import HydraNodeDecision
from security.hydra_nodes import sign_hydra_node_decision
from security.nonce_store import NonceStore
from tests.request_signing_helpers import attach_signature_ed25519, configure_request_signing


def build_payload(data=None, nonce=None, timestamp=None) -> dict:
    payload = {
        "action": "read",
        "actor_id": "actor-alice",
        "device": "laptop-1",
        "nonce": "hydra-test-nonce-default",
        "tenant_id": "t1",
        "timestamp": int(time.time()),
        "user_id": "alice",
        "policy_version": "policy-v1",
        "compute_target": "cpu",
        "compute_risk_level": "low",
        "data_sensitivity": "low",
        "execution_location": "local",
    }
    if data:
        payload.update(data.copy())
    if nonce is not None:
        payload["nonce"] = nonce
    if timestamp is not None:
        payload["timestamp"] = timestamp
    return payload


def sign_payload(payload: dict) -> None:
    attach_signature_ed25519(payload)


def configure_gateway(tmp_path: Path, monkeypatch) -> TestClient:
    configure_request_signing(tmp_path, monkeypatch, gateway_app)
    monkeypatch.setattr(
        gateway_app,
        "nonce_store",
        NonceStore(tmp_path / "used_nonces.json"),
    )
    monkeypatch.setattr(
        gateway_app,
        "audit_chain",
        AuditHashChain(tmp_path / "audit_chain.json"),
    )
    monkeypatch.setattr(gateway_app, "decision_store", DecisionStoreTestDouble())
    return TestClient(gateway_app.app, raise_server_exceptions=False)


def decide_then_execute(client: TestClient, payload: dict):
    decision = client.post("/decide", json=payload)
    assert decision.status_code == 200
    approved = payload.copy()
    approved["decision_id"] = decision.json()["decision_id"]
    approved["decision_signature"] = decision.json()["decision_signature"]
    approved["decision_signature_classic"] = decision.json()["decision_signature_classic"]
    approved["decision_signature_pqc"] = decision.json()["decision_signature_pqc"]
    return client.post("/execute", json=approved)


def decide_denied(client: TestClient, payload: dict):
    decision = client.post("/decide", json=payload)
    assert decision.status_code == 200
    assert decision.json()["decision"] == "DENY"
    return decision


class AllowClient:
    def __init__(self, node_id: str) -> None:
        self.node_id = node_id
        self.calls = []

    def evaluate(self, request_hash: str, policy_version: str) -> HydraNodeDecision:
        self.calls.append((request_hash, policy_version))
        return sign_hydra_node_decision(
            HydraNodeDecision(
                node_id=self.node_id,
                request_hash=request_hash,
                policy_version=policy_version,
                decision="allow",
                reason=f"{self.node_id}_allow",
                timestamp=time.time(),
            )
        )


class OfflineClient:
    def __init__(self, node_id: str) -> None:
        self.node_id = node_id

    def evaluate(self, request_hash: str, policy_version: str) -> HydraNodeDecision:
        raise OSError("node offline")


class TimeoutClient:
    def __init__(self, node_id: str) -> None:
        self.node_id = node_id

    def evaluate(self, request_hash: str, policy_version: str) -> HydraNodeDecision:
        raise TimeoutError("node timed out")


class MaliciousClient:
    def __init__(self, node_id: str) -> None:
        self.node_id = node_id

    def evaluate(self, request_hash: str, policy_version: str) -> HydraNodeDecision:
        return HydraNodeDecision(
            node_id=self.node_id,
            request_hash=request_hash,
            policy_version=policy_version,
            decision="allow",
            reason="unsigned_malicious_allow",
            timestamp=time.time(),
            signature="invalid-signature",
        )


class MismatchedHashClient:
    def __init__(self, node_id: str) -> None:
        self.node_id = node_id

    def evaluate(self, request_hash: str, policy_version: str) -> HydraNodeDecision:
        return sign_hydra_node_decision(
            HydraNodeDecision(
                node_id=self.node_id,
                request_hash="different-request-hash",
                policy_version=policy_version,
                decision="allow",
                reason="mismatched_hash",
                timestamp=time.time(),
            )
        )


def test_valid_request_passes_hydra_consensus(tmp_path: Path, monkeypatch) -> None:
    client = configure_gateway(tmp_path, monkeypatch)
    node_1 = AllowClient("node-1")
    node_2 = AllowClient("node-2")
    node_3 = AllowClient("node-3")
    monkeypatch.setattr(
        gateway_app,
        "hydra_node_clients",
        [node_1, node_2, node_3],
    )
    payload = build_payload()
    sign_payload(payload)

    response = decide_then_execute(client, payload)

    assert response.status_code == 200
    assert response.json() == {"status": "EXECUTED"}
    assert len(node_1.calls[0]) == 2
    assert payload["nonce"] not in node_1.calls[0]
    assert payload["device"] not in node_1.calls[0]


def test_one_node_offline_still_allows_with_two_of_three(tmp_path: Path, monkeypatch) -> None:
    client = configure_gateway(tmp_path, monkeypatch)
    monkeypatch.setattr(
        gateway_app,
        "hydra_node_clients",
        [AllowClient("node-1"), AllowClient("node-2"), OfflineClient("node-3")],
    )
    payload = build_payload()
    sign_payload(payload)

    response = decide_then_execute(client, payload)

    assert response.status_code == 200
    assert response.json() == {"status": "EXECUTED"}


def test_malicious_node_with_invalid_signature_is_ignored(tmp_path: Path, monkeypatch) -> None:
    client = configure_gateway(tmp_path, monkeypatch)
    monkeypatch.setattr(
        gateway_app,
        "hydra_node_clients",
        [AllowClient("node-1"), AllowClient("node-2"), MaliciousClient("node-3")],
    )
    payload = build_payload()
    sign_payload(payload)

    response = decide_then_execute(client, payload)

    assert response.status_code == 200
    assert response.json() == {"status": "EXECUTED"}


def test_inconsistent_request_hash_denies(tmp_path: Path, monkeypatch) -> None:
    client = configure_gateway(tmp_path, monkeypatch)
    monkeypatch.setattr(
        gateway_app,
        "hydra_node_clients",
        [AllowClient("node-1"), MismatchedHashClient("node-2"), AllowClient("node-3")],
    )
    payload = build_payload()
    sign_payload(payload)

    response = decide_denied(client, payload)

    assert response.status_code == 200
    assert response.json()["reason"] == "hydra_denied"


def test_two_nodes_fail_denies(tmp_path: Path, monkeypatch) -> None:
    client = configure_gateway(tmp_path, monkeypatch)
    monkeypatch.setattr(
        gateway_app,
        "hydra_node_clients",
        [AllowClient("node-1"), OfflineClient("node-2"), OfflineClient("node-3")],
    )
    payload = build_payload()
    sign_payload(payload)

    response = decide_denied(client, payload)

    assert response.status_code == 200
    assert response.json()["reason"] == "hydra_denied"


def test_timeout_counts_as_deny_and_blocks_without_majority(tmp_path: Path, monkeypatch) -> None:
    client = configure_gateway(tmp_path, monkeypatch)
    monkeypatch.setattr(
        gateway_app,
        "hydra_node_clients",
        [AllowClient("node-1"), TimeoutClient("node-2"), MaliciousClient("node-3")],
    )
    payload = build_payload()
    sign_payload(payload)

    response = decide_denied(client, payload)

    assert response.status_code == 200
    assert response.json()["reason"] == "hydra_denied"


def test_missing_node_counts_as_deny_and_blocks_without_majority(tmp_path: Path, monkeypatch) -> None:
    client = configure_gateway(tmp_path, monkeypatch)
    monkeypatch.setattr(
        gateway_app,
        "hydra_node_clients",
        [AllowClient("node-1")],
    )
    payload = build_payload()
    sign_payload(payload)

    response = decide_denied(client, payload)

    assert response.status_code == 200
    assert response.json()["reason"] == "hydra_denied"
