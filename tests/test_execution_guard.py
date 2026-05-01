from __future__ import annotations

import time
from pathlib import Path

from fastapi.testclient import TestClient

import gateway.app as gateway_app
from audit.hash_chain import AuditHashChain
from security.decision_store import DecisionStoreTestDouble
from security.execution_guard import (
    build_execution_payload,
    execute_command,
    request_signature_message,
    sign_payload,
)
from security.hydra_consensus import HydraNodeDecision
from security.hydra_nodes import sign_hydra_node_decision
from security.nonce_store import NonceStore
from tests.request_signing_helpers import configure_request_signing, request_private_key_pem


class AllowClient:
    def __init__(self, node_id: str) -> None:
        self.node_id = node_id

    def evaluate(self, request_hash: str, policy_version: str) -> HydraNodeDecision:
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
    monkeypatch.setattr(
        gateway_app,
        "hydra_node_clients",
        [AllowClient("node-1"), AllowClient("node-2"), AllowClient("node-3")],
    )
    monkeypatch.setattr(gateway_app, "decision_store", DecisionStoreTestDouble())
    return TestClient(gateway_app.app, raise_server_exceptions=False)


def test_allowed_command_runs_after_gateway_approval(tmp_path: Path, monkeypatch) -> None:
    client = configure_gateway(tmp_path, monkeypatch)
    compile_target = tmp_path / "allowed_compile_target.py"
    compile_target.write_text("VALUE = 1\n", encoding="utf-8")

    result = execute_command(
        f"python3 -m py_compile {compile_target}",
        {
            "gateway_client": client,
            "request_private_key": request_private_key_pem(),
            "pubkey_id": "test_request_key",
            "tenant_id": "t1",
            "device": "laptop-1",
            "user_id": "alice",
        },
    )

    assert result["returncode"] == 0
    assert "command_hash" in result
    assert "python3 -m py_compile" not in str(result["command_hash"])


def test_denied_command_is_blocked(tmp_path: Path, monkeypatch) -> None:
    client = configure_gateway(tmp_path, monkeypatch)

    result = execute_command(
        "bash -lc 'echo should-not-run'",
        {
            "gateway_client": client,
            "request_private_key": request_private_key_pem(),
            "pubkey_id": "test_request_key",
            "tenant_id": "t1",
            "device": "laptop-1",
        },
    )

    assert result["error"] == "execution_denied"
    assert "command_hash" in result


def test_execution_guard_blocks_when_required_redis_is_down(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("REQUIRE_REDIS", "true")
    monkeypatch.setattr(gateway_app, "redis_available", lambda: False)
    client = configure_gateway(tmp_path, monkeypatch)

    result = execute_command(
        "python3 -m py_compile security/execution_guard.py",
        {
            "gateway_client": client,
            "request_private_key": request_private_key_pem(),
            "pubkey_id": "test_request_key",
            "tenant_id": "t1",
            "device": "laptop-1",
        },
    )

    assert result["error"] == "execution_denied"
    assert result["reason"] == "redis_unavailable"
    assert getattr(gateway_app.decision_store, "records", {}) == {}


def test_tampered_execution_request_is_blocked(tmp_path: Path, monkeypatch) -> None:
    client = configure_gateway(tmp_path, monkeypatch)
    payload = build_execution_payload(
        "python3 -m py_compile security/execution_guard.py",
        {"tenant_id": "t1", "device": "laptop-1"},
    )
    signed = sign_payload(payload, {"request_private_key": request_private_key_pem(), "pubkey_id": "test_request_key"})
    signed["command"] = "python3 -m pytest"

    response = client.post("/decide", json=signed)

    assert response.status_code == 403
    assert response.json()["decision"] == "DENY"
    assert response.json()["reason"] == "invalid_signature"


def test_missing_signature_is_blocked(tmp_path: Path, monkeypatch) -> None:
    client = configure_gateway(tmp_path, monkeypatch)
    payload = build_execution_payload(
        "python3 -m py_compile security/execution_guard.py",
        {"tenant_id": "t1", "device": "laptop-1"},
    )

    response = client.post("/decide", json=payload)

    assert response.status_code == 403
    assert response.json()["decision"] == "DENY"
    assert response.json()["reason"] == "invalid_signature"


def test_execution_signature_matches_gateway_message() -> None:
    payload = build_execution_payload(
        "python3 -m py_compile security/execution_guard.py",
        {"tenant_id": "t1", "device": "laptop-1"},
    )
    signed = sign_payload(payload, {"request_private_key": request_private_key_pem(), "pubkey_id": "test_request_key"})

    assert signed["signature_alg"] == "ed25519"
    assert signed["pubkey_id"] == "test_request_key"
    assert signed["signature"]
