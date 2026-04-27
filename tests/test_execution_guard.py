from __future__ import annotations

import hashlib
import hmac
import time
from pathlib import Path

from fastapi.testclient import TestClient

import gateway.app as gateway_app
from audit.hash_chain import AuditHashChain
from security.execution_guard import (
    build_execution_payload,
    execute_command,
    request_signature_message,
    sign_payload,
)
from security.hydra_consensus import HydraNodeDecision
from security.hydra_nodes import sign_hydra_node_decision
from security.nonce_store import NonceStore


DEVICE_KEY = "device-test-key"


class FakeKeyStore:
    def load_device_key(self, tenant_id: str, device: str) -> dict:
        return {"key": DEVICE_KEY}


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
    monkeypatch.setattr(gateway_app, "keystore", FakeKeyStore())
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
    return TestClient(gateway_app.app, raise_server_exceptions=False)


def test_allowed_command_runs_after_gateway_approval(tmp_path: Path, monkeypatch) -> None:
    client = configure_gateway(tmp_path, monkeypatch)
    compile_target = tmp_path / "allowed_compile_target.py"
    compile_target.write_text("VALUE = 1\n", encoding="utf-8")

    result = execute_command(
        f"python3 -m py_compile {compile_target}",
        {
            "gateway_client": client,
            "device_key": DEVICE_KEY,
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
            "device_key": DEVICE_KEY,
            "tenant_id": "t1",
            "device": "laptop-1",
        },
    )

    assert result["error"] == "execution_denied"
    assert "command_hash" in result


def test_tampered_execution_request_is_blocked(tmp_path: Path, monkeypatch) -> None:
    client = configure_gateway(tmp_path, monkeypatch)
    payload = build_execution_payload(
        "python3 -m py_compile security/execution_guard.py",
        {"tenant_id": "t1", "device": "laptop-1"},
    )
    signed = sign_payload(payload, {"device_key": DEVICE_KEY})
    signed["command"] = "python3 -m pytest"

    response = client.post("/execute", json=signed)

    assert response.status_code == 403
    assert response.json() == {"detail": "FAIL_CLOSED"}


def test_missing_signature_is_blocked(tmp_path: Path, monkeypatch) -> None:
    client = configure_gateway(tmp_path, monkeypatch)
    payload = build_execution_payload(
        "python3 -m py_compile security/execution_guard.py",
        {"tenant_id": "t1", "device": "laptop-1"},
    )

    response = client.post("/execute", json=payload)

    assert response.status_code == 403
    assert response.json() == {"detail": "FAIL_CLOSED"}


def test_execution_signature_matches_gateway_message() -> None:
    payload = build_execution_payload(
        "python3 -m py_compile security/execution_guard.py",
        {"tenant_id": "t1", "device": "laptop-1"},
    )
    signed = sign_payload(payload, {"device_key": DEVICE_KEY})
    expected = hmac.new(
        DEVICE_KEY.encode(),
        request_signature_message(signed).encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()

    assert signed["signature"] == expected
