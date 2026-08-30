from __future__ import annotations

import time
import json
from pathlib import Path

from fastapi.testclient import TestClient

import gateway.app as gateway_app
from audit.hash_chain import AuditHashChain
from security.decision_store import DecisionStoreTestDouble
from security.execution_guard import (
    build_execution_payload,
    classify_command,
    classify_execution_tier,
    enforce_local_execution_policy,
    execute_command,
    govern_escalation_request,
    handle_sandbox_tool_rejection,
    request_signature_message,
    sign_payload,
)
from security.hydra_consensus import HydraNodeDecision, replay_registry_hash as hydra_replay_registry_hash
from security.hydra_nodes import sign_hydra_node_decision
from security.nonce_store import NonceStore
from tests.provenance_helpers import install_runtime_authority, install_signed_runtime_attestation_fixture
from tests.request_signing_helpers import configure_request_signing, request_private_key_pem
from tests.test_gateway_app import _gateway_authorization_request, _seed_gateway_authority_registry


class AllowClient:
    def __init__(self, node_id: str) -> None:
        self.node_id = node_id

    def evaluate(self, request_hash: str, policy_version: str, context: dict | None = None) -> HydraNodeDecision:
        safe_context = context or {}
        policy_hash_value = str(safe_context.get("policy_hash", ""))
        nonce_hash_value = str(safe_context.get("nonce_hash", ""))
        tenant_id = str(safe_context.get("tenant_id", "t1"))
        return sign_hydra_node_decision(
            HydraNodeDecision(
                node_id=self.node_id,
                node_role={"node-1": "primary", "node-2": "secondary", "node-3": "offline_backup"}.get(self.node_id, ""),
                request_hash=request_hash,
                policy_version=policy_version,
                policy_hash=policy_hash_value,
                nonce_hash=nonce_hash_value,
                replay_registry_hash=str(safe_context.get("replay_registry_hash") or hydra_replay_registry_hash(policy_hash_value, nonce_hash_value)),
                nonce_state=str(safe_context.get("nonce_state", "unused")),
                tenant_id=tenant_id,
                tenant_hash=__import__("hashlib").sha256(tenant_id.encode("utf-8")).hexdigest(),
                decision="allow",
                reason=f"{self.node_id}_allow",
                timestamp=time.time(),
                attestation_timestamp=float(safe_context.get("attestation_timestamp", time.time())),
                attestation_hash=f"attestation-hash-{self.node_id}",
                attestation_node_id=f"attested-{self.node_id}",
                attestation_provider_mode="mock_local",
            )
        )


def configure_gateway(tmp_path: Path, monkeypatch) -> TestClient:
    install_runtime_authority(monkeypatch, tmp_path)
    configure_request_signing(tmp_path, monkeypatch, gateway_app)
    gateway_authorization_request = _gateway_authorization_request(f"execution-guard-authz-{tmp_path.name}")
    registry = _seed_gateway_authority_registry(tmp_path, gateway_authorization_request)
    monkeypatch.setenv("USBAY_GATEWAY_AUTHORITY_REGISTRY", str(registry.registry_path))
    monkeypatch.setenv("USBAY_GATEWAY_AUTHZ_REPLAY_DB", str(tmp_path / "gateway_authz_replay.db"))
    monkeypatch.setenv("USBAY_GATEWAY_AUTHZ_AUDIT_PATH", str(tmp_path / "gateway_authz_audit.json"))
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
    install_signed_runtime_attestation_fixture(monkeypatch)
    runtime_revocation_registry_path = tmp_path / "runtime_revocation_registry.json"
    runtime_revocation_registry_path.write_text(
        json.dumps(
            {
                "schema_version": "usbay.runtime_revocation_registry.v1",
                "registry_state": "ACTIVE",
                "revoked_runtime_ids": [],
                "revoked_device_ids": [],
                "revoked_attestation_ids": [],
                "revoked_operator_ids": [],
            },
            sort_keys=True,
        ),
        encoding="utf-8",
    )
    monkeypatch.setenv("USBAY_RUNTIME_REVOCATION_REGISTRY_PATH", str(runtime_revocation_registry_path))
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
    gateway_authorization_request = _gateway_authorization_request(f"execution-guard-valid-{tmp_path.name}")
    registry = _seed_gateway_authority_registry(tmp_path, gateway_authorization_request)
    monkeypatch.setenv("USBAY_GATEWAY_AUTHORITY_REGISTRY", str(registry.registry_path))

    result = execute_command(
        f"python3 -m py_compile {compile_target}",
        {
            "gateway_client": client,
            "request_private_key": request_private_key_pem(),
            "pubkey_id": "test_request_key",
            "tenant_id": "t1",
            "device": "laptop-1",
            "user_id": "alice",
            "gateway_authorization_request": gateway_authorization_request,
        },
    )

    assert result["status"] == "EXECUTED"
    assert "command_hash" in result
    assert "python3 -m py_compile" not in str(result["command_hash"])


class _GatewayResponse:
    def __init__(self, status_code: int, body: dict) -> None:
        self.status_code = status_code
        self._body = body

    def json(self) -> dict:
        return self._body


class _GatewayClientDouble:
    def __init__(self, execute_status: int = 200, execute_body: dict | None = None) -> None:
        self.execute_status = execute_status
        self.execute_body = execute_body or {"status": "EXECUTED"}
        self.paths: list[str] = []

    def post(self, path: str, json: dict) -> _GatewayResponse:
        self.paths.append(path)
        if path == "/decide":
            return _GatewayResponse(
                200,
                {
                    "decision": "ALLOW",
                    "decision_id": "decision-test",
                    "decision_signature": "sha256:test",
                    "decision_signature_classic": "sha256:classic",
                    "decision_signature_pqc": "sha256:pqc",
                },
            )
        if path == "/execute":
            return _GatewayResponse(self.execute_status, self.execute_body)
        return _GatewayResponse(404, {"error": "unknown_path"})


def _guard_metadata(client: _GatewayClientDouble) -> dict:
    return {
        "gateway_client": client,
        "request_private_key": request_private_key_pem(),
        "pubkey_id": "test_request_key",
        "tenant_id": "t1",
        "device": "laptop-1",
        "user_id": "alice",
        "gateway_authorization_request": {"request_id": "unit-authz-request"},
    }


def test_direct_execute_command_run_command_bypass_is_impossible(monkeypatch) -> None:
    client = _GatewayClientDouble()
    monkeypatch.setattr("security.execution_guard._run_command", lambda _cmd: (_ for _ in ()).throw(AssertionError("local sink reached")))

    result = execute_command("python3 -m py_compile security/execution_guard.py", _guard_metadata(client))

    assert result["status"] == "EXECUTED"
    assert client.paths == ["/decide", "/execute"]


def test_authorization_failure_never_reaches_run_command(monkeypatch) -> None:
    client = _GatewayClientDouble(403, {"error": "GATEWAY_AUTHORIZATION_REQUEST_MISSING"})
    monkeypatch.setattr("security.execution_guard._run_command", lambda _cmd: (_ for _ in ()).throw(AssertionError("local sink reached")))

    result = execute_command("python3 -m py_compile security/execution_guard.py", _guard_metadata(client))

    assert result["error"] == "execution_denied"
    assert result["reason"] == "GATEWAY_AUTHORIZATION_REQUEST_MISSING"
    assert client.paths == ["/decide", "/execute"]


def test_unavailable_authorization_dependency_blocks_execution(monkeypatch) -> None:
    client = _GatewayClientDouble(503, {"error": "AUTHORITY_SOURCE_UNAVAILABLE"})
    monkeypatch.setattr("security.execution_guard._run_command", lambda _cmd: (_ for _ in ()).throw(AssertionError("local sink reached")))

    result = execute_command("python3 -m py_compile security/execution_guard.py", _guard_metadata(client))

    assert result["error"] == "execution_denied"
    assert result["reason"] == "AUTHORITY_SOURCE_UNAVAILABLE"


def test_replay_revocation_and_mismatch_block_execution(monkeypatch) -> None:
    monkeypatch.setattr("security.execution_guard._run_command", lambda _cmd: (_ for _ in ()).throw(AssertionError("local sink reached")))
    for reason in ("REPLAY_DETECTED", "AUTHORITY_HUMAN_APPROVAL_REVOKED", "BINDING_POLICY_HASH_MISMATCH"):
        client = _GatewayClientDouble(403, {"error": reason})

        result = execute_command("python3 -m py_compile security/execution_guard.py", _guard_metadata(client))

        assert result["error"] == "execution_denied"
        assert result["reason"] == reason
        assert client.paths == ["/decide", "/execute"]


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
    assert result["reason"] == "explicit_approval_required"
    assert "command_hash" in result


def test_local_execution_policy_classifies_approval_required_risks() -> None:
    rm_policy = classify_command("rm -rf /tmp/example")
    network_policy = classify_command("curl https://example.invalid")
    unsandboxed_policy = classify_command("python3 -m py_compile x.py", {"sandboxed": False})
    chain_policy = classify_command("python3 -m py_compile x.py && echo done")

    assert rm_policy["risk_level"] == "high"
    assert "rm_rf" in rm_policy["reasons"]
    assert "network_access" in network_policy["reasons"]
    assert "unsandboxed_execution" in unsandboxed_policy["reasons"]
    assert "subprocess_chain" in chain_policy["reasons"]


def test_unknown_command_denied_by_default_with_signed_evidence(tmp_path: Path) -> None:
    evidence = tmp_path / "execution_evidence.jsonl"

    decision = enforce_local_execution_policy(
        "python3 -m pytest",
        {
            "tenant_id": "t1",
            "device": "laptop-1",
            "execution_evidence_path": str(evidence),
        },
    )

    assert decision["allowed"] is False
    assert decision["reason"] == "unknown_classification"
    records = evidence.read_text(encoding="utf-8").splitlines()
    assert len(records) == 1
    assert "signature" in records[0]
    assert "python3 -m pytest" not in records[0]


def test_approval_required_command_denied_without_explicit_approval(tmp_path: Path) -> None:
    decision = enforce_local_execution_policy(
        "curl https://example.invalid",
        {
            "tenant_id": "t1",
            "device": "laptop-1",
            "execution_evidence_path": str(tmp_path / "execution_evidence.jsonl"),
        },
    )

    assert decision["allowed"] is False
    assert decision["reason"] == "explicit_approval_required"


def test_approval_required_command_policy_allows_with_explicit_approval(tmp_path: Path) -> None:
    decision = enforce_local_execution_policy(
        "curl https://example.invalid",
        {
            "tenant_id": "t1",
            "device": "laptop-1",
            "execution_evidence_path": str(tmp_path / "execution_evidence.jsonl"),
            "execution_governance_approval": {
                "approved": True,
                "approved_by": "human-operator",
                "reason": "network validation approved",
            },
        },
    )

    assert decision["allowed"] is True
    assert decision["audit_event_hash"]


def test_policy_engine_unavailable_fails_closed(tmp_path: Path) -> None:
    decision = enforce_local_execution_policy(
        "python3 -m py_compile security/execution_guard.py",
        {
            "tenant_id": "t1",
            "device": "laptop-1",
            "execution_evidence_path": str(tmp_path / "execution_evidence.jsonl"),
            "policy_engine_unavailable": True,
        },
    )

    assert decision["allowed"] is False
    assert decision["reason"] == "policy_engine_unavailable"


def test_evidence_unavailable_fails_closed(tmp_path: Path) -> None:
    blocked_dir = tmp_path / "blocked"
    blocked_dir.mkdir()

    decision = enforce_local_execution_policy(
        "python3 -m py_compile security/execution_guard.py",
        {
            "tenant_id": "t1",
            "device": "laptop-1",
            "execution_evidence_path": str(blocked_dir),
        },
    )

    assert decision["allowed"] is False
    assert decision["reason"] == "execution_evidence_unavailable"


def test_py_compile_is_t1_compile_lint_tier() -> None:
    python3_tier = classify_execution_tier("python3 -m py_compile security/execution_guard.py")
    python_tier = classify_execution_tier("python -m py_compile security/execution_guard.py")
    policy = classify_command("python3 -m py_compile security/execution_guard.py")

    assert python3_tier["execution_tier"] == "T1"
    assert python_tier["execution_tier"] == "T1"
    assert policy["classification"] == "allowable"
    assert policy["tier_name"] == "compile_lint"


def test_t1_compile_lint_tool_rejection_never_requests_unsandboxed_escalation() -> None:
    decision = handle_sandbox_tool_rejection(
        "python3 -m py_compile security/execution_guard.py",
        'CreateProcess { message: "Rejected(\\"rejected by user\\")" }',
    )

    assert decision["allowed"] is False
    assert decision["reason"] == "t1_compile_lint_no_unsandboxed_escalation"
    assert decision["execution_tier"] == "T1"
    assert decision["escalation_request_created"] is False
    assert "CreateProcess rejection before Python starts" in decision["sandbox_failure_source"]


def test_repeated_escalation_loop_denied_by_default() -> None:
    request = {
        "type": "sandbox_escalation_request",
        "classification": "approval_required",
        "risk_level": "high",
        "execution_tier": "T3",
        "requires_policy_approval": True,
    }

    decision = govern_escalation_request(
        request,
        {
            "escalation_attempts": 1,
            "execution_governance_approval": {
                "approved": True,
                "approved_by": "operator",
                "reason": "retry requested",
            },
        },
    )

    assert decision["allowed"] is False
    assert decision["reason"] == "repeated_escalation_loop_denied"


def test_unknown_execution_tier_blocks_escalation_prompt() -> None:
    request = {
        "type": "sandbox_escalation_request",
        "classification": "unknown",
        "risk_level": "unknown",
        "execution_tier": "UNKNOWN",
        "requires_policy_approval": True,
    }

    decision = govern_escalation_request(request, {})

    assert decision["allowed"] is False
    assert decision["reason"] == "unknown_escalation_classification"


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
