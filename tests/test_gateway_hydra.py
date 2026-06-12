from __future__ import annotations

import time
import json
from datetime import datetime, timezone
from pathlib import Path

from fastapi.testclient import TestClient

import gateway.app as gateway_app
from audit.hash_chain import AuditHashChain
from security.decision_store import DecisionStoreTestDouble
from security.hydra_consensus import HydraNodeDecision
from security.hydra_consensus import replay_registry_hash as hydra_replay_registry_hash
from security.hydra_nodes import sign_hydra_node_decision
from security.nonce_store import NonceStore
from security.persistent_nonce_store import LocalPersistentNonceStore, initialize_persistent_nonce_store
from governance.correction_proposals import detect_governance_issue, generate_correction_proposal
from governance.proposal_execution_adapter import ProposalExecutionAdapter
from governance.proposal_registry import ProposalRegistry, STATE_APPROVED, initialize_proposal_registry
from tests.provenance_helpers import install_runtime_authority
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
    install_runtime_authority(monkeypatch, tmp_path)
    configure_request_signing(tmp_path, monkeypatch, gateway_app)
    deployment_timestamp = datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    monkeypatch.setattr(
        gateway_app,
        "signed_runtime_attestation_snapshot",
        lambda *args, **kwargs: {
            "attestation_status": "SIGNED",
            "signature_valid": True,
            "deployment_timestamp_utc": deployment_timestamp,
        },
    )
    runtime_nonce_store_path = tmp_path / "runtime_nonce_store.json"
    initialize_persistent_nonce_store(runtime_nonce_store_path)
    monkeypatch.setenv("USBAY_RUNTIME_NONCE_STORE_PATH", str(runtime_nonce_store_path))
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


class FixtureResponse:
    def __init__(self, status_code: int, body: dict) -> None:
        self.status_code = status_code
        self._body = body

    def json(self) -> dict:
        return self._body


def _active_revocation_registry(path: Path) -> None:
    path.write_text(
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


def _execution_eligibility_fixture(tmp_path: Path, approved_payload: dict) -> FixtureResponse:
    timestamp = datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    registry_path = tmp_path / "proposal_registry.json"
    nonce_store_path = tmp_path / "proposal_execution_nonce_store.json"
    revocation_path = tmp_path / "proposal_execution_revocation_registry.json"
    initialize_proposal_registry(registry_path)
    initialize_persistent_nonce_store(nonce_store_path)
    _active_revocation_registry(revocation_path)
    issue = detect_governance_issue(
        "CI_FAILURE",
        observed_failure="hydra approved execution requires PB-298 eligibility",
        source="test_gateway_hydra",
    )
    proposal = generate_correction_proposal(issue, timestamp=timestamp)
    proposal_registry = ProposalRegistry(registry_path)
    proposal_registry.create(proposal, timestamp=timestamp)
    proposal_registry.transition(proposal["proposal_id"], lifecycle_state=STATE_APPROVED, timestamp=timestamp)
    adapter = ProposalExecutionAdapter(
        proposal_registry=proposal_registry,
        nonce_store=LocalPersistentNonceStore(nonce_store_path, now_fn=time.time),
        revocation_registry_path=revocation_path,
        policy_loader=lambda: gateway_app.load_policy_registry(
            provenance_context=gateway_app.runtime_provenance_context()
        ),
    )
    result = adapter.evaluate(
        {
            "proposal_id": proposal["proposal_id"],
            "proposal_hash": proposal["proposal_hash"],
            "approval_id": str(approved_payload["decision_id"]),
            "execution_id": str(approved_payload["decision_id"]),
            "actor": str(approved_payload.get("actor_id", "")),
            "runtime_id": "hydra-runtime",
            "device_id": str(approved_payload.get("device", "")),
            "attestation_id": "hydra-attestation",
            "operator_id": str(approved_payload.get("user_id", "")),
            "nonce": str(approved_payload.get("nonce", "")),
        },
        timestamp=timestamp,
    )
    status = 200 if result["decision"] == "EXECUTION_ELIGIBLE" else 403
    return FixtureResponse(status, {"status": result["execution_state"], "reason_code": result["reason_code"]})


def decide_then_execute(client: TestClient, payload: dict, tmp_path: Path):
    decision = client.post("/decide", json=payload)
    assert decision.status_code == 200
    approved = payload.copy()
    approved["decision_id"] = decision.json()["decision_id"]
    approved["decision_signature"] = decision.json()["decision_signature"]
    approved["decision_signature_classic"] = decision.json()["decision_signature_classic"]
    approved["decision_signature_pqc"] = decision.json()["decision_signature_pqc"]
    return _execution_eligibility_fixture(tmp_path, approved)


def decide_denied(client: TestClient, payload: dict):
    decision = client.post("/decide", json=payload)
    assert decision.status_code == 200
    assert decision.json()["decision"] == "DENY"
    return decision


class AllowClient:
    def __init__(self, node_id: str) -> None:
        self.node_id = node_id
        self.calls = []

    def evaluate(self, request_hash: str, policy_version: str, context: dict | None = None) -> HydraNodeDecision:
        self.calls.append((request_hash, policy_version))
        state = hydra_state(self.node_id, context)
        return sign_hydra_node_decision(
            HydraNodeDecision(
                node_id=self.node_id,
                request_hash=request_hash,
                policy_version=policy_version,
                decision="allow",
                reason=f"{self.node_id}_allow",
                timestamp=time.time(),
                **state,
            )
        )


class OfflineClient:
    def __init__(self, node_id: str) -> None:
        self.node_id = node_id

    def evaluate(self, request_hash: str, policy_version: str, context: dict | None = None) -> HydraNodeDecision:
        raise OSError("node offline")


class TimeoutClient:
    def __init__(self, node_id: str) -> None:
        self.node_id = node_id

    def evaluate(self, request_hash: str, policy_version: str, context: dict | None = None) -> HydraNodeDecision:
        raise TimeoutError("node timed out")


class MaliciousClient:
    def __init__(self, node_id: str) -> None:
        self.node_id = node_id

    def evaluate(self, request_hash: str, policy_version: str, context: dict | None = None) -> HydraNodeDecision:
        state = hydra_state(self.node_id, context)
        return HydraNodeDecision(
            node_id=self.node_id,
            request_hash=request_hash,
            policy_version=policy_version,
            decision="allow",
            reason="unsigned_malicious_allow",
            timestamp=time.time(),
            **state,
            signature="invalid-signature",
        )


class MismatchedHashClient:
    def __init__(self, node_id: str) -> None:
        self.node_id = node_id

    def evaluate(self, request_hash: str, policy_version: str, context: dict | None = None) -> HydraNodeDecision:
        state = hydra_state(self.node_id, context)
        return sign_hydra_node_decision(
            HydraNodeDecision(
                node_id=self.node_id,
                request_hash="different-request-hash",
                policy_version=policy_version,
                decision="allow",
                reason="mismatched_hash",
                timestamp=time.time(),
                **state,
            )
        )


def hydra_state(node_id: str, context: dict | None = None, **overrides) -> dict:
    safe_context = context or {}
    policy_hash = str(overrides.get("policy_hash", safe_context.get("policy_hash", "")))
    nonce_hash = str(overrides.get("nonce_hash", safe_context.get("nonce_hash", "")))
    tenant_id = str(overrides.get("tenant_id", safe_context.get("tenant_id", "t1")))
    state = {
        "node_role": {"node-1": "primary", "node-2": "secondary", "node-3": "offline_backup"}.get(node_id, ""),
        "policy_hash": policy_hash,
        "nonce_hash": nonce_hash,
        "replay_registry_hash": str(
            overrides.get(
                "replay_registry_hash",
                safe_context.get("replay_registry_hash") or hydra_replay_registry_hash(policy_hash, nonce_hash),
            )
        ),
        "nonce_state": str(overrides.get("nonce_state", safe_context.get("nonce_state", "unused"))),
        "tenant_id": tenant_id,
        "tenant_hash": __import__("hashlib").sha256(tenant_id.encode("utf-8")).hexdigest(),
        "attestation_timestamp": float(overrides.get("attestation_timestamp", safe_context.get("attestation_timestamp", time.time()))),
        "attestation_hash": str(overrides.get("attestation_hash", f"attestation-hash-{node_id}")),
        "attestation_node_id": str(overrides.get("attestation_node_id", f"attested-{node_id}")),
        "attestation_provider_mode": str(overrides.get("attestation_provider_mode", "mock_local")),
        "hardware_backed": bool(overrides.get("hardware_backed", False)),
    }
    return state


class StaleClient(AllowClient):
    def evaluate(self, request_hash: str, policy_version: str, context: dict | None = None) -> HydraNodeDecision:
        stale = time.time() - 120
        return sign_hydra_node_decision(
            HydraNodeDecision(
                node_id=self.node_id,
                request_hash=request_hash,
                policy_version=policy_version,
                decision="allow",
                reason=f"{self.node_id}_stale",
                timestamp=stale,
                **hydra_state(self.node_id, context, attestation_timestamp=stale),
            )
        )


class ReplayDivergenceClient(AllowClient):
    def evaluate(self, request_hash: str, policy_version: str, context: dict | None = None) -> HydraNodeDecision:
        return sign_hydra_node_decision(
            HydraNodeDecision(
                node_id=self.node_id,
                request_hash=request_hash,
                policy_version=policy_version,
                decision="allow",
                reason="replay_registry_divergence",
                timestamp=time.time(),
                **hydra_state(self.node_id, context, replay_registry_hash="divergent"),
            )
        )


class PolicyHashMismatchClient(AllowClient):
    def evaluate(self, request_hash: str, policy_version: str, context: dict | None = None) -> HydraNodeDecision:
        return sign_hydra_node_decision(
            HydraNodeDecision(
                node_id=self.node_id,
                request_hash=request_hash,
                policy_version=policy_version,
                decision="allow",
                reason="policy_hash_mismatch",
                timestamp=time.time(),
                **hydra_state(self.node_id, context, policy_hash="different-policy-hash"),
            )
        )


class DenyClient(AllowClient):
    def evaluate(self, request_hash: str, policy_version: str, context: dict | None = None) -> HydraNodeDecision:
        return sign_hydra_node_decision(
            HydraNodeDecision(
                node_id=self.node_id,
                request_hash=request_hash,
                policy_version=policy_version,
                decision="deny",
                reason="explicit_deny",
                timestamp=time.time(),
                **hydra_state(self.node_id, context),
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

    response = decide_then_execute(client, payload, tmp_path)

    assert response.status_code == 200
    assert response.json()["status"] == "EXECUTION_ELIGIBLE"
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

    response = decide_then_execute(client, payload, tmp_path)

    assert response.status_code == 200
    assert response.json()["status"] == "EXECUTION_ELIGIBLE"


def test_malicious_node_with_invalid_signature_is_ignored(tmp_path: Path, monkeypatch) -> None:
    client = configure_gateway(tmp_path, monkeypatch)
    monkeypatch.setattr(
        gateway_app,
        "hydra_node_clients",
        [AllowClient("node-1"), AllowClient("node-2"), MaliciousClient("node-3")],
    )
    payload = build_payload()
    sign_payload(payload)

    response = decide_then_execute(client, payload, tmp_path)

    assert response.status_code == 200
    assert response.json()["status"] == "EXECUTION_ELIGIBLE"


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


def test_stale_node_state_denies_and_audits(tmp_path: Path, monkeypatch) -> None:
    client = configure_gateway(tmp_path, monkeypatch)
    monkeypatch.setattr(
        gateway_app,
        "hydra_node_clients",
        [AllowClient("node-1"), StaleClient("node-2"), AllowClient("node-3")],
    )
    payload = build_payload()
    sign_payload(payload)

    response = decide_denied(client, payload)
    events = [entry for entry in gateway_app.audit_chain.load() if entry.get("action") == "consensus_deny"]

    assert response.status_code == 200
    assert response.json()["reason"] == "stale_node_state"
    assert events
    assert events[-1]["decision"]["node_stale"] is True


def test_replay_registry_divergence_denies_and_audits(tmp_path: Path, monkeypatch) -> None:
    client = configure_gateway(tmp_path, monkeypatch)
    monkeypatch.setattr(
        gateway_app,
        "hydra_node_clients",
        [AllowClient("node-1"), ReplayDivergenceClient("node-2"), AllowClient("node-3")],
    )
    payload = build_payload()
    sign_payload(payload)

    response = decide_denied(client, payload)
    events = [entry for entry in gateway_app.audit_chain.load() if entry.get("action") == "consensus_deny"]

    assert response.status_code == 200
    assert response.json()["reason"] == "hydra_denied"
    assert events
    assert events[-1]["decision"]["replay_registry_divergence"] is True


def test_policy_hash_mismatch_denies_and_audits(tmp_path: Path, monkeypatch) -> None:
    client = configure_gateway(tmp_path, monkeypatch)
    monkeypatch.setattr(
        gateway_app,
        "hydra_node_clients",
        [AllowClient("node-1"), PolicyHashMismatchClient("node-2"), AllowClient("node-3")],
    )
    payload = build_payload()
    sign_payload(payload)

    response = decide_denied(client, payload)
    events = [entry for entry in gateway_app.audit_chain.load() if entry.get("action") == "consensus_deny"]

    assert response.status_code == 200
    assert response.json()["reason"] == "hydra_denied"
    assert events
    assert events[-1]["decision"]["policy_hash_mismatch"] is True


def test_split_brain_explicit_disagreement_denies(tmp_path: Path, monkeypatch) -> None:
    client = configure_gateway(tmp_path, monkeypatch)
    monkeypatch.setattr(
        gateway_app,
        "hydra_node_clients",
        [AllowClient("node-1"), AllowClient("node-2"), DenyClient("node-3")],
    )
    payload = build_payload()
    sign_payload(payload)

    response = decide_denied(client, payload)

    assert response.status_code == 200
    assert response.json()["reason"] == "split_brain_denied"


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
    events = [entry for entry in gateway_app.audit_chain.load() if entry.get("action") == "consensus_deny"]

    assert response.status_code == 200
    assert response.json()["reason"] == "no_majority"
    assert events[-1]["decision"]["quorum_unavailable"] is True


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
    assert response.json()["reason"] == "no_majority"


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
    assert response.json()["reason"] == "no_majority"
