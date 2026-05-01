from __future__ import annotations

import hashlib
import json
import time
from pathlib import Path

from fastapi.testclient import TestClient
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import gateway.app as gateway_app
from audit.hash_chain import AuditHashChain
from security.decision_store import DecisionStoreTestDouble
from security.hydra_consensus import HydraNodeDecision
from security.hydra_nodes import sign_hydra_node_decision
from security.nonce_store import NonceStore
from security.policy_registry import (
    append_policy_log,
    encode_policy_signature,
    file_sha256,
    load_policy_public_key,
    policy_hash,
    policy_pubkey_id,
    public_key_sha256,
    reset_policy_sequence_tracker,
    verify_policy_log,
)
from tests.request_signing_helpers import configure_request_signing, sign_payload_ed25519


POLICY_PATH = Path("governance/simulation_policy.json")
REGISTRY_PATH = Path("governance/policy_registry.json")
REGISTRY_SIGNATURE_PATH = Path("governance/policy_registry.sig")
REGISTRY_PUBLIC_KEY_PATH = Path("governance/policy_public.key")


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
    store = DecisionStoreTestDouble()
    configure_request_signing(tmp_path, monkeypatch, gateway_app)
    monkeypatch.setattr(gateway_app, "nonce_store", NonceStore(tmp_path / "used_nonces.json"))
    monkeypatch.setattr(gateway_app, "audit_chain", AuditHashChain(tmp_path / "audit_chain.json"))
    monkeypatch.setattr(
        gateway_app,
        "hydra_node_clients",
        [AllowClient("node-1"), AllowClient("node-2"), AllowClient("node-3")],
    )
    monkeypatch.setattr(gateway_app, "decision_store", store)
    monkeypatch.setattr(gateway_app, "POLICY_REGISTRY_PATH", REGISTRY_PATH)
    monkeypatch.setattr(gateway_app, "POLICY_REGISTRY_SIGNATURE_PATH", REGISTRY_SIGNATURE_PATH)
    monkeypatch.setattr(gateway_app, "POLICY_REGISTRY_PUBLIC_KEY_PATH", REGISTRY_PUBLIC_KEY_PATH)
    monkeypatch.setattr(gateway_app, "POLICY_RELEASE_MANIFEST_PATH", gateway_app.DEFAULT_POLICY_RELEASE_MANIFEST_PATH)
    monkeypatch.setattr(gateway_app, "POLICY_KEY_CONFIG_PATH", Path("governance/policy_key_config.json"))
    gateway_app.clear_policy_registry_cache()
    client = TestClient(gateway_app.app, raise_server_exceptions=False)
    client.decision_store = store
    return client


def sign_payload(payload: dict) -> dict:
    return sign_payload_ed25519(payload)


def simulation_payload(**overrides) -> dict:
    payload = {
        "type": "simulation",
        "action": "run_simulated_experiment",
        "actor_id": "simulation-actor",
        "simulation_id": f"sim-{time.time_ns()}",
        "purpose": "sandbox policy validation",
        "affected_system": "sandbox",
        "risk_level": "low",
        "real_world_impact": "none",
        "human_review": False,
        "simulation_logs": {"actor_hash": "hashed-actor", "request_hash": "hashed-request"},
        "device": "laptop-1",
        "nonce": f"nonce-{time.time_ns()}",
        "tenant_id": "t1",
        "timestamp": int(time.time()),
        "policy_version": "simulation-policy-v1",
        "compute_target": "cpu",
        "compute_risk_level": "low",
        "data_sensitivity": "low",
        "execution_location": "local",
    }
    payload.update(overrides)
    return sign_payload(payload)


def write_policy_keypair(directory: Path) -> tuple[Path, Path]:
    private_key = Ed25519PrivateKey.generate()
    private_path = directory / f"policy_private_{time.time_ns()}.key"
    public_path = directory / f"policy_public_{time.time_ns()}.key"
    private_path.write_bytes(
        private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    public_path.write_bytes(
        private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )
    return private_path, public_path


def load_test_private_key(private_path: Path) -> Ed25519PrivateKey:
    key = serialization.load_pem_private_key(private_path.read_bytes(), password=None)
    assert isinstance(key, Ed25519PrivateKey)
    return key


def write_release_manifest(
    registry_path: Path,
    signature_path: Path,
    registry: dict,
    manifest_path: Path | None = None,
) -> Path:
    manifest_path = manifest_path or registry_path.parent / "policy_release_manifest.json"
    manifest = {
        "policy_version": registry["version"],
        "policy_hash": policy_hash(registry),
        "policy_pubkey_id": registry["policy_pubkey_id"],
        "created_at": "2026-05-01T00:00:00Z",
        "signed_by_human": "offline_release_signer_hash_test",
        "artifact_hashes": {
            "policy_registry.json": file_sha256(registry_path),
            "policy_registry.json.sig": file_sha256(signature_path),
        },
    }
    manifest_path.write_text(json.dumps(manifest, sort_keys=True), encoding="utf-8")
    return manifest_path


def write_policy_authority(
    directory: Path,
    *,
    key_id: str,
    policy_author: str = "policy_author_hash_test",
    policy_signer: str = "policy_signer_hash_test",
    deployment_operator: str = "deployment_operator_hash_test",
    release_signer: str = "offline_release_signer_hash_test",
    created_at: str = "2026-01-01T00:00:00Z",
    expires_at: str = "2030-01-01T00:00:00Z",
) -> Path:
    authority = {
        "policy_author": policy_author,
        "policy_signer": policy_signer,
        "deployment_operator": deployment_operator,
        "release_signer": release_signer,
        "rotation_policy": {
            "max_age_days": 1461,
            "overlap_period": 30,
        },
        "key_validity": {
            key_id: {
                "created_at": created_at,
                "expires_at": expires_at,
            },
        },
        "dispute_resolution_required": True,
        "dispute_owner_role": "human_policy_authority",
    }
    authority_path = directory / "policy_authority.json"
    authority_path.write_text(json.dumps(authority, sort_keys=True), encoding="utf-8")
    return authority_path


def write_signed_registry(tmp_path: Path, registry: dict, ordered_registry: dict | None = None) -> tuple[Path, Path, Path]:
    registry_path = tmp_path / f"policy_registry_{time.time_ns()}.json"
    signature_path = tmp_path / f"policy_registry_{time.time_ns()}.sig"
    private_path, public_path = write_policy_keypair(tmp_path)
    completed_registry = {
        **registry,
        "policy_pubkey_id": registry.get("policy_pubkey_id") or policy_pubkey_id(load_policy_public_key(public_path)),
        "policy_sequence": registry.get("policy_sequence", 1),
        "policy_author": registry.get("policy_author", "policy_author_hash_test"),
        "policy_signer": registry.get("policy_signer", "policy_signer_hash_test"),
        "deployment_operator": registry.get("deployment_operator", "deployment_operator_hash_test"),
        "valid_from": registry.get("valid_from", "2026-01-01T00:00:00Z"),
        "valid_until": registry.get("valid_until", "2030-01-01T00:00:00Z"),
    }
    if ordered_registry is not None:
        completed_ordered_registry = {
            **ordered_registry,
            "policy_pubkey_id": completed_registry["policy_pubkey_id"],
            "policy_sequence": completed_registry["policy_sequence"],
            "policy_author": completed_registry["policy_author"],
            "policy_signer": completed_registry["policy_signer"],
            "deployment_operator": completed_registry["deployment_operator"],
            "valid_from": completed_registry["valid_from"],
            "valid_until": completed_registry["valid_until"],
        }
    else:
        completed_ordered_registry = completed_registry
    registry_path.write_text(json.dumps(completed_ordered_registry), encoding="utf-8")
    signature_path.write_text(
        f"{encode_policy_signature(completed_registry, load_test_private_key(private_path))}\n",
        encoding="utf-8",
    )
    write_release_manifest(registry_path, signature_path, completed_registry)
    return registry_path, signature_path, public_path


def trust_policy_public_key(monkeypatch, public_path: Path) -> str:
    pubkey_id = policy_pubkey_id(load_policy_public_key(public_path))
    monkeypatch.setenv("USBAY_POLICY_PUBKEY_ALLOWLIST", pubkey_id)
    monkeypatch.delenv("USBAY_POLICY_PUBKEY_REVOKED", raising=False)
    return pubkey_id


def test_simulation_policy_defaults_fail_closed() -> None:
    policy = json.loads(POLICY_PATH.read_text(encoding="utf-8"))

    assert policy["default"] == "DENY"
    assert policy["simulation_requires_actor_id"] is True
    assert policy["block_unknown_real_world_impact"] is True
    assert policy["critical_infrastructure_requires_human_review"] is True
    assert policy["allow_raw_sensitive_data_in_simulation_logs"] is False


def test_missing_actor_id_denied(tmp_path: Path, monkeypatch) -> None:
    client = configure_gateway(tmp_path, monkeypatch)
    payload = simulation_payload()
    payload.pop("actor_id")
    payload = sign_payload(payload)

    response = client.post("/decide", json=payload)

    assert response.status_code == 403
    assert response.json()["decision"] == "DENY"
    assert response.json()["reason"] == "missing_actor"


def test_unknown_real_world_impact_denied(tmp_path: Path, monkeypatch) -> None:
    client = configure_gateway(tmp_path, monkeypatch)

    response = client.post("/decide", json=simulation_payload(real_world_impact="unknown"))

    assert response.status_code == 403
    assert response.json()["reason"] == "simulation_unknown_real_world_impact"


def test_critical_infrastructure_without_human_review_denied(tmp_path: Path, monkeypatch) -> None:
    client = configure_gateway(tmp_path, monkeypatch)

    response = client.post(
        "/decide",
        json=simulation_payload(affected_system="energy", risk_level="high"),
    )

    assert response.status_code == 403
    assert response.json()["reason"] == "simulation_requires_human_review"


def test_critical_infrastructure_with_human_review_allowed(tmp_path: Path, monkeypatch) -> None:
    client = configure_gateway(tmp_path, monkeypatch)

    response = client.post(
        "/decide",
        json=simulation_payload(
            affected_system="energy",
            risk_level="high",
            real_world_impact="reviewed_contained",
            human_review=True,
        ),
    )

    assert response.status_code == 200
    assert response.json()["decision"] == "ALLOW"


def test_low_risk_sandbox_simulation_allowed(tmp_path: Path, monkeypatch) -> None:
    client = configure_gateway(tmp_path, monkeypatch)

    response = client.post("/decide", json=simulation_payload())

    assert response.status_code == 200
    body = response.json()
    record = client.decision_store.records[body["decision_id"]]
    assert body["decision"] == "ALLOW"
    assert record["simulation_id"]
    assert record["risk_level"] == "low"
    assert record["policy_hash"] == gateway_app.load_policy_registry()["policy_hash"]
    assert record["policy_signature_valid"] is True
    assert record["policy_pubkey_id"] == gateway_app.load_policy_registry()["policy_pubkey_id"]
    assert record["audit_hash"]
    assert record["actor_hash"] == hashlib.sha256(b"simulation-actor").hexdigest()
    assert "actor_id" not in json.dumps(record)


def test_raw_sensitive_data_in_simulation_logs_denied(tmp_path: Path, monkeypatch) -> None:
    client = configure_gateway(tmp_path, monkeypatch)

    response = client.post(
        "/decide",
        json=simulation_payload(simulation_logs={"raw_sensitive_data": "classified"}),
    )

    assert response.status_code == 403
    assert response.json()["reason"] == "simulation_logs_sensitive_data"


def test_policy_registry_version_endpoint(tmp_path: Path, monkeypatch) -> None:
    client = configure_gateway(tmp_path, monkeypatch)
    registry = gateway_app.load_policy_registry()

    response = client.get("/policy/version")

    assert response.status_code == 200
    assert response.json() == {
        "version": "1.0",
        "policy_version": "1.0",
        "last_updated": "2026-04-30T00:00:00Z",
        "authority": "human_policy_owner",
        "policy_signature_valid": True,
        "policy_pubkey_id": registry["policy_pubkey_id"],
        "policy_sequence": registry["policy_sequence"],
        "policy_hash": registry["policy_hash"],
        "valid_from": registry["valid_from"],
        "valid_until": registry["valid_until"],
    }


def test_health_reports_signed_policy_state(tmp_path: Path, monkeypatch) -> None:
    client = configure_gateway(tmp_path, monkeypatch)

    response = client.get("/health")

    assert response.status_code == 200
    assert response.json() == {
        "status": "OK",
        "mode": "NORMAL",
        "reason": "ok",
        "redis_available": False,
        "nonce_store_available": True,
        "replay_protection_active": True,
        "policy_state": "valid",
        "policy_signature_valid": True,
        "registry_version": "1.0",
        "policy_hash": gateway_app.load_policy_registry()["policy_hash"],
        "policy_sequence": gateway_app.load_policy_registry()["policy_sequence"],
        "policy_pubkey_id": gateway_app.load_policy_registry()["policy_pubkey_id"],
        "compute_policy_state": "valid",
    }


def test_health_fails_closed_when_registry_invalid(tmp_path: Path, monkeypatch) -> None:
    client = configure_gateway(tmp_path, monkeypatch)
    monkeypatch.setattr(gateway_app, "POLICY_REGISTRY_PATH", tmp_path / "missing_registry.json")
    gateway_app.clear_policy_registry_cache()

    response = client.get("/health")

    assert response.status_code == 503
    assert response.json() == {
        "status": "FAIL_CLOSED",
        "mode": "FAIL_CLOSED",
        "reason": "policy_registry_unavailable",
        "redis_available": False,
        "nonce_store_available": True,
        "replay_protection_active": True,
        "policy_signature_valid": False,
        "registry_version": None,
        "compute_policy_state": "valid",
    }


def test_unknown_affected_system_denied(tmp_path: Path, monkeypatch) -> None:
    client = configure_gateway(tmp_path, monkeypatch)

    response = client.post("/decide", json=simulation_payload(affected_system="unregistered_system"))

    assert response.status_code == 403
    assert response.json()["reason"] == "simulation_unknown_affected_system"


def test_removed_registry_system_changes_decision(tmp_path: Path, monkeypatch) -> None:
    registry = {
        "version": "1.1",
        "critical_infrastructure": ["rail", "health", "water", "finance"],
        "last_updated": "2026-04-30T01:00:00Z",
        "authority": "human_policy_owner",
    }
    registry_path, signature_path, public_path = write_signed_registry(tmp_path, registry)
    trust_policy_public_key(monkeypatch, public_path)
    client = configure_gateway(tmp_path, monkeypatch)
    monkeypatch.setattr(gateway_app, "POLICY_REGISTRY_PATH", registry_path)
    monkeypatch.setattr(gateway_app, "POLICY_REGISTRY_SIGNATURE_PATH", signature_path)
    monkeypatch.setattr(gateway_app, "POLICY_REGISTRY_PUBLIC_KEY_PATH", public_path)
    gateway_app.clear_policy_registry_cache()

    response = client.post(
        "/decide",
        json=simulation_payload(
            affected_system="energy",
            risk_level="high",
            real_world_impact="reviewed_contained",
            human_review=True,
        ),
    )

    assert response.status_code == 403
    assert response.json()["reason"] == "simulation_unknown_affected_system"


def test_missing_policy_registry_fails_closed(tmp_path: Path, monkeypatch) -> None:
    client = configure_gateway(tmp_path, monkeypatch)
    monkeypatch.setattr(gateway_app, "POLICY_REGISTRY_PATH", tmp_path / "missing_registry.json")
    gateway_app.clear_policy_registry_cache()

    response = client.post("/decide", json=simulation_payload())

    assert response.status_code == 403
    assert response.json()["reason"] == "policy_registry_unavailable"


def test_valid_signed_policy_registry_passes_startup(tmp_path: Path, monkeypatch) -> None:
    registry = {
        "version": "2.0",
        "critical_infrastructure": ["energy"],
        "last_updated": "2026-04-30T02:00:00Z",
        "authority": "human_policy_owner",
    }
    registry_path, signature_path, public_path = write_signed_registry(tmp_path, registry)
    trust_policy_public_key(monkeypatch, public_path)
    monkeypatch.setattr(gateway_app, "POLICY_REGISTRY_PATH", registry_path)
    monkeypatch.setattr(gateway_app, "POLICY_REGISTRY_SIGNATURE_PATH", signature_path)
    monkeypatch.setattr(gateway_app, "POLICY_REGISTRY_PUBLIC_KEY_PATH", public_path)
    gateway_app.clear_policy_registry_cache()

    gateway_app.validate_policy_registry_startup()
    loaded = gateway_app.load_policy_registry()

    assert loaded["version"] == "2.0"
    assert loaded["policy_signature_valid"] is True
    assert loaded["policy_pubkey_id"]


def test_pgp_is_not_used_by_gateway_runtime() -> None:
    gateway_source = Path(gateway_app.__file__).read_text(encoding="utf-8").lower()
    policy_registry_source = Path("security/policy_registry.py").read_text(encoding="utf-8").lower()

    assert "gnupg" not in gateway_source
    assert "gpg" not in gateway_source
    assert "pgp" not in gateway_source
    assert "gnupg" not in policy_registry_source
    assert "gpg" not in policy_registry_source
    assert "pgp" not in policy_registry_source


def test_ed25519_remains_only_runtime_policy_signature_path() -> None:
    policy_registry_source = Path("security/policy_registry.py").read_text(encoding="utf-8")

    assert "Ed25519PublicKey" in policy_registry_source
    assert "hmac" not in policy_registry_source.lower()
    assert "gnupg" not in policy_registry_source.lower()


def test_policy_private_key_not_required_at_runtime(tmp_path: Path, monkeypatch) -> None:
    registry = {
        "version": "2.1",
        "critical_infrastructure": ["energy"],
        "last_updated": "2026-04-30T03:00:00Z",
        "authority": "human_policy_owner",
    }
    registry_path, signature_path, public_path = write_signed_registry(tmp_path, registry)
    trust_policy_public_key(monkeypatch, public_path)
    for private_path in tmp_path.glob("policy_private_*.key"):
        private_path.unlink()
    monkeypatch.setattr(gateway_app, "POLICY_REGISTRY_PATH", registry_path)
    monkeypatch.setattr(gateway_app, "POLICY_REGISTRY_SIGNATURE_PATH", signature_path)
    monkeypatch.setattr(gateway_app, "POLICY_REGISTRY_PUBLIC_KEY_PATH", public_path)
    gateway_app.clear_policy_registry_cache()

    gateway_app.validate_policy_registry_startup()
    loaded = gateway_app.load_policy_registry()

    assert loaded["version"] == "2.1"
    assert loaded["policy_signature_valid"] is True


def test_policy_release_manifest_hash_mismatch_fails_closed(tmp_path: Path, monkeypatch) -> None:
    registry = {
        "version": "1.0",
        "critical_infrastructure": ["energy"],
        "last_updated": "2026-04-30T02:00:00Z",
        "authority": "human_policy_owner",
    }
    registry_path, signature_path, public_path = write_signed_registry(tmp_path, registry)
    trust_policy_public_key(monkeypatch, public_path)
    manifest_path = tmp_path / "policy_release_manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["artifact_hashes"]["policy_registry.json"] = "0" * 64
    manifest_path.write_text(json.dumps(manifest, sort_keys=True), encoding="utf-8")
    client = configure_gateway(tmp_path, monkeypatch)
    monkeypatch.setattr(gateway_app, "POLICY_REGISTRY_PATH", registry_path)
    monkeypatch.setattr(gateway_app, "POLICY_REGISTRY_SIGNATURE_PATH", signature_path)
    monkeypatch.setattr(gateway_app, "POLICY_REGISTRY_PUBLIC_KEY_PATH", public_path)
    gateway_app.clear_policy_registry_cache()

    response = client.post("/decide", json=simulation_payload())

    assert response.status_code == 403
    assert response.json()["reason"] == "policy_release_manifest_mismatch"


def test_policy_release_manifest_missing_policy_version_fails_closed(tmp_path: Path, monkeypatch) -> None:
    registry = {
        "version": "1.0",
        "critical_infrastructure": ["energy"],
        "last_updated": "2026-04-30T02:00:00Z",
        "authority": "human_policy_owner",
    }
    registry_path, signature_path, public_path = write_signed_registry(tmp_path, registry)
    trust_policy_public_key(monkeypatch, public_path)
    manifest_path = tmp_path / "policy_release_manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest.pop("policy_version")
    manifest_path.write_text(json.dumps(manifest, sort_keys=True), encoding="utf-8")
    client = configure_gateway(tmp_path, monkeypatch)
    monkeypatch.setattr(gateway_app, "POLICY_REGISTRY_PATH", registry_path)
    monkeypatch.setattr(gateway_app, "POLICY_REGISTRY_SIGNATURE_PATH", signature_path)
    monkeypatch.setattr(gateway_app, "POLICY_REGISTRY_PUBLIC_KEY_PATH", public_path)
    gateway_app.clear_policy_registry_cache()

    response = client.post("/decide", json=simulation_payload())

    assert response.status_code == 403
    assert response.json()["reason"] == "policy_release_manifest_invalid"


def test_tampered_policy_registry_fails_closed(tmp_path: Path, monkeypatch) -> None:
    registry = {
        "version": "1.0",
        "critical_infrastructure": ["energy"],
        "last_updated": "2026-04-30T02:00:00Z",
        "authority": "human_policy_owner",
    }
    registry_path, signature_path, public_path = write_signed_registry(tmp_path, registry)
    trust_policy_public_key(monkeypatch, public_path)
    tampered_registry = json.loads(registry_path.read_text(encoding="utf-8"))
    tampered_registry["critical_infrastructure"] = ["finance"]
    registry_path.write_text(json.dumps(tampered_registry), encoding="utf-8")
    client = configure_gateway(tmp_path, monkeypatch)
    monkeypatch.setattr(gateway_app, "POLICY_REGISTRY_PATH", registry_path)
    monkeypatch.setattr(gateway_app, "POLICY_REGISTRY_SIGNATURE_PATH", signature_path)
    monkeypatch.setattr(gateway_app, "POLICY_REGISTRY_PUBLIC_KEY_PATH", public_path)
    gateway_app.clear_policy_registry_cache()

    response = client.post("/decide", json=simulation_payload())

    assert response.status_code == 403
    assert response.json()["reason"] in {"policy_registry_signature_invalid", "policy_public_key_not_allowed"}


def test_missing_policy_registry_signature_fails_closed(tmp_path: Path, monkeypatch) -> None:
    registry_path = tmp_path / "policy_registry.json"
    registry = {
        "version": "1.0",
        "critical_infrastructure": ["energy"],
        "last_updated": "2026-04-30T02:00:00Z",
        "authority": "human_policy_owner",
    }
    registry_path.write_text(json.dumps(registry), encoding="utf-8")
    client = configure_gateway(tmp_path, monkeypatch)
    monkeypatch.setattr(gateway_app, "POLICY_REGISTRY_PATH", registry_path)
    monkeypatch.setattr(gateway_app, "POLICY_REGISTRY_SIGNATURE_PATH", tmp_path / "missing.sig")
    gateway_app.clear_policy_registry_cache()

    response = client.post("/decide", json=simulation_payload())

    assert response.status_code == 403
    assert response.json()["reason"] == "policy_registry_signature_missing"


def test_modified_policy_registry_version_fails_closed(tmp_path: Path, monkeypatch) -> None:
    registry = {
        "version": "1.0",
        "critical_infrastructure": ["energy"],
        "last_updated": "2026-04-30T02:00:00Z",
        "authority": "human_policy_owner",
    }
    registry_path, signature_path, public_path = write_signed_registry(tmp_path, registry)
    trust_policy_public_key(monkeypatch, public_path)
    tampered_registry = json.loads(registry_path.read_text(encoding="utf-8"))
    tampered_registry["version"] = "1.1"
    registry_path.write_text(json.dumps(tampered_registry), encoding="utf-8")
    client = configure_gateway(tmp_path, monkeypatch)
    monkeypatch.setattr(gateway_app, "POLICY_REGISTRY_PATH", registry_path)
    monkeypatch.setattr(gateway_app, "POLICY_REGISTRY_SIGNATURE_PATH", signature_path)
    monkeypatch.setattr(gateway_app, "POLICY_REGISTRY_PUBLIC_KEY_PATH", public_path)
    gateway_app.clear_policy_registry_cache()

    response = client.post("/decide", json=simulation_payload())

    assert response.status_code == 403
    assert response.json()["reason"] in {"policy_registry_signature_invalid", "policy_public_key_not_allowed"}


def test_wrong_policy_public_key_fails_closed(tmp_path: Path, monkeypatch) -> None:
    registry = {
        "version": "1.0",
        "critical_infrastructure": ["energy"],
        "last_updated": "2026-04-30T02:00:00Z",
        "authority": "human_policy_owner",
    }
    registry_path, signature_path, _public_path = write_signed_registry(tmp_path, registry)
    _wrong_private_path, wrong_public_path = write_policy_keypair(tmp_path)
    trust_policy_public_key(monkeypatch, wrong_public_path)
    client = configure_gateway(tmp_path, monkeypatch)
    monkeypatch.setattr(gateway_app, "POLICY_REGISTRY_PATH", registry_path)
    monkeypatch.setattr(gateway_app, "POLICY_REGISTRY_SIGNATURE_PATH", signature_path)
    monkeypatch.setattr(gateway_app, "POLICY_REGISTRY_PUBLIC_KEY_PATH", wrong_public_path)
    gateway_app.clear_policy_registry_cache()

    response = client.post("/decide", json=simulation_payload())

    assert response.status_code == 403
    assert response.json()["reason"] in {"policy_registry_signature_invalid", "policy_public_key_not_allowed"}


def test_policy_registry_json_key_order_does_not_break_signature(tmp_path: Path, monkeypatch) -> None:
    registry = {
        "version": "1.0",
        "critical_infrastructure": ["energy"],
        "last_updated": "2026-04-30T02:00:00Z",
        "authority": "human_policy_owner",
    }
    reordered_registry = {
        "authority": "human_policy_owner",
        "last_updated": "2026-04-30T02:00:00Z",
        "critical_infrastructure": ["energy"],
        "version": "1.0",
    }
    registry_path, signature_path, public_path = write_signed_registry(
        tmp_path,
        registry,
        ordered_registry=reordered_registry,
    )
    trust_policy_public_key(monkeypatch, public_path)
    client = configure_gateway(tmp_path, monkeypatch)
    monkeypatch.setattr(gateway_app, "POLICY_REGISTRY_PATH", registry_path)
    monkeypatch.setattr(gateway_app, "POLICY_REGISTRY_SIGNATURE_PATH", signature_path)
    monkeypatch.setattr(gateway_app, "POLICY_REGISTRY_PUBLIC_KEY_PATH", public_path)
    gateway_app.clear_policy_registry_cache()

    response = client.post(
        "/decide",
        json=simulation_payload(
            affected_system="energy",
            risk_level="high",
            real_world_impact="reviewed_contained",
            human_review=True,
        ),
    )

    assert response.status_code == 200
    assert response.json()["decision"] == "ALLOW"


def test_revoked_policy_public_key_fails_closed(tmp_path: Path, monkeypatch) -> None:
    registry = {
        "version": "1.0",
        "critical_infrastructure": ["energy"],
        "last_updated": "2026-04-30T02:00:00Z",
        "authority": "human_policy_owner",
    }
    registry_path, signature_path, public_path = write_signed_registry(tmp_path, registry)
    pubkey_id = trust_policy_public_key(monkeypatch, public_path)
    monkeypatch.setenv("USBAY_POLICY_PUBKEY_REVOKED", pubkey_id)
    client = configure_gateway(tmp_path, monkeypatch)
    monkeypatch.setattr(gateway_app, "POLICY_REGISTRY_PATH", registry_path)
    monkeypatch.setattr(gateway_app, "POLICY_REGISTRY_SIGNATURE_PATH", signature_path)
    monkeypatch.setattr(gateway_app, "POLICY_REGISTRY_PUBLIC_KEY_PATH", public_path)
    gateway_app.clear_policy_registry_cache()

    response = client.post("/decide", json=simulation_payload())

    assert response.status_code == 403
    assert response.json()["reason"] == "policy_public_key_revoked"


def test_expired_policy_fails_closed(tmp_path: Path, monkeypatch) -> None:
    registry = {
        "version": "1.0",
        "critical_infrastructure": ["energy"],
        "last_updated": "2026-04-30T02:00:00Z",
        "authority": "human_policy_owner",
        "valid_from": "2020-01-01T00:00:00Z",
        "valid_until": "2021-01-01T00:00:00Z",
    }
    registry_path, signature_path, public_path = write_signed_registry(tmp_path, registry)
    trust_policy_public_key(monkeypatch, public_path)
    client = configure_gateway(tmp_path, monkeypatch)
    monkeypatch.setattr(gateway_app, "POLICY_REGISTRY_PATH", registry_path)
    monkeypatch.setattr(gateway_app, "POLICY_REGISTRY_SIGNATURE_PATH", signature_path)
    monkeypatch.setattr(gateway_app, "POLICY_REGISTRY_PUBLIC_KEY_PATH", public_path)
    gateway_app.clear_policy_registry_cache()

    response = client.post("/decide", json=simulation_payload())

    assert response.status_code == 403
    assert response.json()["reason"] == "policy_expired"


def test_unknown_policy_key_fails_closed(tmp_path: Path, monkeypatch) -> None:
    registry = {
        "version": "1.0",
        "critical_infrastructure": ["energy"],
        "last_updated": "2026-04-30T02:00:00Z",
        "authority": "human_policy_owner",
        "policy_pubkey_id": "key_unknown",
    }
    registry_path, signature_path, public_path = write_signed_registry(tmp_path, registry)
    monkeypatch.setenv("USBAY_POLICY_ACTIVE_KEYS", "key_2026_01")
    monkeypatch.delenv("USBAY_POLICY_PUBKEY_ALLOWLIST", raising=False)
    client = configure_gateway(tmp_path, monkeypatch)
    monkeypatch.setattr(gateway_app, "POLICY_REGISTRY_PATH", registry_path)
    monkeypatch.setattr(gateway_app, "POLICY_REGISTRY_SIGNATURE_PATH", signature_path)
    monkeypatch.setattr(gateway_app, "POLICY_REGISTRY_PUBLIC_KEY_PATH", public_path)
    gateway_app.clear_policy_registry_cache()

    response = client.post("/decide", json=simulation_payload())

    assert response.status_code == 403
    assert response.json()["reason"] == "policy_public_key_not_allowed"


def test_valid_logical_policy_key_and_valid_time_passes(tmp_path: Path, monkeypatch) -> None:
    registry = {
        "version": "1.0",
        "critical_infrastructure": ["energy"],
        "last_updated": "2026-04-30T02:00:00Z",
        "authority": "human_policy_owner",
        "policy_pubkey_id": "key_test_rotation",
        "valid_from": "2026-01-01T00:00:00Z",
        "valid_until": "2030-01-01T00:00:00Z",
    }
    registry_path, signature_path, public_path = write_signed_registry(tmp_path, registry)
    key_config_path = tmp_path / "policy_key_config.json"
    key_config_path.write_text(
        json.dumps(
            {
                "active_keys": ["key_test_rotation"],
                "revoked_keys": [],
                "key_map": {"key_test_rotation": public_path.name},
            }
        ),
        encoding="utf-8",
    )
    client = configure_gateway(tmp_path, monkeypatch)
    monkeypatch.setattr(gateway_app, "POLICY_REGISTRY_PATH", registry_path)
    monkeypatch.setattr(gateway_app, "POLICY_REGISTRY_SIGNATURE_PATH", signature_path)
    monkeypatch.setattr(gateway_app, "POLICY_REGISTRY_PUBLIC_KEY_PATH", public_path)
    monkeypatch.setattr(gateway_app, "POLICY_KEY_CONFIG_PATH", key_config_path)
    gateway_app.clear_policy_registry_cache()

    response = client.post(
        "/decide",
        json=simulation_payload(
            affected_system="energy",
            risk_level="high",
            real_world_impact="reviewed_contained",
            human_review=True,
        ),
    )

    assert response.status_code == 200
    assert response.json()["policy_pubkey_id"] == "key_test_rotation"


def test_older_policy_sequence_is_denied_as_rollback(tmp_path: Path, monkeypatch) -> None:
    reset_policy_sequence_tracker()
    key_id = "key_test_rollback"
    registry_newer = {
        "version": "1.0",
        "critical_infrastructure": ["energy"],
        "last_updated": "2026-04-30T02:00:00Z",
        "authority": "human_policy_owner",
        "policy_pubkey_id": key_id,
        "policy_sequence": 10,
    }
    registry_path, signature_path, public_path = write_signed_registry(tmp_path, registry_newer)
    key_config_path = tmp_path / "policy_key_config.json"
    key_config_path.write_text(
        json.dumps(
            {
                "active_keys": [key_id],
                "revoked_keys": [],
                "drift_window_seconds": 300,
                "key_map": {key_id: public_path.name},
            }
        ),
        encoding="utf-8",
    )
    client = configure_gateway(tmp_path, monkeypatch)
    monkeypatch.setattr(gateway_app, "POLICY_REGISTRY_PATH", registry_path)
    monkeypatch.setattr(gateway_app, "POLICY_REGISTRY_SIGNATURE_PATH", signature_path)
    monkeypatch.setattr(gateway_app, "POLICY_REGISTRY_PUBLIC_KEY_PATH", public_path)
    monkeypatch.setattr(gateway_app, "POLICY_KEY_CONFIG_PATH", key_config_path)
    gateway_app.clear_policy_registry_cache()
    first = client.post("/decide", json=simulation_payload())
    assert first.status_code == 200

    private_candidates = sorted(tmp_path.glob("policy_private_*.key"))
    assert private_candidates
    older_registry = json.loads(registry_path.read_text(encoding="utf-8"))
    older_registry["policy_sequence"] = 9
    registry_path.write_text(json.dumps(older_registry), encoding="utf-8")
    signature_path.write_text(
        encode_policy_signature(older_registry, load_test_private_key(private_candidates[-1])) + "\n",
        encoding="utf-8",
    )
    write_release_manifest(registry_path, signature_path, older_registry)
    gateway_app.clear_policy_registry_cache()
    second = client.post("/decide", json=simulation_payload())

    assert second.status_code == 403
    assert second.json()["reason"] == "rollback_detected"


def test_future_policy_outside_drift_is_denied(tmp_path: Path, monkeypatch) -> None:
    reset_policy_sequence_tracker()
    registry = {
        "version": "1.0",
        "critical_infrastructure": ["energy"],
        "last_updated": "2026-04-30T02:00:00Z",
        "authority": "human_policy_owner",
        "valid_from": "2100-01-01T00:00:00Z",
        "valid_until": "2101-01-01T00:00:00Z",
    }
    registry_path, signature_path, public_path = write_signed_registry(tmp_path, registry)
    trust_policy_public_key(monkeypatch, public_path)
    client = configure_gateway(tmp_path, monkeypatch)
    monkeypatch.setattr(gateway_app, "POLICY_REGISTRY_PATH", registry_path)
    monkeypatch.setattr(gateway_app, "POLICY_REGISTRY_SIGNATURE_PATH", signature_path)
    monkeypatch.setattr(gateway_app, "POLICY_REGISTRY_PUBLIC_KEY_PATH", public_path)
    gateway_app.clear_policy_registry_cache()

    response = client.post("/decide", json=simulation_payload())

    assert response.status_code == 403
    assert response.json()["reason"] == "policy_not_yet_valid"


def test_valid_policy_sequence_and_trusted_time_passes(tmp_path: Path, monkeypatch) -> None:
    reset_policy_sequence_tracker()
    registry = {
        "version": "1.0",
        "critical_infrastructure": ["energy"],
        "last_updated": "2026-04-30T02:00:00Z",
        "authority": "human_policy_owner",
        "policy_sequence": 22,
        "valid_from": "2026-01-01T00:00:00Z",
        "valid_until": "2030-01-01T00:00:00Z",
    }
    registry_path, signature_path, public_path = write_signed_registry(tmp_path, registry)
    trust_policy_public_key(monkeypatch, public_path)
    client = configure_gateway(tmp_path, monkeypatch)
    monkeypatch.setattr(gateway_app, "POLICY_REGISTRY_PATH", registry_path)
    monkeypatch.setattr(gateway_app, "POLICY_REGISTRY_SIGNATURE_PATH", signature_path)
    monkeypatch.setattr(gateway_app, "POLICY_REGISTRY_PUBLIC_KEY_PATH", public_path)
    gateway_app.clear_policy_registry_cache()

    response = client.post("/decide", json=simulation_payload())

    assert response.status_code == 200
    assert response.json()["policy_sequence"] == 22


def test_same_policy_sequence_passes(tmp_path: Path, monkeypatch) -> None:
    reset_policy_sequence_tracker()
    key_id = "key_test_same_sequence"
    registry = {
        "version": "1.0",
        "critical_infrastructure": ["energy"],
        "last_updated": "2026-04-30T02:00:00Z",
        "authority": "human_policy_owner",
        "policy_pubkey_id": key_id,
        "policy_sequence": 7,
    }
    registry_path, signature_path, public_path = write_signed_registry(tmp_path, registry)
    key_config_path = tmp_path / "policy_key_config.json"
    key_config_path.write_text(
        json.dumps(
            {
                "active_keys": [key_id],
                "revoked_keys": [],
                "drift_window_seconds": 300,
                "key_map": {key_id: public_path.name},
            }
        ),
        encoding="utf-8",
    )
    client = configure_gateway(tmp_path, monkeypatch)
    monkeypatch.setattr(gateway_app, "POLICY_REGISTRY_PATH", registry_path)
    monkeypatch.setattr(gateway_app, "POLICY_REGISTRY_SIGNATURE_PATH", signature_path)
    monkeypatch.setattr(gateway_app, "POLICY_REGISTRY_PUBLIC_KEY_PATH", public_path)
    monkeypatch.setattr(gateway_app, "POLICY_KEY_CONFIG_PATH", key_config_path)
    gateway_app.clear_policy_registry_cache()

    first = client.post("/decide", json=simulation_payload())
    gateway_app.clear_policy_registry_cache()
    second = client.post("/decide", json=simulation_payload())

    assert first.status_code == 200
    assert second.status_code == 200
    assert second.json()["policy_sequence"] == 7


def test_higher_policy_sequence_passes(tmp_path: Path, monkeypatch) -> None:
    reset_policy_sequence_tracker()
    key_id = "key_test_higher_sequence"
    registry = {
        "version": "1.0",
        "critical_infrastructure": ["energy"],
        "last_updated": "2026-04-30T02:00:00Z",
        "authority": "human_policy_owner",
        "policy_pubkey_id": key_id,
        "policy_sequence": 7,
    }
    registry_path, signature_path, public_path = write_signed_registry(tmp_path, registry)
    key_config_path = tmp_path / "policy_key_config.json"
    key_config_path.write_text(
        json.dumps(
            {
                "active_keys": [key_id],
                "revoked_keys": [],
                "drift_window_seconds": 300,
                "key_map": {key_id: public_path.name},
            }
        ),
        encoding="utf-8",
    )
    client = configure_gateway(tmp_path, monkeypatch)
    monkeypatch.setattr(gateway_app, "POLICY_REGISTRY_PATH", registry_path)
    monkeypatch.setattr(gateway_app, "POLICY_REGISTRY_SIGNATURE_PATH", signature_path)
    monkeypatch.setattr(gateway_app, "POLICY_REGISTRY_PUBLIC_KEY_PATH", public_path)
    monkeypatch.setattr(gateway_app, "POLICY_KEY_CONFIG_PATH", key_config_path)
    gateway_app.clear_policy_registry_cache()
    first = client.post("/decide", json=simulation_payload())
    assert first.status_code == 200

    private_candidates = sorted(tmp_path.glob("policy_private_*.key"))
    higher_registry = json.loads(registry_path.read_text(encoding="utf-8"))
    higher_registry["policy_sequence"] = 8
    registry_path.write_text(json.dumps(higher_registry), encoding="utf-8")
    signature_path.write_text(
        encode_policy_signature(higher_registry, load_test_private_key(private_candidates[-1])) + "\n",
        encoding="utf-8",
    )
    write_release_manifest(registry_path, signature_path, higher_registry)
    gateway_app.clear_policy_registry_cache()
    second = client.post("/decide", json=simulation_payload())

    assert second.status_code == 200
    assert second.json()["policy_sequence"] == 8


def test_public_key_pin_correct_hash_passes(tmp_path: Path, monkeypatch) -> None:
    registry = {
        "version": "1.0",
        "critical_infrastructure": ["energy"],
        "last_updated": "2026-04-30T02:00:00Z",
        "authority": "human_policy_owner",
        "policy_pubkey_id": "key_test_pin",
    }
    registry_path, signature_path, public_path = write_signed_registry(tmp_path, registry)
    key_config_path = tmp_path / "policy_key_config.json"
    key_config_path.write_text(
        json.dumps(
            {
                "active_keys": ["key_test_pin"],
                "revoked_keys": [],
                "drift_window_seconds": 300,
                "public_key_sha256": {
                    "key_test_pin": public_key_sha256(load_policy_public_key(public_path)),
                },
                "key_map": {"key_test_pin": public_path.name},
            }
        ),
        encoding="utf-8",
    )
    client = configure_gateway(tmp_path, monkeypatch)
    monkeypatch.setattr(gateway_app, "POLICY_REGISTRY_PATH", registry_path)
    monkeypatch.setattr(gateway_app, "POLICY_REGISTRY_SIGNATURE_PATH", signature_path)
    monkeypatch.setattr(gateway_app, "POLICY_REGISTRY_PUBLIC_KEY_PATH", public_path)
    monkeypatch.setattr(gateway_app, "POLICY_KEY_CONFIG_PATH", key_config_path)
    gateway_app.clear_policy_registry_cache()

    response = client.post("/decide", json=simulation_payload())

    assert response.status_code == 200


def test_public_key_pin_wrong_hash_fails_closed(tmp_path: Path, monkeypatch) -> None:
    registry = {
        "version": "1.0",
        "critical_infrastructure": ["energy"],
        "last_updated": "2026-04-30T02:00:00Z",
        "authority": "human_policy_owner",
        "policy_pubkey_id": "key_test_bad_pin",
    }
    registry_path, signature_path, public_path = write_signed_registry(tmp_path, registry)
    key_config_path = tmp_path / "policy_key_config.json"
    key_config_path.write_text(
        json.dumps(
            {
                "active_keys": ["key_test_bad_pin"],
                "revoked_keys": [],
                "drift_window_seconds": 300,
                "public_key_sha256": {"key_test_bad_pin": "0" * 64},
                "key_map": {"key_test_bad_pin": public_path.name},
            }
        ),
        encoding="utf-8",
    )
    client = configure_gateway(tmp_path, monkeypatch)
    monkeypatch.setattr(gateway_app, "POLICY_REGISTRY_PATH", registry_path)
    monkeypatch.setattr(gateway_app, "POLICY_REGISTRY_SIGNATURE_PATH", signature_path)
    monkeypatch.setattr(gateway_app, "POLICY_REGISTRY_PUBLIC_KEY_PATH", public_path)
    monkeypatch.setattr(gateway_app, "POLICY_KEY_CONFIG_PATH", key_config_path)
    gateway_app.clear_policy_registry_cache()

    response = client.post("/decide", json=simulation_payload())

    assert response.status_code == 403
    assert response.json()["reason"] == "public_key_pin_mismatch"


def test_revoked_key_config_change_propagates_to_deny(tmp_path: Path, monkeypatch) -> None:
    key_id = "key_test_revoke_propagation"
    registry = {
        "version": "1.0",
        "critical_infrastructure": ["energy"],
        "last_updated": "2026-04-30T02:00:00Z",
        "authority": "human_policy_owner",
        "policy_pubkey_id": key_id,
    }
    registry_path, signature_path, public_path = write_signed_registry(tmp_path, registry)
    key_config_path = tmp_path / "policy_key_config.json"
    key_config = {
        "active_keys": [key_id],
        "revoked_keys": [],
        "drift_window_seconds": 300,
        "key_map": {key_id: public_path.name},
    }
    key_config_path.write_text(json.dumps(key_config), encoding="utf-8")
    client = configure_gateway(tmp_path, monkeypatch)
    monkeypatch.setattr(gateway_app, "POLICY_REGISTRY_PATH", registry_path)
    monkeypatch.setattr(gateway_app, "POLICY_REGISTRY_SIGNATURE_PATH", signature_path)
    monkeypatch.setattr(gateway_app, "POLICY_REGISTRY_PUBLIC_KEY_PATH", public_path)
    monkeypatch.setattr(gateway_app, "POLICY_KEY_CONFIG_PATH", key_config_path)
    gateway_app.clear_policy_registry_cache()

    allowed = client.post("/decide", json=simulation_payload())
    key_config["revoked_keys"] = [key_id]
    key_config_path.write_text(json.dumps(key_config), encoding="utf-8")
    denied = client.post("/decide", json=simulation_payload())

    assert allowed.status_code == 200
    assert denied.status_code == 403
    assert denied.json()["reason"] == "policy_public_key_revoked"


def test_expired_policy_outside_drift_fails_closed(tmp_path: Path, monkeypatch) -> None:
    reset_policy_sequence_tracker()
    registry = {
        "version": "1.0",
        "critical_infrastructure": ["energy"],
        "last_updated": "2026-04-30T02:00:00Z",
        "authority": "human_policy_owner",
        "valid_from": "2020-01-01T00:00:00Z",
        "valid_until": "2020-01-02T00:00:00Z",
    }
    registry_path, signature_path, public_path = write_signed_registry(tmp_path, registry)
    trust_policy_public_key(monkeypatch, public_path)
    client = configure_gateway(tmp_path, monkeypatch)
    monkeypatch.setattr(gateway_app, "POLICY_REGISTRY_PATH", registry_path)
    monkeypatch.setattr(gateway_app, "POLICY_REGISTRY_SIGNATURE_PATH", signature_path)
    monkeypatch.setattr(gateway_app, "POLICY_REGISTRY_PUBLIC_KEY_PATH", public_path)
    gateway_app.clear_policy_registry_cache()

    response = client.post("/decide", json=simulation_payload())

    assert response.status_code == 403
    assert response.json()["reason"] == "policy_expired"


def test_policy_separation_of_duties_violation_fails_closed(tmp_path: Path, monkeypatch) -> None:
    registry = {
        "version": "1.0",
        "critical_infrastructure": ["energy"],
        "last_updated": "2026-04-30T02:00:00Z",
        "authority": "human_policy_owner",
        "policy_author": "same_actor_hash",
        "policy_signer": "same_actor_hash",
        "deployment_operator": "deployment_operator_hash_test",
    }
    _private_path, public_path = write_policy_keypair(tmp_path)
    registry_path = tmp_path / "invalid_duties_registry.json"
    signature_path = tmp_path / "invalid_duties_registry.sig"
    completed_registry = {
        **registry,
        "policy_pubkey_id": policy_pubkey_id(load_policy_public_key(public_path)),
        "policy_sequence": 1,
        "valid_from": "2026-01-01T00:00:00Z",
        "valid_until": "2030-01-01T00:00:00Z",
    }
    registry_path.write_text(json.dumps(completed_registry), encoding="utf-8")
    signature_path.write_text("invalid-signature\n", encoding="utf-8")
    trust_policy_public_key(monkeypatch, public_path)
    client = configure_gateway(tmp_path, monkeypatch)
    monkeypatch.setattr(gateway_app, "POLICY_REGISTRY_PATH", registry_path)
    monkeypatch.setattr(gateway_app, "POLICY_REGISTRY_SIGNATURE_PATH", signature_path)
    monkeypatch.setattr(gateway_app, "POLICY_REGISTRY_PUBLIC_KEY_PATH", public_path)
    gateway_app.clear_policy_registry_cache()

    response = client.post("/decide", json=simulation_payload())

    assert response.status_code == 403
    assert response.json()["reason"] == "separation_of_duties_violation"


def test_unauthorized_policy_change_fails_closed(tmp_path: Path, monkeypatch) -> None:
    registry = {
        "version": "1.0",
        "critical_infrastructure": ["energy"],
        "last_updated": "2026-04-30T02:00:00Z",
        "authority": "human_policy_owner",
        "policy_author": "unauthorized_author_hash",
        "policy_signer": "policy_signer_hash_test",
        "deployment_operator": "deployment_operator_hash_test",
    }
    registry_path, signature_path, public_path = write_signed_registry(tmp_path, registry)
    pubkey_id = trust_policy_public_key(monkeypatch, public_path)
    write_policy_authority(tmp_path, key_id=pubkey_id)
    client = configure_gateway(tmp_path, monkeypatch)
    monkeypatch.setattr(gateway_app, "POLICY_REGISTRY_PATH", registry_path)
    monkeypatch.setattr(gateway_app, "POLICY_REGISTRY_SIGNATURE_PATH", signature_path)
    monkeypatch.setattr(gateway_app, "POLICY_REGISTRY_PUBLIC_KEY_PATH", public_path)
    gateway_app.clear_policy_registry_cache()

    response = client.post("/decide", json=simulation_payload())

    assert response.status_code == 403
    assert response.json()["reason"] == "unauthorized_policy_change"


def test_expired_policy_authority_key_fails_closed(tmp_path: Path, monkeypatch) -> None:
    registry = {
        "version": "1.0",
        "critical_infrastructure": ["energy"],
        "last_updated": "2026-04-30T02:00:00Z",
        "authority": "human_policy_owner",
    }
    registry_path, signature_path, public_path = write_signed_registry(tmp_path, registry)
    pubkey_id = trust_policy_public_key(monkeypatch, public_path)
    write_policy_authority(
        tmp_path,
        key_id=pubkey_id,
        created_at="2020-01-01T00:00:00Z",
        expires_at="2020-01-02T00:00:00Z",
    )
    client = configure_gateway(tmp_path, monkeypatch)
    monkeypatch.setattr(gateway_app, "POLICY_REGISTRY_PATH", registry_path)
    monkeypatch.setattr(gateway_app, "POLICY_REGISTRY_SIGNATURE_PATH", signature_path)
    monkeypatch.setattr(gateway_app, "POLICY_REGISTRY_PUBLIC_KEY_PATH", public_path)
    gateway_app.clear_policy_registry_cache()

    response = client.post("/decide", json=simulation_payload())

    assert response.status_code == 403
    assert response.json()["reason"] == "policy_key_expired"


def test_policy_state_endpoint_reports_governance_state(tmp_path: Path, monkeypatch) -> None:
    client = configure_gateway(tmp_path, monkeypatch)

    response = client.get("/policy/state")

    assert response.status_code == 200
    assert response.json()["policy_state"] == "valid"
    assert response.json()["policy_signature_valid"] is True
    assert response.json()["policy_hash"]


def test_tampered_policy_log_is_invalid(tmp_path: Path) -> None:
    registry = {
        "version": "1.0",
        "critical_infrastructure": ["energy"],
        "last_updated": "2026-04-30T02:00:00Z",
        "authority": "human_policy_owner",
        "policy_pubkey_id": "key_test_log",
        "policy_sequence": 1,
        "policy_author": "policy_author_hash_test",
        "policy_signer": "policy_signer_hash_test",
        "deployment_operator": "deployment_operator_hash_test",
        "valid_from": "2026-01-01T00:00:00Z",
        "valid_until": "2030-01-01T00:00:00Z",
    }
    log_path = tmp_path / "policy_log.jsonl"
    entry = append_policy_log(registry, log_path, "signature-test")
    assert verify_policy_log(log_path, policy_hash(registry)) is True

    tampered_entry = {**entry, "previous_hash": "f" * 64}
    log_path.write_text(json.dumps(tampered_entry, sort_keys=True) + "\n", encoding="utf-8")

    assert verify_policy_log(log_path, policy_hash(registry)) is False
