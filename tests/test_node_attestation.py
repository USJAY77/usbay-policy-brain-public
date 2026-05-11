from __future__ import annotations

import json
import time
from pathlib import Path

import pytest

from audit.immutable_ledger import append_evidence_event, export_evidence_bundle
from security.node_identity import canonical_json, default_public_identity, generate_node_id
from security.runtime_attestation import (
    AttestationError,
    challenge_nonce,
    create_attestation_document,
    reset_attestation_replay_cache,
    sign_attestation_document,
    validate_attestation_document,
)


def _policy(path: Path, *, require_hardware: bool = False, role: str = "primary") -> Path:
    identity = default_public_identity("node-1")
    path.write_text(
        canonical_json(
            {
                "required_attestation_mode": "mock_local",
                "allowed_node_roles": ["primary", "secondary", "offline_backup", "gateway"],
                "attestation_ttl_seconds": 30,
                "require_hardware_backing": require_hardware,
                "production_rejects_mock": True,
                "enrolled_nodes": {
                    "node-1": {
                        "role": role,
                        "public_identity": identity,
                    }
                },
            }
        ),
        encoding="utf-8",
    )
    return path


def _document(*, timestamp: float | None = None, role: str = "primary", hardware_backed: bool = False) -> tuple[dict, str]:
    request_hash = "request-attestation-hash"
    created_at = time.time() if timestamp is None else timestamp
    challenge = challenge_nonce(request_hash=request_hash, logical_node_id="node-1", timestamp=created_at)
    return (
        create_attestation_document(
            logical_node_id="node-1",
            node_role=role,
            challenge=challenge,
            provider_mode="mock_local",
            hardware_backed=hardware_backed,
            timestamp=created_at,
        ),
        challenge,
    )


@pytest.fixture(autouse=True)
def _reset_attestation(monkeypatch):
    reset_attestation_replay_cache()
    monkeypatch.delenv("USBAY_ENV", raising=False)
    monkeypatch.delenv("USBAY_ENVIRONMENT", raising=False)
    yield
    reset_attestation_replay_cache()


def test_valid_mock_attestation_passes_in_development() -> None:
    document, challenge = _document()

    evidence = validate_attestation_document(document, expected_challenge=challenge)

    assert evidence["node_id"] == generate_node_id(default_public_identity("node-1"))
    assert evidence["node_role"] == "primary"
    assert evidence["provider_mode"] == "mock_local"
    assert evidence["attestation_hash"] == document["attestation_hash"]


def test_mock_attestation_rejected_in_production(monkeypatch) -> None:
    monkeypatch.setenv("USBAY_ENV", "production")
    document, challenge = _document()

    with pytest.raises(AttestationError, match="mock_attestation_rejected_in_production"):
        validate_attestation_document(document, expected_challenge=challenge)


def test_stale_attestation_fails_closed() -> None:
    stale = time.time() - 120
    document, challenge = _document(timestamp=stale)

    with pytest.raises(AttestationError, match="attestation_stale"):
        validate_attestation_document(document, expected_challenge=challenge)


def test_replayed_nonce_fails_closed() -> None:
    document, challenge = _document()
    validate_attestation_document(document, expected_challenge=challenge)

    with pytest.raises(AttestationError, match="attestation_replay_detected"):
        validate_attestation_document(document, expected_challenge=challenge)


def test_invalid_signature_fails_closed() -> None:
    document, challenge = _document()
    document["signature"] = "bad-signature"

    with pytest.raises(AttestationError, match="attestation_signature_invalid"):
        validate_attestation_document(document, expected_challenge=challenge)


def test_unknown_node_id_fails_closed() -> None:
    created_at = time.time()
    challenge = challenge_nonce(request_hash="request-attestation-hash", logical_node_id="node-x", timestamp=created_at)
    document = create_attestation_document(
        logical_node_id="node-x",
        node_role="primary",
        challenge=challenge,
        provider_mode="mock_local",
        timestamp=created_at,
    )

    with pytest.raises(AttestationError, match="node_id_unknown"):
        validate_attestation_document(document, expected_challenge=challenge)


def test_unauthorized_role_fails_closed() -> None:
    document, challenge = _document(role="gateway")

    with pytest.raises(AttestationError, match="role_unauthorized"):
        validate_attestation_document(document, expected_challenge=challenge)


def test_missing_hardware_backed_flag_fails_closed_when_required(tmp_path: Path) -> None:
    policy_path = _policy(tmp_path / "node_attestation_policy.json", require_hardware=True)
    document, challenge = _document(hardware_backed=False)

    with pytest.raises(AttestationError, match="hardware_backing_required"):
        validate_attestation_document(document, expected_challenge=challenge, policy_path=policy_path)


def test_attestation_evidence_included_in_exported_bundle(tmp_path: Path) -> None:
    document, challenge = _document()
    evidence = validate_attestation_document(document, expected_challenge=challenge)
    ledger = tmp_path / "audit.jsonl"
    consensus_bundle = {
        "node_ids": ["node-1"],
        "policy_hash": "policy-hash",
        "consensus_result": "allow",
        "attestation_evidence": [evidence],
        "attestation_evidence_hash": document["attestation_hash"],
        "sha256_evidence_hash": "consensus-hash",
        "consensus_signature": "consensus-signature",
    }
    append_evidence_event(
        ledger,
        action="decision_created",
        decision={
            "node_id": evidence["node_id"],
            "policy_hash": "policy-hash",
            "decision": "ALLOW",
            "consensus_result": "allow",
            "consensus_evidence_bundle": consensus_bundle,
        },
    )

    export_evidence_bundle(ledger, tmp_path / "export")
    exported = json.loads((tmp_path / "export" / "consensus_evidence.json").read_text(encoding="utf-8"))

    assert next(iter(exported.values()))["attestation_evidence"][0]["attestation_hash"] == document["attestation_hash"]


def test_no_secret_leakage_in_attestation_evidence() -> None:
    document, challenge = _document()
    evidence = validate_attestation_document(document, expected_challenge=challenge)
    combined = json.dumps({"document": document, "evidence": evidence}, sort_keys=True).lower()

    assert "raw_device_id" not in combined
    assert "device_serial" not in combined
    assert "private" + "_" + "key" not in combined
