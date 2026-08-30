from __future__ import annotations

import base64
import json

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from governance.device_identity_lifecycle import public_key_fingerprint
from governance.verifier_continuity import (
    VERIFIER_CONTRADICTION_DETECTED,
    VERIFIER_CONTINUITY_ACTIVE,
    VERIFIER_CONTINUITY_DEGRADED,
    VERIFIER_CONTINUITY_STALE,
    VERIFIER_EPOCH_REPLAY_BLOCKED,
    VERIFIER_FAILOVER_ACTIVE,
    VERIFIER_NODE_UNAVAILABLE,
    VERIFIER_QUORUM_FAILED,
    VERIFIER_QUORUM_REACHED,
    VERIFIER_SIGNATURE_INVALID,
    signable_verifier_message,
    validate_verifier_continuity,
)


NOW = "2026-05-20T00:00:00Z"
POLICY_HASH = "a" * 64
EPOCH = "epoch-2026-05-20-1"
GROUP = "primary-verifier-quorum"


def _keypair() -> tuple[Ed25519PrivateKey, str]:
    private_key = Ed25519PrivateKey.generate()
    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("utf-8")
    return private_key, public_pem


def _node(private_key: Ed25519PrivateKey, public_pem: str, node_id: str, **overrides) -> dict:
    node = {
        "verifier_node_id": node_id,
        "verifier_role": "primary",
        "verifier_hash": public_key_fingerprint(public_pem),
        "quorum_group": GROUP,
        "consensus_epoch": EPOCH,
        "continuity_window": "300",
        "last_verified_at": "2026-05-20T00:00:00Z",
        "policy_hash": POLICY_HASH,
        "signature_status": "SIGNED",
        "continuity_state": VERIFIER_CONTINUITY_ACTIVE,
    }
    node.update(overrides)
    node["signature"] = base64.b64encode(private_key.sign(signable_verifier_message(node))).decode("ascii")
    return node


def _node_set():
    keypairs = [_keypair(), _keypair(), _keypair()]
    nodes = [_node(private, public, f"verifier-{index}") for index, (private, public) in enumerate(keypairs, start=1)]
    trusted = {public_key_fingerprint(public): public for _private, public in keypairs}
    return nodes, trusted, keypairs


def _validate(nodes, trusted, **overrides):
    kwargs = {
        "trusted_public_keys": trusted,
        "expected_policy_hash": POLICY_HASH,
        "quorum_required": 2,
        "used_consensus_epochs": set(),
        "now_utc": NOW,
    }
    kwargs.update(overrides)
    return validate_verifier_continuity(nodes, **kwargs)


def test_verifier_quorum_reaches_continuity() -> None:
    nodes, trusted, _keypairs = _node_set()

    result = _validate(nodes, trusted)

    assert result.verified is True
    assert result.continuity_state == VERIFIER_CONTINUITY_ACTIVE
    assert VERIFIER_QUORUM_REACHED in result.reason_codes
    assert result.audit_evidence["quorum_evidence"]["matching"] == 3


def test_quorum_failure_blocks() -> None:
    nodes, trusted, _keypairs = _node_set()
    nodes[1]["continuity_state"] = VERIFIER_NODE_UNAVAILABLE
    nodes[1]["signature"] = base64.b64encode(_keypairs[1][0].sign(signable_verifier_message(nodes[1]))).decode("ascii")
    nodes[2]["continuity_state"] = VERIFIER_NODE_UNAVAILABLE
    nodes[2]["signature"] = base64.b64encode(_keypairs[2][0].sign(signable_verifier_message(nodes[2]))).decode("ascii")

    result = _validate(nodes, trusted)

    assert result.verified is False
    assert result.continuity_state == VERIFIER_CONTINUITY_DEGRADED
    assert VERIFIER_QUORUM_FAILED in result.reason_codes
    assert VERIFIER_NODE_UNAVAILABLE in result.reason_codes


def test_contradiction_detection_blocks() -> None:
    nodes, trusted, keypairs = _node_set()
    nodes[2]["quorum_group"] = "conflicting-quorum"
    nodes[2]["signature"] = base64.b64encode(keypairs[2][0].sign(signable_verifier_message(nodes[2]))).decode("ascii")

    result = _validate(nodes, trusted)

    assert result.verified is False
    assert result.continuity_state == VERIFIER_CONTRADICTION_DETECTED
    assert VERIFIER_CONTRADICTION_DETECTED in result.reason_codes


def test_stale_continuity_degrades_and_blocks() -> None:
    nodes, trusted, keypairs = _node_set()
    for index, node in enumerate(nodes):
        node["last_verified_at"] = "2026-05-19T23:00:00Z"
        node["signature"] = base64.b64encode(keypairs[index][0].sign(signable_verifier_message(node))).decode("ascii")

    result = _validate(nodes, trusted)

    assert result.verified is False
    assert result.continuity_state == VERIFIER_CONTINUITY_DEGRADED
    assert VERIFIER_CONTINUITY_STALE in result.reason_codes


def test_failover_continuity_validates_with_quorum() -> None:
    nodes, trusted, keypairs = _node_set()
    nodes[1]["verifier_role"] = "failover"
    nodes[1]["continuity_state"] = VERIFIER_FAILOVER_ACTIVE
    nodes[1]["signature"] = base64.b64encode(keypairs[1][0].sign(signable_verifier_message(nodes[1]))).decode("ascii")

    result = _validate(nodes[:2], trusted)

    assert result.verified is True
    assert result.continuity_state == VERIFIER_FAILOVER_ACTIVE
    assert VERIFIER_FAILOVER_ACTIVE in result.reason_codes
    assert VERIFIER_QUORUM_REACHED in result.reason_codes


def test_replayed_epoch_blocks() -> None:
    nodes, trusted, _keypairs = _node_set()

    result = _validate(nodes, trusted, used_consensus_epochs={EPOCH})

    assert result.verified is False
    assert VERIFIER_EPOCH_REPLAY_BLOCKED in result.reason_codes


def test_invalid_verifier_signature_blocks() -> None:
    nodes, trusted, _keypairs = _node_set()
    nodes[0]["policy_hash"] = "b" * 64

    result = _validate(nodes, trusted)

    assert result.verified is False
    assert VERIFIER_SIGNATURE_INVALID in result.reason_codes


def test_verifier_audit_evidence_is_hash_only_and_redacted() -> None:
    nodes, trusted, _keypairs = _node_set()

    result = _validate(nodes, trusted)
    encoded = json.dumps(result.to_dict(), sort_keys=True)

    assert result.audit_evidence["verifier_node_hashes"]
    assert result.audit_evidence["continuity_epoch_hash"]
    assert "verifier-1" not in encoded
    assert GROUP not in encoded
    assert EPOCH not in encoded
    assert "PRIVATE " + "KEY" not in encoded
    assert "approval_" + "contents" not in encoded
    assert "raw_" + "payload" not in encoded
    assert "token" not in encoded.lower()
