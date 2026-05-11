from __future__ import annotations

import hashlib
import hmac
import json
import os
import time
from pathlib import Path
from typing import Any

from security.node_identity import (
    DEFAULT_NODE_ATTESTATION_POLICY_PATH,
    canonical_json,
    default_public_identity,
    generate_node_id,
    load_node_attestation_policy,
    public_identity_hash,
)


class AttestationError(RuntimeError):
    pass


_USED_CHALLENGES: set[str] = set()


def environment_mode() -> str:
    raw = os.getenv("USBAY_ENV", os.getenv("USBAY_ENVIRONMENT", "test")).strip().lower()
    return "production" if raw in {"prod", "production"} else "test"


def attestation_secret() -> str:
    return os.getenv("USBAY_ATTESTATION_SIGNING_SECRET", "usbay-local-attestation-dev-secret")


def attestation_hash(document: dict[str, Any]) -> str:
    payload = dict(document)
    payload.pop("attestation_hash", None)
    return hashlib.sha256(canonical_json(payload).encode("utf-8")).hexdigest()


def challenge_nonce(*, request_hash: str, logical_node_id: str, timestamp: float | None = None) -> str:
    payload = {
        "request_hash": str(request_hash),
        "logical_node_id": str(logical_node_id),
        "timestamp": int(timestamp or time.time()),
    }
    return hashlib.sha256(canonical_json(payload).encode("utf-8")).hexdigest()


def _signature_payload(document: dict[str, Any]) -> dict[str, Any]:
    payload = dict(document)
    payload.pop("signature", None)
    payload.pop("attestation_hash", None)
    return payload


def sign_attestation_document(document: dict[str, Any], secret: str | None = None) -> str:
    return hmac.new(
        (secret or attestation_secret()).encode("utf-8"),
        canonical_json(_signature_payload(document)).encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()


def create_attestation_document(
    *,
    logical_node_id: str,
    node_role: str,
    challenge: str,
    provider_mode: str = "mock_local",
    hardware_backed: bool = False,
    public_identity: dict[str, Any] | None = None,
    timestamp: float | None = None,
) -> dict[str, Any]:
    identity = public_identity or default_public_identity(logical_node_id)
    created_at = float(timestamp or time.time())
    document = {
        "type": "usbay_node_attestation_v1",
        "logical_node_id": str(logical_node_id),
        "node_id": generate_node_id(identity),
        "node_role": str(node_role),
        "public_identity_hash": public_identity_hash(identity),
        "provider_mode": str(provider_mode),
        "hardware_backed": bool(hardware_backed),
        "challenge_nonce": str(challenge),
        "timestamp": created_at,
        "signature_alg": "HMAC-SHA256-MOCK" if provider_mode == "mock_local" else "PROVIDER-SIGNED",
    }
    document["signature"] = sign_attestation_document(document)
    document["attestation_hash"] = attestation_hash(document)
    return document


def validate_attestation_document(
    document: dict[str, Any] | None,
    *,
    expected_challenge: str,
    policy_path: Path | str = DEFAULT_NODE_ATTESTATION_POLICY_PATH,
    now: float | None = None,
    mark_nonce_used: bool = True,
) -> dict[str, Any]:
    if not isinstance(document, dict):
        raise AttestationError("attestation_missing")
    policy = load_node_attestation_policy(policy_path)
    current = float(now or time.time())
    logical_node_id = str(document.get("logical_node_id", ""))
    enrolled = policy["enrolled_nodes"].get(logical_node_id)
    if enrolled is None:
        raise AttestationError("node_id_unknown")
    if document.get("node_id") != enrolled["node_id"]:
        raise AttestationError("node_id_unknown")
    if document.get("public_identity_hash") != enrolled["public_identity_hash"]:
        raise AttestationError("node_id_unknown")
    if document.get("node_role") != enrolled["role"]:
        raise AttestationError("role_unauthorized")
    if document.get("node_role") not in policy["allowed_node_roles"]:
        raise AttestationError("role_unauthorized")
    provider_mode = str(document.get("provider_mode", ""))
    if provider_mode != policy["required_attestation_mode"]:
        raise AttestationError("provider_mode_not_allowed")
    if provider_mode == "mock_local" and policy["production_rejects_mock"] and environment_mode() == "production":
        raise AttestationError("mock_attestation_rejected_in_production")
    if policy["require_hardware_backing"] and document.get("hardware_backed") is not True:
        raise AttestationError("hardware_backing_required")
    if document.get("challenge_nonce") != expected_challenge:
        raise AttestationError("attestation_nonce_mismatch")
    try:
        ts = float(document.get("timestamp"))
    except Exception as exc:
        raise AttestationError("attestation_timestamp_invalid") from exc
    if current - ts > policy["attestation_ttl_seconds"] or ts > current + policy["attestation_ttl_seconds"]:
        raise AttestationError("attestation_stale")
    if mark_nonce_used:
        challenge = str(document.get("challenge_nonce", ""))
        if challenge in _USED_CHALLENGES:
            raise AttestationError("attestation_replay_detected")
    expected_signature = sign_attestation_document(document)
    if not hmac.compare_digest(str(document.get("signature", "")), expected_signature):
        raise AttestationError("attestation_signature_invalid")
    expected_hash = attestation_hash(document)
    if document.get("attestation_hash") != expected_hash:
        raise AttestationError("attestation_hash_invalid")
    if mark_nonce_used:
        _USED_CHALLENGES.add(str(document.get("challenge_nonce", "")))
    return {
        "logical_node_id": logical_node_id,
        "node_id": str(document["node_id"]),
        "node_role": str(document["node_role"]),
        "provider_mode": provider_mode,
        "hardware_backed": bool(document.get("hardware_backed")),
        "attestation_hash": str(document["attestation_hash"]),
        "attestation_timestamp": float(document["timestamp"]),
        "public_identity_hash": str(document["public_identity_hash"]),
    }


def reset_attestation_replay_cache() -> None:
    _USED_CHALLENGES.clear()
