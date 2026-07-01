from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import gateway.app as gateway_app

# Purpose: canonical runtime attestation fixtures for governed gateway tests.
# Governance scope: signed runtime trust state used by execution test fixtures.
# Fail-closed expectation: helpers install only verifiable signed attestation inputs.
# Sensitive-data handling: generated key material is test-local and never logged.


RUNTIME_TRUST_STATE_FIELDS = (
    "attestation_status",
    "signature_valid",
)


def _runtime_attestation_keypair() -> tuple[str, str]:
    private_key = Ed25519PrivateKey.generate()
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("utf-8")
    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("utf-8")
    return private_pem, public_pem


def runtime_trust_state(snapshot: dict[str, Any]) -> dict[str, Any]:
    return {field: snapshot.get(field) for field in RUNTIME_TRUST_STATE_FIELDS}


def install_signed_runtime_attestation_fixture(
    monkeypatch,
    *,
    deployment_timestamp_utc: str | None = None,
) -> dict[str, str]:
    private_key, public_key = _runtime_attestation_keypair()
    timestamp = deployment_timestamp_utc or datetime.now(timezone.utc).replace(
        microsecond=0
    ).isoformat().replace("+00:00", "Z")
    monkeypatch.setenv("USBAY_RUNTIME_ATTESTATION_PRIVATE_KEY_PEM", private_key)
    monkeypatch.setenv("USBAY_RUNTIME_ATTESTATION_PUBLIC_KEY_PEM", public_key)
    monkeypatch.setenv("USBAY_DEPLOYMENT_TIMESTAMP_UTC", timestamp)
    registry = gateway_app.load_policy_registry(
        provenance_context=gateway_app.runtime_provenance_context()
    )
    snapshot = gateway_app.signed_runtime_attestation_snapshot(
        runtime_snapshot={
            "mode": "NORMAL",
            "reason": "ok",
            "policy_version": registry["version"],
            "policy_hash": registry["policy_hash"],
        },
        deployment_health={
            "schema_version": "usbay.deployment_runtime_health.v1",
            "status": "READY",
            "startup_status": "READY",
            "health_evidence_hash": "signed-runtime-attestation-fixture",
            "reason_codes": [],
        },
    )
    enforcement = gateway_app.validate_attestation_freshness_for_runtime(snapshot)
    if enforcement.get("decision") == gateway_app.RUNTIME_ENFORCEMENT_DENY:
        raise AssertionError(
            f"invalid_runtime_attestation_fixture:{enforcement.get('reason_code')}"
        )
    monkeypatch.setattr(
        gateway_app,
        "signed_runtime_attestation_snapshot",
        lambda *args, **kwargs: snapshot.copy(),
    )
    return snapshot


__all__ = [
    "RUNTIME_TRUST_STATE_FIELDS",
    "install_signed_runtime_attestation_fixture",
    "runtime_trust_state",
]
