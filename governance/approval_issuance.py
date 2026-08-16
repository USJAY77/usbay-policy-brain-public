"""USBAY authenticated approval issuance (GAP-1).

Assurance level: LOCAL_ED25519_KEY_REGISTRY.

An approval may enter the authority registry ONLY when accompanied by an
issuance envelope signed (Ed25519) by a registered, non-revoked, authorized
issuer. The registry stores issuer PUBLIC keys only; private keys are held
externally by the human issuer and never persisted by this codebase.

What this proves: the party registering the approval controlled the private
key of a registered issuer, and the signed payload binds every
security-relevant approval field (any post-signature mutation invalidates
the signature or the binding checks).

What this does NOT prove (labeled residual): that the issuer key was
delivered to a specific human — issuer key registration is the local trust
bootstrap and remains an externally-governed human step. No production PKI,
IdP, HSM, KMS, or CA is implemented or claimed.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Mapping, Optional

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from audit.ledger import canonical_json_bytes, sha256_bytes

_ISO = "%Y-%m-%dT%H:%M:%SZ"

# Bounded freshness for a signed issuance envelope: it must be presented to
# the registry shortly after signing (anti-stale), with small skew tolerance.
ISSUANCE_MAX_AGE_SECONDS = 900
ISSUANCE_MAX_CLOCK_SKEW_SECONDS = 120

ISSUANCE_REQUIRED_FIELDS = (
    "issuer_id",
    "actor_id",
    "authorization_id",
    "binding_hash",
    "issued_at",
    "expires_at",
    "nonce",
    "tenant_reference",
    "execution_id",
)


class ApprovalIssuanceDenied(Exception):
    """Fail-closed rejection of an approval issuance attempt."""

    def __init__(self, reason_code: str):
        super().__init__(reason_code)
        self.reason_code = reason_code


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def generate_issuer_keypair() -> tuple[str, str]:
    """Generate an Ed25519 keypair (private_pem, public_pem).

    Helper for the external/human issuer bootstrap and for tests. The
    registry itself never calls this and never stores the private key.
    """
    private = Ed25519PrivateKey.generate()
    private_pem = private.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode("ascii")
    public_pem = (
        private.public_key()
        .public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        .decode("ascii")
    )
    return private_pem, public_pem


def canonical_issuance_bytes(payload: Mapping[str, Any]) -> bytes:
    """Canonical byte representation of the issuance payload for signing."""
    ordered = {key: payload.get(key) for key in ISSUANCE_REQUIRED_FIELDS}
    return canonical_json_bytes(ordered)


def issuance_payload_hash(payload: Mapping[str, Any]) -> str:
    return sha256_bytes(canonical_issuance_bytes(payload))


def sign_issuance(private_key_pem: str, payload: Mapping[str, Any]) -> str:
    """Sign a canonical issuance payload; returns hex signature.

    Called by the EXTERNAL issuer (human tooling / tests) — never invoked
    autonomously by the execution path.
    """
    key = serialization.load_pem_private_key(
        private_key_pem.encode("ascii"), password=None
    )
    if not isinstance(key, Ed25519PrivateKey):
        raise ValueError("ISSUANCE:private_key_NOT_ED25519")
    return key.sign(canonical_issuance_bytes(payload)).hex()


def verify_issuance_signature(
    public_key_pem: str, payload: Mapping[str, Any], signature_hex: str
) -> bool:
    """True only when signature verifies over the canonical payload."""
    try:
        key = serialization.load_pem_public_key(public_key_pem.encode("ascii"))
        if not isinstance(key, Ed25519PublicKey):
            return False
        key.verify(bytes.fromhex(signature_hex), canonical_issuance_bytes(payload))
        return True
    except (InvalidSignature, ValueError, TypeError):
        return False
    except Exception:
        return False


def build_issuance_payload(
    *,
    issuer_id: str,
    actor_id: str,
    authorization_id: str,
    binding_hash: str,
    tenant_reference: str,
    nonce: str,
    execution_id: Optional[str] = None,
    issued_at: Optional[str] = None,
    valid_for_seconds: int = 600,
) -> dict:
    """Build the canonical issuance payload the issuer signs.

    Issuer-side helper (human tooling / tests); the registry only verifies.
    """
    issued = (
        datetime.strptime(issued_at, _ISO).replace(tzinfo=timezone.utc)
        if issued_at is not None
        else _utc_now()
    )
    from datetime import timedelta

    return {
        "issuer_id": issuer_id,
        "actor_id": actor_id,
        "authorization_id": authorization_id,
        "binding_hash": binding_hash,
        "issued_at": issued.strftime(_ISO),
        "expires_at": (issued + timedelta(seconds=valid_for_seconds)).strftime(_ISO),
        "nonce": nonce,
        "tenant_reference": tenant_reference,
        "execution_id": execution_id,
    }


def validate_issuance_schema(payload: Any, signature: Any) -> Optional[str]:
    """Return a deny reason code for malformed envelopes, else None."""
    if not isinstance(payload, Mapping):
        return "ISSUANCE_PAYLOAD_MISSING"
    for field in ISSUANCE_REQUIRED_FIELDS:
        if field == "execution_id":
            continue  # optional; None means not contract-pinned
        value = payload.get(field)
        if not isinstance(value, str) or not value.strip():
            return "ISSUANCE_PAYLOAD_MALFORMED"
    execution_id = payload.get("execution_id")
    if execution_id is not None and (
        not isinstance(execution_id, str) or not execution_id.strip()
    ):
        return "ISSUANCE_PAYLOAD_MALFORMED"
    if not isinstance(signature, str) or not signature.strip():
        return "AUTHENTICATION_FAILED"
    return None


def validate_issuance_freshness(payload: Mapping[str, Any]) -> Optional[str]:
    """Return a deny reason code for stale/future/inconsistent timestamps."""
    try:
        issued_at = datetime.strptime(payload["issued_at"], _ISO).replace(
            tzinfo=timezone.utc
        )
        expires_at = datetime.strptime(payload["expires_at"], _ISO).replace(
            tzinfo=timezone.utc
        )
    except Exception:
        return "ISSUANCE_TIMESTAMP_MALFORMED"
    now = _utc_now()
    age = (now - issued_at).total_seconds()
    if age > ISSUANCE_MAX_AGE_SECONDS:
        return "ISSUANCE_STALE"
    if age < -ISSUANCE_MAX_CLOCK_SKEW_SECONDS:
        return "ISSUANCE_FROM_FUTURE"
    if expires_at <= issued_at:
        return "ISSUANCE_EXPIRY_INVALID"
    if now >= expires_at:
        return "APPROVAL_EXPIRED"
    return None
