from __future__ import annotations

import base64
import hashlib
import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from governance.deployment_runtime_health import canonical_json, load_deployment_runtime_policy, sha256_text


SCHEMA_VERSION = "usbay.signed_runtime_attestation.v1"
SIGNATURE_ALGORITHM = "Ed25519"
PRIVATE_KEY_ENV = "USBAY_RUNTIME_ATTESTATION_" + "PRIVATE_KEY_PEM"
PUBLIC_KEY_ENV = "USBAY_RUNTIME_ATTESTATION_PUBLIC_KEY_PEM"
RUNTIME_ATTESTATION_SIGNED = "RUNTIME_ATTESTATION_SIGNED"
RUNTIME_ATTESTATION_MISSING = "RUNTIME_ATTESTATION_MISSING"
RUNTIME_ATTESTATION_INVALID = "RUNTIME_ATTESTATION_INVALID"
RUNTIME_ATTESTATION_POLICY_MISMATCH = "RUNTIME_ATTESTATION_POLICY_MISMATCH"
RUNTIME_ATTESTATION_BLOCKED = "RUNTIME_ATTESTATION_BLOCKED"
FORBIDDEN_DIAGNOSTIC_TERMS = (
    "PRIVATE " + "KEY",
    "approval_" + "contents",
    "raw_" + "payload",
    "secret",
    "token",
)


class RuntimeAttestationAuthorityError(RuntimeError):
    pass


@dataclass(frozen=True)
class RuntimeAttestationVerification:
    valid: bool
    status: str
    reason_codes: tuple[str, ...]
    attestation_hash: str
    signer_fingerprint: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "valid": self.valid,
            "status": self.status,
            "reason_codes": list(self.reason_codes),
            "attestation_hash": self.attestation_hash,
            "signer_fingerprint": self.signer_fingerprint,
        }


def signed_payload(attestation: dict[str, Any]) -> dict[str, Any]:
    payload = dict(attestation)
    payload.pop("signature", None)
    payload.pop("signature_valid", None)
    payload.pop("verification", None)
    return payload


def attestation_hash(attestation: dict[str, Any]) -> str:
    return sha256_text(canonical_json(signed_payload(attestation)))


def public_key_fingerprint(public_key_pem: str) -> str:
    public_key = _load_public_key(public_key_pem)
    der = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return hashlib.sha256(der).hexdigest()


def public_key_from_private_key(private_key_pem: str) -> str:
    private_key = _load_private_key(private_key_pem)
    return private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("utf-8")


def create_signed_runtime_attestation(
    *,
    root: Path,
    deployment_health: dict[str, Any],
    runtime_snapshot: dict[str, Any],
    audit_chain_entries: list[dict[str, Any]] | None,
    audit_chain_valid: bool,
    private_key_pem: str,
    public_key_pem: str | None = None,
    deployment_timestamp_utc: str,
) -> dict[str, Any]:
    if not private_key_pem:
        raise RuntimeAttestationAuthorityError(RUNTIME_ATTESTATION_MISSING)
    derived_public = public_key_from_private_key(private_key_pem)
    trusted_public = normalize_public_key_pem(public_key_pem or derived_public)
    if trusted_public != normalize_public_key_pem(derived_public):
        raise RuntimeAttestationAuthorityError(RUNTIME_ATTESTATION_INVALID)

    policy = load_deployment_runtime_policy(root)
    policy_hash = str(runtime_snapshot.get("policy_hash", ""))
    policy_version = str(runtime_snapshot.get("policy_version", ""))
    deployment_status = str(deployment_health.get("status", ""))
    runtime_mode = str(runtime_snapshot.get("mode", ""))
    audit_entries = audit_chain_entries or []
    audit_status = "VERIFIED" if audit_chain_valid else "INVALID"
    ready = (
        deployment_status == "READY"
        and runtime_mode == "NORMAL"
        and bool(policy_hash)
        and audit_status == "VERIFIED"
    )

    reason_codes = [RUNTIME_ATTESTATION_SIGNED if ready else RUNTIME_ATTESTATION_BLOCKED]
    if not ready:
        reason_codes.append(RUNTIME_ATTESTATION_INVALID)

    attestation = {
        "schema_version": SCHEMA_VERSION,
        "attestation_status": "SIGNED" if ready else "BLOCKED",
        "signature_algorithm": SIGNATURE_ALGORITHM,
        "startup_command_hash": sha256_text(str(policy.get("startup_command", ""))),
        "runtime_mode": runtime_mode,
        "deployment_health_status": deployment_status,
        "deployment_health_hash": str(deployment_health.get("health_evidence_hash", "")),
        "policy_version": policy_version,
        "policy_hash": policy_hash,
        "audit_chain_status": audit_status,
        "audit_chain_hash": sha256_text(canonical_json(audit_entries)),
        "deployment_timestamp_utc": str(deployment_timestamp_utc),
        "signer_fingerprint": public_key_fingerprint(trusted_public),
        "reason_codes": reason_codes,
    }
    _assert_safe(attestation)
    signature = _sign(attestation_hash(attestation), private_key_pem)
    attestation["signature"] = signature
    verification = verify_runtime_attestation(attestation, trusted_public)
    attestation["signature_valid"] = verification.valid
    attestation["verification"] = verification.to_dict()
    _assert_safe(attestation)
    return attestation


def missing_runtime_attestation(reason_code: str = RUNTIME_ATTESTATION_MISSING) -> dict[str, Any]:
    payload = {
        "schema_version": SCHEMA_VERSION,
        "attestation_status": "BLOCKED",
        "signature_algorithm": SIGNATURE_ALGORITHM,
        "signature_valid": False,
        "reason_codes": [reason_code, RUNTIME_ATTESTATION_BLOCKED],
        "attestation_hash": "",
        "signer_fingerprint": "",
    }
    _assert_safe(payload)
    return payload


def runtime_attestation_from_environment(
    *,
    root: Path,
    deployment_health: dict[str, Any],
    runtime_snapshot: dict[str, Any],
    audit_chain_entries: list[dict[str, Any]] | None,
    audit_chain_valid: bool,
    deployment_timestamp_utc: str,
) -> dict[str, Any]:
    private_key_pem = os.getenv(PRIVATE_KEY_ENV, "")
    public_key_pem = os.getenv(PUBLIC_KEY_ENV, "")
    if not private_key_pem:
        return missing_runtime_attestation(RUNTIME_ATTESTATION_MISSING)
    try:
        return create_signed_runtime_attestation(
            root=root,
            deployment_health=deployment_health,
            runtime_snapshot=runtime_snapshot,
            audit_chain_entries=audit_chain_entries,
            audit_chain_valid=audit_chain_valid,
            private_key_pem=private_key_pem,
            public_key_pem=public_key_pem or None,
            deployment_timestamp_utc=deployment_timestamp_utc,
        )
    except RuntimeAttestationAuthorityError as exc:
        return missing_runtime_attestation(str(exc) or RUNTIME_ATTESTATION_INVALID)
    except Exception:
        return missing_runtime_attestation(RUNTIME_ATTESTATION_INVALID)


def verify_runtime_attestation(attestation: dict[str, Any], public_key_pem: str, *, expected_policy_hash: str = "") -> RuntimeAttestationVerification:
    reason_codes: list[str] = []
    try:
        _assert_safe(attestation)
        if attestation.get("schema_version") != SCHEMA_VERSION:
            reason_codes.append(RUNTIME_ATTESTATION_INVALID)
        if expected_policy_hash and attestation.get("policy_hash") != expected_policy_hash:
            reason_codes.append(RUNTIME_ATTESTATION_POLICY_MISMATCH)
        fingerprint = public_key_fingerprint(public_key_pem)
        if attestation.get("signer_fingerprint") != fingerprint:
            reason_codes.append(RUNTIME_ATTESTATION_INVALID)
        signature = str(attestation.get("signature", ""))
        if not signature:
            reason_codes.append(RUNTIME_ATTESTATION_MISSING)
        elif not _verify(attestation_hash(attestation), signature, public_key_pem):
            reason_codes.append(RUNTIME_ATTESTATION_INVALID)
        if attestation.get("attestation_status") != "SIGNED":
            reason_codes.append(RUNTIME_ATTESTATION_BLOCKED)
        if not reason_codes:
            reason_codes.append(RUNTIME_ATTESTATION_SIGNED)
        valid = reason_codes == [RUNTIME_ATTESTATION_SIGNED]
        return RuntimeAttestationVerification(
            valid=valid,
            status="VERIFIED" if valid else "BLOCKED",
            reason_codes=tuple(dict.fromkeys(reason_codes)),
            attestation_hash=attestation_hash(attestation) if isinstance(attestation, dict) else "",
            signer_fingerprint=fingerprint,
        )
    except RuntimeAttestationAuthorityError:
        return RuntimeAttestationVerification(
            valid=False,
            status="BLOCKED",
            reason_codes=(RUNTIME_ATTESTATION_INVALID,),
            attestation_hash="",
            signer_fingerprint="",
        )


def normalize_public_key_pem(public_key_pem: str) -> str:
    public_key = _load_public_key(public_key_pem)
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("utf-8")


def _load_private_key(private_key_pem: str) -> Ed25519PrivateKey:
    try:
        key = serialization.load_pem_private_key(private_key_pem.encode("utf-8"), password=None)
    except Exception as exc:
        raise RuntimeAttestationAuthorityError(RUNTIME_ATTESTATION_INVALID) from exc
    if not isinstance(key, Ed25519PrivateKey):
        raise RuntimeAttestationAuthorityError(RUNTIME_ATTESTATION_INVALID)
    return key


def _load_public_key(public_key_pem: str) -> Ed25519PublicKey:
    try:
        normalized = public_key_pem.strip().replace("\\r\\n", "\n").replace("\\n", "\n").replace("\r\n", "\n").replace("\r", "\n")
        key = serialization.load_pem_public_key(normalized.encode("utf-8"))
    except Exception as exc:
        raise RuntimeAttestationAuthorityError(RUNTIME_ATTESTATION_INVALID) from exc
    if not isinstance(key, Ed25519PublicKey):
        raise RuntimeAttestationAuthorityError(RUNTIME_ATTESTATION_INVALID)
    return key


def _sign(payload_hash: str, private_key_pem: str) -> str:
    private_key = _load_private_key(private_key_pem)
    return base64.b64encode(private_key.sign(payload_hash.encode("utf-8"))).decode("ascii")


def _verify(payload_hash: str, signature: str, public_key_pem: str) -> bool:
    try:
        public_key = _load_public_key(public_key_pem)
        public_key.verify(base64.b64decode(signature.encode("ascii")), payload_hash.encode("utf-8"))
        return True
    except (InvalidSignature, ValueError, TypeError, RuntimeAttestationAuthorityError):
        return False


def _assert_safe(value: Any) -> None:
    text = canonical_json(value)
    if any(term.lower() in text.lower() for term in FORBIDDEN_DIAGNOSTIC_TERMS):
        raise RuntimeAttestationAuthorityError(RUNTIME_ATTESTATION_INVALID)
