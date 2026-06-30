from __future__ import annotations

from typing import Any

from governance.evidence_contracts import EVIDENCE_POLICY_VERSION, EVIDENCE_SIGNATURE_SCHEMA, parse_timestamp
from governance.execution_contracts import sha256_json


ALLOWED_SIGNER_ROLES = frozenset({"USBAY_OPERATOR", "USBAY_AUDITOR", "USBAY_ADMIN"})
REJECTED_SIGNER_ROLES = frozenset({"AI_AGENT", "CODEX", "AUTOMATION", "SYSTEM"})
SIGNATURE_ALGORITHM = "USBAY-DETERMINISTIC-LOCAL-SIGNATURE-PLACEHOLDER-v1"


def expected_signature_hash(signature: dict[str, Any]) -> str:
    return sha256_json(
        {
            "manifest_hash": signature.get("manifest_hash", ""),
            "signer_id": signature.get("signer_id", ""),
            "signer_role": signature.get("signer_role", ""),
            "algorithm": signature.get("algorithm", SIGNATURE_ALGORITHM),
            "created_at": signature.get("created_at", ""),
            "policy_version": signature.get("policy_version", EVIDENCE_POLICY_VERSION),
        }
    )


def build_evidence_signature(
    *,
    manifest_hash: str,
    signer_id: str,
    signer_role: str,
    created_at: str,
    policy_version: str = EVIDENCE_POLICY_VERSION,
) -> dict[str, Any]:
    signature = {
        "schema": EVIDENCE_SIGNATURE_SCHEMA,
        "signature_id": "",
        "manifest_hash": str(manifest_hash),
        "signer_id": str(signer_id),
        "signer_role": str(signer_role),
        "signature_hash": "",
        "algorithm": SIGNATURE_ALGORITHM,
        "created_at": str(created_at),
        "policy_version": str(policy_version),
    }
    signature["signature_id"] = f"evidence-signature-{sha256_json(signature | {'signature_id': '', 'signature_hash': ''})[:24]}"
    signature["signature_hash"] = expected_signature_hash(signature)
    return signature


def validate_evidence_signature(signature: dict[str, Any] | None, *, manifest_hash: str) -> tuple[bool, tuple[str, ...]]:
    if not isinstance(signature, dict):
        return False, ("EVIDENCE_SIGNATURE_MISSING",)
    reasons: list[str] = []
    required = ("signature_id", "manifest_hash", "signer_id", "signer_role", "signature_hash", "algorithm", "created_at", "policy_version")
    for field in required:
        if signature.get(field) in ("", None):
            reasons.append(f"EVIDENCE_SIGNATURE_{field.upper()}_MISSING")
    if signature.get("schema") != EVIDENCE_SIGNATURE_SCHEMA:
        reasons.append("EVIDENCE_SIGNATURE_SCHEMA_INVALID")
    if signature.get("manifest_hash") != manifest_hash:
        reasons.append("EVIDENCE_SIGNATURE_MANIFEST_HASH_MISMATCH")
    role = str(signature.get("signer_role", "")).upper()
    if role in REJECTED_SIGNER_ROLES:
        reasons.append(f"EVIDENCE_SIGNATURE_SIGNER_ROLE_REJECTED:{role}")
    elif role not in ALLOWED_SIGNER_ROLES:
        reasons.append(f"EVIDENCE_SIGNATURE_SIGNER_ROLE_UNKNOWN:{role or 'MISSING'}")
    if parse_timestamp(signature.get("created_at")) is None:
        reasons.append("EVIDENCE_SIGNATURE_CREATED_AT_INVALID")
    if signature.get("algorithm") != SIGNATURE_ALGORITHM:
        reasons.append("EVIDENCE_SIGNATURE_ALGORITHM_INVALID")
    if signature.get("signature_hash") != expected_signature_hash(signature):
        reasons.append("EVIDENCE_SIGNATURE_INVALID")
    return not reasons, tuple(sorted(set(reasons)))
