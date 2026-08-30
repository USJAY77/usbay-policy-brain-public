from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


POLICY_SIGNATURE_VALIDATOR_VERSION = "pb216-policy-registry-signature-renewal-v1"
DEFAULT_POLICY_REGISTRY_PATH = Path("governance/policy_registry.json")
REQUIRED_SIGNATURE_FIELDS = ("policy_hash", "signature_id", "signed_at", "signer", "active", "expires_at")


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _parse_utc(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def _is_sha256(value: Any) -> bool:
    return isinstance(value, str) and len(value) == 64 and all(ch in "0123456789abcdef" for ch in value)


def load_policy_registry(path: str | Path = DEFAULT_POLICY_REGISTRY_PATH) -> dict[str, Any]:
    registry_path = Path(path)
    if not registry_path.exists():
        raise ValueError("MISSING_POLICY")
    try:
        payload = json.loads(registry_path.read_text(encoding="utf-8"))
    except Exception as exc:
        raise ValueError("MALFORMED_POLICY_REGISTRY") from exc
    if not isinstance(payload, dict):
        raise ValueError("MALFORMED_POLICY_REGISTRY")
    return payload


def validate_policy_signature_registry(
    registry: dict[str, Any],
    *,
    now: datetime | None = None,
) -> dict[str, Any]:
    gaps: list[str] = []
    policy_hash = registry.get("policy_hash")
    if not _is_sha256(policy_hash):
        gaps.append("MALFORMED_POLICY_HASH")
    if registry.get("active") is not True:
        gaps.append("POLICY_NOT_ACTIVE")

    signature = registry.get("signature_metadata")
    if not isinstance(signature, dict):
        gaps.append("SIGNATURE_MISSING")
        signature = {}

    for field in REQUIRED_SIGNATURE_FIELDS:
        if field not in signature:
            gaps.append(f"MISSING_SIGNATURE_{field.upper()}")

    signature_policy_hash = signature.get("policy_hash")
    if signature_policy_hash != policy_hash:
        gaps.append("SIGNATURE_POLICY_HASH_MISMATCH")
    if not isinstance(signature.get("signature_id"), str) or not signature.get("signature_id"):
        gaps.append("MALFORMED_SIGNATURE_ID")
    if not isinstance(signature.get("signer"), str) or not signature.get("signer"):
        gaps.append("MALFORMED_SIGNER")
    if signature.get("active") is not True:
        gaps.append("SIGNATURE_NOT_ACTIVE")

    clock = now or _utc_now()
    try:
        signed_at = _parse_utc(str(signature.get("signed_at")))
        if signed_at > clock:
            gaps.append("SIGNATURE_MALFORMED")
    except Exception:
        gaps.append("SIGNATURE_MALFORMED")
    try:
        expires_at = _parse_utc(str(signature.get("expires_at")))
        if expires_at <= clock:
            gaps.append("SIGNATURE_EXPIRED")
    except Exception:
        gaps.append("SIGNATURE_MALFORMED")

    decision = "VERIFIED" if not gaps else "FAIL_CLOSED"
    return {
        "decision": decision,
        "gaps": sorted(set(gaps)),
        "policy_hash": policy_hash if isinstance(policy_hash, str) else None,
        "signature_id": signature.get("signature_id") if isinstance(signature.get("signature_id"), str) else None,
        "signed_at": signature.get("signed_at") if isinstance(signature.get("signed_at"), str) else None,
        "signer": signature.get("signer") if isinstance(signature.get("signer"), str) else None,
        "active": registry.get("active") is True and signature.get("active") is True,
        "validator_version": POLICY_SIGNATURE_VALIDATOR_VERSION,
        "production_activation_allowed": False,
    }


def validate_policy_registry_file(path: str | Path = DEFAULT_POLICY_REGISTRY_PATH) -> dict[str, Any]:
    try:
        registry = load_policy_registry(path)
    except ValueError as exc:
        return {
            "decision": "FAIL_CLOSED",
            "gaps": [str(exc)],
            "policy_hash": None,
            "signature_id": None,
            "validator_version": POLICY_SIGNATURE_VALIDATOR_VERSION,
            "production_activation_allowed": False,
        }
    return validate_policy_signature_registry(registry)
