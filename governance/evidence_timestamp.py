from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from governance.evidence_contracts import EVIDENCE_POLICY_VERSION, EVIDENCE_TIMESTAMP_SCHEMA, parse_timestamp
from governance.execution_contracts import sha256_json


TIMESTAMP_INTEGRATION_STATUS = "NOT_IMPLEMENTED"
ALLOWED_TIMESTAMP_AUTHORITIES = frozenset({"USBAY_LOCAL_RFC3161_PLACEHOLDER"})


def build_evidence_timestamp(
    *,
    manifest_hash: str,
    timestamp_authority: str,
    issued_at: str,
    policy_version: str = EVIDENCE_POLICY_VERSION,
) -> dict[str, Any]:
    token_seed = {
        "manifest_hash": str(manifest_hash),
        "timestamp_authority": str(timestamp_authority),
        "issued_at": str(issued_at),
        "policy_version": str(policy_version),
    }
    timestamp = {
        "schema": EVIDENCE_TIMESTAMP_SCHEMA,
        "timestamp_id": f"evidence-timestamp-{sha256_json(token_seed)[:24]}",
        "manifest_hash": str(manifest_hash),
        "timestamp_token_hash": sha256_json(token_seed),
        "timestamp_authority": str(timestamp_authority),
        "issued_at": str(issued_at),
        "policy_version": str(policy_version),
        "verification_status": "BLOCKED",
        "timestamp_integration_status": TIMESTAMP_INTEGRATION_STATUS,
    }
    return timestamp


def validate_evidence_timestamp(
    timestamp: dict[str, Any] | None,
    *,
    manifest_hash: str,
    artifact_created_at_values: list[str],
    now: datetime | None = None,
) -> tuple[bool, tuple[str, ...]]:
    if not isinstance(timestamp, dict):
        return False, ("EVIDENCE_TIMESTAMP_MISSING",)
    reasons: list[str] = []
    required = ("timestamp_id", "manifest_hash", "timestamp_token_hash", "timestamp_authority", "issued_at", "policy_version", "verification_status")
    for field in required:
        if timestamp.get(field) in ("", None):
            reasons.append(f"EVIDENCE_TIMESTAMP_{field.upper()}_MISSING")
    if timestamp.get("schema") != EVIDENCE_TIMESTAMP_SCHEMA:
        reasons.append("EVIDENCE_TIMESTAMP_SCHEMA_INVALID")
    if timestamp.get("manifest_hash") != manifest_hash:
        reasons.append("EVIDENCE_TIMESTAMP_MANIFEST_HASH_MISMATCH")
    if timestamp.get("timestamp_authority") not in ALLOWED_TIMESTAMP_AUTHORITIES:
        reasons.append("EVIDENCE_TIMESTAMP_AUTHORITY_UNKNOWN")
    if timestamp.get("timestamp_integration_status") != TIMESTAMP_INTEGRATION_STATUS:
        reasons.append("EVIDENCE_TIMESTAMP_INTEGRATION_STATUS_INVALID")
    issued_at = parse_timestamp(timestamp.get("issued_at"))
    effective_now = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    if issued_at is None:
        reasons.append("EVIDENCE_TIMESTAMP_ISSUED_AT_INVALID")
    else:
        if issued_at > effective_now:
            reasons.append("EVIDENCE_TIMESTAMP_FUTURE")
        for created_at_value in artifact_created_at_values:
            created_at = parse_timestamp(created_at_value)
            if created_at is not None and issued_at < created_at:
                reasons.append("EVIDENCE_TIMESTAMP_BEFORE_ARTIFACT")
                break
    expected_hash = sha256_json(
        {
            "manifest_hash": timestamp.get("manifest_hash", ""),
            "timestamp_authority": timestamp.get("timestamp_authority", ""),
            "issued_at": timestamp.get("issued_at", ""),
            "policy_version": timestamp.get("policy_version", EVIDENCE_POLICY_VERSION),
        }
    )
    if timestamp.get("timestamp_token_hash") != expected_hash:
        reasons.append("EVIDENCE_TIMESTAMP_TOKEN_INVALID")
    return not reasons, tuple(sorted(set(reasons)))
