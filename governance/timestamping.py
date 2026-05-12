from __future__ import annotations

from typing import Any

from governance.interfaces import GovernanceValidationResult, TimestampVerificationResult


def validate_timestamp_verification_interface(payload: dict[str, Any]) -> GovernanceValidationResult:
    """Validate timestamp verification result shape at the timestamp boundary.

    Governance scope: ensures timestamp evidence exposes deterministic validity,
    message imprint, and timestamp hash fields. Cryptographic TSA validation is
    performed by the timestamp proof verifier.
    Fail-closed expectation: missing verification metadata denies acceptance.
    Sensitive-data handling: timestamp evidence contains hashes only.
    """

    failures: list[str] = []
    if not isinstance(payload, dict):
        return GovernanceValidationResult(False, ("GOVERNANCE_TIMESTAMP_VERIFICATION_INVALID",))
    if not isinstance(payload.get("valid"), bool):
        failures.append("GOVERNANCE_TIMESTAMP_VALIDITY_MISSING")
    if not payload.get("message_imprint"):
        failures.append("GOVERNANCE_TIMESTAMP_MESSAGE_IMPRINT_MISSING")
    if not payload.get("timestamp_hash"):
        failures.append("GOVERNANCE_TIMESTAMP_HASH_MISSING")
    if "failures" in payload and not isinstance(payload.get("failures"), list):
        failures.append("GOVERNANCE_TIMESTAMP_FAILURES_INVALID")
    return GovernanceValidationResult(not failures, tuple(sorted(set(failures))))


def timestamp_verification_from_payload(payload: dict[str, Any]) -> TimestampVerificationResult:
    result = validate_timestamp_verification_interface(payload)
    if not result.valid:
        raise ValueError(",".join(result.failures))
    return TimestampVerificationResult(
        valid=bool(payload["valid"]),
        message_imprint=str(payload["message_imprint"]),
        timestamp_hash=str(payload["timestamp_hash"]),
        failures=tuple(str(failure) for failure in payload.get("failures", [])),
    )

