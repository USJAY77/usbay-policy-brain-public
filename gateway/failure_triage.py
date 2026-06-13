from __future__ import annotations

from enum import Enum
from typing import Any


FAILURE_TRIAGE_VERSION = "pb217-runtime-gateway-failure-triage-v1"


class GatewayFailureClassification(str, Enum):
    MALFORMED_REQUEST = "MALFORMED_REQUEST"
    UNKNOWN_POLICY_HASH = "UNKNOWN_POLICY_HASH"
    EVALUATOR_TIMEOUT = "EVALUATOR_TIMEOUT"
    AUDIT_WRITE_FAILED = "AUDIT_WRITE_FAILED"
    CONNECTOR_DISABLED = "CONNECTOR_DISABLED"
    APPROVAL_REQUIRED = "APPROVAL_REQUIRED"
    SIGNATURE_INVALID = "SIGNATURE_INVALID"


def classify_gateway_failure(gaps: list[str] | tuple[str, ...] | None) -> GatewayFailureClassification:
    normalized = {str(gap).upper() for gap in gaps or []}
    if any("AUDIT_WRITE_FAILED" in gap or "AUDIT" in gap for gap in normalized):
        return GatewayFailureClassification.AUDIT_WRITE_FAILED
    if any("TIMEOUT" in gap for gap in normalized):
        return GatewayFailureClassification.EVALUATOR_TIMEOUT
    if any("SIGNATURE" in gap or "POLICY_NOT_ACTIVE" in gap for gap in normalized):
        return GatewayFailureClassification.SIGNATURE_INVALID
    if any("UNKNOWN_POLICY_HASH" in gap or "POLICY_HASH_MISMATCH" in gap for gap in normalized):
        return GatewayFailureClassification.UNKNOWN_POLICY_HASH
    if any("CONNECTOR_DISABLED" in gap for gap in normalized):
        return GatewayFailureClassification.CONNECTOR_DISABLED
    if any("APPROVAL" in gap or "HUMAN" in gap for gap in normalized):
        return GatewayFailureClassification.APPROVAL_REQUIRED
    return GatewayFailureClassification.MALFORMED_REQUEST


def governed_fail_response(
    gaps: list[str],
    *,
    policy_hash: str | None = None,
    audit: dict[str, Any] | None = None,
    gateway_version: str,
) -> dict[str, Any]:
    classification = classify_gateway_failure(gaps)
    return {
        "decision": "FAIL_CLOSED",
        "status": "FAIL",
        "approved": False,
        "failure_classification": classification.value,
        "gaps": sorted(set(gaps)),
        "policy_hash": policy_hash,
        "gateway_version": gateway_version,
        "failure_triage_version": FAILURE_TRIAGE_VERSION,
        "audit": audit,
        "external_calls_performed": False,
        "production_automation_activated": False,
    }
