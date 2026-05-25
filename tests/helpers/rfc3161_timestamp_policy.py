from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
POLICY_PATH = ROOT / "governance" / "rfc3161_timestamp_policy.json"


REQUIRED_EVIDENCE_FIELDS = (
    "timestamp_token",
    "timestamp_utc",
    "hash_algorithm",
    "message_imprint_sha256",
    "signature_state",
    "tsa_authority_id",
    "audit_events",
)


def load_timestamp_policy(path: Path = POLICY_PATH) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def valid_timestamp_evidence(policy: dict[str, Any] | None = None) -> dict[str, Any]:
    resolved_policy = policy or load_timestamp_policy()
    return {
        "audit_events": list(resolved_policy["audit_required_events"]),
        "hash_algorithm": "sha256",
        "message_imprint_sha256": "a" * 64,
        "signature_state": "SIGNED_PLACEHOLDER",
        "timestamp_token": "RFC3161_TIMESTAMP_TOKEN_PLACEHOLDER_NON_PRODUCTION",
        "timestamp_utc": "2026-05-25T00:00:00Z",
        "tsa_authority_id": resolved_policy["placeholder_tsa_authority"]["authority_id"],
    }


def verify_timestamp_evidence(
    evidence: dict[str, Any] | None,
    *,
    policy: dict[str, Any] | None = None,
    observed_at: str = "2026-05-25T00:01:00Z",
) -> dict[str, Any]:
    resolved_policy = policy or load_timestamp_policy()
    if evidence is None:
        return _fail_closed("RFC3161_TIMESTAMP_MISSING")
    if not isinstance(evidence, dict):
        return _fail_closed("RFC3161_TIMESTAMP_MALFORMED")

    missing = [field for field in REQUIRED_EVIDENCE_FIELDS if field not in evidence]
    if missing:
        return _fail_closed("RFC3161_TIMESTAMP_MALFORMED", missing_fields=missing)

    if not evidence.get("timestamp_token"):
        return _fail_closed("RFC3161_TIMESTAMP_MISSING")

    algorithm = evidence.get("hash_algorithm")
    if algorithm not in resolved_policy["allowed_hash_algorithms"]:
        return _fail_closed("RFC3161_TIMESTAMP_UNSUPPORTED_HASH_ALGORITHM", hash_algorithm=algorithm)

    message_imprint = evidence.get("message_imprint_sha256")
    if not isinstance(message_imprint, str) or len(message_imprint) != 64:
        return _fail_closed("RFC3161_TIMESTAMP_MALFORMED")

    if evidence.get("signature_state") != "SIGNED_PLACEHOLDER":
        return _fail_closed("RFC3161_TIMESTAMP_UNSIGNED")

    if evidence.get("tsa_authority_id") != resolved_policy["placeholder_tsa_authority"]["authority_id"]:
        return _fail_closed("RFC3161_TIMESTAMP_UNKNOWN_TSA_AUTHORITY")

    required_events = set(resolved_policy["audit_required_events"])
    audit_events = evidence.get("audit_events")
    if not isinstance(audit_events, list) or not required_events.issubset(set(audit_events)):
        return _fail_closed("RFC3161_TIMESTAMP_AUDIT_EVENTS_MISSING")

    drift = abs((_parse_utc(observed_at) - _parse_utc(str(evidence["timestamp_utc"]))).total_seconds())
    if drift > int(resolved_policy["timestamp_accuracy_seconds"]):
        return _fail_closed("RFC3161_TIMESTAMP_CLOCK_DRIFT_EXCEEDED", drift_seconds=int(drift))

    return {
        "decision": "PASS",
        "fail_closed": False,
        "hash_algorithm": algorithm,
        "non_production_scaffolding": resolved_policy["non_production_scaffolding"],
        "placeholder_tsa_authority": True,
        "production_tsa_authority": False,
        "reason": "RFC3161_TIMESTAMP_EVIDENCE_VALID",
        "timestamp_accuracy_seconds": resolved_policy["timestamp_accuracy_seconds"],
    }


def timestamp_queue_overload_evidence(*, queue_depth: int, queue_capacity: int) -> dict[str, Any]:
    return _fail_closed(
        "RFC3161_TIMESTAMP_QUEUE_OVERLOADED",
        queue_capacity=queue_capacity,
        queue_depth=queue_depth,
    )


def _parse_utc(value: str) -> datetime:
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(timezone.utc)
    except ValueError:
        raise AssertionError(_fail_closed("RFC3161_TIMESTAMP_MALFORMED")) from None


def _fail_closed(reason: str, **details: Any) -> dict[str, Any]:
    evidence: dict[str, Any] = {
        "decision": "FAIL_CLOSED",
        "fail_closed": True,
        "reason": reason,
        "silent_pass": False,
    }
    evidence.update(details)
    return evidence
