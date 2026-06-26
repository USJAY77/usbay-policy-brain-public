from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from typing import Any


RUNTIME_TRUST_VERSION = "pb266-270-runtime-trust-pilot-activation-v1"
DEFAULT_POLICY_HASH = "88d1aaa62bbe011c9f51d7f159a7526a2fe283b94314e8c9b9cce73b199f04d1"
REQUIRED_LEDGER_FIELDS = ("ledger_id", "policy_hash", "approval_id", "actor", "timestamp", "audit_hash")


def canonical_json(data: Any) -> str:
    return json.dumps(data, sort_keys=True, separators=(",", ":"))


def sha256_json(data: Any) -> str:
    return hashlib.sha256(canonical_json(data).encode("utf-8")).hexdigest()


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def parse_utc(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def runtime_ledger_binding_contract_json() -> dict[str, Any]:
    return {
        "contract_version": RUNTIME_TRUST_VERSION,
        "required_fields": list(REQUIRED_LEDGER_FIELDS),
        "binds": ["approvals", "actions", "decisions", "audit_events"],
        "missing_ledger_record_outcome": "FAIL_CLOSED",
        "production_activation_allowed": False,
    }


def validate_runtime_ledger_record(record: dict[str, Any] | None) -> dict[str, Any]:
    if not isinstance(record, dict):
        return {"decision": "FAIL_CLOSED", "gaps": ["MISSING_LEDGER_RECORD"], "contract_version": RUNTIME_TRUST_VERSION}
    gaps: list[str] = []
    for field in REQUIRED_LEDGER_FIELDS:
        if not isinstance(record.get(field), str) or not record.get(field):
            gaps.append(f"MISSING_{field.upper()}")
    if record.get("policy_hash") != DEFAULT_POLICY_HASH:
        gaps.append("UNKNOWN_POLICY_HASH")
    return {
        "decision": "VERIFIED" if not gaps else "FAIL_CLOSED",
        "gaps": sorted(set(gaps)),
        "ledger_hash": sha256_json(record) if not gaps else None,
        "contract_version": RUNTIME_TRUST_VERSION,
    }


@dataclass(frozen=True)
class NonceRecord:
    nonce: str
    action_id: str
    expires_at: str
    state: str = "BLOCKED"

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["contract_version"] = RUNTIME_TRUST_VERSION
        return payload


def approval_nonce_store_contract_json() -> dict[str, Any]:
    return {
        "contract_version": RUNTIME_TRUST_VERSION,
        "nonce_must_be_unique": True,
        "missing_nonce_outcome": "BLOCKED",
        "reused_nonce_outcome": "BLOCKED",
        "expired_nonce_outcome": "BLOCKED",
        "default_action_state": "BLOCKED",
    }


def validate_nonce(nonce: str | None, *, expires_at: str | None, used_nonces: set[str] | None = None, now: str | None = None) -> dict[str, Any]:
    gaps: list[str] = []
    if not nonce:
        gaps.append("MISSING_NONCE")
    elif nonce in (used_nonces or set()):
        gaps.append("NONCE_REUSED")
    try:
        if not expires_at or parse_utc(expires_at) <= parse_utc(now or utc_now()):
            gaps.append("NONCE_EXPIRED")
    except Exception:
        gaps.append("NONCE_EXPIRED")
    return {
        "decision": "VERIFIED" if not gaps else "BLOCKED",
        "action_state": "READY_FOR_REVIEW" if not gaps else "BLOCKED",
        "gaps": sorted(set(gaps)),
        "contract_version": RUNTIME_TRUST_VERSION,
    }


def device_operator_attestation_contract_json() -> dict[str, Any]:
    return {
        "contract_version": RUNTIME_TRUST_VERSION,
        "required_fields": ["device_id", "attestation_id", "operator_id", "approval_id"],
        "unknown_device_outcome": "BLOCKED",
        "unknown_operator_outcome": "BLOCKED",
        "missing_attestation_outcome": "BLOCKED",
        "production_activation_allowed": False,
    }


def validate_device_operator_attestation(
    payload: dict[str, Any],
    *,
    known_devices: set[str],
    known_operators: set[str],
) -> dict[str, Any]:
    gaps: list[str] = []
    if not isinstance(payload, dict):
        gaps.append("MALFORMED_ATTESTATION")
        payload = {}
    for field in ("device_id", "attestation_id", "operator_id", "approval_id"):
        if not isinstance(payload.get(field), str) or not payload.get(field):
            gaps.append(f"MISSING_{field.upper()}")
    if payload.get("device_id") and payload.get("device_id") not in known_devices:
        gaps.append("UNKNOWN_DEVICE")
    if payload.get("operator_id") and payload.get("operator_id") not in known_operators:
        gaps.append("UNKNOWN_OPERATOR")
    return {
        "decision": "VERIFIED" if not gaps else "BLOCKED",
        "gaps": sorted(set(gaps)),
        "production_activation_allowed": False,
        "contract_version": RUNTIME_TRUST_VERSION,
    }


def detect_replay_event(
    *,
    approval_id: str,
    action_id: str,
    nonce: str,
    audit_event_hash: str,
    seen_approvals: set[str],
    seen_actions: set[str],
    seen_nonces: set[str],
    seen_audit_events: set[str],
) -> dict[str, Any]:
    gaps: list[str] = []
    if approval_id in seen_approvals:
        gaps.append("DUPLICATE_APPROVAL")
    if action_id in seen_actions:
        gaps.append("DUPLICATE_ACTION")
    if nonce in seen_nonces:
        gaps.append("DUPLICATE_NONCE")
    if audit_event_hash in seen_audit_events:
        gaps.append("DUPLICATE_AUDIT_CHAIN_EVENT")
    evidence = {
        "approval_id_hash": sha256_json(approval_id),
        "action_id_hash": sha256_json(action_id),
        "nonce_hash": sha256_json(nonce),
        "audit_event_hash": audit_event_hash,
        "gaps": sorted(set(gaps)),
    }
    return {
        "decision": "FAIL_CLOSED" if gaps else "VERIFIED",
        "gaps": sorted(set(gaps)),
        "replay_evidence_hash": sha256_json(evidence),
        "contract_version": RUNTIME_TRUST_VERSION,
    }


def pilot_activation_contract_json() -> dict[str, Any]:
    return {
        "contract_version": RUNTIME_TRUST_VERSION,
        "default_state": "BLOCKED",
        "activation_execution_allowed": False,
        "conditions": {
            "policy_approved": True,
            "human_approval_approved": True,
            "attestation_valid": True,
            "nonce_valid": True,
            "replay_protection_clean": True,
            "runtime_ledger_bound": True,
        },
    }


def evaluate_pilot_activation(
    *,
    policy_approved: bool,
    human_approval_approved: bool,
    attestation_valid: bool,
    nonce_valid: bool,
    replay_protection_clean: bool,
    runtime_ledger_bound: bool,
) -> dict[str, Any]:
    checks = {
        "POLICY_NOT_APPROVED": policy_approved,
        "HUMAN_APPROVAL_NOT_APPROVED": human_approval_approved,
        "ATTESTATION_INVALID": attestation_valid,
        "NONCE_INVALID": nonce_valid,
        "REPLAY_PROTECTION_DIRTY": replay_protection_clean,
        "RUNTIME_LEDGER_NOT_BOUND": runtime_ledger_bound,
    }
    gaps = sorted(reason for reason, ok in checks.items() if not ok)
    return {
        "decision": "READY_FOR_REVIEW" if not gaps else "BLOCKED",
        "state": "READY_FOR_REVIEW" if not gaps else "BLOCKED",
        "gaps": gaps,
        "activation_execution_allowed": False,
        "contract_version": RUNTIME_TRUST_VERSION,
    }
