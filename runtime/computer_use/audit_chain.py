from __future__ import annotations

import hashlib
import json
import uuid
from dataclasses import asdict, dataclass
from typing import Any, Iterable


GENESIS_PREVIOUS_HASH = "GENESIS"
VALID = "VALID"
CHAIN_BROKEN = "CHAIN_BROKEN"


@dataclass(frozen=True)
class DecisionAuditRecord:
    decision_id: str
    timestamp: str
    decision: str
    reason: str
    risk_level: str
    policy_version: str
    approval_state: str
    previous_hash: str
    current_hash: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class AuditChainOutput:
    audit_chain_id: str
    chain_length: int
    genesis_hash: str
    latest_hash: str
    verification_status: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def decision_hash(
    *,
    previous_hash: str,
    decision_id: str,
    timestamp: str,
    decision: str,
    risk_level: str,
    policy_version: str,
) -> str:
    payload = previous_hash + decision_id + timestamp + decision + risk_level + policy_version
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def append_decision_record(
    records: Iterable[DecisionAuditRecord | dict[str, Any]],
    *,
    decision_id: str,
    timestamp: str,
    decision: str,
    reason: str,
    risk_level: str,
    policy_version: str,
    approval_state: str,
) -> DecisionAuditRecord:
    existing = [_coerce_record(record) for record in records]
    previous_hash = existing[-1].current_hash if existing else GENESIS_PREVIOUS_HASH
    current_hash = decision_hash(
        previous_hash=previous_hash,
        decision_id=decision_id,
        timestamp=timestamp,
        decision=decision,
        risk_level=risk_level,
        policy_version=policy_version,
    )
    return DecisionAuditRecord(
        decision_id=decision_id,
        timestamp=timestamp,
        decision=decision,
        reason=reason,
        risk_level=risk_level,
        policy_version=policy_version,
        approval_state=approval_state,
        previous_hash=previous_hash,
        current_hash=current_hash,
    )


def verify_chain(records: Iterable[DecisionAuditRecord | dict[str, Any]]) -> str:
    coerced = [_coerce_record(record) for record in records]
    if not coerced:
        return CHAIN_BROKEN
    expected_previous = GENESIS_PREVIOUS_HASH
    seen_hashes: set[str] = set()
    for record in coerced:
        if record.previous_hash != expected_previous:
            return CHAIN_BROKEN
        expected_current = decision_hash(
            previous_hash=record.previous_hash,
            decision_id=record.decision_id,
            timestamp=record.timestamp,
            decision=record.decision,
            risk_level=record.risk_level,
            policy_version=record.policy_version,
        )
        if record.current_hash != expected_current:
            return CHAIN_BROKEN
        if record.current_hash in seen_hashes:
            return CHAIN_BROKEN
        seen_hashes.add(record.current_hash)
        expected_previous = record.current_hash
    return VALID


def audit_chain_output(records: Iterable[DecisionAuditRecord | dict[str, Any]]) -> AuditChainOutput:
    coerced = [_coerce_record(record) for record in records]
    status = verify_chain(coerced)
    genesis_hash = coerced[0].current_hash if coerced else ""
    latest_hash = coerced[-1].current_hash if coerced else ""
    audit_chain_id = "cua-chain-" + _hash_json([record.to_dict() for record in coerced])[:16]
    return AuditChainOutput(
        audit_chain_id=audit_chain_id,
        chain_length=len(coerced),
        genesis_hash=genesis_hash,
        latest_hash=latest_hash,
        verification_status=status,
    )


def fail_closed_decision_for_chain(records: Iterable[DecisionAuditRecord | dict[str, Any]]) -> dict[str, str]:
    status = verify_chain(records)
    if status == VALID:
        return {"decision": "ALLOW", "reason": "AUDIT_CHAIN_VALID", "verification_status": status}
    return {"decision": "FAIL_CLOSED", "reason": "AUDIT_CHAIN_BROKEN", "verification_status": status}


def _coerce_record(record: DecisionAuditRecord | dict[str, Any]) -> DecisionAuditRecord:
    if isinstance(record, DecisionAuditRecord):
        return record
    try:
        return DecisionAuditRecord(
            decision_id=str(record["decision_id"]),
            timestamp=str(record["timestamp"]),
            decision=str(record["decision"]),
            reason=str(record["reason"]),
            risk_level=str(record["risk_level"]),
            policy_version=str(record["policy_version"]),
            approval_state=str(record["approval_state"]),
            previous_hash=str(record["previous_hash"]),
            current_hash=str(record["current_hash"]),
        )
    except KeyError as exc:
        raise ValueError("DECISION_AUDIT_RECORD_REQUIRED_FIELD_MISSING") from exc


def _hash_json(payload: Any) -> str:
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256((uuid.NAMESPACE_URL.hex + canonical).encode("utf-8")).hexdigest()
