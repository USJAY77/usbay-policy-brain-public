"""Local hash-only audit persistence for publication decisions."""

from __future__ import annotations

import re
from typing import Any

from publication.models import (
    AuditPersistenceResult,
    BlockReason,
    PublicationAuditEvent,
    PublicationDecision,
    RegistryRecord,
    hash_payload,
    is_sha256_ref,
)


RAW_SENSITIVE_PATTERNS = (
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    re.compile(r"\b(?:password|passwd|secret|token|api[_-]?key)\s*[:=]", re.IGNORECASE),
    re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.IGNORECASE),
    re.compile(r"\b(?:\d[ -]*?){13,19}\b"),
    re.compile(r"\b(?:customer confidential|raw customer data)\b", re.IGNORECASE),
)


class LocalAuditStore:
    """Append-only in-memory audit event store for local validation."""

    def __init__(self) -> None:
        self._events: tuple[PublicationAuditEvent, ...] = ()

    @property
    def events(self) -> tuple[PublicationAuditEvent, ...]:
        return self._events

    def append(self, event: PublicationAuditEvent) -> AuditPersistenceResult:
        self._events = (*self._events, event)
        return AuditPersistenceResult.persisted_event(event=event)


def create_publication_audit_event(
    *,
    record: RegistryRecord,
    decision: PublicationDecision | str,
    block_reason: BlockReason | str,
    sensitive_scan_hash: str,
    approval_hash: str,
    validator_hash: str,
    extra_payload: dict[str, Any] | None = None,
    store: LocalAuditStore | None = None,
) -> AuditPersistenceResult:
    raw_check = _reject_raw_sensitive_payload(extra_payload or {})
    if raw_check is not None:
        return AuditPersistenceResult.blocked(
            artifact_id=record.artifact_id,
            reason=raw_check,
            policy_version=record.policy_version,
            evidence_hashes={"registry_hash": record.stable_hash()},
        )

    required_hashes = {
        "classification_hash": record.classification_hash,
        "sensitive_scan_hash": sensitive_scan_hash,
        "approval_hash": approval_hash,
        "validator_hash": validator_hash,
    }
    missing = tuple(name for name, value in required_hashes.items() if not is_sha256_ref(value))
    if missing:
        return AuditPersistenceResult.blocked(
            artifact_id=record.artifact_id,
            reason=BlockReason.EVIDENCE_CHAIN_MISSING,
            policy_version=record.policy_version,
            evidence_hashes={"missing_hash_fields_hash": hash_payload(missing)},
        )

    event = PublicationAuditEvent(
        artifact_id=record.artifact_id,
        artifact_version=record.version,
        decision=str(getattr(decision, "value", decision)),
        block_reason=str(getattr(block_reason, "value", block_reason)),
        policy_version=record.policy_version,
        classification_hash=record.classification_hash,
        sensitive_scan_hash=sensitive_scan_hash,
        approval_hash=approval_hash,
        validator_hash=validator_hash,
    )
    if store is not None:
        return store.append(event)
    return AuditPersistenceResult.persisted_event(event=event)


def _reject_raw_sensitive_payload(payload: dict[str, Any]) -> BlockReason | None:
    rendered = repr(payload)
    for pattern in RAW_SENSITIVE_PATTERNS:
        if pattern.search(rendered):
            return BlockReason.RAW_SENSITIVE_DATA_PRESENT
    return None
