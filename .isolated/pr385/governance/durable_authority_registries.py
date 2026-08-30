from __future__ import annotations

import json
import threading
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping

from governance.hashing import is_sha256_reference, sha256_reference


REGISTRY_SCHEMA_VERSION = "usbay.durable_authority_registry.v1"
EVIDENCE_SCHEMA_VERSION = "usbay.durable_authority_registry.evidence.v1"

VALID = "VALID"
MISSING = "MISSING"
REVOKED = "REVOKED"
EXPIRED = "EXPIRED"
MISMATCH = "MISMATCH"
MALFORMED = "MALFORMED"
UNKNOWN = "UNKNOWN"

CREATE = "CREATE"
UPDATE = "UPDATE"
REVOKE = "REVOKE"

HUMAN_APPROVAL = "human_approval"
ACTIVATION = "activation"
CHALLENGE = "challenge"
IDENTITY = "identity"
VERIFIER = "verifier"
ATTESTATION = "attestation"

AUTHORITY_DOMAINS = frozenset(
    {
        HUMAN_APPROVAL,
        ACTIVATION,
        CHALLENGE,
        IDENTITY,
        VERIFIER,
        ATTESTATION,
    }
)

ACTIVE_STATUSES = frozenset(
    {
        "ACTIVE",
        "APPROVED",
        "ISSUED",
        "ENROLLED",
        "VALID",
        "ACTIVATED",
        "PASS",
    }
)
BLOCKED_STATUSES = frozenset({"BLOCKED", "DENIED", "FAILED", "UNKNOWN", "PENDING"})
GENESIS_HASH = "sha256:" + ("0" * 64)
POLICY_BOUND_DOMAINS = frozenset({HUMAN_APPROVAL, ACTIVATION})

FORBIDDEN_FIELD_NAMES = frozenset(
    {
        "password",
        "secret",
        "credential",
        "credentials",
        "api_key",
        "private_key",
        "access_token",
        "refresh_token",
        "token",
        "cookie",
        "raw_payload",
        "raw_customer_data",
        "prompt",
        "personal_data",
    }
)


class AuthorityRegistryError(RuntimeError):
    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


@dataclass(frozen=True)
class AuthorityResolution:
    status: str
    reason_code: str
    domain: str
    authority_reference: str
    tenant_reference: str = ""
    environment_reference: str = ""
    record_hash: str = ""
    event_hash: str = ""
    evidence_reference: str = ""
    execution_authorized: bool = False
    runtime_allow: bool = False
    policy_brain_execution_authority: bool = False
    euria_execution_authority: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "reason_code": self.reason_code,
            "domain": self.domain,
            "authority_reference": self.authority_reference,
            "tenant_reference": self.tenant_reference,
            "environment_reference": self.environment_reference,
            "record_hash": self.record_hash,
            "event_hash": self.event_hash,
            "evidence_reference": self.evidence_reference,
            "execution_authorized": False,
            "runtime_allow": False,
            "policy_brain_execution_authority": False,
            "euria_execution_authority": False,
        }


class DurableAuthorityRegistry:
    """Append-only durable authority registry for Gateway request-time lookup."""

    _locks: dict[str, threading.RLock] = {}
    _locks_guard = threading.Lock()

    def __init__(self, registry_path: str | Path, *, evidence_path: str | Path | None = None) -> None:
        self.registry_path = Path(registry_path)
        self.evidence_path = Path(evidence_path) if evidence_path is not None else self.registry_path.with_suffix(".evidence.jsonl")
        key = str(self.registry_path.resolve())
        with self._locks_guard:
            self._lock = self._locks.setdefault(key, threading.RLock())

    def create_authority(self, domain: str, record: Mapping[str, Any], *, timestamp: str | None = None) -> dict[str, Any]:
        return self._append_authority_event(CREATE, domain, record, timestamp=timestamp)

    def update_authority(self, domain: str, record: Mapping[str, Any], *, timestamp: str | None = None, expected_latest_hash: str | None = None) -> dict[str, Any]:
        return self._append_authority_event(UPDATE, domain, record, timestamp=timestamp, expected_latest_hash=expected_latest_hash)

    def revoke_authority(
        self,
        domain: str,
        authority_reference: str,
        *,
        tenant_reference: str,
        environment_reference: str,
        reason_code: str,
        timestamp: str | None = None,
    ) -> dict[str, Any]:
        latest = self._latest(domain, authority_reference)
        if latest is None:
            raise AuthorityRegistryError("AUTHORITY_RECORD_MISSING")
        record = dict(latest["record"])
        if record.get("tenant_reference") != tenant_reference or record.get("environment_reference") != environment_reference:
            raise AuthorityRegistryError("AUTHORITY_SCOPE_MISMATCH")
        record.update(
            {
                "current_status": REVOKED,
                "revoked": True,
                "revoked_at": timestamp or _utc_now(),
                "revocation_reason_code": str(reason_code or "AUTHORITY_REVOKED"),
            }
        )
        return self._append_authority_event(REVOKE, domain, record, timestamp=timestamp)

    def resolve_human_approval(self, authority_reference: str, **criteria: Any) -> dict[str, Any]:
        return self.resolve_authority(HUMAN_APPROVAL, authority_reference, **criteria).to_dict()

    def resolve_activation(self, authority_reference: str, **criteria: Any) -> dict[str, Any]:
        return self.resolve_authority(ACTIVATION, authority_reference, **criteria).to_dict()

    def resolve_challenge(self, authority_reference: str, **criteria: Any) -> dict[str, Any]:
        return self.resolve_authority(CHALLENGE, authority_reference, **criteria).to_dict()

    def resolve_identity(self, authority_reference: str, **criteria: Any) -> dict[str, Any]:
        return self.resolve_authority(IDENTITY, authority_reference, **criteria).to_dict()

    def resolve_verifier(self, authority_reference: str, **criteria: Any) -> dict[str, Any]:
        return self.resolve_authority(VERIFIER, authority_reference, **criteria).to_dict()

    def resolve_attestation(self, authority_reference: str, **criteria: Any) -> dict[str, Any]:
        return self.resolve_authority(ATTESTATION, authority_reference, **criteria).to_dict()

    def resolve_authority(
        self,
        domain: str,
        authority_reference: str,
        *,
        tenant_reference: str,
        environment_reference: str,
        policy_reference: str | None = None,
        policy_hash: str | None = None,
        subject_reference: str | None = None,
        verifier_reference: str | None = None,
        now: datetime | str | None = None,
    ) -> AuthorityResolution:
        if domain not in AUTHORITY_DOMAINS or not is_sha256_reference(authority_reference):
            return _resolution(MALFORMED, "AUTHORITY_LOOKUP_MALFORMED", domain, authority_reference)
        if not is_sha256_reference(tenant_reference) or not is_sha256_reference(environment_reference):
            return _resolution(MALFORMED, "AUTHORITY_SCOPE_MALFORMED", domain, authority_reference)
        try:
            latest = self._latest(domain, authority_reference)
        except AuthorityRegistryError as exc:
            return _resolution(UNKNOWN, exc.code, domain, authority_reference)
        if latest is None:
            return _resolution(MISSING, "AUTHORITY_RECORD_MISSING", domain, authority_reference)

        record = latest["record"]
        malformed_reason = _record_malformed_reason(record)
        if malformed_reason:
            return _resolution(MALFORMED, malformed_reason, domain, authority_reference, record=record, event=latest)
        if record.get("tenant_reference") != tenant_reference:
            return _resolution(MISMATCH, "AUTHORITY_TENANT_MISMATCH", domain, authority_reference, record=record, event=latest)
        if record.get("environment_reference") != environment_reference:
            return _resolution(MISMATCH, "AUTHORITY_ENVIRONMENT_MISMATCH", domain, authority_reference, record=record, event=latest)
        if domain in POLICY_BOUND_DOMAINS:
            if record.get("policy_reference") != policy_reference or record.get("policy_hash") != policy_hash:
                return _resolution(MISMATCH, "AUTHORITY_POLICY_BINDING_MISMATCH", domain, authority_reference, record=record, event=latest)
        elif policy_reference is not None and record.get("policy_reference") not in (None, "", policy_reference):
            return _resolution(MISMATCH, "AUTHORITY_POLICY_REFERENCE_MISMATCH", domain, authority_reference, record=record, event=latest)
        if subject_reference is not None and record.get("subject_reference") not in (None, "", subject_reference):
            return _resolution(MISMATCH, "AUTHORITY_SUBJECT_MISMATCH", domain, authority_reference, record=record, event=latest)
        if verifier_reference is not None and record.get("verifier_reference") not in (None, "", verifier_reference):
            return _resolution(MISMATCH, "AUTHORITY_VERIFIER_MISMATCH", domain, authority_reference, record=record, event=latest)
        if record.get("revoked") is True or latest["event_type"] == REVOKE or str(record.get("current_status", "")).upper() == REVOKED:
            return _resolution(REVOKED, "AUTHORITY_REVOKED", domain, authority_reference, record=record, event=latest)

        comparison_time = _coerce_time(now)
        if comparison_time is None:
            return _resolution(MALFORMED, "AUTHORITY_LOOKUP_TIMESTAMP_INVALID", domain, authority_reference, record=record, event=latest)
        time_reason = _time_validity_reason(record, comparison_time)
        if time_reason:
            status = EXPIRED if time_reason == "AUTHORITY_EXPIRED" else MALFORMED
            return _resolution(status, time_reason, domain, authority_reference, record=record, event=latest)
        status = str(record.get("current_status", "")).upper()
        if status in BLOCKED_STATUSES or status not in ACTIVE_STATUSES:
            return _resolution(UNKNOWN, "AUTHORITY_STATUS_UNKNOWN", domain, authority_reference, record=record, event=latest)
        if record.get("ai_generated_only") is True or record.get("source_system") == "EURIA":
            return _resolution(MISMATCH, "AUTHORITY_SOURCE_NOT_HUMAN_CONTROLLED", domain, authority_reference, record=record, event=latest)
        if record.get("evidence_write_status") == "FAILED":
            return _resolution(UNKNOWN, "AUTHORITY_EVIDENCE_WRITE_FAILED", domain, authority_reference, record=record, event=latest)
        return _resolution(VALID, "AUTHORITY_VALID", domain, authority_reference, record=record, event=latest)

    def _append_authority_event(
        self,
        event_type: str,
        domain: str,
        record: Mapping[str, Any],
        *,
        timestamp: str | None,
        expected_latest_hash: str | None = None,
    ) -> dict[str, Any]:
        if event_type not in {CREATE, UPDATE, REVOKE}:
            raise AuthorityRegistryError("AUTHORITY_EVENT_TYPE_INVALID")
        normalized_record = _normalize_record(domain, record, event_type)
        event_time = timestamp or _utc_now()
        _assert_safe_payload(normalized_record)
        with self._lock:
            events = self._read_events()
            previous_hash = events[-1]["event_hash"] if events else GENESIS_HASH
            latest = _latest_from_events(events, domain, normalized_record["authority_reference"])
            if expected_latest_hash is not None and (latest is None or latest.get("event_hash") != expected_latest_hash):
                raise AuthorityRegistryError("STALE_AUTHORITY_WRITER")
            if event_type == CREATE and latest is not None and latest["event_type"] != REVOKE and latest["record"].get("revoked") is not True:
                raise AuthorityRegistryError("DUPLICATE_AUTHORITY_RECORD")
            if event_type in {UPDATE, REVOKE} and latest is None:
                raise AuthorityRegistryError("AUTHORITY_RECORD_MISSING")
            if latest is not None and (latest["event_type"] == REVOKE or latest["record"].get("revoked") is True) and event_type != REVOKE:
                raise AuthorityRegistryError("REVOKED_AUTHORITY_FINAL")
            evidence = self._write_evidence(event_type, normalized_record, previous_hash, event_time)
            event = {
                "schema_version": REGISTRY_SCHEMA_VERSION,
                "event_type": event_type,
                "domain": domain,
                "authority_reference": normalized_record["authority_reference"],
                "timestamp": event_time,
                "previous_event_hash": previous_hash,
                "record": normalized_record,
                "evidence_hash": evidence["evidence_hash"],
                "event_hash": "",
            }
            event["event_hash"] = sha256_reference({key: value for key, value in event.items() if key != "event_hash"})
            self.registry_path.parent.mkdir(parents=True, exist_ok=True)
            with self.registry_path.open("a", encoding="utf-8") as handle:
                handle.write(json.dumps(event, sort_keys=True, separators=(",", ":")) + "\n")
            return dict(event)

    def _write_evidence(self, event_type: str, record: Mapping[str, Any], previous_hash: str, timestamp: str) -> dict[str, Any]:
        evidence = {
            "schema_version": EVIDENCE_SCHEMA_VERSION,
            "event_type": event_type,
            "domain": record["domain"],
            "authority_reference": record["authority_reference"],
            "tenant_reference": record["tenant_reference"],
            "environment_reference": record["environment_reference"],
            "policy_reference": record.get("policy_reference", ""),
            "policy_hash": record.get("policy_hash", ""),
            "subject_reference": record.get("subject_reference", ""),
            "verifier_reference": record.get("verifier_reference", ""),
            "provenance_evidence_reference": record.get("provenance_evidence_reference", ""),
            "previous_event_hash": previous_hash,
            "timestamp": timestamp,
            "execution_authorized": False,
            "runtime_allow": False,
            "evidence_hash": "",
        }
        evidence["evidence_hash"] = sha256_reference({key: value for key, value in evidence.items() if key != "evidence_hash"})
        _assert_safe_payload(evidence)
        self.evidence_path.parent.mkdir(parents=True, exist_ok=True)
        with self.evidence_path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(evidence, sort_keys=True, separators=(",", ":")) + "\n")
        return evidence

    def _read_events(self) -> list[dict[str, Any]]:
        with self._lock:
            return _read_events(self.registry_path)

    def _latest(self, domain: str, authority_reference: str) -> dict[str, Any] | None:
        return _latest_from_events(self._read_events(), domain, authority_reference)


def resolve_human_approval(registry_path: str | Path, authority_reference: str, **criteria: Any) -> dict[str, Any]:
    return DurableAuthorityRegistry(registry_path).resolve_human_approval(authority_reference, **criteria)


def resolve_activation(registry_path: str | Path, authority_reference: str, **criteria: Any) -> dict[str, Any]:
    return DurableAuthorityRegistry(registry_path).resolve_activation(authority_reference, **criteria)


def resolve_challenge(registry_path: str | Path, authority_reference: str, **criteria: Any) -> dict[str, Any]:
    return DurableAuthorityRegistry(registry_path).resolve_challenge(authority_reference, **criteria)


def resolve_identity(registry_path: str | Path, authority_reference: str, **criteria: Any) -> dict[str, Any]:
    return DurableAuthorityRegistry(registry_path).resolve_identity(authority_reference, **criteria)


def resolve_verifier(registry_path: str | Path, authority_reference: str, **criteria: Any) -> dict[str, Any]:
    return DurableAuthorityRegistry(registry_path).resolve_verifier(authority_reference, **criteria)


def resolve_attestation(registry_path: str | Path, authority_reference: str, **criteria: Any) -> dict[str, Any]:
    return DurableAuthorityRegistry(registry_path).resolve_attestation(authority_reference, **criteria)


def _normalize_record(domain: str, record: Mapping[str, Any], event_type: str) -> dict[str, Any]:
    if domain not in AUTHORITY_DOMAINS or not isinstance(record, Mapping):
        raise AuthorityRegistryError("AUTHORITY_RECORD_MALFORMED")
    normalized = dict(record)
    normalized["schema_version"] = str(normalized.get("schema_version") or REGISTRY_SCHEMA_VERSION)
    normalized["domain"] = domain
    normalized["event_version"] = str(normalized.get("event_version") or "v1")
    normalized["revoked"] = bool(normalized.get("revoked", False) or event_type == REVOKE)
    if event_type == REVOKE:
        normalized["current_status"] = REVOKED
    normalized["record_hash"] = sha256_reference({key: value for key, value in normalized.items() if key != "record_hash"})
    reason = _record_malformed_reason(normalized)
    if reason:
        raise AuthorityRegistryError(reason)
    return normalized


def _record_malformed_reason(record: Mapping[str, Any]) -> str:
    required = (
        "schema_version",
        "domain",
        "authority_reference",
        "tenant_reference",
        "environment_reference",
        "issued_at",
        "current_status",
        "provenance_evidence_reference",
        "record_hash",
    )
    if any(record.get(field) in (None, "") for field in required):
        return "AUTHORITY_RECORD_REQUIRED_FIELD_MISSING"
    if record.get("schema_version") != REGISTRY_SCHEMA_VERSION:
        return "AUTHORITY_RECORD_SCHEMA_INVALID"
    if record.get("domain") not in AUTHORITY_DOMAINS:
        return "AUTHORITY_DOMAIN_INVALID"
    for field in ("authority_reference", "tenant_reference", "environment_reference", "provenance_evidence_reference"):
        if not is_sha256_reference(record.get(field)):
            return f"{field.upper()}_INVALID"
    for field in ("policy_reference", "policy_hash", "subject_reference", "verifier_reference"):
        value = record.get(field)
        if value not in (None, "") and not is_sha256_reference(value):
            return f"{field.upper()}_INVALID"
    if record.get("record_hash") != sha256_reference({key: value for key, value in record.items() if key != "record_hash"}):
        return "AUTHORITY_RECORD_HASH_MISMATCH"
    return ""


def _time_validity_reason(record: Mapping[str, Any], now: datetime) -> str:
    issued_at = _parse_time(record.get("issued_at"))
    if issued_at is None:
        return "AUTHORITY_ISSUED_AT_INVALID"
    if issued_at > now:
        return "AUTHORITY_NOT_YET_VALID"
    effective_raw = record.get("effective_at")
    if effective_raw not in (None, ""):
        effective_at = _parse_time(effective_raw)
        if effective_at is None:
            return "AUTHORITY_EFFECTIVE_AT_INVALID"
        if effective_at > now:
            return "AUTHORITY_NOT_YET_VALID"
    expires_raw = record.get("expires_at")
    if expires_raw not in (None, ""):
        expires_at = _parse_time(expires_raw)
        if expires_at is None:
            return "AUTHORITY_EXPIRES_AT_INVALID"
        if expires_at <= now:
            return "AUTHORITY_EXPIRED"
        if expires_at <= issued_at:
            return "AUTHORITY_TIMESTAMP_ORDER_INVALID"
    revoked_at = record.get("revoked_at")
    if revoked_at not in (None, "") and _parse_time(revoked_at) is None:
        return "AUTHORITY_REVOKED_AT_INVALID"
    return ""


def _read_events(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    events: list[dict[str, Any]] = []
    previous_hash = GENESIS_HASH
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        try:
            event = json.loads(line)
        except Exception as exc:
            raise AuthorityRegistryError("AUTHORITY_REGISTRY_CORRUPT") from exc
        if not isinstance(event, dict) or event.get("schema_version") != REGISTRY_SCHEMA_VERSION:
            raise AuthorityRegistryError("AUTHORITY_REGISTRY_CORRUPT")
        if event.get("previous_event_hash") != previous_hash:
            raise AuthorityRegistryError("AUTHORITY_REGISTRY_CHAIN_BROKEN")
        expected = sha256_reference({key: value for key, value in event.items() if key != "event_hash"})
        if event.get("event_hash") != expected:
            raise AuthorityRegistryError("AUTHORITY_REGISTRY_HASH_MISMATCH")
        previous_hash = str(event["event_hash"])
        events.append(event)
    return events


def _latest_from_events(events: list[dict[str, Any]], domain: str, authority_reference: str) -> dict[str, Any] | None:
    latest: dict[str, Any] | None = None
    for event in events:
        if event.get("domain") == domain and event.get("authority_reference") == authority_reference:
            latest = event
    return latest


def _resolution(status: str, reason_code: str, domain: str, authority_reference: str, *, record: Mapping[str, Any] | None = None, event: Mapping[str, Any] | None = None) -> AuthorityResolution:
    return AuthorityResolution(
        status=status,
        reason_code=reason_code,
        domain=domain,
        authority_reference=authority_reference,
        tenant_reference=str(record.get("tenant_reference", "")) if isinstance(record, Mapping) else "",
        environment_reference=str(record.get("environment_reference", "")) if isinstance(record, Mapping) else "",
        record_hash=str(record.get("record_hash", "")) if isinstance(record, Mapping) else "",
        event_hash=str(event.get("event_hash", "")) if isinstance(event, Mapping) else "",
        evidence_reference=str(event.get("evidence_hash", "")) if isinstance(event, Mapping) else "",
    )


def _assert_safe_payload(value: Any) -> None:
    if isinstance(value, Mapping):
        for key, item in value.items():
            if str(key).lower() in FORBIDDEN_FIELD_NAMES:
                raise AuthorityRegistryError("AUTHORITY_PAYLOAD_SENSITIVE_DATA_FORBIDDEN")
            _assert_safe_payload(item)
    elif isinstance(value, (list, tuple, set)):
        for item in value:
            _assert_safe_payload(item)


def _coerce_time(value: datetime | str | None) -> datetime | None:
    if value is None:
        return datetime.now(timezone.utc)
    if isinstance(value, datetime):
        if value.tzinfo is None:
            return None
        return value.astimezone(timezone.utc)
    return _parse_time(value)


def _parse_time(value: Any) -> datetime | None:
    if not isinstance(value, str) or "T" not in value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return None
    return parsed.astimezone(timezone.utc)


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


__all__ = [
    "ACTIVATION",
    "ATTESTATION",
    "CHALLENGE",
    "EXPIRED",
    "HUMAN_APPROVAL",
    "IDENTITY",
    "MALFORMED",
    "MISSING",
    "MISMATCH",
    "REGISTRY_SCHEMA_VERSION",
    "REVOKED",
    "UNKNOWN",
    "VALID",
    "VERIFIER",
    "AuthorityRegistryError",
    "AuthorityResolution",
    "DurableAuthorityRegistry",
    "resolve_activation",
    "resolve_attestation",
    "resolve_challenge",
    "resolve_human_approval",
    "resolve_identity",
    "resolve_verifier",
]
