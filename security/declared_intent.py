"""Bounded declarations, never approval or execution authority.

A signed declaration proves what the authenticated caller supplied, not that
an independent human approved it. Purpose codes match exactly; no inference.
"""
from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Any

from gateway.request_identity import IDENTIFIER_RE, RequestIdentityError, parse_unique_json_object
from governance.hashing import canonical_json, is_sha256_reference, sha256_reference

SCHEMA = "usbay.intent_governance.declared_intent.v1"
MAX_CANONICAL_BYTES = 8192
CODE = re.compile(r"[a-z][a-z0-9_-]{0,63}\Z")
IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}\Z")
UTC_TIME = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z\Z")
FIELDS = frozenset({"schema_version", "declaration_source", "intent_id", "request_id",
                    "correlation_id", "tenant_id", "actor_id", "environment", "purpose",
                    "action_class", "resource_scope", "issued_at", "expires_at", "nonce",
                    "intent_hash"})


class IntentError(RuntimeError):
    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


def parse_object(raw: Any) -> dict:
    try:
        value = parse_unique_json_object(raw, reason_code="INTENT_MALFORMED")
        # Deep snapshot, not a shallow alias to a caller-mutable resource list.
        encoded = canonical_json(value)
        if len(encoded.encode("utf-8")) > MAX_CANONICAL_BYTES:
            raise IntentError("INTENT_SIZE_EXCEEDED")
        return parse_unique_json_object(encoded, reason_code="INTENT_MALFORMED")
    except (RequestIdentityError, ValueError, TypeError, UnicodeError, RecursionError) as exc:
        raise IntentError("INTENT_MALFORMED") from exc


def intent_hash(intent: dict) -> str:
    """Hash only; this function grants no authenticity or authority."""
    value = parse_object(intent)
    if set(value) != FIELDS:
        raise IntentError("INTENT_FIELDS_INVALID")
    return sha256_reference({key: item for key, item in value.items() if key != "intent_hash"})


def utc_time(value: Any) -> datetime:
    if not isinstance(value, str) or not UTC_TIME.fullmatch(value):
        raise IntentError("INTENT_TIME_INVALID")
    try:
        return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except ValueError as exc:
        raise IntentError("INTENT_TIME_INVALID") from exc


def parse_identity_time(value: Any) -> datetime:
    """Parse an authenticated identity timestamp using its established contract."""
    if not isinstance(value, str) or "T" not in value:
        raise IntentError("INTENT_TIME_INVALID")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise IntentError("INTENT_TIME_INVALID") from exc
    if parsed.tzinfo is None:
        raise IntentError("INTENT_TIME_INVALID")
    return parsed.astimezone(timezone.utc)


def validate_declaration(raw: Any, *, now: datetime) -> dict:
    value = parse_object(raw)
    if set(value) != FIELDS:
        raise IntentError("INTENT_FIELDS_INVALID")
    if value["schema_version"] != SCHEMA or value["declaration_source"] != "human_declared":
        raise IntentError("INTENT_DECLARATION_REQUIRED")
    for key in ("intent_id", "nonce"):
        if not isinstance(value[key], str) or not IDENTIFIER.fullmatch(value[key]):
            raise IntentError("INTENT_IDENTIFIER_INVALID")
    for key in ("tenant_id", "actor_id", "request_id", "correlation_id", "environment"):
        if not isinstance(value[key], str) or not IDENTIFIER_RE.fullmatch(value[key]):
            raise IntentError("INTENT_SCOPE_INVALID")
    for key in ("purpose", "action_class"):
        if not isinstance(value[key], str) or not CODE.fullmatch(value[key]):
            raise IntentError("INTENT_SCOPE_INVALID")
    resources = value["resource_scope"]
    if (not isinstance(resources, list) or not 1 <= len(resources) <= 32
            or not all(is_sha256_reference(r) for r in resources)
            or resources != sorted(set(resources))):
        raise IntentError("INTENT_RESOURCE_SCOPE_INVALID")
    if not is_sha256_reference(value["intent_hash"]) or value["intent_hash"] != intent_hash(value):
        raise IntentError("INTENT_HASH_MISMATCH")
    if not isinstance(now, datetime) or now.tzinfo is None or now.utcoffset() is None:
        raise IntentError("INTENT_TIME_INVALID")
    issued, expires = utc_time(value["issued_at"]), utc_time(value["expires_at"])
    if issued > now or expires <= now or expires <= issued:
        raise IntentError("INTENT_NOT_CURRENT")
    return value


def validate_operation(operation: Any, intent: dict) -> None:
    operation = parse_object(operation)
    if set(operation) != {"purpose", "action_class", "resource_reference"}:
        raise IntentError("INTENT_OPERATION_INVALID")
    if (operation["purpose"] != intent["purpose"]
            or operation["action_class"] != intent["action_class"]
            or not is_sha256_reference(operation["resource_reference"])
            or operation["resource_reference"] not in intent["resource_scope"]):
        raise IntentError("INTENT_SCOPE_MISMATCH")
