from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from audit.hash_chain import append_event


AUDIT_WRITER_VERSION = "pb208-audit-writer-contract-v1"
DEFAULT_AUDIT_PATH = Path("tmp/pb208_gateway_audit_chain.json")
SENSITIVE_KEYS = {
    "token",
    "secret",
    "password",
    "authorization",
    "api_key",
    "private_key",
    "raw_diff",
    "raw_payload",
}


class AuditWriteError(RuntimeError):
    pass


def canonical_json(data: Any) -> str:
    return json.dumps(data, sort_keys=True, separators=(",", ":"))


def sha256_json(data: Any) -> str:
    return hashlib.sha256(canonical_json(data).encode("utf-8")).hexdigest()


def redact(value: Any) -> Any:
    if isinstance(value, dict):
        redacted: dict[str, Any] = {}
        for key, item in value.items():
            normalized = str(key).lower()
            if normalized in SENSITIVE_KEYS or any(marker in normalized for marker in SENSITIVE_KEYS):
                continue
            else:
                redacted[key] = redact(item)
        return redacted
    if isinstance(value, list):
        return [redact(item) for item in value]
    return value


def write_audit_record(
    event_type: str,
    payload: dict[str, Any],
    *,
    audit_path: str | Path = DEFAULT_AUDIT_PATH,
) -> dict[str, Any]:
    if not isinstance(event_type, str) or not event_type:
        raise AuditWriteError("AUDIT_EVENT_TYPE_MISSING")
    if not isinstance(payload, dict):
        raise AuditWriteError("AUDIT_PAYLOAD_MALFORMED")
    try:
        safe_payload = redact(payload)
        payload_hash = sha256_json(safe_payload)
        record = {
            "event_type": event_type,
            "decision": str(payload.get("decision", "ALLOW")).upper(),
            "payload": safe_payload,
            "payload_hash": payload_hash,
            "policy_hash": str(payload.get("policy_hash", "UNKNOWN_POLICY_HASH")),
            "tenant_id": str(payload.get("tenant_id", "t1")),
            "audit_writer_version": AUDIT_WRITER_VERSION,
        }
        chain_event = append_event(event_type, record, Path(audit_path))
        return {
            "decision": "PASS",
            "event_type": event_type,
            "payload_hash": payload_hash,
            "audit_hash": chain_event["hash_current"],
            "hash_prev": chain_event["hash_prev"],
            "timestamp": chain_event["timestamp"],
            "audit_writer_version": AUDIT_WRITER_VERSION,
            "record": record,
        }
    except AuditWriteError:
        raise
    except Exception as exc:
        raise AuditWriteError("AUDIT_WRITE_FAILED") from exc
