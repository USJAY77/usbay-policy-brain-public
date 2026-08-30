"""Local Suricata EVE JSON evidence adapter.

The adapter never calls Suricata or the network. It accepts caller-provided
EVE JSON, redacts sensitive network fields, and emits hash-only evidence.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

from publication.models import hash_payload


POLICY_VERSION = "USBAY-SURICATA-001"
REDACTION_MARKER = "REDACTED_HASH_ONLY"

SENSITIVE_KEYS = {
    "src_ip",
    "dest_ip",
    "hostname",
    "rrname",
    "url",
    "payload",
    "payload_printable",
    "packet",
    "packet_info",
    "username",
    "user_agent",
}
SENSITIVE_PATHS = {
    ("dns", "rrname"),
    ("http", "hostname"),
    ("http", "url"),
    ("http", "http_user_agent"),
}


@dataclass(frozen=True)
class SuricataEvidenceResult:
    accepted: bool
    blocked: bool
    severity: int | None
    threshold: int
    redacted_event: dict[str, Any]
    evidence_hash: str
    policy_version: str
    reason: str


def evaluate_suricata_eve_json(
    events: dict[str, Any] | list[Any] | str,
    *,
    threshold: int | None,
    policy_version: str = POLICY_VERSION,
    require_alert: bool = True,
) -> SuricataEvidenceResult:
    if threshold is None or not isinstance(threshold, int):
        return _blocked("SURICATA_THRESHOLD_MISSING", None, -1, {}, policy_version)

    try:
        parsed = _parse_events(events)
    except (TypeError, json.JSONDecodeError, ValueError):
        return _blocked("SURICATA_EVE_JSON_MALFORMED", None, threshold, {}, policy_version)

    if not parsed:
        return _blocked("SURICATA_EVE_JSON_MISSING", None, threshold, {}, policy_version)

    redacted_events: list[dict[str, Any]] = []
    severities: list[int] = []
    for event in parsed:
        if not isinstance(event, dict):
            return _blocked("SURICATA_EVENT_UNSUPPORTED_SCHEMA", None, threshold, {}, policy_version)
        if event.get("event_type") != "alert":
            if require_alert:
                return _blocked("SURICATA_NON_ALERT_EVENT", None, threshold, {}, policy_version)
            continue
        alert = event.get("alert")
        if not isinstance(alert, dict):
            return _blocked("SURICATA_ALERT_MISSING", None, threshold, {}, policy_version)
        severity = alert.get("severity")
        if not isinstance(severity, int):
            return _blocked("SURICATA_ALERT_SEVERITY_INVALID", None, threshold, {}, policy_version)
        severities.append(severity)
        redacted_event = _redact_event(event)
        if _contains_unredacted_sensitive_value(redacted_event):
            return _blocked("SURICATA_REDACTION_FAILED", severity, threshold, {}, policy_version)
        redacted_events.append(redacted_event)

    if not severities:
        return _blocked("SURICATA_ALERT_MISSING", None, threshold, {}, policy_version)

    highest_risk_severity = min(severities)
    payload = _evidence_payload(
        accepted=True,
        blocked=highest_risk_severity <= threshold,
        severity=highest_risk_severity,
        threshold=threshold,
        redacted_event={"events": redacted_events},
        policy_version=policy_version,
        reason="SURICATA_SEVERITY_THRESHOLD_BLOCKED" if highest_risk_severity <= threshold else "SURICATA_EVIDENCE_ACCEPTED",
    )
    return SuricataEvidenceResult(
        accepted=True,
        blocked=highest_risk_severity <= threshold,
        severity=highest_risk_severity,
        threshold=threshold,
        redacted_event=payload["redacted_event"],
        evidence_hash=hash_payload(payload),
        policy_version=policy_version,
        reason=str(payload["reason"]),
    )


def _parse_events(events: dict[str, Any] | list[Any] | str) -> list[Any]:
    if isinstance(events, str):
        text = events.strip()
        if not text:
            raise ValueError("empty Suricata EVE JSON")
        try:
            decoded = json.loads(text)
        except json.JSONDecodeError:
            if "\n" not in text:
                raise
            return [json.loads(line) for line in text.splitlines() if line.strip()]
    else:
        decoded = events
    if isinstance(decoded, dict):
        return [decoded]
    if isinstance(decoded, list):
        return decoded
    raise TypeError("Suricata EVE JSON must be object or array")


def _redact_event(value: Any, path: tuple[str, ...] = ()) -> Any:
    if isinstance(value, dict):
        redacted: dict[str, Any] = {}
        for key, child in sorted(value.items()):
            key_text = str(key)
            child_path = (*path, key_text)
            if key_text in SENSITIVE_KEYS or child_path[-2:] in SENSITIVE_PATHS:
                redacted[key_text] = _redacted_value(child)
            else:
                redacted[key_text] = _redact_event(child, child_path)
        return redacted
    if isinstance(value, list):
        return [_redact_event(item, path) for item in value]
    return value


def _redacted_value(value: Any) -> dict[str, str | bool]:
    return {
        "redacted": True,
        "redaction": REDACTION_MARKER,
        "value_hash": hash_payload({"redacted_value": value}),
    }


def _contains_unredacted_sensitive_value(redacted_event: dict[str, Any]) -> bool:
    rendered = json.dumps(redacted_event, sort_keys=True, default=str).lower()
    forbidden_fragments = (
        "192.0.2.",
        "198.51.100.",
        "203.0.113.",
        "example.com",
        "corp.internal",
        "evil.test",
        "secret",
        "payload-bytes",
        "mozilla/",
        "alice",
    )
    return any(fragment in rendered for fragment in forbidden_fragments)


def _evidence_payload(
    *,
    accepted: bool,
    blocked: bool,
    severity: int | None,
    threshold: int,
    redacted_event: dict[str, Any],
    policy_version: str,
    reason: str,
) -> dict[str, Any]:
    return {
        "accepted": accepted,
        "blocked": blocked,
        "severity": severity,
        "threshold": threshold,
        "redacted_event": redacted_event,
        "policy_version": policy_version,
        "reason": reason,
    }


def _blocked(
    reason: str,
    severity: int | None,
    threshold: int,
    redacted_event: dict[str, Any],
    policy_version: str,
) -> SuricataEvidenceResult:
    payload = _evidence_payload(
        accepted=False,
        blocked=True,
        severity=severity,
        threshold=threshold,
        redacted_event=redacted_event,
        policy_version=policy_version,
        reason=reason,
    )
    return SuricataEvidenceResult(
        accepted=False,
        blocked=True,
        severity=severity,
        threshold=threshold,
        redacted_event=redacted_event,
        evidence_hash=hash_payload(payload),
        policy_version=policy_version,
        reason=reason,
    )
