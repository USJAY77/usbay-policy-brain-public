from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Any


VALIDATION_EVIDENCE_RECORDER_VERSION = "pb338-validation-evidence-recorder-v1"
REQUIRED_FIELDS = (
    "command",
    "result",
    "duration_seconds",
    "timestamp",
    "actor",
    "branch",
    "commit",
    "changed_files",
    "validation_output_summary",
)
SENSITIVE_MARKERS = ("secret", "token", "private key", "authorization:", "bearer ")


def _canonical_json(payload: Any) -> str:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)


def _hash_payload(payload: Any) -> str:
    return hashlib.sha256(_canonical_json(payload).encode("utf-8")).hexdigest()


def redact_validation_summary(summary: str) -> str:
    redacted = summary
    lowered = redacted.lower()
    if any(marker in lowered for marker in SENSITIVE_MARKERS):
        return "REDACTED_SENSITIVE_VALIDATION_SUMMARY"
    return redacted


@dataclass(frozen=True)
class ValidationEvidenceRecord:
    command: str
    result: str
    duration_seconds: float
    timestamp: str
    actor: str
    branch: str
    commit: str
    changed_files: tuple[str, ...]
    validation_output_summary: str
    policy_version: str = VALIDATION_EVIDENCE_RECORDER_VERSION

    def to_dict(self) -> dict[str, Any]:
        payload = {
            "policy_version": self.policy_version,
            "command": self.command,
            "result": self.result,
            "duration_seconds": self.duration_seconds,
            "timestamp": self.timestamp,
            "actor": self.actor,
            "branch": self.branch,
            "commit": self.commit,
            "changed_files": list(self.changed_files),
            "validation_output_summary": redact_validation_summary(self.validation_output_summary),
        }
        payload["record_hash"] = _hash_payload(payload)
        return payload


def validate_evidence_record(record: dict[str, Any] | None) -> dict[str, Any]:
    gaps: list[str] = []
    if not isinstance(record, dict):
        return {
            "policy_version": VALIDATION_EVIDENCE_RECORDER_VERSION,
            "decision": "FAIL_CLOSED",
            "gaps": ["VALIDATION_EVIDENCE_RECORD_MISSING"],
        }

    for field in REQUIRED_FIELDS:
        if record.get(field) in ("", None, [], ()):
            gaps.append(f"VALIDATION_EVIDENCE_{field.upper()}_MISSING")

    if record.get("policy_version") != VALIDATION_EVIDENCE_RECORDER_VERSION:
        gaps.append("VALIDATION_EVIDENCE_POLICY_VERSION_MISMATCH")

    summary = str(record.get("validation_output_summary", ""))
    if redact_validation_summary(summary) != summary:
        gaps.append("VALIDATION_EVIDENCE_SUMMARY_CONTAINS_SENSITIVE_MARKER")

    return {
        "policy_version": VALIDATION_EVIDENCE_RECORDER_VERSION,
        "decision": "FAIL_CLOSED" if gaps else "RECORDED",
        "gaps": sorted(set(gaps)),
    }


def validation_evidence_contract() -> dict[str, Any]:
    return {
        "policy_version": VALIDATION_EVIDENCE_RECORDER_VERSION,
        "required_fields": list(REQUIRED_FIELDS),
        "sensitive_payload_policy": "redact_summary_and_fail_closed_on_raw_sensitive_marker",
        "command_execution_performed": False,
    }
