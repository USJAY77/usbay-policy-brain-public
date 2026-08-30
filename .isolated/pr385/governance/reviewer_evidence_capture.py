from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from enum import Enum
from typing import Any


REVIEWER_EVIDENCE_CAPTURE_VERSION = "pb343-reviewer-evidence-capture-v1"
REQUIRED_REVIEW_FIELDS = (
    "reviewer_identity",
    "timestamp",
    "approval_status",
    "policy_version",
    "review_evidence_hash",
)


class ApprovalStatus(str, Enum):
    APPROVED = "APPROVED"
    CHANGES_REQUESTED = "CHANGES_REQUESTED"
    BLOCKED = "BLOCKED"


def _canonical_json(payload: Any) -> str:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)


def sha256_review_evidence(payload: Any) -> str:
    return hashlib.sha256(_canonical_json(payload).encode("utf-8")).hexdigest()


def _is_sha256(value: Any) -> bool:
    return isinstance(value, str) and len(value) == 64 and all(ch in "0123456789abcdef" for ch in value.lower())


@dataclass(frozen=True)
class ReviewerEvidence:
    reviewer_identity: str
    timestamp: str
    approval_status: ApprovalStatus
    review_evidence_hash: str
    policy_version: str = REVIEWER_EVIDENCE_CAPTURE_VERSION

    def to_dict(self) -> dict[str, str]:
        return {
            "reviewer_identity": self.reviewer_identity,
            "timestamp": self.timestamp,
            "approval_status": self.approval_status.value,
            "policy_version": self.policy_version,
            "review_evidence_hash": self.review_evidence_hash,
            "contract_version": REVIEWER_EVIDENCE_CAPTURE_VERSION,
        }


def reviewer_evidence_capture_schema() -> dict[str, Any]:
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "title": "USBAY Reviewer Evidence Capture",
        "type": "object",
        "additionalProperties": False,
        "required": ["contract_version", *REQUIRED_REVIEW_FIELDS],
        "properties": {
            "contract_version": {"type": "string", "const": REVIEWER_EVIDENCE_CAPTURE_VERSION},
            "reviewer_identity": {"type": "string", "minLength": 1},
            "timestamp": {"type": "string", "minLength": 1},
            "approval_status": {"type": "string", "enum": [status.value for status in ApprovalStatus]},
            "policy_version": {"type": "string", "const": REVIEWER_EVIDENCE_CAPTURE_VERSION},
            "review_evidence_hash": {"type": "string", "pattern": "^[0-9a-fA-F]{64}$"},
        },
    }


def validate_reviewer_evidence(payload: dict[str, Any] | None) -> dict[str, Any]:
    gaps: list[str] = []
    if not isinstance(payload, dict):
        return {
            "policy_version": REVIEWER_EVIDENCE_CAPTURE_VERSION,
            "decision": "FAIL_CLOSED",
            "gaps": ["REVIEWER_EVIDENCE_MISSING"],
        }

    if payload.get("contract_version") != REVIEWER_EVIDENCE_CAPTURE_VERSION:
        gaps.append("REVIEWER_EVIDENCE_CONTRACT_VERSION_MISMATCH")
    if payload.get("policy_version") != REVIEWER_EVIDENCE_CAPTURE_VERSION:
        gaps.append("REVIEWER_EVIDENCE_POLICY_VERSION_MISMATCH")

    for field in REQUIRED_REVIEW_FIELDS:
        if payload.get(field) in ("", None):
            gaps.append(f"REVIEWER_EVIDENCE_{field.upper()}_MISSING")

    if payload.get("approval_status") not in {status.value for status in ApprovalStatus}:
        gaps.append("REVIEWER_EVIDENCE_APPROVAL_STATUS_INVALID")
    if not _is_sha256(payload.get("review_evidence_hash")):
        gaps.append("REVIEWER_EVIDENCE_HASH_INVALID")

    return {
        "policy_version": REVIEWER_EVIDENCE_CAPTURE_VERSION,
        "decision": "RECORDED" if not gaps else "FAIL_CLOSED",
        "gaps": sorted(set(gaps)),
    }
