from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from enum import Enum
from typing import Any


FAILURE_CLASSIFIER_VERSION = "pb335-failure-classifier-v1"


class FailureClass(str, Enum):
    TEST_FAILURE = "TEST_FAILURE"
    POLICY_FAILURE = "POLICY_FAILURE"
    EVIDENCE_FAILURE = "EVIDENCE_FAILURE"
    MERGE_CONFLICT = "MERGE_CONFLICT"
    BRANCH_PROTECTION = "BRANCH_PROTECTION"
    AUTH_FAILURE = "AUTH_FAILURE"
    NETWORK_FAILURE = "NETWORK_FAILURE"
    UNKNOWN_FAILURE = "UNKNOWN_FAILURE"


CLASSIFICATION_PATTERNS: tuple[tuple[FailureClass, tuple[str, ...]], ...] = (
    (FailureClass.MERGE_CONFLICT, ("<<<<<<<", "merge conflict", "conflict marker", "unmerged paths")),
    (FailureClass.AUTH_FAILURE, ("authentication failed", "authorization failed", "403", "forbidden", "bad credentials")),
    (FailureClass.NETWORK_FAILURE, ("could not resolve host", "network is unreachable", "connection timed out", "dns")),
    (FailureClass.BRANCH_PROTECTION, ("branch protection", "required status check", "protected branch", "ruleset")),
    (FailureClass.POLICY_FAILURE, ("policy", "signature", "governance-check", "policy-verification")),
    (FailureClass.EVIDENCE_FAILURE, ("evidence", "manifest", "lineage", "merkle", "audit hash")),
    (FailureClass.TEST_FAILURE, ("pytest", "assertionerror", "failed", "error collecting", "traceback")),
)


@dataclass(frozen=True)
class FailureClassification:
    failure_class: FailureClass
    decision: str
    audit_reason: str
    input_hash: str
    policy_version: str = FAILURE_CLASSIFIER_VERSION

    def to_dict(self) -> dict[str, str]:
        return {
            "policy_version": self.policy_version,
            "failure_class": self.failure_class.value,
            "decision": self.decision,
            "audit_reason": self.audit_reason,
            "input_hash": self.input_hash,
        }


def _canonical_input(payload: Any) -> str:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)


def _hash_input(payload: Any) -> str:
    return hashlib.sha256(_canonical_input(payload).encode("utf-8")).hexdigest()


def classify_failure(payload: dict[str, Any] | str | None) -> FailureClassification:
    rendered = _canonical_input(payload)
    lowered = rendered.lower()
    input_hash = _hash_input(payload)

    if not lowered or lowered == "null":
        return FailureClassification(
            failure_class=FailureClass.UNKNOWN_FAILURE,
            decision="FAIL_CLOSED",
            audit_reason="EMPTY_FAILURE_INPUT",
            input_hash=input_hash,
        )

    for failure_class, patterns in CLASSIFICATION_PATTERNS:
        if any(pattern in lowered for pattern in patterns):
            return FailureClassification(
                failure_class=failure_class,
                decision="CLASSIFIED",
                audit_reason=f"{failure_class.value}_PATTERN_MATCH",
                input_hash=input_hash,
            )

    return FailureClassification(
        failure_class=FailureClass.UNKNOWN_FAILURE,
        decision="FAIL_CLOSED",
        audit_reason="NO_DETERMINISTIC_PATTERN_MATCH",
        input_hash=input_hash,
    )


def failure_classifier_contract() -> dict[str, Any]:
    return {
        "policy_version": FAILURE_CLASSIFIER_VERSION,
        "failure_classes": [failure_class.value for failure_class in FailureClass],
        "unknown_failure_decision": "FAIL_CLOSED",
        "audit_reason_required": True,
        "deterministic_input_hash": "sha256(canonical_json(input))",
    }
