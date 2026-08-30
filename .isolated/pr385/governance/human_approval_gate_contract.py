from __future__ import annotations

from dataclasses import dataclass
from typing import Any


HUMAN_APPROVAL_GATE_VERSION = "pb339-human-approval-gate-v1"
REQUIRED_APPROVAL_FIELDS = (
    "validation_passed",
    "blast_radius",
    "changed_files",
    "policy_version",
    "human_reviewer",
    "approval_timestamp",
)


@dataclass(frozen=True)
class HumanApprovalDecision:
    decision: str
    reason_codes: tuple[str, ...]
    policy_version: str = HUMAN_APPROVAL_GATE_VERSION

    def to_dict(self) -> dict[str, Any]:
        return {
            "policy_version": self.policy_version,
            "decision": self.decision,
            "reason_codes": list(self.reason_codes),
        }


def evaluate_human_approval(
    approval: dict[str, Any] | None,
    *,
    actor: str,
    auto_merge_requested: bool = False,
    production_execution_requested: bool = False,
) -> HumanApprovalDecision:
    reasons: list[str] = []
    if not isinstance(approval, dict):
        return HumanApprovalDecision(decision="BLOCKED", reason_codes=("HUMAN_APPROVAL_EVIDENCE_MISSING",))

    for field in REQUIRED_APPROVAL_FIELDS:
        if approval.get(field) in ("", None, [], ()):
            reasons.append(f"HUMAN_APPROVAL_{field.upper()}_MISSING")

    if approval.get("policy_version") != HUMAN_APPROVAL_GATE_VERSION:
        reasons.append("HUMAN_APPROVAL_POLICY_VERSION_MISMATCH")
    if approval.get("validation_passed") is not True:
        reasons.append("VALIDATION_NOT_PASSED")
    if approval.get("human_reviewer") == actor:
        reasons.append("SELF_APPROVAL_BLOCKED")
    if auto_merge_requested:
        reasons.append("AUTOMATIC_MERGE_BLOCKED")
    if production_execution_requested:
        reasons.append("AUTOMATIC_PRODUCTION_EXECUTION_BLOCKED")

    return HumanApprovalDecision(
        decision="BLOCKED" if reasons else "APPROVED_FOR_PUBLICATION",
        reason_codes=tuple(sorted(set(reasons))),
    )


def human_approval_gate_contract() -> dict[str, Any]:
    return {
        "policy_version": HUMAN_APPROVAL_GATE_VERSION,
        "required_evidence": list(REQUIRED_APPROVAL_FIELDS),
        "blocked": [
            "self_approval",
            "automatic_merge",
            "automatic_production_execution",
        ],
        "merge_decision_without_human_approval": "BLOCKED",
    }
