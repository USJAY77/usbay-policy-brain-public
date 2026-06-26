from __future__ import annotations

from dataclasses import dataclass
from typing import Any


MERGE_BLOCKER_RULESET_VERSION = "pb340-merge-blocker-ruleset-v1"
REQUIRED_CHECKS = (
    "audit-artifact-guard",
    "production-readiness",
    "governance-check",
    "policy-verification",
    "codeql-quality",
)


@dataclass(frozen=True)
class MergeRulesetDecision:
    decision: str
    blockers: tuple[str, ...]
    policy_version: str = MERGE_BLOCKER_RULESET_VERSION

    def to_dict(self) -> dict[str, Any]:
        return {
            "policy_version": self.policy_version,
            "decision": self.decision,
            "blockers": list(self.blockers),
        }


def verify_merge_ruleset(
    *,
    checks: dict[str, str],
    branch_protection_active: bool,
    policy_verification_active: bool,
    audit_evidence_available: bool,
    unresolved_blockers: tuple[str, ...] = (),
) -> MergeRulesetDecision:
    blockers: list[str] = []

    for check in REQUIRED_CHECKS:
        if checks.get(check) != "success":
            blockers.append(f"REQUIRED_CHECK_NOT_SUCCESS:{check}")

    if not branch_protection_active:
        blockers.append("BRANCH_PROTECTION_INACTIVE")
    if not policy_verification_active:
        blockers.append("POLICY_VERIFICATION_INACTIVE")
    if not audit_evidence_available:
        blockers.append("AUDIT_EVIDENCE_UNAVAILABLE")
    blockers.extend(f"UNRESOLVED_BLOCKER:{blocker}" for blocker in unresolved_blockers)

    return MergeRulesetDecision(
        decision="BLOCKED" if blockers else "MERGE_ELIGIBLE",
        blockers=tuple(sorted(set(blockers))),
    )


def merge_blocker_ruleset_contract() -> dict[str, Any]:
    return {
        "policy_version": MERGE_BLOCKER_RULESET_VERSION,
        "required_checks": list(REQUIRED_CHECKS),
        "branch_protection_required": True,
        "policy_verification_required": True,
        "audit_evidence_required": True,
        "allowed_decisions": ["MERGE_ELIGIBLE", "BLOCKED"],
    }
