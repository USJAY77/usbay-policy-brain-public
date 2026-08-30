from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any


BRANCH_GUARD_VERSION = "pb336-branch-guard-v1"
PB_BRANCH_PATTERN = re.compile(r"^usbay/pb-(?P<pb>[0-9]+)-[a-z0-9-]+$")
PB_TOKEN_PATTERN = re.compile(r"pb[-_]?([0-9]+)", re.IGNORECASE)
REQUIRED_AUDIT_FIELDS = ("actor", "device", "decision", "timestamp", "policy_version")


@dataclass(frozen=True)
class BranchGuardDecision:
    decision: str
    reason_codes: tuple[str, ...]
    policy_version: str = BRANCH_GUARD_VERSION

    def to_dict(self) -> dict[str, Any]:
        return {
            "policy_version": self.policy_version,
            "decision": self.decision,
            "reason_codes": list(self.reason_codes),
        }


def _missing_audit_fields(audit: dict[str, Any] | None) -> tuple[str, ...]:
    if not isinstance(audit, dict):
        return ("BRANCH_AUDIT_RECORD_MISSING",)
    return tuple(f"BRANCH_AUDIT_{field.upper()}_MISSING" for field in REQUIRED_AUDIT_FIELDS if not audit.get(field))


def evaluate_branch_operation(
    *,
    branch_name: str,
    base_ref: str,
    changed_files: tuple[str, ...],
    operation: str,
    audit: dict[str, Any] | None,
) -> BranchGuardDecision:
    reasons: list[str] = []

    if operation == "force_push":
        reasons.append("FORCE_PUSH_BLOCKED")
    if branch_name in {"main", "master", "origin/main", "origin/master"}:
        reasons.append("DIRECT_MAIN_EDIT_BLOCKED")
    if base_ref != "origin/main":
        reasons.append("BASE_REF_NOT_ORIGIN_MAIN")

    match = PB_BRANCH_PATTERN.fullmatch(branch_name)
    if not match:
        reasons.append("BRANCH_NAME_NOT_SINGLE_PB")
    else:
        branch_pb = match.group("pb")
        tokens = set(PB_TOKEN_PATTERN.findall(branch_name))
        if tokens != {branch_pb}:
            reasons.append("MULTI_PB_BRANCH_BLOCKED")

    if not changed_files:
        reasons.append("TRACKED_FILE_SCOPE_MISSING")
    if any(path.startswith("governance/evidence/") for path in changed_files):
        reasons.append("EVIDENCE_PATH_REQUIRES_EXPLICIT_SCOPE")

    reasons.extend(_missing_audit_fields(audit))

    return BranchGuardDecision(
        decision="BLOCK" if reasons else "ALLOW",
        reason_codes=tuple(sorted(set(reasons))),
    )


def branch_guard_contract() -> dict[str, Any]:
    return {
        "policy_version": BRANCH_GUARD_VERSION,
        "allowed": [
            "branch_from_origin_main",
            "one_pb_per_branch",
            "tracked_file_scope_validation",
        ],
        "blocked": [
            "force_push",
            "direct_main_edits",
            "multi_pb_branches",
            "branch_mutation_without_audit_record",
        ],
        "required_audit_fields": list(REQUIRED_AUDIT_FIELDS),
    }
