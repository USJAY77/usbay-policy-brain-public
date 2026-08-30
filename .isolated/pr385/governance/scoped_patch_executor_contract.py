from __future__ import annotations

from dataclasses import dataclass
from pathlib import PurePosixPath
from typing import Any


SCOPED_PATCH_EXECUTOR_VERSION = "pb337-scoped-patch-executor-v1"


@dataclass(frozen=True)
class PatchScopeDecision:
    decision: str
    reason_codes: tuple[str, ...]
    policy_version: str = SCOPED_PATCH_EXECUTOR_VERSION

    def to_dict(self) -> dict[str, Any]:
        return {
            "policy_version": self.policy_version,
            "decision": self.decision,
            "reason_codes": list(self.reason_codes),
        }


def _normalize(path: str) -> str:
    normalized = PurePosixPath(path).as_posix()
    if normalized.startswith("../") or "/../" in normalized or normalized == "..":
        return ""
    return normalized.lstrip("./")


def _is_allowed(path: str, allowlist: tuple[str, ...]) -> bool:
    return any(path == allowed or path.startswith(f"{allowed.rstrip('/')}/") for allowed in allowlist)


def evaluate_patch_scope(
    *,
    changed_files: tuple[str, ...],
    file_allowlist: tuple[str, ...],
    evidence_mutation_explicitly_scoped: bool = False,
) -> PatchScopeDecision:
    reasons: list[str] = []
    normalized_allowlist = tuple(filter(None, (_normalize(path) for path in file_allowlist)))

    if not normalized_allowlist:
        reasons.append("PATCH_ALLOWLIST_MISSING")
    if not changed_files:
        reasons.append("PATCH_CHANGED_FILES_MISSING")

    for raw_path in changed_files:
        path = _normalize(raw_path)
        if not path:
            reasons.append("PATCH_PATH_UNSAFE")
            continue
        if not _is_allowed(path, normalized_allowlist):
            reasons.append("PATCH_OUTSIDE_SCOPE")
        if path.startswith("governance/evidence/") and not evidence_mutation_explicitly_scoped:
            reasons.append("EVIDENCE_PATH_IMMUTABLE")

    return PatchScopeDecision(
        decision="BLOCK" if reasons else "ALLOW",
        reason_codes=tuple(sorted(set(reasons))),
    )


def scoped_patch_executor_contract() -> dict[str, Any]:
    return {
        "policy_version": SCOPED_PATCH_EXECUTOR_VERSION,
        "explicit_file_allowlist_required": True,
        "outside_scope_decision": "BLOCK",
        "evidence_paths_immutable_by_default": True,
        "uncertainty_decision": "BLOCK",
    }
