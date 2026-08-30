from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Mapping, Sequence

from governance.hashing import sha256_reference


READY = "READY"
DEGRADED = "DEGRADED"
MISSING = "MISSING"
STALE = "STALE"
INCOMPATIBLE = "INCOMPATIBLE"
UNVERIFIED = "UNVERIFIED"
BLOCKED = "BLOCKED"

ALLOW = "ALLOW"
DECISION_BLOCKED = "BLOCKED"

SUPPORTED_DEPENDENCY_TYPES = frozenset(
    {
        "internal_service",
        "adapter",
        "evidence_store",
        "policy_source",
        "approval_service",
        "runtime_dependency",
    }
)
SUPPORTED_STATUSES = frozenset({READY, DEGRADED, MISSING, STALE, INCOMPATIBLE, UNVERIFIED, BLOCKED})
REQUIRED_FIELDS = (
    "dependency_id",
    "dependency_type",
    "required",
    "readiness_status",
    "health_status",
    "compatibility_status",
    "integrity_status",
    "last_verified_at",
    "freshness_window_seconds",
    "expected_version",
    "observed_version",
    "evidence_hash",
    "final_decision",
)


@dataclass(frozen=True)
class DependencyReadinessDecision:
    final_decision: str
    reason_code: str
    dependency_count: int
    blocked_dependency_hashes: tuple[str, ...]
    evidence_hash: str
    execution_may_continue: bool = False

    def to_dict(self) -> dict[str, Any]:
        payload = {
            "final_decision": self.final_decision,
            "reason_code": self.reason_code,
            "dependency_count": self.dependency_count,
            "blocked_dependency_hashes": list(self.blocked_dependency_hashes),
            "evidence_hash": self.evidence_hash,
            "execution_may_continue": self.execution_may_continue,
        }
        return {**payload, "decision_hash": sha256_reference(payload)}


def evaluate_dependency_readiness(
    dependencies: Sequence[Mapping[str, Any]] | None,
    *,
    observed_at: str,
    degraded_operation_permitted: bool = False,
) -> DependencyReadinessDecision:
    try:
        return _evaluate_dependency_readiness(
            dependencies,
            observed_at=observed_at,
            degraded_operation_permitted=degraded_operation_permitted,
        )
    except Exception:
        return _blocked("INTERNAL_ERROR", (), 0)


def _evaluate_dependency_readiness(
    dependencies: Sequence[Mapping[str, Any]] | None,
    *,
    observed_at: str,
    degraded_operation_permitted: bool,
) -> DependencyReadinessDecision:
    observed = _parse_time(observed_at)
    if observed is None:
        return _blocked("MALFORMED_READINESS_RECORD", (), 0)
    if not isinstance(dependencies, Sequence) or isinstance(dependencies, (str, bytes)) or not dependencies:
        return _blocked("DEPENDENCY_MISSING", (), 0)

    blocked: list[str] = []
    for dependency in dependencies:
        reason = _dependency_block_reason(
            dependency,
            observed=observed,
            degraded_operation_permitted=degraded_operation_permitted,
        )
        if reason:
            blocked.append(sha256_reference(_redacted_dependency(dependency)))

    if blocked:
        return DependencyReadinessDecision(
            final_decision=DECISION_BLOCKED,
            reason_code="DEPENDENCY_NOT_READY",
            dependency_count=len(dependencies),
            blocked_dependency_hashes=tuple(sorted(blocked)),
            evidence_hash=sha256_reference({"blocked": sorted(blocked), "count": len(dependencies)}),
        )

    evidence = {
        "dependency_hashes": [sha256_reference(_redacted_dependency(dependency)) for dependency in dependencies],
        "observed_at": observed_at,
        "result": READY,
    }
    return DependencyReadinessDecision(
        final_decision=ALLOW,
        reason_code="DEPENDENCIES_READY",
        dependency_count=len(dependencies),
        blocked_dependency_hashes=(),
        evidence_hash=sha256_reference(evidence),
        execution_may_continue=True,
    )


def _dependency_block_reason(
    dependency: Mapping[str, Any],
    *,
    observed: datetime,
    degraded_operation_permitted: bool,
) -> str:
    if not isinstance(dependency, Mapping):
        return "MALFORMED_READINESS_RECORD"
    if any(field not in dependency for field in REQUIRED_FIELDS):
        return "MALFORMED_READINESS_RECORD"
    if dependency.get("dependency_type") not in SUPPORTED_DEPENDENCY_TYPES:
        return "UNSUPPORTED_DEPENDENCY_TYPE"
    if dependency.get("readiness_status") not in SUPPORTED_STATUSES:
        return "UNKNOWN_DEPENDENCY_STATUS"
    if not _is_hash(dependency.get("evidence_hash")):
        return "MISSING_READINESS_EVIDENCE"
    if dependency.get("expected_version") != dependency.get("observed_version"):
        return "VERSION_MISMATCH"
    if not _fresh(dependency, observed):
        return "DEPENDENCY_STALE"
    if dependency.get("readiness_status") == READY:
        return ""
    if dependency.get("readiness_status") == DEGRADED:
        if dependency.get("required") is True:
            return "REQUIRED_DEPENDENCY_DEGRADED"
        return "" if degraded_operation_permitted is True else "OPTIONAL_DEGRADED_NOT_PERMITTED"
    return str(dependency.get("readiness_status"))


def _fresh(dependency: Mapping[str, Any], observed: datetime) -> bool:
    verified = _parse_time(dependency.get("last_verified_at"))
    window = dependency.get("freshness_window_seconds")
    if verified is None or not isinstance(window, int) or window <= 0:
        return False
    return 0 <= (observed - verified).total_seconds() <= window


def _redacted_dependency(dependency: Mapping[str, Any] | None) -> dict[str, Any]:
    if not isinstance(dependency, Mapping):
        return {}
    return {
        "dependency_id": dependency.get("dependency_id", ""),
        "dependency_type": dependency.get("dependency_type", ""),
        "required": dependency.get("required", ""),
        "readiness_status": dependency.get("readiness_status", ""),
        "expected_version": dependency.get("expected_version", ""),
        "observed_version": dependency.get("observed_version", ""),
        "evidence_hash": dependency.get("evidence_hash", ""),
        "final_decision": dependency.get("final_decision", ""),
    }


def _is_hash(value: Any) -> bool:
    return isinstance(value, str) and value.startswith("sha256:") and len(value) == 71 and all(char in "0123456789abcdef" for char in value[7:])


def _parse_time(value: Any) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(timezone.utc)
    except ValueError:
        return None


def _blocked(reason_code: str, blocked_hashes: Sequence[str], count: int) -> DependencyReadinessDecision:
    return DependencyReadinessDecision(
        final_decision=DECISION_BLOCKED,
        reason_code=reason_code,
        dependency_count=count,
        blocked_dependency_hashes=tuple(sorted(blocked_hashes)),
        evidence_hash=sha256_reference({"blocked": sorted(blocked_hashes), "count": count, "reason": reason_code}),
    )
