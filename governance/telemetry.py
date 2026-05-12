from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Any, Callable, TypeVar

from governance.interfaces import GovernanceValidationResult

T = TypeVar("T")


@dataclass(frozen=True)
class GovernanceTelemetryMetric:
    """Audit-safe timing and artifact telemetry for governance validation."""

    domain: str
    operation: str
    validation_latency_ns: int
    artifact_count: int
    valid: bool
    failure_count: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "domain": self.domain,
            "operation": self.operation,
            "validation_latency_ns": self.validation_latency_ns,
            "artifact_count": self.artifact_count,
            "valid": self.valid,
            "failure_count": self.failure_count,
        }


def artifact_count_for_payload(domain: str, payload: dict[str, Any]) -> int:
    if domain == "evidence":
        records = payload.get("records")
        return len(records) if isinstance(records, list) else 0
    if domain == "chronology":
        targets = payload.get("targets")
        return len(targets) if isinstance(targets, list) else 0
    if domain == "trust_policy":
        signers = payload.get("allowed_signers")
        return len(signers) if isinstance(signers, list) else 0
    if domain == "timestamping":
        return 1 if payload else 0
    return 0


def measure_governance_validation(
    domain: str,
    operation: str,
    validator: Callable[[dict[str, Any]], GovernanceValidationResult],
    payload: dict[str, Any],
    *,
    artifact_count: int | None = None,
) -> tuple[GovernanceValidationResult, GovernanceTelemetryMetric]:
    """Measure validation without changing the underlying validation decision.

    Governance scope: wraps boundary validators only and records aggregate,
    audit-safe metrics.
    Fail-closed expectation: validator exceptions are converted into invalid
    results so callers never accept ambiguous telemetry paths.
    Sensitive-data handling: payload contents are not serialized or logged.
    """

    start = time.perf_counter_ns()
    try:
        result = validator(payload)
    except Exception:
        elapsed = time.perf_counter_ns() - start
        result = GovernanceValidationResult(False, (f"GOVERNANCE_{domain.upper()}_VALIDATION_UNAVAILABLE",))
        return (
            result,
            GovernanceTelemetryMetric(
                domain=domain,
                operation=operation,
                validation_latency_ns=elapsed,
                artifact_count=artifact_count if artifact_count is not None else artifact_count_for_payload(domain, payload),
                valid=False,
                failure_count=len(result.failures),
            ),
        )
    elapsed = time.perf_counter_ns() - start
    metric = GovernanceTelemetryMetric(
        domain=domain,
        operation=operation,
        validation_latency_ns=elapsed,
        artifact_count=artifact_count if artifact_count is not None else artifact_count_for_payload(domain, payload),
        valid=result.valid,
        failure_count=len(result.failures),
    )
    return result, metric
