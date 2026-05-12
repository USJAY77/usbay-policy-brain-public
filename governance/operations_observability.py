from __future__ import annotations

import json
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from governance.dependencies import build_governance_dependency_map, validate_governance_dependency_map
from governance.release_integrity import (
    DEFAULT_BASELINE_TAG,
    GovernanceReleaseIntegrityError,
    build_release_integrity_manifest,
    canonical_json,
    load_release_integrity_manifest,
    trust_policy_fingerprint,
    validate_release_integrity_manifest,
)


@dataclass(frozen=True)
class GovernanceOperationalMetrics:
    """Audit-safe operational metrics for governance diagnostics."""

    validation_latency_ns: int
    release_integrity_latency_ns: int
    trust_policy_validation_count: int
    dependency_drift_events: int
    rollback_validation_events: int
    fail_closed_rejection_count: int
    artifact_counts: dict[str, int]

    def to_dict(self) -> dict[str, Any]:
        return {
            "validation_latency_ns": self.validation_latency_ns,
            "release_integrity_latency_ns": self.release_integrity_latency_ns,
            "trust_policy_validation_count": self.trust_policy_validation_count,
            "dependency_drift_events": self.dependency_drift_events,
            "rollback_validation_events": self.rollback_validation_events,
            "fail_closed_rejection_count": self.fail_closed_rejection_count,
            "artifact_counts": dict(self.artifact_counts),
        }


@dataclass(frozen=True)
class GovernanceHealthSnapshot:
    """Deterministic governance health snapshot with public metadata only."""

    valid: bool
    signer_continuity_status: str
    dependency_graph_hash: str
    release_baseline_status: str
    trust_policy_fingerprint: str
    regression_suite_status: str
    failures: tuple[str, ...]
    metrics: GovernanceOperationalMetrics

    def to_dict(self) -> dict[str, Any]:
        return {
            "valid": self.valid,
            "signer_continuity_status": self.signer_continuity_status,
            "dependency_graph_hash": self.dependency_graph_hash,
            "release_baseline_status": self.release_baseline_status,
            "trust_policy_fingerprint": self.trust_policy_fingerprint,
            "regression_suite_status": self.regression_suite_status,
            "failures": list(self.failures),
            "metrics": self.metrics.to_dict(),
        }


def collect_governance_health_snapshot(
    root: Path,
    *,
    release_manifest: dict[str, Any] | None = None,
    baseline_tag: str = DEFAULT_BASELINE_TAG,
    rollback_targets: tuple[str, ...] = (),
    regression_suite_status: str = "not_run",
    dependency_module_sources: dict[str, str] | None = None,
) -> GovernanceHealthSnapshot:
    """Collect a deterministic read-only governance operations snapshot.

    Governance scope: observes dependency graph, release integrity, signer
    continuity, rollback validation, and aggregate fail-closed counts.
    Fail-closed expectation: any ambiguity is reported as invalid health.
    Sensitive-data handling: only public hashes, counts, and status labels are
    returned; payload bodies and private material are never serialized.
    """

    root = root.resolve()
    failures: list[str] = []
    validation_start = time.perf_counter_ns()
    dependency_state = validate_governance_dependency_map(root, module_sources=dependency_module_sources)
    dependency_duration = time.perf_counter_ns() - validation_start
    failures.extend(dependency_state.failures)
    dependency_graph = dependency_state.metadata.get("dependency_graph", {}) if dependency_state.metadata else {}
    dependency_hash = str(dependency_graph.get("graph_hash", ""))
    dependency_drift_events = sum(
        1
        for failure in dependency_state.failures
        if "DEPENDENCY" in failure or "CIRCULAR" in failure or "RUNTIME_COUPLING" in failure or "FORBIDDEN_DOMAIN" in failure
    )

    trust_validation_count = 0
    try:
        trust_fingerprint = trust_policy_fingerprint(root)
        signer_status = "valid"
        trust_validation_count += 1
    except GovernanceReleaseIntegrityError as exc:
        trust_fingerprint = ""
        signer_status = "invalid"
        failures.append(str(exc))
        trust_validation_count += 1

    release_start = time.perf_counter_ns()
    rollback_validation_events = 1 if rollback_targets else 0
    try:
        manifest = release_manifest or build_release_integrity_manifest(
            root,
            release_id="governance-operations-health",
            governance_baseline_tag=baseline_tag,
        )
        release_summary = validate_release_integrity_manifest(
            manifest,
            root,
            expected_baseline_tag=baseline_tag,
            rollback_targets=rollback_targets,
        )
        baseline_status = "valid"
    except GovernanceReleaseIntegrityError as exc:
        release_summary = None
        baseline_status = "invalid"
        failures.extend(str(exc).split(","))
    release_duration = time.perf_counter_ns() - release_start

    artifact_counts = {
        "governance_modules": int(dependency_state.metadata.get("artifact_counts", {}).get("modules", 0)) if dependency_state.metadata else 0,
        "dependency_edges": int(dependency_state.metadata.get("artifact_counts", {}).get("edges", 0)) if dependency_state.metadata else 0,
        "trust_policy_validations": trust_validation_count,
        "rollback_validations": rollback_validation_events,
    }
    fail_closed_count = len([failure for failure in failures if failure])
    metrics = GovernanceOperationalMetrics(
        validation_latency_ns=dependency_duration + release_duration,
        release_integrity_latency_ns=release_duration,
        trust_policy_validation_count=trust_validation_count,
        dependency_drift_events=dependency_drift_events,
        rollback_validation_events=rollback_validation_events,
        fail_closed_rejection_count=fail_closed_count,
        artifact_counts=artifact_counts,
    )
    return GovernanceHealthSnapshot(
        valid=fail_closed_count == 0,
        signer_continuity_status=signer_status,
        dependency_graph_hash=dependency_hash or (build_governance_dependency_map(root).graph_hash if not dependency_module_sources else ""),
        release_baseline_status=baseline_status,
        trust_policy_fingerprint=trust_fingerprint,
        regression_suite_status=regression_suite_status,
        failures=tuple(sorted(set(failure for failure in failures if failure))),
        metrics=metrics,
    )


def verify_governance_status(root: Path, **kwargs: Any) -> GovernanceHealthSnapshot:
    snapshot = collect_governance_health_snapshot(root, **kwargs)
    if not snapshot.valid:
        raise GovernanceReleaseIntegrityError(",".join(snapshot.failures))
    return snapshot


def verify_release_integrity_status(
    root: Path,
    manifest_path: Path | None = None,
    *,
    baseline_tag: str = DEFAULT_BASELINE_TAG,
    rollback_targets: tuple[str, ...] = (),
) -> dict[str, Any]:
    manifest = load_release_integrity_manifest(manifest_path) if manifest_path else build_release_integrity_manifest(
        root,
        release_id="governance-operations-release-check",
        governance_baseline_tag=baseline_tag,
    )
    summary = validate_release_integrity_manifest(
        manifest,
        root,
        expected_baseline_tag=baseline_tag,
        rollback_targets=rollback_targets,
    )
    return summary.to_dict()


def verify_dependency_graph_status(root: Path) -> dict[str, Any]:
    result = validate_governance_dependency_map(root)
    if not result.valid:
        raise GovernanceReleaseIntegrityError(",".join(result.failures))
    return result.metadata.get("dependency_graph", {})


def verify_signer_continuity_status(root: Path) -> dict[str, str]:
    return {"signer_continuity_status": "valid", "trust_policy_fingerprint": trust_policy_fingerprint(root)}


def verify_baseline_lineage_status(root: Path, *, baseline_tag: str = DEFAULT_BASELINE_TAG) -> dict[str, Any]:
    manifest = build_release_integrity_manifest(
        root,
        release_id="governance-operations-baseline-check",
        governance_baseline_tag=baseline_tag,
    )
    summary = validate_release_integrity_manifest(manifest, root, expected_baseline_tag=baseline_tag)
    return {
        "release_baseline_status": "valid",
        "governance_baseline_tag": summary.governance_baseline_tag,
        "dependency_graph_hash": summary.dependency_graph_hash,
    }


def diagnostics_json(payload: dict[str, Any]) -> str:
    return canonical_json(payload)
