"""Fail-closed publication runtime evidence consistency gate."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

from publication.models import EvidenceConsistencyResult, hash_payload, is_sha256_ref


EVIDENCE_CONSISTENCY_POLICY_VERSION = "USBAY-PUBGOV-033"
REQUIRED_EVIDENCE_COMPONENT_ORDER = (
    "registry",
    "classification",
    "sensitive_scan",
    "human_approval",
    "audit_persistence",
    "connector_gate",
    "runtime_aggregator",
    "evidence_chain",
    "final_publication_report",
    "commit_scope",
    "policy_bundle",
    "finalization_gate",
    "publication_lock",
    "lock_release",
    "release_blocker",
    "release_blocker_integrity",
)


def validate_evidence_consistency_gate(
    *,
    components: Sequence[Mapping[str, Any]] | None,
    runtime_policy_version: str,
    runtime_generation_id: str,
) -> EvidenceConsistencyResult:
    """Approve only when all publication evidence belongs to one ordered runtime generation."""

    compared_artifacts: list[str] = []
    if not components:
        return _blocked(
            reason="MISSING_ARTIFACT",
            failed_component="components",
            compared_artifacts=(),
            components=(),
            runtime_policy_version=runtime_policy_version,
            runtime_generation_id=runtime_generation_id,
        )

    normalized_components: list[dict[str, Any]] = []
    seen: set[str] = set()
    timestamps: set[str] = set()
    for component in components:
        name = str(component.get("component", ""))
        compared_artifacts.append(name or "UNKNOWN")
        if name not in REQUIRED_EVIDENCE_COMPONENT_ORDER:
            return _blocked("UNKNOWN_DEPENDENCY", name or "UNKNOWN", tuple(compared_artifacts), components, runtime_policy_version, runtime_generation_id)
        if name in seen:
            return _blocked("DUPLICATED_ARTIFACT", name, tuple(compared_artifacts), components, runtime_policy_version, runtime_generation_id)
        seen.add(name)

        evidence_hash = component.get("evidence_hash")
        if not is_sha256_ref(evidence_hash if isinstance(evidence_hash, str) else None):
            return _blocked("MALFORMED_EVIDENCE", name, tuple(compared_artifacts), components, runtime_policy_version, runtime_generation_id)
        expected_evidence_hash = component.get("expected_evidence_hash")
        if expected_evidence_hash and evidence_hash != expected_evidence_hash:
            return _blocked("HASH_MISMATCH", name, tuple(compared_artifacts), components, runtime_policy_version, runtime_generation_id)
        if component.get("runtime_policy_version") != runtime_policy_version:
            return _blocked("POLICY_VERSION_MISMATCH", name, tuple(compared_artifacts), components, runtime_policy_version, runtime_generation_id)
        if component.get("runtime_generation_id") != runtime_generation_id:
            return _blocked("INCONSISTENT_RUNTIME_GENERATION", name, tuple(compared_artifacts), components, runtime_policy_version, runtime_generation_id)
        timestamp = component.get("runtime_timestamp")
        if timestamp:
            timestamps.add(str(timestamp))
        normalized_components.append(_normalize_component(component))

    actual_order = tuple(component["component"] for component in normalized_components)
    if actual_order != REQUIRED_EVIDENCE_COMPONENT_ORDER:
        return _blocked("UNORDERED_CHAIN", "component_order", tuple(compared_artifacts), components, runtime_policy_version, runtime_generation_id)

    missing = tuple(name for name in REQUIRED_EVIDENCE_COMPONENT_ORDER if name not in seen)
    if missing:
        return _blocked("MISSING_ARTIFACT", missing[0], tuple(compared_artifacts), components, runtime_policy_version, runtime_generation_id)

    if len(timestamps) > 1:
        return _blocked("TIMESTAMP_DRIFT", "runtime_timestamp", tuple(compared_artifacts), components, runtime_policy_version, runtime_generation_id)

    consistency_hash = hash_payload(
        {
            "policy_version": EVIDENCE_CONSISTENCY_POLICY_VERSION,
            "runtime_policy_version": runtime_policy_version,
            "runtime_generation_id": runtime_generation_id,
            "components": normalized_components,
            "raw_payload_stored": False,
        }
    )
    return EvidenceConsistencyResult(
        approved=True,
        consistency_hash=consistency_hash,
        compared_artifacts=actual_order,
        failed_component="",
        reason="EVIDENCE_CONSISTENCY_APPROVED",
        policy_version=EVIDENCE_CONSISTENCY_POLICY_VERSION,
    )


def _blocked(
    reason: str,
    failed_component: str,
    compared_artifacts: tuple[str, ...],
    components: Sequence[Mapping[str, Any]],
    runtime_policy_version: str,
    runtime_generation_id: str,
) -> EvidenceConsistencyResult:
    consistency_hash = hash_payload(
        {
            "policy_version": EVIDENCE_CONSISTENCY_POLICY_VERSION,
            "runtime_policy_version": runtime_policy_version,
            "runtime_generation_id": runtime_generation_id,
            "reason": reason,
            "failed_component": failed_component,
            "compared_artifacts": compared_artifacts,
            "component_count": len(components),
            "raw_payload_stored": False,
        }
    )
    return EvidenceConsistencyResult(
        approved=False,
        consistency_hash=consistency_hash,
        compared_artifacts=compared_artifacts,
        failed_component=failed_component,
        reason=reason,
        policy_version=EVIDENCE_CONSISTENCY_POLICY_VERSION,
    )


def _normalize_component(component: Mapping[str, Any]) -> dict[str, str]:
    return {
        "component": str(component["component"]),
        "evidence_hash": str(component["evidence_hash"]),
        "runtime_policy_version": str(component["runtime_policy_version"]),
        "runtime_generation_id": str(component["runtime_generation_id"]),
        "component_policy_version": str(component.get("component_policy_version", "")),
        "runtime_timestamp": str(component.get("runtime_timestamp", "")),
        "expected_evidence_hash": str(component.get("expected_evidence_hash", "")),
    }
