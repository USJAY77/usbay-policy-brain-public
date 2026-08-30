from __future__ import annotations

import json
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
POLICY_PATH = ROOT / "governance" / "media_governance_watchtower_policy.json"
MANIFEST_PATH = ROOT / "artifacts" / "media-governance-watchtower-manifest.json"
METRIC_FIELDS = (
    "drift_event_count",
    "unresolved_disputes",
    "revocation_frequency",
    "export_failures",
    "lineage_breaks",
    "approval_regressions",
    "jurisdiction_conflicts",
    "distribution_scope_failures",
)


def load_media_governance_watchtower_policy(path: Path = POLICY_PATH) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def load_media_governance_watchtower_manifest(path: Path = MANIFEST_PATH) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def valid_watchtower_metrics() -> dict[str, Any]:
    return {
        "approval_regressions": 0,
        "distribution_scope_failures": 0,
        "drift_event_count": 0,
        "export_failures": 0,
        "governance_health_score": 100,
        "governance_visibility_present": True,
        "jurisdiction_conflicts": 0,
        "lineage_breaks": 0,
        "revocation_frequency": 0,
        "unresolved_disputes": 0,
    }


def verify_governance_watchtower(
    metrics: dict[str, Any] | None,
    *,
    policy: dict[str, Any] | None = None,
) -> dict[str, Any]:
    resolved_policy = policy or load_media_governance_watchtower_policy()
    if resolved_policy.get("non_production_scaffolding") is not True:
        return _fail_closed("MEDIA_WATCHTOWER_POLICY_SCOPE_UNCLEAR")
    if resolved_policy.get("governance_watchtower_enabled") is not True:
        return _fail_closed("MEDIA_WATCHTOWER_DISABLED")
    if resolved_policy.get("governance_health_scoring_enabled") is not True:
        return _fail_closed("MEDIA_WATCHTOWER_HEALTH_SCORING_DISABLED")
    if metrics is None:
        return _fail_closed("MEDIA_WATCHTOWER_VISIBILITY_MISSING")
    if not isinstance(metrics, dict):
        return _fail_closed("MEDIA_WATCHTOWER_METRICS_MALFORMED")
    if metrics.get("governance_visibility_present") is not True:
        return _fail_closed("MEDIA_WATCHTOWER_VISIBILITY_MISSING")

    missing = [field for field in METRIC_FIELDS if field not in metrics]
    if missing:
        return _fail_closed("MEDIA_WATCHTOWER_METRICS_MISSING", missing_fields=missing)

    thresholds = resolved_policy["thresholds"]
    score = int(metrics.get("governance_health_score", 0))
    if metrics["lineage_breaks"] >= thresholds["lineage_breaks"]:
        return _fail_closed("MEDIA_WATCHTOWER_LINEAGE_INSTABILITY")
    if metrics["jurisdiction_conflicts"] >= thresholds["jurisdiction_conflicts"]:
        return _fail_closed("MEDIA_WATCHTOWER_UNRESOLVED_JURISDICTION_CONFLICTS")
    if metrics["drift_event_count"] >= thresholds["drift_event_count"]:
        return _fail_closed("MEDIA_WATCHTOWER_REPEATED_DRIFT_EVENTS", escalation_state="GOVERNANCE_DEGRADED")
    if metrics["revocation_frequency"] >= thresholds["revocation_frequency"]:
        return _fail_closed("MEDIA_WATCHTOWER_REPEATED_REVOCATION_EVENTS", escalation_state="GOVERNANCE_DEGRADED")
    if metrics["export_failures"] >= thresholds["export_failures"]:
        return _fail_closed("MEDIA_WATCHTOWER_EXPORT_FAILURE_PATTERN", escalation_state="GOVERNANCE_DEGRADED")
    if metrics["distribution_scope_failures"] >= thresholds["distribution_scope_failures"]:
        return _fail_closed("MEDIA_WATCHTOWER_DISTRIBUTION_GOVERNANCE_DECAY", escalation_state="GOVERNANCE_DEGRADED")
    if score <= thresholds["critical_score"]:
        return _fail_closed("MEDIA_WATCHTOWER_GOVERNANCE_CRITICAL", escalation_state="GOVERNANCE_CRITICAL")

    return {
        "decision": "PASS",
        "escalation_state": _state_for_score(score),
        "fail_closed": False,
        "governance_health_score": score,
        "non_production_scaffolding": True,
        "reason": "MEDIA_WATCHTOWER_GOVERNANCE_HEALTH_VALID",
    }


def verify_watchtower_manifest(
    manifest: dict[str, Any] | None,
    *,
    policy: dict[str, Any] | None = None,
) -> dict[str, Any]:
    resolved_policy = policy or load_media_governance_watchtower_policy()
    if manifest is None:
        return _fail_closed("MEDIA_WATCHTOWER_MANIFEST_MISSING")
    if not isinstance(manifest, dict):
        return _fail_closed("MEDIA_WATCHTOWER_MANIFEST_MALFORMED")
    if manifest.get("non_production_demo") is not True:
        return _fail_closed("MEDIA_WATCHTOWER_MANIFEST_SCOPE_UNCLEAR")
    if manifest.get("escalation_state") not in resolved_policy["governance_health_states"]:
        return _fail_closed("MEDIA_WATCHTOWER_ESCALATION_STATE_UNKNOWN")
    flags = manifest.get("fail_closed_flags")
    if not isinstance(flags, dict) or any(value is not True for value in flags.values()):
        return _fail_closed("MEDIA_WATCHTOWER_FAIL_CLOSED_FLAGS_MISSING")
    metrics = {
        "approval_regressions": manifest.get("approval_regressions", 0),
        "distribution_scope_failures": manifest.get("distribution_scope_failures", 0),
        "drift_event_count": manifest.get("drift_event_count", 0),
        "export_failures": manifest.get("export_failure_count", 0),
        "governance_health_score": manifest.get("governance_health_score", 0),
        "governance_visibility_present": True,
        "jurisdiction_conflicts": manifest.get("jurisdiction_conflict_count", 0),
        "lineage_breaks": manifest.get("lineage_break_count", 0),
        "revocation_frequency": manifest.get("revocation_frequency", 0),
        "unresolved_disputes": manifest.get("unresolved_disputes", 0),
    }
    return verify_governance_watchtower(metrics, policy=resolved_policy)


def _state_for_score(score: int) -> str:
    if score >= 85:
        return "GOVERNANCE_HEALTHY"
    if score >= 70:
        return "GOVERNANCE_WARNING"
    return "GOVERNANCE_DEGRADED"


def _fail_closed(reason: str, **details: Any) -> dict[str, Any]:
    evidence: dict[str, Any] = {
        "decision": "FAIL_CLOSED",
        "fail_closed": True,
        "reason": reason,
        "silent_pass": False,
    }
    evidence.update(details)
    return evidence
