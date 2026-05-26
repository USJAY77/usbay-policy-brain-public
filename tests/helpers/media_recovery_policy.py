from __future__ import annotations

import json
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
POLICY_PATH = ROOT / "governance" / "media_recovery_policy.json"
MANIFEST_PATH = ROOT / "artifacts" / "media-recovery-governance-manifest.json"


def load_media_recovery_policy(path: Path = POLICY_PATH) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def load_media_recovery_manifest(path: Path = MANIFEST_PATH) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def valid_recovery_evidence() -> dict[str, Any]:
    return {
        "drift_reset_completed": True,
        "failed_reauthorization_count": 0,
        "human_signoff": True,
        "incident_lineage_resolved": True,
        "jurisdiction_conflict_resolved": True,
        "post_incident_review_completed": True,
        "reauthorization_state": "REAUTHORIZATION_ALLOWED",
        "recovery_attempt_count": 1,
        "recovery_evidence_fresh": True,
        "recovery_state": "RECOVERY_APPROVED",
        "repeat_incident_frequency": 0,
        "revocation_resolved": True,
        "unresolved_incident_count": 0,
        "unresolved_lineage_breaks": 0,
        "unresolved_watchtower_failures": 0,
        "watchtower_clearance": True,
    }


def verify_media_recovery(
    evidence: dict[str, Any] | None,
    *,
    policy: dict[str, Any] | None = None,
) -> dict[str, Any]:
    resolved_policy = policy or load_media_recovery_policy()
    if resolved_policy.get("non_production_scaffolding") is not True:
        return _fail_closed("MEDIA_RECOVERY_POLICY_SCOPE_UNCLEAR")
    if resolved_policy.get("controlled_reauthorization_required") is not True:
        return _fail_closed("MEDIA_RECOVERY_REAUTHORIZATION_POLICY_DISABLED")
    if evidence is None:
        return _fail_closed("MEDIA_RECOVERY_REVIEW_MISSING")
    if not isinstance(evidence, dict):
        return _fail_closed("MEDIA_RECOVERY_EVIDENCE_MALFORMED")

    thresholds = resolved_policy["thresholds"]
    if evidence.get("recovery_state") not in resolved_policy["recovery_states"]:
        return _fail_closed("MEDIA_RECOVERY_STATE_UNKNOWN")
    if evidence.get("reauthorization_state") not in resolved_policy["recovery_states"]:
        return _fail_closed("MEDIA_REAUTHORIZATION_STATE_UNKNOWN")
    if evidence.get("post_incident_review_completed") is not True:
        return _fail_closed("MEDIA_RECOVERY_REVIEW_MISSING")
    if evidence.get("incident_lineage_resolved") is not True:
        return _fail_closed("MEDIA_RECOVERY_INCIDENT_LINEAGE_UNRESOLVED")
    if evidence.get("recovery_evidence_fresh") is not True:
        return _fail_closed("MEDIA_RECOVERY_EVIDENCE_STALE")
    if evidence.get("repeat_incident_frequency", 0) >= thresholds["repeat_incident_frequency"]:
        return _fail_closed("MEDIA_RECOVERY_REPEAT_INCIDENT_PATTERN")
    if evidence.get("human_signoff") is not True:
        return _fail_closed("MEDIA_RECOVERY_HUMAN_SIGNOFF_MISSING")
    if evidence.get("watchtower_clearance") is not True:
        return _fail_closed("MEDIA_RECOVERY_WATCHTOWER_CLEARANCE_MISSING")
    if evidence.get("revocation_resolved") is not True:
        return _fail_closed("MEDIA_RECOVERY_AFTER_REVOCATION_BLOCKED")
    if evidence.get("jurisdiction_conflict_resolved") is not True:
        return _fail_closed("MEDIA_RECOVERY_AFTER_JURISDICTION_CONFLICT_BLOCKED")
    if evidence.get("drift_reset_completed") is not True:
        return _fail_closed("MEDIA_RECOVERY_AFTER_DRIFT_WITHOUT_RESET")
    if evidence.get("unresolved_incident_count", 0) >= thresholds["unresolved_incident_count"]:
        return _fail_closed("MEDIA_RECOVERY_UNRESOLVED_INCIDENT")
    if evidence.get("unresolved_lineage_breaks", 0) >= thresholds["unresolved_lineage_breaks"]:
        return _fail_closed("MEDIA_RECOVERY_INCIDENT_LINEAGE_UNRESOLVED")
    if evidence.get("unresolved_watchtower_failures", 0) >= thresholds["unresolved_watchtower_failures"]:
        return _fail_closed("MEDIA_RECOVERY_WATCHTOWER_CLEARANCE_MISSING")
    if evidence.get("failed_reauthorization_count", 0) >= thresholds["failed_reauthorization_count"]:
        return _fail_closed("MEDIA_RECOVERY_FAILED_REAUTHORIZATION_PATTERN")
    if evidence.get("recovery_attempt_count", 0) > thresholds["recovery_attempt_count"]:
        return _fail_closed("MEDIA_RECOVERY_REPEAT_INCIDENT_PATTERN")
    if evidence.get("recovery_state") in {"RECOVERY_PENDING", "RECOVERY_REVIEW_REQUIRED", "RECOVERY_UNDER_INVESTIGATION"}:
        return _fail_closed("MEDIA_RECOVERY_REVIEW_MISSING")
    if evidence.get("recovery_state") in {"RECOVERY_REJECTED", "REAUTHORIZATION_BLOCKED", "GOVERNANCE_FAIL_CLOSED"}:
        return _fail_closed("MEDIA_RECOVERY_REAUTHORIZATION_BLOCKED")
    if evidence.get("reauthorization_state") != "REAUTHORIZATION_ALLOWED":
        return _fail_closed("MEDIA_RECOVERY_REAUTHORIZATION_BLOCKED")

    return {
        "decision": "PASS",
        "fail_closed": False,
        "non_production_scaffolding": True,
        "reason": "MEDIA_RECOVERY_REAUTHORIZATION_VALID",
        "reauthorization_audit_visible": True,
    }


def verify_media_recovery_manifest(
    manifest: dict[str, Any] | None,
    *,
    policy: dict[str, Any] | None = None,
) -> dict[str, Any]:
    if manifest is None:
        return _fail_closed("MEDIA_RECOVERY_MANIFEST_MISSING")
    if not isinstance(manifest, dict):
        return _fail_closed("MEDIA_RECOVERY_MANIFEST_MALFORMED")
    if manifest.get("non_production_demo") is not True:
        return _fail_closed("MEDIA_RECOVERY_MANIFEST_SCOPE_UNCLEAR")
    flags = manifest.get("fail_closed_flags")
    if not isinstance(flags, dict) or any(value is not True for value in flags.values()):
        return _fail_closed("MEDIA_RECOVERY_FAIL_CLOSED_FLAGS_MISSING")
    evidence = valid_recovery_evidence()
    evidence["recovery_state"] = manifest.get("recovery_state")
    evidence["reauthorization_state"] = manifest.get("reauthorization_state")
    evidence["unresolved_incident_count"] = manifest.get("unresolved_incident_count", 0)
    evidence["post_incident_review_completed"] = bool(manifest.get("recovery_review_reference"))
    evidence["watchtower_clearance"] = bool(manifest.get("watchtower_clearance_reference"))
    evidence["human_signoff"] = bool(manifest.get("escalation_reference"))
    evidence["incident_lineage_resolved"] = bool(manifest.get("incident_lineage_reference"))
    return verify_media_recovery(evidence, policy=policy)


def _fail_closed(reason: str) -> dict[str, Any]:
    return {"decision": "FAIL_CLOSED", "fail_closed": True, "reason": reason, "silent_pass": False}
