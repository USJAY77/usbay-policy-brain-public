from __future__ import annotations

import json
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
POLICY_PATH = ROOT / "governance" / "media_human_escalation_policy.json"
MANIFEST_PATH = ROOT / "artifacts" / "media-human-escalation-manifest.json"


def load_media_human_escalation_policy(path: Path = POLICY_PATH) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def load_media_human_escalation_manifest(path: Path = MANIFEST_PATH) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def valid_human_escalation_evidence() -> dict[str, Any]:
    return {
        "escalation_chain_present": True,
        "escalation_response_time": 300,
        "escalation_state": "ESCALATION_APPROVED",
        "governance_health_score": 100,
        "human_review_completed": True,
        "mass_revocation_count": 0,
        "multi_region_conflict": False,
        "regulator_dispute_count": 0,
        "repeated_crisis_events": 0,
        "unresolved_escalations": 0,
        "unresolved_freeze_states": 0,
    }


def verify_human_escalation(
    evidence: dict[str, Any] | None,
    *,
    policy: dict[str, Any] | None = None,
) -> dict[str, Any]:
    resolved_policy = policy or load_media_human_escalation_policy()
    if resolved_policy.get("non_production_scaffolding") is not True:
        return _fail_closed("MEDIA_ESCALATION_POLICY_SCOPE_UNCLEAR")
    if resolved_policy.get("human_escalation_required") is not True:
        return _fail_closed("MEDIA_ESCALATION_POLICY_DISABLED")
    if evidence is None:
        return _fail_closed("MEDIA_HUMAN_REVIEW_MISSING")
    if not isinstance(evidence, dict):
        return _fail_closed("MEDIA_ESCALATION_EVIDENCE_MALFORMED")

    thresholds = resolved_policy["thresholds"]
    state = evidence.get("escalation_state")
    if state not in resolved_policy["escalation_states"]:
        return _fail_closed("MEDIA_ESCALATION_STATE_UNKNOWN")
    if evidence.get("escalation_chain_present") is not True:
        return _fail_closed("MEDIA_ESCALATION_CHAIN_MISSING")
    if evidence.get("human_review_completed") is not True:
        return _fail_closed("MEDIA_HUMAN_REVIEW_MISSING")
    if evidence.get("escalation_response_time", 0) > thresholds["escalation_response_time_seconds"]:
        return _fail_closed("MEDIA_ESCALATION_TIMEOUT")
    if evidence.get("governance_health_score", 100) <= thresholds["governance_critical_score"] and state != "ESCALATION_APPROVED":
        return _fail_closed("MEDIA_GOVERNANCE_CRITICAL_WITHOUT_REVIEW")
    if evidence.get("unresolved_escalations", 0) >= thresholds["unresolved_escalations"]:
        return _fail_closed("MEDIA_UNRESOLVED_ESCALATION")
    if evidence.get("repeated_crisis_events", 0) >= thresholds["repeated_crisis_events"]:
        return _fail_closed("MEDIA_REPEATED_CRISIS_EVENTS")
    if evidence.get("regulator_dispute_count", 0) >= thresholds["regulator_dispute_count"]:
        return _fail_closed("MEDIA_REGULATOR_DISPUTE_ESCALATION")
    if evidence.get("mass_revocation_count", 0) >= thresholds["mass_revocation_count"]:
        return _fail_closed("MEDIA_MASS_REVOCATION_EVENT")
    if evidence.get("unresolved_freeze_states", 0) >= thresholds["unresolved_freeze_states"]:
        return _fail_closed("MEDIA_UNRESOLVED_FREEZE_STATE")
    if evidence.get("multi_region_conflict") is True:
        return _fail_closed("MEDIA_MULTI_REGION_CRISIS_CONFLICT")
    if state in {"ESCALATION_PENDING", "ESCALATION_REVIEW_REQUIRED", "ESCALATION_IN_PROGRESS", "CRISIS_GOVERNANCE_ACTIVE"}:
        return _fail_closed("MEDIA_UNRESOLVED_CRISIS_STATE")
    if state in {"ESCALATION_REJECTED", "GOVERNANCE_FAIL_CLOSED"}:
        return _fail_closed("MEDIA_ESCALATION_REJECTED")

    return {
        "decision": "PASS",
        "escalation_state": state,
        "fail_closed": False,
        "human_escalation_audit_visible": True,
        "non_production_scaffolding": True,
        "reason": "MEDIA_HUMAN_ESCALATION_VALID",
    }


def verify_human_escalation_manifest(
    manifest: dict[str, Any] | None,
    *,
    policy: dict[str, Any] | None = None,
) -> dict[str, Any]:
    if manifest is None:
        return _fail_closed("MEDIA_ESCALATION_MANIFEST_MISSING")
    if not isinstance(manifest, dict):
        return _fail_closed("MEDIA_ESCALATION_MANIFEST_MALFORMED")
    if manifest.get("non_production_demo") is not True:
        return _fail_closed("MEDIA_ESCALATION_MANIFEST_SCOPE_UNCLEAR")
    flags = manifest.get("fail_closed_flags")
    if not isinstance(flags, dict) or any(value is not True for value in flags.values()):
        return _fail_closed("MEDIA_ESCALATION_FAIL_CLOSED_FLAGS_MISSING")
    evidence = {
        "escalation_chain_present": bool(manifest.get("escalation_review_reference")),
        "escalation_response_time": 300,
        "escalation_state": manifest.get("escalation_state"),
        "governance_health_score": manifest.get("governance_health_score"),
        "human_review_completed": True,
        "mass_revocation_count": 0,
        "multi_region_conflict": False,
        "regulator_dispute_count": manifest.get("regulator_dispute_count"),
        "repeated_crisis_events": manifest.get("crisis_event_count"),
        "unresolved_escalations": manifest.get("unresolved_escalations"),
        "unresolved_freeze_states": 0,
    }
    return verify_human_escalation(evidence, policy=policy)


def _fail_closed(reason: str) -> dict[str, Any]:
    return {"decision": "FAIL_CLOSED", "fail_closed": True, "reason": reason, "silent_pass": False}
