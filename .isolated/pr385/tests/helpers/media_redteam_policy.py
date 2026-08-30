from __future__ import annotations

import json
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
POLICY_PATH = ROOT / "governance" / "media_redteam_policy.json"
MANIFEST_PATH = ROOT / "artifacts" / "media-redteam-governance-manifest.json"

ATTACK_STATES = {
    "ADVERSARIAL_GOVERNANCE_DETECTED": "MEDIA_ADVERSARIAL_GOVERNANCE_DETECTED",
    "LINEAGE_COMPROMISE_DETECTED": "MEDIA_LINEAGE_CORRUPTION_DETECTED",
    "APPROVAL_FORGERY_DETECTED": "MEDIA_FORGED_APPROVAL_CHAIN_DETECTED",
    "DISTRIBUTION_SPOOF_DETECTED": "MEDIA_DISTRIBUTION_SCOPE_SPOOFING_DETECTED",
    "GOVERNANCE_BYPASS_ATTEMPT": "MEDIA_GOVERNANCE_BYPASS_ATTEMPT",
    "GOVERNANCE_FAIL_CLOSED": "MEDIA_ADVERSARIAL_GOVERNANCE_FAIL_CLOSED",
}

METRIC_FAILURES = {
    "export_tamper_events": "MEDIA_EXPORT_MANIFEST_TAMPERING_DETECTED",
    "fake_escalation_attempts": "MEDIA_FAKE_HUMAN_ESCALATION_DETECTED",
    "forged_approval_attempts": "MEDIA_FORGED_APPROVAL_CHAIN_DETECTED",
    "governance_bypass_attempts": "MEDIA_GOVERNANCE_BYPASS_ATTEMPT",
    "lineage_corruption_events": "MEDIA_LINEAGE_CORRUPTION_DETECTED",
    "replay_attack_attempts": "MEDIA_TIMESTAMP_REPLAY_ATTACK_DETECTED",
    "spoofed_distribution_events": "MEDIA_DISTRIBUTION_SCOPE_SPOOFING_DETECTED",
}


def load_media_redteam_policy(path: Path = POLICY_PATH) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def load_media_redteam_manifest(path: Path = MANIFEST_PATH) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def valid_redteam_evidence() -> dict[str, Any]:
    return {
        "adversarial_event_type": "GOVERNANCE_ATTACK_SIMULATION",
        "cross_region_policy_conflict_attack": False,
        "export_tamper_events": 0,
        "fake_escalation_attempts": 0,
        "forged_approval_attempts": 0,
        "governance_attack_state": "GOVERNANCE_ATTACK_SIMULATION",
        "governance_bypass_attempts": 0,
        "lineage_corruption_events": 0,
        "mass_governance_drift_event": False,
        "non_production_demo": True,
        "recovery_bypass_attempt": False,
        "replay_attack_attempts": 0,
        "spoofed_distribution_events": 0,
        "watchtower_suppression_attempt": False,
    }


def verify_media_redteam(
    evidence: dict[str, Any] | None,
    *,
    policy: dict[str, Any] | None = None,
) -> dict[str, Any]:
    resolved_policy = policy or load_media_redteam_policy()
    if resolved_policy.get("non_production_scaffolding") is not True:
        return _fail_closed("MEDIA_REDTEAM_POLICY_SCOPE_UNCLEAR")
    if resolved_policy.get("adversarial_governance_testing_enabled") is not True:
        return _fail_closed("MEDIA_REDTEAM_TESTING_DISABLED")
    if evidence is None:
        return _fail_closed("MEDIA_REDTEAM_EVIDENCE_MISSING")
    if not isinstance(evidence, dict):
        return _fail_closed("MEDIA_REDTEAM_EVIDENCE_MALFORMED")
    if evidence.get("non_production_demo") is not True:
        return _fail_closed("MEDIA_REDTEAM_EVIDENCE_SCOPE_UNCLEAR")

    state = evidence.get("governance_attack_state")
    if state not in resolved_policy["adversarial_governance_states"]:
        return _fail_closed("MEDIA_REDTEAM_ATTACK_STATE_UNKNOWN")
    if state in ATTACK_STATES:
        return _fail_closed(ATTACK_STATES[state], audit_visible=True)

    thresholds = resolved_policy["thresholds"]
    for metric, reason in METRIC_FAILURES.items():
        if evidence.get(metric, 0) >= thresholds[metric]:
            return _fail_closed(reason, audit_visible=True)

    if evidence.get("recovery_bypass_attempt") is True:
        return _fail_closed("MEDIA_RECOVERY_BYPASS_ATTEMPT", audit_visible=True)
    if evidence.get("watchtower_suppression_attempt") is True:
        return _fail_closed("MEDIA_WATCHTOWER_SUPPRESSION_ATTEMPT", audit_visible=True)
    if evidence.get("cross_region_policy_conflict_attack") is True:
        return _fail_closed("MEDIA_CROSS_REGION_POLICY_CONFLICT_ATTACK", audit_visible=True)
    if evidence.get("mass_governance_drift_event") is True:
        return _fail_closed("MEDIA_MASS_GOVERNANCE_DRIFT_EVENT", audit_visible=True)

    return {
        "adversarial_governance_audit_visible": True,
        "decision": "PASS",
        "fail_closed": False,
        "non_production_scaffolding": True,
        "reason": "MEDIA_REDTEAM_GOVERNANCE_CLEAR",
    }


def verify_media_redteam_manifest(
    manifest: dict[str, Any] | None,
    *,
    policy: dict[str, Any] | None = None,
) -> dict[str, Any]:
    if manifest is None:
        return _fail_closed("MEDIA_REDTEAM_MANIFEST_MISSING")
    if not isinstance(manifest, dict):
        return _fail_closed("MEDIA_REDTEAM_MANIFEST_MALFORMED")
    if manifest.get("non_production_demo") is not True:
        return _fail_closed("MEDIA_REDTEAM_MANIFEST_SCOPE_UNCLEAR")
    flags = manifest.get("fail_closed_flags")
    if not isinstance(flags, dict) or any(value is not True for value in flags.values()):
        return _fail_closed("MEDIA_REDTEAM_FAIL_CLOSED_FLAGS_MISSING")

    evidence = valid_redteam_evidence()
    evidence.update(
        {
            "adversarial_event_type": manifest.get("adversarial_event_type"),
            "export_tamper_events": manifest.get("export_tamper_events", 0),
            "fake_escalation_attempts": manifest.get("fake_escalation_attempts", 0),
            "forged_approval_attempts": manifest.get("forged_approval_attempts", 0),
            "governance_attack_state": manifest.get("governance_attack_state"),
            "governance_bypass_attempts": manifest.get("governance_bypass_attempts", 0),
            "lineage_corruption_events": manifest.get("lineage_corruption_events", 0),
            "replay_attack_attempts": manifest.get("replay_attack_attempts", 0),
            "spoofed_distribution_events": manifest.get("spoofed_distribution_events", 0),
        }
    )
    return verify_media_redteam(evidence, policy=policy)


def _fail_closed(reason: str, *, audit_visible: bool = False) -> dict[str, Any]:
    evidence: dict[str, Any] = {"decision": "FAIL_CLOSED", "fail_closed": True, "reason": reason, "silent_pass": False}
    if audit_visible:
        evidence["adversarial_governance_audit_visible"] = True
    return evidence
