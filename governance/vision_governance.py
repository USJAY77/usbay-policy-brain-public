from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from governance.vision_agent_contracts import (
    ALLOWED_PREVIEW_ACTION_TYPES,
    BLOCKED_ACTION_TYPES,
    OBSERVATION_SCHEMA,
    ACTION_PROPOSAL_SCHEMA,
    build_vision_audit_record,
    canonical_json,
    sha256_json,
    validate_action_proposal,
    validate_vision_human_approval,
    validate_vision_observation,
)


VISION_POLICY_VERSION = "usbay.pb-vision.governed-agent-control.v1"
DECISION_ALLOWED_PREVIEW = "ALLOWED_PREVIEW"
DECISION_HUMAN_REVIEW_REQUIRED = "HUMAN_REVIEW_REQUIRED"
DECISION_BLOCKED = "BLOCKED"
EXECUTION_ADAPTER_STATUS = "DISABLED"
LOW_CONFIDENCE_THRESHOLD = 0.70

PRODUCTION_MARKERS = (
    "prod",
    "production",
    "release",
    "promote",
    "main",
    "master",
)

VISION_REASON_CODE_MAP = {
    "VISION_OBSERVATION_MISSING": "VISION_OBSERVATION_MISSING",
    "VISION_ALLOWED_PREVIEW_ONLY": "VISION_ACTION_BLOCKED",
    "VISION_LOW_CONFIDENCE_REQUIRES_HUMAN_REVIEW": "VISION_ACTION_BLOCKED",
    "VISION_HUMAN_APPROVAL_REQUIRED": "VISION_ACTION_BLOCKED",
}


@dataclass(frozen=True)
class VisionGovernanceDecision:
    decision: str
    reason_codes: tuple[str, ...]
    policy_version: str
    audit_record: dict[str, Any]
    execution_adapter_status: str = EXECUTION_ADAPTER_STATUS

    def to_dict(self) -> dict[str, Any]:
        return {
            "decision": self.decision,
            "reason_codes": list(self.reason_codes),
            "policy_version": self.policy_version,
            "audit_record": self.audit_record,
            "execution_adapter_status": self.execution_adapter_status,
        }


def _now_text(now: datetime | None) -> str:
    effective_now = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    return effective_now.isoformat().replace("+00:00", "Z")


def _hash_state(value: Any) -> str:
    if not isinstance(value, dict):
        return ""
    return sha256_json(value)


def _runtime_ready(runtime_state: dict[str, Any] | None) -> bool:
    return (
        isinstance(runtime_state, dict)
        and runtime_state.get("status") == "READY"
        and runtime_state.get("fail_closed") is False
        and bool(runtime_state.get("evidence_hash"))
    )


def _pbsec_ready(pbsec_state: dict[str, Any] | None) -> bool:
    if not isinstance(pbsec_state, dict):
        return False
    if pbsec_state.get("status") in {"APPROVED", "VERIFIED", "READY"} and pbsec_state.get("production_release_approved") is True:
        return True
    gates = pbsec_state.get("gates")
    if isinstance(gates, dict) and gates:
        return all(
            isinstance(gate, dict)
            and gate.get("decision") in {"VERIFIED", "APPROVED"}
            and gate.get("fail_closed") is False
            for gate in gates.values()
        )
    return False


def _production_like(proposal: dict[str, Any] | None) -> bool:
    if not isinstance(proposal, dict):
        return False
    haystack = canonical_json(
        {
            "requested_action": proposal.get("requested_action", ""),
            "target": proposal.get("target", ""),
            "parameters": proposal.get("parameters", {}),
            "reason": proposal.get("reason", ""),
            "risk_level": proposal.get("risk_level", ""),
        }
    ).lower()
    return any(marker in haystack for marker in PRODUCTION_MARKERS) or str(proposal.get("risk_level", "")).upper() == "HIGH"


def _append_reason(reasons: list[str], code: str) -> None:
    if code not in reasons:
        reasons.append(code)


def canonical_vision_reason_codes(reason_codes: list[str] | tuple[str, ...]) -> list[str]:
    canonical: list[str] = []
    for reason in reason_codes:
        reason_text = str(reason)
        mapped = VISION_REASON_CODE_MAP.get(reason_text)
        if mapped is None and reason_text.startswith("VISION_OBSERVATION_"):
            mapped = "VISION_OBSERVATION_MISSING"
        if mapped is None and reason_text.startswith(("VISION_PROPOSAL_", "VISION_EXECUTION_", "VISION_UNKNOWN_")):
            mapped = "VISION_ACTION_BLOCKED"
        if mapped is None and reason_text.startswith(("VISION_RUNTIME_", "VISION_PBSEC_", "VISION_APPROVAL_")):
            mapped = "VISION_GOVERNANCE_BYPASS"
        if mapped is None and reason_text.startswith("VISION_"):
            mapped = "VISION_GOVERNANCE_BYPASS"
        if mapped and mapped not in canonical:
            canonical.append(mapped)
    return sorted(canonical)


def _decision_result(
    *,
    observation: dict[str, Any] | None,
    proposal: dict[str, Any] | None,
    decision: str,
    reason_codes: list[str],
    runtime_state: dict[str, Any] | None,
    pbsec_state: dict[str, Any] | None,
    previous_audit_hash: str,
    generated_at: str,
) -> VisionGovernanceDecision:
    safe_proposal = proposal if isinstance(proposal, dict) else {}
    policy_version = str(safe_proposal.get("policy_version") or VISION_POLICY_VERSION)
    audit_record = build_vision_audit_record(
        observation=observation,
        proposal=proposal,
        decision=decision,
        reason_codes=reason_codes,
        policy_version=policy_version,
        runtime_state_hash=_hash_state(runtime_state),
        pbsec_state_hash=_hash_state(pbsec_state),
        previous_audit_hash=previous_audit_hash,
        generated_at=generated_at,
    )
    return VisionGovernanceDecision(
        decision=decision,
        reason_codes=tuple(sorted(set(reason_codes))),
        policy_version=policy_version,
        audit_record=audit_record,
    )


def evaluate_vision_governance(
    *,
    observation: dict[str, Any] | None,
    proposal: dict[str, Any] | None,
    runtime_state: dict[str, Any] | None,
    pbsec_state: dict[str, Any] | None,
    approval: dict[str, Any] | None = None,
    previous_audit_hash: str = "",
    now: datetime | None = None,
) -> VisionGovernanceDecision:
    generated_at = _now_text(now)
    reasons: list[str] = []

    observation_validation = validate_vision_observation(observation)
    if not observation_validation.valid:
        reasons.extend(observation_validation.reason_codes)

    proposal_validation = validate_action_proposal(proposal)
    if not proposal_validation.valid:
        reasons.extend(proposal_validation.reason_codes)

    action_type = str(proposal.get("action_type", "") if isinstance(proposal, dict) else "")
    if action_type in BLOCKED_ACTION_TYPES:
        _append_reason(reasons, f"VISION_EXECUTION_ACTION_BLOCKED:{action_type}")
    if action_type and action_type not in ALLOWED_PREVIEW_ACTION_TYPES and action_type not in BLOCKED_ACTION_TYPES:
        _append_reason(reasons, f"VISION_UNKNOWN_ACTION_BLOCKED:{action_type}")

    if not _runtime_ready(runtime_state):
        _append_reason(reasons, "VISION_RUNTIME_GOVERNANCE_STATE_INVALID")

    prod_like = _production_like(proposal)
    if prod_like and not _pbsec_ready(pbsec_state):
        _append_reason(reasons, "VISION_PBSEC_STATE_INVALID_FOR_PRODUCTION")

    if isinstance(proposal, dict) and isinstance(observation, dict):
        if proposal.get("observation_id") != observation.get("observation_id"):
            _append_reason(reasons, "VISION_PROPOSAL_OBSERVATION_MISMATCH")
        if proposal.get("device_id") != observation.get("device_id"):
            _append_reason(reasons, "VISION_PROPOSAL_DEVICE_MISMATCH")

    confidence_values = []
    if isinstance(observation, dict) and isinstance(observation.get("confidence"), (int, float)):
        confidence_values.append(float(observation["confidence"]))
    if isinstance(proposal, dict) and isinstance(proposal.get("confidence"), (int, float)):
        confidence_values.append(float(proposal["confidence"]))
    low_confidence = bool(confidence_values) and min(confidence_values) < LOW_CONFIDENCE_THRESHOLD
    if low_confidence:
        _append_reason(reasons, "VISION_LOW_CONFIDENCE_REQUIRES_HUMAN_REVIEW")

    requires_human = bool(proposal.get("requires_human_approval") if isinstance(proposal, dict) else False) or prod_like
    approval_valid = False
    if requires_human and approval is not None:
        effective_now = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
        approval_validation = validate_vision_human_approval(
            approval,
            proposal=proposal,
            expected_scope="REVIEW_ONLY",
            now=effective_now,
        )
        approval_valid = approval_validation.valid
        if not approval_valid:
            reasons.extend(approval_validation.reason_codes)

    blocking_reasons = [
        reason
        for reason in reasons
        if reason
        and reason
        not in {
            "VISION_LOW_CONFIDENCE_REQUIRES_HUMAN_REVIEW",
        }
    ]
    if blocking_reasons:
        return _decision_result(
            observation=observation,
            proposal=proposal,
            decision=DECISION_BLOCKED,
            reason_codes=reasons,
            runtime_state=runtime_state,
            pbsec_state=pbsec_state,
            previous_audit_hash=previous_audit_hash,
            generated_at=generated_at,
        )

    if low_confidence:
        return _decision_result(
            observation=observation,
            proposal=proposal,
            decision=DECISION_HUMAN_REVIEW_REQUIRED,
            reason_codes=reasons,
            runtime_state=runtime_state,
            pbsec_state=pbsec_state,
            previous_audit_hash=previous_audit_hash,
            generated_at=generated_at,
        )

    if requires_human and not approval_valid:
        _append_reason(reasons, "VISION_HUMAN_APPROVAL_REQUIRED")
        return _decision_result(
            observation=observation,
            proposal=proposal,
            decision=DECISION_HUMAN_REVIEW_REQUIRED,
            reason_codes=reasons,
            runtime_state=runtime_state,
            pbsec_state=pbsec_state,
            previous_audit_hash=previous_audit_hash,
            generated_at=generated_at,
        )

    if action_type == "READ_ONLY_NAVIGATION":
        _append_reason(reasons, "VISION_ALLOWED_PREVIEW_ONLY")
        return _decision_result(
            observation=observation,
            proposal=proposal,
            decision=DECISION_ALLOWED_PREVIEW,
            reason_codes=reasons,
            runtime_state=runtime_state,
            pbsec_state=pbsec_state,
            previous_audit_hash=previous_audit_hash,
            generated_at=generated_at,
        )

    _append_reason(reasons, "VISION_REVIEW_ONLY_PREVIEW_REQUIRED")
    return _decision_result(
        observation=observation,
        proposal=proposal,
        decision=DECISION_HUMAN_REVIEW_REQUIRED,
        reason_codes=reasons,
        runtime_state=runtime_state,
        pbsec_state=pbsec_state,
        previous_audit_hash=previous_audit_hash,
        generated_at=generated_at,
    )


def empty_vision_dashboard_state() -> dict[str, Any]:
    observation = {
        "schema": OBSERVATION_SCHEMA,
        "observation_id": "",
        "generated_at": "",
        "device_id": "",
        "source": "UNAVAILABLE",
        "screenshot_hash": "",
        "redaction_applied": True,
        "raw_screenshot_logged": False,
        "detected_ui_elements": [],
        "detected_text_summary": "",
        "confidence": 0.0,
        "errors": ["VISION_OBSERVATION_MISSING"],
    }
    proposal = {
        "schema": ACTION_PROPOSAL_SCHEMA,
        "proposal_id": "",
        "observation_id": "",
        "requested_action": "",
        "action_type": "UI_INSPECTION",
        "target": "",
        "parameters": {},
        "reason": "",
        "confidence": 0.0,
        "requested_by_agent": "",
        "device_id": "",
        "policy_version": VISION_POLICY_VERSION,
        "requires_human_approval": True,
        "risk_level": "UNKNOWN",
        "created_at": "",
    }
    decision = evaluate_vision_governance(
        observation=None,
        proposal=None,
        runtime_state=None,
        pbsec_state=None,
    )
    vision_reason_codes = canonical_vision_reason_codes(decision.reason_codes)
    return {
        "schema_version": "usbay.vision.demo_dashboard_state.v1",
        "latest_observation_status": "BLOCKED",
        "latest_action_proposal_status": decision.decision,
        "audit_status": "VALID",
        "evidence_status": "VALID",
        "lineage_status": "VALID",
        "human_approval_status": "REQUIRED",
        "blocked_action_types": sorted(BLOCKED_ACTION_TYPES),
        "allowed_preview_action_types": sorted(ALLOWED_PREVIEW_ACTION_TYPES),
        "human_approval_required": True,
        "audit_hash": decision.audit_record["audit_hash"],
        "vision_reason_codes": vision_reason_codes,
        "reason_codes": vision_reason_codes,
        "raw_reason_codes": list(decision.reason_codes),
        "raw_screenshot_not_stored": observation["raw_screenshot_logged"] is False,
        "execution_adapter_status": EXECUTION_ADAPTER_STATUS,
        "observation": observation,
        "proposal": proposal,
    }
