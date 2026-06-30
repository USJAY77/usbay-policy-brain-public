from __future__ import annotations

import hashlib
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from governance.execution_contracts import (
    BLOCKED_CAPABILITIES,
    EXECUTION_POLICY_VERSION,
    EXECUTION_REQUEST_SCHEMA,
    PREVIEW_CAPABILITIES,
    canonical_json,
    sha256_json,
    validate_execution_approval,
)
from governance.execution_governance import (
    ADAPTER_STATUS,
    DECISION_ALLOWED_PREVIEW,
    DECISION_BLOCKED,
    DECISION_HUMAN_REVIEW_REQUIRED,
    EXECUTION_ENGINE_STATUS,
    evaluate_execution_governance,
    state_hash,
)
from governance.vision_agent_contracts import (
    BLOCKED_ACTION_TYPES,
    ACTION_PROPOSAL_SCHEMA,
    sanitize_for_vision_audit,
    validate_action_proposal,
)


BRIDGE_SCHEMA = "usbay.vision_execution.bridge.v1"
LINEAGE_SCHEMA = "usbay.vision_execution.audit_lineage.v1"
BRIDGE_POLICY_VERSION = "usbay.pb-vx.vision-execution-bridge.v1"

VISION_TO_EXECUTION_CAPABILITY = {
    "READ_ONLY_NAVIGATION": "READ_ONLY_NAVIGATION",
    "UI_INSPECTION": "DASHBOARD_PREVIEW",
    "COPY_TEXT": "REPORT_GENERATION",
    "PREPARE_COMMAND": "REPORT_GENERATION",
    "PREPARE_GITHUB_COMMENT": "ISSUE_COMMENT_DRAFT",
    "PREPARE_PR_DESCRIPTION": "PR_DESCRIPTION_DRAFT",
}

BLOCKED_MAPPINGS = frozenset(
    {
        *BLOCKED_ACTION_TYPES,
        "PRODUCTION_DEPLOY",
    }
)

SECRET_MARKERS = (
    "password",
    "secret",
    "token",
    "cookie",
    "authorization",
    "api_key",
    "apikey",
    "private_key",
    "credential",
    "session",
)
RAW_SCREENSHOT_KEYS = {
    "raw_screenshot",
    "raw_screenshot_payload",
    "screenshot_payload",
    "screenshot_bytes",
    "image_bytes",
    "base64_screenshot",
}
PRODUCTION_MARKERS = ("prod", "production", "release", "deploy", "promote")


@dataclass(frozen=True)
class BridgeResult:
    decision: str
    reason_codes: tuple[str, ...]
    bridge_contract: dict[str, Any]
    execution_request: dict[str, Any]
    execution_decision: dict[str, Any]
    audit_lineage: dict[str, Any]
    execution_engine_status: str = EXECUTION_ENGINE_STATUS
    adapter_status: str = ADAPTER_STATUS

    def to_dict(self) -> dict[str, Any]:
        return {
            "decision": self.decision,
            "reason_codes": list(self.reason_codes),
            "bridge_contract": self.bridge_contract,
            "execution_request": self.execution_request,
            "execution_decision": self.execution_decision,
            "audit_lineage": self.audit_lineage,
            "execution_engine_status": self.execution_engine_status,
            "adapter_status": self.adapter_status,
        }


def _now_text(now: datetime | None) -> str:
    effective_now = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    return effective_now.isoformat().replace("+00:00", "Z")


def _append_reason(reasons: list[str], code: str) -> None:
    if code not in reasons:
        reasons.append(code)


def _hash_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _id(prefix: str, payload: Any) -> str:
    return f"{prefix}-{sha256_json(payload)[:24]}"


def _production_like(value: Any) -> bool:
    haystack = canonical_json(value).lower()
    return any(marker in haystack for marker in PRODUCTION_MARKERS)


def _external_target(proposal: dict[str, Any]) -> bool:
    target = str(proposal.get("target", "")).lower()
    parameters = proposal.get("parameters", {})
    return target.startswith(("http://", "https://", "github:", "external:")) or (
        isinstance(parameters, dict) and bool(parameters.get("external_target"))
    )


def _redact_parameters(value: Any) -> Any:
    if isinstance(value, dict):
        redacted: dict[str, Any] = {}
        redacted_key_hashes: list[str] = []
        for key, item in value.items():
            key_text = str(key)
            lowered = key_text.lower()
            if key_text in RAW_SCREENSHOT_KEYS or any(marker in lowered for marker in SECRET_MARKERS):
                redacted_key_hashes.append(_hash_text(key_text))
                continue
            redacted[key_text] = _redact_parameters(item)
        if redacted_key_hashes:
            redacted["redacted_field_hashes"] = sorted(redacted_key_hashes)
        return redacted
    if isinstance(value, list):
        return [_redact_parameters(item) for item in value]
    return value


def requires_bridge_human_approval(proposal: dict[str, Any]) -> bool:
    action_type = str(proposal.get("action_type", ""))
    risk = str(proposal.get("risk_level", "")).upper()
    return (
        action_type in {"PREPARE_COMMAND", "PREPARE_GITHUB_COMMENT", "PREPARE_PR_DESCRIPTION"}
        or risk in {"MEDIUM", "HIGH"}
        or _external_target(proposal)
        or _production_like(proposal)
        or action_type in BLOCKED_MAPPINGS
    )


def map_proposal_to_execution_request(
    proposal: dict[str, Any] | None,
    *,
    observation_id: str,
    vision_audit_hash: str,
    runtime_state_hash: str,
    pbsec_state_hash: str,
    created_at: str,
) -> tuple[dict[str, Any], tuple[str, ...]]:
    reasons: list[str] = []
    if not isinstance(proposal, dict):
        return {}, ("VX_PROPOSAL_MISSING",)

    proposal_validation = validate_action_proposal(proposal)
    if not proposal_validation.valid:
        reasons.extend(proposal_validation.reason_codes)

    action_type = str(proposal.get("action_type", ""))
    if action_type in BLOCKED_MAPPINGS:
        _append_reason(reasons, f"VX_MAPPING_ACTION_BLOCKED:{action_type}")
    elif action_type not in VISION_TO_EXECUTION_CAPABILITY:
        _append_reason(reasons, f"VX_MAPPING_ACTION_UNKNOWN:{action_type or 'MISSING'}")

    capability = VISION_TO_EXECUTION_CAPABILITY.get(action_type, "")
    if capability in BLOCKED_CAPABILITIES:
        _append_reason(reasons, f"VX_MAPPING_CAPABILITY_BLOCKED:{capability}")
    elif capability and capability not in PREVIEW_CAPABILITIES:
        _append_reason(reasons, f"VX_MAPPING_CAPABILITY_UNKNOWN:{capability}")

    parameters = proposal.get("parameters", {})
    mapped_parameters = _redact_parameters(parameters if isinstance(parameters, dict) else {})
    request_seed = {
        "proposal_id": proposal.get("proposal_id", ""),
        "observation_id": observation_id,
        "capability": capability,
        "target": proposal.get("target", ""),
        "created_at": created_at,
    }
    request = {
        "schema": EXECUTION_REQUEST_SCHEMA,
        "request_id": _id("vx-exec-request", request_seed),
        "proposal_id": str(proposal.get("proposal_id", "")),
        "capability": capability,
        "target": str(proposal.get("target", "")),
        "parameters": mapped_parameters,
        "requested_by": str(proposal.get("requested_by_agent", "")),
        "requested_at": created_at,
        "policy_version": str(proposal.get("policy_version") or EXECUTION_POLICY_VERSION),
        "runtime_state_hash": runtime_state_hash,
        "pbsec_state_hash": pbsec_state_hash,
        "vision_audit_hash": vision_audit_hash,
        "requires_human_approval": requires_bridge_human_approval(proposal),
        "risk_level": str(proposal.get("risk_level", "")),
    }
    return request, tuple(sorted(set(reasons)))


def _approval_link_valid(approval: dict[str, Any] | None, *, proposal: dict[str, Any], request: dict[str, Any]) -> tuple[bool, list[str]]:
    reasons: list[str] = []
    if not isinstance(approval, dict):
        return False, ["VX_HUMAN_APPROVAL_MISSING"]
    if approval.get("proposal_id") != proposal.get("proposal_id"):
        reasons.append("VX_APPROVAL_PROPOSAL_LINK_MISMATCH")
    if approval.get("request_id") != request.get("request_id"):
        reasons.append("VX_APPROVAL_EXECUTION_REQUEST_LINK_MISMATCH")
    return not reasons, reasons


def _pbsec_005_verified(pbsec_state: dict[str, Any] | None) -> bool:
    if not isinstance(pbsec_state, dict):
        return False
    gate = pbsec_state.get("PB-SEC-005")
    if isinstance(gate, dict):
        return gate.get("state") == "VERIFIED" or gate.get("decision") in {"VERIFIED", "APPROVED"}
    gates = pbsec_state.get("gates")
    if isinstance(gates, dict):
        gate = gates.get("PB-SEC-005")
        return isinstance(gate, dict) and gate.get("decision") in {"VERIFIED", "APPROVED"} and gate.get("fail_closed") is False
    return pbsec_state.get("production_release_approved") is True and pbsec_state.get("status") in {"APPROVED", "VERIFIED", "READY"}


def build_bridge_contract(
    *,
    observation_id: str,
    proposal_id: str,
    execution_request_id: str,
    human_approval_id: str,
    execution_decision_id: str,
    vision_audit_hash: str,
    execution_audit_hash: str,
    runtime_state_hash: str,
    pbsec_state_hash: str,
    policy_version: str,
    created_at: str,
    fail_closed: bool,
    reason_codes: list[str] | tuple[str, ...],
) -> dict[str, Any]:
    return {
        "schema": BRIDGE_SCHEMA,
        "bridge_id": _id(
            "vx-bridge",
            {
                "observation_id": observation_id,
                "proposal_id": proposal_id,
                "execution_request_id": execution_request_id,
                "created_at": created_at,
            },
        ),
        "observation_id": str(observation_id),
        "proposal_id": str(proposal_id),
        "execution_request_id": str(execution_request_id),
        "human_approval_id": str(human_approval_id),
        "execution_decision_id": str(execution_decision_id),
        "vision_audit_hash": str(vision_audit_hash),
        "execution_audit_hash": str(execution_audit_hash),
        "runtime_state_hash": str(runtime_state_hash),
        "pbsec_state_hash": str(pbsec_state_hash),
        "policy_version": str(policy_version),
        "created_at": str(created_at),
        "fail_closed": bool(fail_closed),
        "reason_codes": sorted({str(code) for code in reason_codes if code}),
    }


def validate_bridge_contract(contract: dict[str, Any] | None) -> tuple[bool, tuple[str, ...]]:
    if not isinstance(contract, dict):
        return False, ("VX_BRIDGE_CONTRACT_MISSING",)
    reasons: list[str] = []
    required = (
        "observation_id",
        "proposal_id",
        "execution_request_id",
        "vision_audit_hash",
        "runtime_state_hash",
        "pbsec_state_hash",
        "policy_version",
    )
    for field in required:
        if contract.get(field) in ("", None):
            reasons.append(f"VX_BRIDGE_{field.upper()}_MISSING")
    if contract.get("schema") != BRIDGE_SCHEMA:
        reasons.append("VX_BRIDGE_SCHEMA_INVALID")
    return not reasons, tuple(sorted(set(reasons)))


def build_audit_lineage(
    *,
    observation: dict[str, Any] | None,
    proposal: dict[str, Any] | None,
    execution_request: dict[str, Any] | None,
    approval: dict[str, Any] | None,
    execution_decision: dict[str, Any] | None,
    previous_audit_hash: str,
    generated_at: str,
) -> dict[str, Any]:
    observation_hash = sha256_json(sanitize_for_vision_audit(observation or {}))
    proposal_hash = sha256_json(sanitize_for_vision_audit(proposal or {}))
    execution_request_hash = sha256_json(sanitize_for_vision_audit(execution_request or {}))
    approval_hash = sha256_json(sanitize_for_vision_audit(approval or {}))
    execution_decision_hash = sha256_json(sanitize_for_vision_audit(execution_decision or {}))
    missing_links = [
        name
        for name, payload in (
            ("observation_hash", observation),
            ("proposal_hash", proposal),
            ("execution_request_hash", execution_request),
            ("execution_decision_hash", execution_decision),
        )
        if not isinstance(payload, dict) or not payload
    ]
    lineage = {
        "schema": LINEAGE_SCHEMA,
        "observation_hash": observation_hash,
        "proposal_hash": proposal_hash,
        "execution_request_hash": execution_request_hash,
        "approval_hash": approval_hash,
        "execution_decision_hash": execution_decision_hash,
        "previous_audit_hash": str(previous_audit_hash),
        "lineage_hash": "",
        "generated_at": str(generated_at),
        "secrets_logged": False,
        "raw_payload_logged": False,
        "raw_screenshot_logged": False,
        "fail_closed": bool(missing_links),
        "reason_codes": [f"VX_LINEAGE_{link.upper()}_MISSING" for link in missing_links],
    }
    lineage["lineage_hash"] = sha256_json(lineage | {"lineage_hash": ""})
    return lineage


def evaluate_vision_execution_bridge(
    *,
    observation: dict[str, Any] | None,
    proposal: dict[str, Any] | None,
    vision_audit_hash: str,
    runtime_state: dict[str, Any] | None,
    pbsec_state: dict[str, Any] | None,
    approval: dict[str, Any] | None = None,
    previous_audit_hash: str = "",
    now: datetime | None = None,
) -> BridgeResult:
    created_at = _now_text(now)
    reasons: list[str] = []
    observation_id = str(observation.get("observation_id", "") if isinstance(observation, dict) else "")
    proposal_id = str(proposal.get("proposal_id", "") if isinstance(proposal, dict) else "")
    runtime_state_hash = state_hash(runtime_state)
    pbsec_state_hash = state_hash(pbsec_state)

    if not observation_id:
        _append_reason(reasons, "VX_OBSERVATION_ID_MISSING")
    if not proposal_id:
        _append_reason(reasons, "VX_PROPOSAL_ID_MISSING")
    if not vision_audit_hash:
        _append_reason(reasons, "VX_VISION_AUDIT_HASH_MISSING")
    if not runtime_state_hash:
        _append_reason(reasons, "VX_RUNTIME_STATE_HASH_MISSING")
    if not pbsec_state_hash:
        _append_reason(reasons, "VX_PBSEC_STATE_HASH_MISSING")

    request, mapping_reasons = map_proposal_to_execution_request(
        proposal,
        observation_id=observation_id,
        vision_audit_hash=vision_audit_hash,
        runtime_state_hash=runtime_state_hash,
        pbsec_state_hash=pbsec_state_hash,
        created_at=created_at,
    )
    reasons.extend(mapping_reasons)
    if not request.get("policy_version"):
        _append_reason(reasons, "VX_POLICY_VERSION_MISSING")
    if not request.get("request_id"):
        _append_reason(reasons, "VX_EXECUTION_REQUEST_ID_MISSING")
    if _production_like(request):
        _append_reason(reasons, "VX_PRODUCTION_OR_DEPLOY_TARGET_BLOCKED")

    requires_human = bool(request.get("requires_human_approval"))
    approval_for_execution = approval
    if requires_human:
        link_valid, link_reasons = _approval_link_valid(approval, proposal=proposal or {}, request=request)
        if not link_valid and approval is None and not reasons:
            execution_decision = {
                "decision": DECISION_HUMAN_REVIEW_REQUIRED,
                "reason_codes": ["VX_HUMAN_APPROVAL_MISSING"],
                "audit_record": {},
            }
            bridge_contract = build_bridge_contract(
                observation_id=observation_id,
                proposal_id=proposal_id,
                execution_request_id=str(request.get("request_id", "")),
                human_approval_id="",
                execution_decision_id=_id("vx-decision", execution_decision),
                vision_audit_hash=vision_audit_hash,
                execution_audit_hash="",
                runtime_state_hash=runtime_state_hash,
                pbsec_state_hash=pbsec_state_hash,
                policy_version=str(request.get("policy_version", "")),
                created_at=created_at,
                fail_closed=True,
                reason_codes=["VX_HUMAN_APPROVAL_MISSING"],
            )
            lineage = build_audit_lineage(
                observation=observation,
                proposal=proposal,
                execution_request=request,
                approval=approval,
                execution_decision=execution_decision,
                previous_audit_hash=previous_audit_hash,
                generated_at=created_at,
            )
            return BridgeResult(
                decision=DECISION_HUMAN_REVIEW_REQUIRED,
                reason_codes=("VX_HUMAN_APPROVAL_MISSING",),
                bridge_contract=bridge_contract,
                execution_request=request,
                execution_decision=execution_decision,
                audit_lineage=lineage,
            )
        reasons.extend(link_reasons)
        if isinstance(approval, dict):
            approval_validation = validate_execution_approval(
                approval,
                request=request,
                expected_scope="PREVIEW_ONLY",
                pbsec_state=pbsec_state,
                now=(now or datetime.now(timezone.utc)).astimezone(timezone.utc),
            )
            if not approval_validation.valid:
                reasons.extend(approval_validation.reason_codes)
            if _production_like(approval) and not _pbsec_005_verified(pbsec_state):
                _append_reason(reasons, "VX_APPROVAL_PRODUCTION_PBSEC005_NOT_VERIFIED")

    bridge_contract = build_bridge_contract(
        observation_id=observation_id,
        proposal_id=proposal_id,
        execution_request_id=str(request.get("request_id", "")),
        human_approval_id=str(approval.get("approval_id", "") if isinstance(approval, dict) else ""),
        execution_decision_id="",
        vision_audit_hash=vision_audit_hash,
        execution_audit_hash="",
        runtime_state_hash=runtime_state_hash,
        pbsec_state_hash=pbsec_state_hash,
        policy_version=str(request.get("policy_version", "")),
        created_at=created_at,
        fail_closed=bool(reasons),
        reason_codes=reasons,
    )
    valid_bridge, bridge_reasons = validate_bridge_contract(bridge_contract)
    if not valid_bridge:
        reasons.extend(bridge_reasons)

    if reasons:
        execution_decision = {
            "decision": DECISION_BLOCKED,
            "reason_codes": sorted(set(reasons)),
            "audit_record": {},
        }
    else:
        execution_result = evaluate_execution_governance(
            request=request,
            runtime_state=runtime_state,
            pbsec_state=pbsec_state,
            approval=approval_for_execution,
            previous_audit_hash=previous_audit_hash,
            now=now,
        )
        execution_decision = execution_result.to_dict()
        reasons.extend(execution_result.reason_codes)

    decision = str(execution_decision.get("decision", DECISION_BLOCKED))
    execution_audit_hash = ""
    audit_record = execution_decision.get("audit_record", {})
    if isinstance(audit_record, dict):
        execution_audit_hash = str(audit_record.get("audit_hash", ""))
    execution_decision_id = _id("vx-decision", execution_decision)
    bridge_contract = bridge_contract | {
        "execution_decision_id": execution_decision_id,
        "execution_audit_hash": execution_audit_hash,
        "fail_closed": decision != DECISION_ALLOWED_PREVIEW,
        "reason_codes": sorted(set(reasons)),
    }
    lineage = build_audit_lineage(
        observation=observation,
        proposal=proposal,
        execution_request=request,
        approval=approval,
        execution_decision=execution_decision,
        previous_audit_hash=previous_audit_hash,
        generated_at=created_at,
    )
    return BridgeResult(
        decision=decision,
        reason_codes=tuple(sorted(set(reasons))),
        bridge_contract=bridge_contract,
        execution_request=request,
        execution_decision=execution_decision,
        audit_lineage=lineage,
    )


def empty_bridge_dashboard_state() -> dict[str, Any]:
    result = evaluate_vision_execution_bridge(
        observation=None,
        proposal=None,
        vision_audit_hash="",
        runtime_state=None,
        pbsec_state=None,
    )
    return {
        "schema_version": "usbay.vision_execution.demo_dashboard_state.v1",
        "latest_observation_id": "",
        "latest_proposal_id": "",
        "latest_execution_request_id": "",
        "latest_human_approval_status": "MISSING",
        "latest_execution_decision": result.decision,
        "bridge_status": DECISION_BLOCKED,
        "lineage_hash": result.audit_lineage["lineage_hash"],
        "reason_codes": list(result.reason_codes),
        "adapter_status": ADAPTER_STATUS,
        "execution_engine_status": EXECUTION_ENGINE_STATUS,
    }
