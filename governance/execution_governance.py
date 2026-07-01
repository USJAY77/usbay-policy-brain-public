from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from governance.execution_contracts import (
    BLOCKED_CAPABILITIES,
    EXECUTION_POLICY_VERSION,
    EXECUTION_REQUEST_SCHEMA,
    PREVIEW_CAPABILITIES,
    build_execution_audit_record,
    canonical_json,
    sha256_json,
    validate_execution_approval,
    validate_execution_request,
)


DECISION_ALLOWED_PREVIEW = "EXECUTION_ALLOWED_PREVIEW"
DECISION_HUMAN_REVIEW_REQUIRED = "HUMAN_REVIEW_REQUIRED"
DECISION_BLOCKED = "EXECUTION_BLOCKED"
EXECUTION_ENGINE_STATUS = "DISABLED"
ADAPTER_STATUS = "NOT_IMPLEMENTED"
DISABLED_ADAPTER_STATUS = "EXECUTION_DISABLED"

PRODUCTION_MARKERS = ("prod", "production", "release", "deploy", "promote")
UNKNOWN_TARGETS = frozenset({"", "unknown", "UNKNOWN", "UNSPECIFIED", "TBD"})


@dataclass(frozen=True)
class ExecutionGovernanceDecision:
    decision: str
    reason_codes: tuple[str, ...]
    policy_version: str
    audit_record: dict[str, Any]
    execution_engine_status: str = EXECUTION_ENGINE_STATUS
    adapter_status: str = ADAPTER_STATUS

    def to_dict(self) -> dict[str, Any]:
        return {
            "decision": self.decision,
            "reason_codes": list(self.reason_codes),
            "policy_version": self.policy_version,
            "audit_record": self.audit_record,
            "execution_engine_status": self.execution_engine_status,
            "adapter_status": self.adapter_status,
        }


def _now_text(now: datetime | None) -> str:
    effective_now = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    return effective_now.isoformat().replace("+00:00", "Z")


def _append_reason(reasons: list[str], code: str) -> None:
    if code not in reasons:
        reasons.append(code)


def state_hash(value: dict[str, Any] | None) -> str:
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


def _runtime_stale_or_pb020_missing(runtime_state: dict[str, Any] | None) -> list[str]:
    if not isinstance(runtime_state, dict):
        return ["EXEC_RUNTIME_STATE_MISSING"]
    reason_codes = runtime_state.get("reason_codes", [])
    if not isinstance(reason_codes, list):
        reason_codes = []
    reasons: list[str] = []
    if runtime_state.get("pb020_decision") in {"", "UNKNOWN", None}:
        reasons.append("EXEC_PB020_EVIDENCE_MISSING")
    if any("STALE" in str(code) for code in reason_codes):
        reasons.append("EXEC_PB020_EVIDENCE_STALE")
    return reasons


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


def _production_like(request: dict[str, Any] | None) -> bool:
    if not isinstance(request, dict):
        return False
    haystack = canonical_json(
        {
            "capability": request.get("capability", ""),
            "target": request.get("target", ""),
            "parameters": request.get("parameters", {}),
            "risk_level": request.get("risk_level", ""),
        }
    ).lower()
    return any(marker in haystack for marker in PRODUCTION_MARKERS)


def _security_sensitive(request: dict[str, Any] | None) -> bool:
    if not isinstance(request, dict):
        return True
    return str(request.get("capability", "")) in {"FILE_READ", "REPORT_GENERATION", "GOVERNANCE_STATUS_READ"} or _production_like(request)


def _result(
    *,
    request: dict[str, Any] | None,
    decision: str,
    reason_codes: list[str],
    previous_audit_hash: str,
    generated_at: str,
) -> ExecutionGovernanceDecision:
    safe_request = request if isinstance(request, dict) else {}
    policy_version = str(safe_request.get("policy_version") or EXECUTION_POLICY_VERSION)
    audit = build_execution_audit_record(
        request=request,
        decision=decision,
        reason_codes=reason_codes,
        previous_audit_hash=previous_audit_hash,
        generated_at=generated_at,
        adapter_status=DISABLED_ADAPTER_STATUS,
    )
    return ExecutionGovernanceDecision(
        decision=decision,
        reason_codes=tuple(sorted(set(reason_codes))),
        policy_version=policy_version,
        audit_record=audit,
    )


def evaluate_execution_governance(
    *,
    request: dict[str, Any] | None,
    runtime_state: dict[str, Any] | None,
    pbsec_state: dict[str, Any] | None,
    approval: dict[str, Any] | None = None,
    previous_audit_hash: str = "",
    now: datetime | None = None,
) -> ExecutionGovernanceDecision:
    generated_at = _now_text(now)
    reasons: list[str] = []

    validation = validate_execution_request(request)
    if not validation.valid:
        reasons.extend(validation.reason_codes)

    capability = str(request.get("capability", "") if isinstance(request, dict) else "")
    if capability in BLOCKED_CAPABILITIES:
        _append_reason(reasons, f"EXEC_REAL_CAPABILITY_BLOCKED:{capability}")
    elif capability and capability not in PREVIEW_CAPABILITIES:
        _append_reason(reasons, f"EXEC_UNKNOWN_CAPABILITY_BLOCKED:{capability}")

    if isinstance(request, dict):
        target = str(request.get("target", ""))
        if target in UNKNOWN_TARGETS:
            _append_reason(reasons, "EXEC_TARGET_UNKNOWN")

    if not _runtime_ready(runtime_state):
        _append_reason(reasons, "EXEC_RUNTIME_GOVERNANCE_STATE_INVALID")
    for reason in _runtime_stale_or_pb020_missing(runtime_state):
        _append_reason(reasons, reason)

    if _security_sensitive(request) and not _pbsec_ready(pbsec_state):
        _append_reason(reasons, "EXEC_PBSEC_STATE_INVALID")

    if _production_like(request):
        _append_reason(reasons, "EXEC_PRODUCTION_TARGET_BLOCKED")

    requires_human = bool(request.get("requires_human_approval") if isinstance(request, dict) else False)
    approval_valid = False
    if requires_human:
        if approval is None:
            _append_reason(reasons, "EXEC_HUMAN_APPROVAL_MISSING")
        else:
            effective_now = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
            approval_validation = validate_execution_approval(
                approval,
                request=request,
                expected_scope="PREVIEW_ONLY",
                pbsec_state=pbsec_state,
                now=effective_now,
            )
            approval_valid = approval_validation.valid
            if not approval_valid:
                reasons.extend(approval_validation.reason_codes)

    if reasons:
        return _result(
            request=request,
            decision=DECISION_BLOCKED,
            reason_codes=reasons,
            previous_audit_hash=previous_audit_hash,
            generated_at=generated_at,
        )

    _append_reason(reasons, "EXEC_ALLOWED_PREVIEW_ONLY")
    return _result(
        request=request,
        decision=DECISION_ALLOWED_PREVIEW,
        reason_codes=reasons,
        previous_audit_hash=previous_audit_hash,
        generated_at=generated_at,
    )


def empty_execution_dashboard_state() -> dict[str, Any]:
    request = {
        "schema": EXECUTION_REQUEST_SCHEMA,
        "request_id": "",
        "proposal_id": "",
        "capability": "",
        "target": "",
        "parameters": {},
        "requested_by": "",
        "requested_at": "",
        "policy_version": EXECUTION_POLICY_VERSION,
        "runtime_state_hash": "",
        "pbsec_state_hash": "",
        "vision_audit_hash": "",
        "requires_human_approval": True,
        "risk_level": "UNKNOWN",
    }
    decision = evaluate_execution_governance(
        request=None,
        runtime_state=None,
        pbsec_state=None,
    )
    return {
        "schema_version": "usbay.execution.demo_dashboard_state.v1",
        "execution_engine_status": EXECUTION_ENGINE_STATUS,
        "adapter_status": ADAPTER_STATUS,
        "latest_execution_request": request,
        "latest_execution_decision": decision.decision,
        "blocked_capabilities": sorted(BLOCKED_CAPABILITIES),
        "preview_only_capabilities": sorted(PREVIEW_CAPABILITIES),
        "required_human_approval": True,
        "reason_codes": list(decision.reason_codes),
        "audit_hash": decision.audit_record["audit_hash"],
        "production_release_blocked": True,
    }
