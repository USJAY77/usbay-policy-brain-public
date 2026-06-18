from __future__ import annotations

from typing import Any

from governance.release_gate_contracts import build_release_audit_record, validate_release_request


def evaluate_release_request(request: dict[str, Any] | None) -> dict[str, Any]:
    validation = validate_release_request(request)
    decision = "BLOCKED" if not validation.valid else "REVIEW_REQUIRED"
    return {
        "schema": "usbay.release.decision.v1",
        "release_gate_status": decision,
        "release_decision": decision,
        "reason_codes": list(validation.reason_codes),
        "audit_record": build_release_audit_record(release=request, action="request_evaluation", reason_codes=validation.reason_codes),
        "deploy_enabled": False,
        "publish_enabled": False,
        "merge_enabled": False,
        "push_enabled": False,
        "rollback_enabled": False,
        "restart_enabled": False,
        "promote_enabled": False,
        "activate_enabled": False,
    }


def evaluate_release_readiness(readiness: dict[str, Any] | None) -> dict[str, Any]:
    if not isinstance(readiness, dict):
        return {"release_readiness_status": "BLOCKED", "reason_codes": ["RELEASE_READINESS_MALFORMED"], "fail_closed": True}
    reasons = [str(code) for code in readiness.get("reason_codes", []) if code]
    status = "BLOCKED" if readiness.get("release_readiness_status") != "READY" or reasons else "APPROVED_FOR_RELEASE"
    return {
        "release_readiness_status": readiness.get("release_readiness_status", "BLOCKED"),
        "release_decision": status,
        "reason_codes": sorted(set(reasons)),
        "fail_closed": status != "APPROVED_FOR_RELEASE",
        "deploy_enabled": False,
        "rollback_enabled": False,
        "auto_promoted": False,
    }


def evaluate_release_decision(*, request: dict[str, Any] | None, readiness: dict[str, Any] | None) -> dict[str, Any]:
    request_result = evaluate_release_request(request)
    readiness_result = evaluate_release_readiness(readiness)
    reasons = sorted(set(request_result.get("reason_codes", []) + readiness_result.get("reason_codes", [])))
    if reasons or readiness_result.get("release_decision") != "APPROVED_FOR_RELEASE":
        decision = "BLOCKED"
    elif request and request.get("decision") == "APPROVED_FOR_RELEASE":
        decision = "APPROVED_FOR_RELEASE"
    else:
        decision = "REVIEW_REQUIRED"
    return {
        "schema": "usbay.release.decision.v1",
        "release_gate_status": decision,
        "release_decision": decision,
        "release_target_environment": str(request.get("target_environment", "") if isinstance(request, dict) else ""),
        "reason_codes": reasons,
        "fail_closed": decision != "APPROVED_FOR_RELEASE",
        "audit_record": build_release_audit_record(release=request, action="release_decision", reason_codes=reasons),
        "deploy_enabled": False,
        "publish_enabled": False,
        "merge_enabled": False,
        "push_enabled": False,
        "rollback_enabled": False,
        "restart_enabled": False,
        "promote_enabled": False,
        "activate_enabled": False,
    }


def empty_release_gate_dashboard_state() -> dict[str, Any]:
    return {
        "release_gate_status": "BLOCKED",
        "release_readiness_status": "BLOCKED",
        "release_decision": "BLOCKED",
        "release_target_environment": "",
        "release_manifest_status": "BLOCKED",
        "rollback_plan_status": "MISSING",
        "release_reason_codes": ["RELEASE_REQUEST_MISSING"],
        "auto_deployed": False,
        "auto_released": False,
        "auto_rolled_back": False,
        "auto_promoted": False,
    }
