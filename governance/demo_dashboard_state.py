from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from governance.runtime_governance_state import DEFAULT_MAX_AGE_HOURS, runtime_governance_state_snapshot
from governance.execution_governance import empty_execution_dashboard_state
from governance.vision_governance import empty_vision_dashboard_state
from governance.vision_execution_bridge import empty_bridge_dashboard_state
from governance.operator_queue import empty_operator_queue_dashboard_state
from governance.work_orchestrator import empty_work_orchestrator_dashboard_state
from governance.governance_metrics import empty_metrics_dashboard_state
from governance.evidence_verifier import empty_evidence_trust_dashboard_state
from governance.connector_registry import empty_connector_dashboard_state
from governance.runtime_observability import empty_runtime_observation_dashboard_state
from governance.audit_registry import empty_audit_registry_dashboard_state
from governance.policy_registry import empty_policy_registry_dashboard_state
from governance.release_gate import empty_release_gate_dashboard_state


VERIFIED = "VERIFIED"
BLOCKED = "BLOCKED"
MISSING = "MISSING"
STALE = "STALE"
MALFORMED = "MALFORMED"

PB_EVIDENCE: dict[str, tuple[str, ...]] = {
    "PB-015": (
        "governance/evidence/pb015_maturity/pb015_maturity_report.json",
        "governance/evidence/pb015_maturity/pb015_capability_matrix.json",
        "governance/evidence/pb015_maturity/pb015_governance_scorecard.json",
    ),
    "PB-016": (
        "governance/evidence/pb016_improvement/pb016_governance_improvement_plan.json",
        "governance/evidence/pb016_improvement/pb016_governance_priority_matrix.json",
        "governance/evidence/pb016_improvement/pb016_governance_roadmap.json",
        "governance/evidence/pb016_improvement/pb016_governance_action_register.json",
    ),
    "PB-017": (
        "governance/evidence/pb017_action_tracking/pb017_governance_action_tracker.json",
        "governance/evidence/pb017_action_tracking/pb017_governance_progress_report.json",
        "governance/evidence/pb017_action_tracking/pb017_governance_completion_report.json",
        "governance/evidence/pb017_action_tracking/pb017_governance_status_dashboard.json",
    ),
    "PB-018": (
        "governance/evidence/pb018_agent_governance/pb018_agent_governance_certificate.json",
        "governance/evidence/pb018_agent_governance/pb018_agent_risk_assessment.json",
        "governance/evidence/pb018_agent_governance/pb018_agent_scorecard.json",
        "governance/evidence/pb018_agent_governance/pb018_agent_attestation.json",
    ),
    "PB-019": (
        "governance/evidence/pb019_certification_explanation/pb019_certification_failure_report.json",
        "governance/evidence/pb019_certification_explanation/pb019_certification_gap_report.json",
        "governance/evidence/pb019_certification_explanation/pb019_required_actions.json",
        "governance/evidence/pb019_certification_explanation/pb019_certification_explanation.json",
    ),
    "PB-020": (
        "governance/evidence/pb020_freshness_report.json",
        "governance/evidence/pb020_staleness_report.json",
        "governance/evidence/pb020_version_alignment_report.json",
        "governance/evidence/pb020_evidence_freshness_scorecard.json",
    ),
}

PBSEC_EVIDENCE: dict[str, tuple[str, ...]] = {
    "PB-SEC-001": ("governance/evidence/pbsec001_zap/zap_security_gate.json",),
    "PB-SEC-002": ("governance/evidence/pbsec002_dependency_security/dependency_security_gate.json",),
    "PB-SEC-003": ("governance/evidence/pbsec003_authentication_security/authentication_security_gate.json",),
    "PB-SEC-004": ("governance/evidence/pbsec004_external_pentest/external_pentest_gate.json",),
    "PB-SEC-005": ("governance/evidence/pbsec005_production_release/production_release_gate.json",),
}

LINEAGE = (
    "PB-015",
    "PB-016",
    "PB-017",
    "PB-018",
    "PB-020",
    "Runtime",
    "Promote",
    "Production",
)


def _parse_timestamp(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _read_json_record(root: Path, relative_path: str, *, now: datetime, max_age_hours: float) -> dict[str, Any]:
    path = root / relative_path
    if not path.is_file():
        return {
            "source_file": relative_path,
            "state": MISSING,
            "decision": MISSING,
            "fail_closed": True,
            "generated_at": "",
            "errors": [f"EVIDENCE_MISSING:{relative_path}"],
            "blockers": [f"EVIDENCE_MISSING:{relative_path}"],
        }
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return {
            "source_file": relative_path,
            "state": MALFORMED,
            "decision": BLOCKED,
            "fail_closed": True,
            "generated_at": "",
            "errors": [f"EVIDENCE_MALFORMED:{relative_path}"],
            "blockers": [f"EVIDENCE_MALFORMED:{relative_path}"],
        }
    if not isinstance(payload, dict):
        return {
            "source_file": relative_path,
            "state": MALFORMED,
            "decision": BLOCKED,
            "fail_closed": True,
            "generated_at": "",
            "errors": [f"EVIDENCE_OBJECT_REQUIRED:{relative_path}"],
            "blockers": [f"EVIDENCE_OBJECT_REQUIRED:{relative_path}"],
        }

    raw_errors = payload.get("errors", [])
    errors = [str(error) for error in raw_errors] if isinstance(raw_errors, list) else ["EVIDENCE_ERRORS_MALFORMED"]
    generated_at = str(payload.get("generated_at", ""))
    parsed = _parse_timestamp(generated_at)
    stale = False
    if parsed is None:
        errors.append("EVIDENCE_TIMESTAMP_MISSING_OR_INVALID")
    else:
        age_hours = (now - parsed).total_seconds() / 3600
        stale = age_hours < 0 or age_hours > max_age_hours
        if stale:
            errors.append("EVIDENCE_STALE")

    decision = str(payload.get("decision", "UNKNOWN"))
    fail_closed = payload.get("fail_closed") is not False
    if stale:
        state = STALE
    elif decision == VERIFIED and not fail_closed and not errors:
        state = VERIFIED
    else:
        state = BLOCKED

    return {
        "source_file": relative_path,
        "state": state,
        "decision": decision,
        "fail_closed": fail_closed or state != VERIFIED,
        "generated_at": generated_at,
        "errors": errors,
        "blockers": errors if state != VERIFIED else [],
    }


def _group_status(records: list[dict[str, Any]]) -> str:
    states = {record["state"] for record in records}
    if MALFORMED in states:
        return MALFORMED
    if MISSING in states:
        return MISSING
    if STALE in states:
        return STALE
    if BLOCKED in states:
        return BLOCKED
    return VERIFIED


def _summarize_group(group_id: str, paths: tuple[str, ...], *, root: Path, now: datetime, max_age_hours: float) -> dict[str, Any]:
    records = [_read_json_record(root, path, now=now, max_age_hours=max_age_hours) for path in paths]
    blockers = [blocker for record in records for blocker in record["blockers"]]
    return {
        "id": group_id,
        "state": _group_status(records),
        "decision": VERIFIED if all(record["decision"] == VERIFIED for record in records) else BLOCKED,
        "fail_closed": any(record["fail_closed"] for record in records),
        "generated_at": max((record["generated_at"] for record in records if record["generated_at"]), default=""),
        "errors": [error for record in records for error in record["errors"]],
        "blockers": blockers,
        "source_files": list(paths),
        "files": records,
    }


def build_governance_demo_state(
    *,
    root: Path,
    runtime_snapshot: dict[str, Any] | None = None,
    deployment_snapshot: dict[str, Any] | None = None,
    max_age_hours: float = DEFAULT_MAX_AGE_HOURS,
    now: datetime | None = None,
) -> dict[str, Any]:
    effective_now = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    pb_status = {
        group_id: _summarize_group(group_id, paths, root=root, now=effective_now, max_age_hours=max_age_hours)
        for group_id, paths in PB_EVIDENCE.items()
    }
    pbsec_status = {
        group_id: _summarize_group(group_id, paths, root=root, now=effective_now, max_age_hours=max_age_hours)
        for group_id, paths in PBSEC_EVIDENCE.items()
    }
    runtime_governance = runtime_governance_state_snapshot(root=root, max_age_hours=max_age_hours)
    deployment = deployment_snapshot if isinstance(deployment_snapshot, dict) else {}
    runtime = runtime_snapshot if isinstance(runtime_snapshot, dict) else {}
    promote_state = str(runtime_governance.get("promote_state", "PROMOTE_BLOCKED"))
    security_chain = runtime_governance.get("security_gate_chain")
    if not isinstance(security_chain, dict):
        security_chain = {}
    security_blockers = security_chain.get("blockers", [])
    if not isinstance(security_blockers, list):
        security_blockers = []
    runtime_reason_codes = runtime_governance.get("reason_codes", [])
    if not isinstance(runtime_reason_codes, list):
        runtime_reason_codes = []
    deployment_reason_codes = deployment.get("reason_codes", [])
    if not isinstance(deployment_reason_codes, list):
        deployment_reason_codes = []

    production_ready = (
        runtime_governance.get("production_release_approved") is True
        and promote_state == "PROMOTE_READY"
        and deployment.get("status") == "READY"
    )
    fail_closed_blockers = sorted(
        dict.fromkeys(
            [str(item) for item in security_blockers + runtime_reason_codes + deployment_reason_codes if item]
        )
    )
    timeline_records = [
        {
            "scope": scope,
            "source_file": file_record["source_file"],
            "state": file_record["state"],
            "decision": file_record["decision"],
            "generated_at": file_record["generated_at"],
        }
        for scope, group in {**pb_status, **pbsec_status}.items()
        for file_record in group["files"]
        if file_record["generated_at"]
    ]
    timeline_records.sort(key=lambda record: record["generated_at"])

    return {
        "schema_version": "usbay.governance_demo_dashboard_state.v1",
        "generated_at": effective_now.isoformat().replace("+00:00", "Z"),
        "evidence_paths_consumed": [
            path
            for paths in list(PB_EVIDENCE.values()) + list(PBSEC_EVIDENCE.values())
            for path in paths
        ],
        "pb_status": pb_status,
        "pbsec_status": pbsec_status,
        "runtime_governance_state": runtime_governance,
        "runtime_readiness": runtime.get("status", runtime_governance.get("status", "BLOCKED")),
        "deployment_readiness": deployment.get("status", "UNKNOWN"),
        "policy_validator_state": VERIFIED if runtime_governance.get("status") == "READY" else BLOCKED,
        "promote_state": promote_state,
        "promote_reason": runtime_governance.get("reason", "UNKNOWN"),
        "production_readiness_state": "RELEASE_READY" if production_ready else "RELEASE_BLOCKED",
        "human_approval_status": "APPROVED" if runtime_governance.get("production_release_approved") is True else "MISSING",
        "fail_closed_blockers": fail_closed_blockers,
        "evidence_lineage": list(LINEAGE),
        "runtime_health_correlation": {
            "pb020_blocked": pb_status["PB-020"]["state"] != VERIFIED,
            "pbsec_blocked": any(group["state"] != VERIFIED for group in pbsec_status.values()),
            "deployment_readiness_failure": deployment.get("status") != "READY",
            "production_approval_missing": runtime_governance.get("production_release_approved") is not True,
        },
        "execution_framework": empty_execution_dashboard_state(),
        "vision_agent_control": empty_vision_dashboard_state(),
        "vision_execution_bridge": empty_bridge_dashboard_state(),
        "operator_review_queue": empty_operator_queue_dashboard_state(),
        "work_orchestrator": empty_work_orchestrator_dashboard_state(),
        "governance_metrics": empty_metrics_dashboard_state(),
        "evidence_trust": empty_evidence_trust_dashboard_state(),
        "connector_governance": empty_connector_dashboard_state(),
        "runtime_observation": empty_runtime_observation_dashboard_state(),
        "audit_registry": empty_audit_registry_dashboard_state(),
        "policy_registry": empty_policy_registry_dashboard_state(),
        "release_gate": empty_release_gate_dashboard_state(),
        "event_timeline": timeline_records,
    }
