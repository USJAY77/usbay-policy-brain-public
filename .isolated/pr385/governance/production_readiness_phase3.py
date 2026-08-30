from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable, Mapping, Sequence

from governance.hashing import SHA256_PREFIX, sha256_bytes, sha256_reference


PHASE3_SCHEMA = "usbay.production_readiness.phase3.operational_resilience.v1"
PHASE3_EVIDENCE_SCHEMA = "usbay.production_readiness.phase3.evidence_export.v1"
PHASE3_APPROVAL_SCHEMA = "usbay.production_readiness.phase3.release_approval.v1"
PHASE3_APPROVAL_PERSISTENCE_SCHEMA = "usbay.production_readiness.phase3.approval_persistence.v1"
PHASE3_POLICY_VERSION = "usbay.production-readiness.phase3.v1"
PHASE3_EVALUATOR_VERSION = "production-readiness-phase3-evaluator-v1"
DEFAULT_PHASE3_MANIFEST_PATH = Path("governance/evidence/production_readiness_phase3_manifest.json")

READY = "READY"
DEGRADED = "DEGRADED"
BLOCKED = "BLOCKED"
APPROVED = "APPROVED"

MAX_EVIDENCE_AGE_DAYS = 90
MAX_CREDENTIAL_ROTATION_AGE_DAYS = 90
MAX_BACKUP_AGE_HOURS = 24
MAX_RESTORE_AGE_DAYS = 30
MAX_DR_EXERCISE_AGE_DAYS = 180
MAX_ALERT_AGE_HOURS = 24

FALSE_FLAGS = {
    "execution_allowed": False,
    "provider_execution": False,
    "production_activation": False,
    "deployment_authorized": False,
    "release_authorized": False,
}

MANDATORY_CONTROLS = (
    "secrets_credential_governance",
    "monitoring_alerting_governance",
    "backup_governance",
    "restore_validation",
    "disaster_recovery_governance",
    "incident_response_governance",
    "operational_runbooks",
    "release_approval_workflow",
    "change_management_governance",
    "human_approval_persistence",
)

SENSITIVE_KEYS = frozenset(
    {
        "secret",
        "secret_value",
        "token",
        "password",
        "private_key",
        "credential",
        "certificate",
        "raw_payload",
        "approval_contents",
        "value",
    }
)

PLACEHOLDER_VALUES = frozenset({"", "CHANGE_ME", "CHANGEME", "PLACEHOLDER", "TODO", "TBD", "example", "dummy"})
ALLOWED_STORAGE_CLASSES = frozenset({"EXTERNAL_SECRET_MANAGER", "OIDC_REFERENCE", "HSM_REFERENCE", "KMS_REFERENCE"})
REQUIRED_MONITORING_SIGNALS = frozenset(
    {
        "service_health",
        "governance_decisions",
        "runtime_denials",
        "audit_chain_integrity",
        "dependency_degradation",
        "provider_health",
        "failed_human_approvals",
        "release_gate",
        "evidence_export_failure",
    }
)
REQUIRED_RUNBOOKS = frozenset(
    {
        "service_degradation",
        "governance_engine_unavailable",
        "audit_chain_failure",
        "provider_unavailable",
        "human_approval_unavailable",
        "evidence_export_failure",
        "dependency_failure",
        "backup_failure",
        "restore_failure",
        "incident_escalation",
        "rollback",
        "emergency_production_stop",
    }
)
REQUIRED_RUNBOOK_FIELDS = frozenset(
    {
        "runbook_id",
        "version",
        "owner",
        "trigger_condition",
        "preconditions",
        "ordered_actions",
        "prohibited_actions",
        "required_evidence",
        "required_human_approval",
        "rollback_step",
        "completion_state",
        "validation_command",
    }
)


@dataclass(frozen=True)
class Phase3ControlResult:
    control_id: str
    state: str
    risk: str
    blocker_status: bool
    reason_codes: tuple[str, ...]
    evidence_references: tuple[str, ...]
    evidence_hashes: Mapping[str, str]

    def to_dict(self) -> dict[str, Any]:
        return {
            "control_id": self.control_id,
            "state": self.state,
            "risk": self.risk,
            "blocker_status": self.blocker_status,
            "reason_codes": list(self.reason_codes),
            "evidence_references": list(self.evidence_references),
            "evidence_hashes": dict(self.evidence_hashes),
        }


@dataclass(frozen=True)
class Phase3Evaluation:
    readiness_outcome: str
    evaluation_id: str
    manifest_version: str
    commit_sha: str
    branch: str
    policy_version: str
    evaluator_version: str
    timestamp: str
    approval_state: str
    release_state: str
    blockers: tuple[str, ...]
    risks: tuple[str, ...]
    evidence_references: tuple[str, ...]
    evidence_hashes: Mapping[str, str]
    control_results: tuple[Phase3ControlResult, ...]
    execution_allowed: bool = False
    provider_execution: bool = False
    production_activation: bool = False
    deployment_authorized: bool = False
    release_authorized: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "readiness_outcome": self.readiness_outcome,
            "evaluation_id": self.evaluation_id,
            "manifest_version": self.manifest_version,
            "commit_sha": self.commit_sha,
            "branch": self.branch,
            "policy_version": self.policy_version,
            "evaluator_version": self.evaluator_version,
            "timestamp": self.timestamp,
            "approval_state": self.approval_state,
            "release_state": self.release_state,
            "blockers": list(self.blockers),
            "risks": list(self.risks),
            "evidence_references": list(self.evidence_references),
            "evidence_hashes": dict(self.evidence_hashes),
            "control_results": [result.to_dict() for result in self.control_results],
            **FALSE_FLAGS,
        }


def load_phase3_manifest(path: Path = DEFAULT_PHASE3_MANIFEST_PATH) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def load_phase3_manifest_safely(path: Path = DEFAULT_PHASE3_MANIFEST_PATH) -> Mapping[str, Any] | None:
    try:
        return load_phase3_manifest(path)
    except (OSError, json.JSONDecodeError):
        return None


def deterministic_phase3_approval_hash(approval: Mapping[str, Any]) -> str:
    return sha256_reference({key: value for key, value in approval.items() if key != "approval_hash"})


def deterministic_persistence_hash(record: Mapping[str, Any]) -> str:
    return sha256_reference({key: value for key, value in record.items() if key != "persistence_hash"})


def evaluate_phase3_readiness(
    manifest: Mapping[str, Any] | None,
    *,
    approval: Mapping[str, Any] | None = None,
    commit_sha: str,
    branch: str,
    timestamp: str,
    root: Path = Path("."),
) -> Phase3Evaluation:
    try:
        return _evaluate_phase3_readiness(
            manifest,
            approval=approval,
            commit_sha=commit_sha,
            branch=branch,
            timestamp=timestamp,
            root=root,
        )
    except Exception:
        return _blocked_evaluation(
            commit_sha=commit_sha,
            branch=branch,
            timestamp=timestamp,
            reasons=("PR3_EVALUATOR_EXCEPTION",),
        )


def export_phase3_evidence(evaluation: Phase3Evaluation) -> dict[str, Any]:
    payload = {
        "schema_version": PHASE3_EVIDENCE_SCHEMA,
        "evaluation_id": evaluation.evaluation_id,
        "manifest_version": evaluation.manifest_version,
        "commit_sha": evaluation.commit_sha,
        "branch": evaluation.branch,
        "control_results": [result.to_dict() for result in evaluation.control_results],
        "blockers": list(evaluation.blockers),
        "risks": list(evaluation.risks),
        "evidence_references": list(evaluation.evidence_references),
        "evidence_hashes": dict(evaluation.evidence_hashes),
        "policy_version": evaluation.policy_version,
        "evaluator_version": evaluation.evaluator_version,
        "timestamp": evaluation.timestamp,
        "approval_state": evaluation.approval_state,
        "release_state": evaluation.release_state,
        "readiness_outcome": evaluation.readiness_outcome,
        **FALSE_FLAGS,
    }
    if _contains_sensitive_key(payload):
        raise ValueError("phase3 evidence export contains sensitive field")
    return {**payload, "evidence_export_hash": sha256_reference(payload)}


def _evaluate_phase3_readiness(
    manifest: Mapping[str, Any] | None,
    *,
    approval: Mapping[str, Any] | None,
    commit_sha: str,
    branch: str,
    timestamp: str,
    root: Path,
) -> Phase3Evaluation:
    if not isinstance(manifest, Mapping):
        return _blocked_evaluation(
            commit_sha=commit_sha,
            branch=branch,
            timestamp=timestamp,
            reasons=("PR3_MANIFEST_MISSING",),
        )
    header_reasons = _validate_manifest_header(manifest)
    controls = manifest.get("controls")
    if not isinstance(controls, list):
        return _blocked_evaluation(
            commit_sha=commit_sha,
            branch=branch,
            timestamp=timestamp,
            reasons=(*header_reasons, "PR3_CONTROLS_MISSING"),
            manifest_version=str(manifest.get("manifest_version", "")),
        )

    control_results = tuple(_evaluate_control(control, root=root, timestamp=timestamp) for control in controls)
    observed = tuple(result.control_id for result in control_results)
    missing = tuple(control_id for control_id in MANDATORY_CONTROLS if control_id not in observed)
    unknown = tuple(control_id for control_id in observed if control_id not in MANDATORY_CONTROLS)
    duplicates = tuple(sorted({control_id for control_id in observed if observed.count(control_id) > 1}))
    structural_reasons = [
        *header_reasons,
        *(f"PR3_CONTROL_MISSING:{control_id}" for control_id in missing),
        *(f"PR3_CONTROL_UNKNOWN:{control_id}" for control_id in unknown),
        *(f"PR3_CONTROL_DUPLICATE:{control_id}" for control_id in duplicates),
    ]

    evidence_references = tuple(sorted({ref for result in control_results for ref in result.evidence_references}))
    evidence_hashes = _combined_evidence_hashes(control_results)
    preliminary_blockers = tuple(
        sorted({*structural_reasons, *(reason for result in control_results for reason in result.reason_codes)})
    )
    preliminary_state = READY if not preliminary_blockers and observed == MANDATORY_CONTROLS else BLOCKED
    evaluation_seed = {
        "manifest_version": manifest.get("manifest_version"),
        "commit_sha": commit_sha,
        "branch": branch,
        "policy_version": PHASE3_POLICY_VERSION,
        "timestamp": timestamp,
        "preliminary_state": preliminary_state,
        "control_results": [result.to_dict() for result in control_results],
        "blockers": list(preliminary_blockers),
    }
    evaluation_id = sha256_reference(evaluation_seed)
    approval_state, approval_reasons = _validate_release_approval(
        approval,
        expected_commit_sha=commit_sha,
        expected_branch=branch,
        expected_evaluation_id=evaluation_id,
        expected_manifest_version=str(manifest.get("manifest_version", "")),
        expected_policy_version=PHASE3_POLICY_VERSION,
        now=timestamp,
    )
    blockers = tuple(sorted({*preliminary_blockers, *approval_reasons}))
    if blockers:
        outcome = BLOCKED
    elif any(result.state == DEGRADED for result in control_results):
        outcome = DEGRADED
    else:
        outcome = READY
    risks = tuple(sorted({result.risk for result in control_results if result.risk}))
    return Phase3Evaluation(
        readiness_outcome=outcome,
        evaluation_id=evaluation_id,
        manifest_version=str(manifest.get("manifest_version", "")),
        commit_sha=commit_sha,
        branch=branch,
        policy_version=PHASE3_POLICY_VERSION,
        evaluator_version=PHASE3_EVALUATOR_VERSION,
        timestamp=timestamp,
        approval_state=approval_state,
        release_state="NOT_AUTHORIZED",
        blockers=blockers,
        risks=risks,
        evidence_references=evidence_references,
        evidence_hashes=evidence_hashes,
        control_results=control_results,
    )


def _validate_manifest_header(manifest: Mapping[str, Any]) -> tuple[str, ...]:
    reasons: list[str] = []
    if manifest.get("schema") != PHASE3_SCHEMA:
        reasons.append("PR3_MANIFEST_SCHEMA_INVALID")
    if manifest.get("policy_version") != PHASE3_POLICY_VERSION:
        reasons.append("PR3_MANIFEST_POLICY_VERSION_INVALID")
    if _contains_sensitive_key(manifest):
        reasons.append("PR3_SENSITIVE_FIELD_PRESENT")
    for flag, expected in FALSE_FLAGS.items():
        if manifest.get(flag, expected) is not False:
            reasons.append(f"PR3_EXECUTION_FLAG_NOT_FALSE:{flag}")
    return tuple(sorted(set(reasons)))


def _evaluate_control(control: Any, *, root: Path, timestamp: str) -> Phase3ControlResult:
    if not isinstance(control, Mapping):
        return _control_result("UNKNOWN", BLOCKED, "CRITICAL", True, ("PR3_CONTROL_MALFORMED",), (), {})
    control_id = str(control.get("control_id", "UNKNOWN"))
    reasons: list[str] = []
    if control.get("status") not in {READY, DEGRADED, BLOCKED}:
        reasons.append(f"PR3_CONTROL_STATUS_INVALID:{control_id}")
    if control.get("blocker_status") is True:
        reasons.append(f"PR3_CONTROL_BLOCKER_PRESENT:{control_id}")
    if control.get("risk") in {"CRITICAL", "HIGH"} and control.get("blocker_status") is True:
        reasons.append(f"PR3_CONTROL_HIGH_RISK_BLOCKER:{control_id}")
    if _contains_sensitive_key(control):
        reasons.append(f"PR3_CONTROL_SENSITIVE_FIELD_PRESENT:{control_id}")
    evidence_references, evidence_hashes, evidence_reasons = _validate_evidence(control, root=root, timestamp=timestamp)
    reasons.extend(evidence_reasons)
    validator = CONTROL_VALIDATORS.get(control_id)
    if validator is None:
        reasons.append(f"PR3_CONTROL_UNKNOWN:{control_id}")
    else:
        reasons.extend(validator(control, timestamp))
    state = BLOCKED if reasons else str(control.get("status", BLOCKED))
    return _control_result(
        control_id,
        state,
        str(control.get("risk", "CRITICAL")),
        bool(control.get("blocker_status", bool(reasons))),
        reasons,
        evidence_references,
        evidence_hashes,
    )


def _validate_secrets(control: Mapping[str, Any], timestamp: str) -> list[str]:
    reasons: list[str] = []
    credentials = control.get("credentials")
    if not isinstance(credentials, list) or not credentials:
        return ["PR3_SECRET_INVENTORY_MISSING"]
    for item in credentials:
        if not isinstance(item, Mapping):
            reasons.append("PR3_SECRET_METADATA_MALFORMED")
            continue
        secret_id = str(item.get("secret_id", "UNKNOWN"))
        if _is_placeholder(str(item.get("owner", ""))):
            reasons.append(f"PR3_SECRET_OWNER_MISSING:{secret_id}")
        if item.get("storage_class") not in ALLOWED_STORAGE_CLASSES:
            reasons.append(f"PR3_SECRET_STORAGE_CLASS_INVALID:{secret_id}")
        if item.get("environment_separation") is not True:
            reasons.append(f"PR3_SECRET_ENVIRONMENT_SEPARATION_MISSING:{secret_id}")
        if item.get("revocation_status") != "READY":
            reasons.append(f"PR3_SECRET_REVOCATION_NOT_READY:{secret_id}")
        if _is_stale(str(item.get("rotation_evidence_timestamp", "")), timestamp, days=MAX_CREDENTIAL_ROTATION_AGE_DAYS):
            reasons.append(f"PR3_SECRET_ROTATION_STALE:{secret_id}")
        if item.get("plaintext_detected") is True or item.get("repository_secret_detected") is True:
            reasons.append(f"PR3_SECRET_UNSAFE_REPOSITORY_STATE:{secret_id}")
    return reasons


def _validate_monitoring(control: Mapping[str, Any], timestamp: str) -> list[str]:
    reasons: list[str] = []
    alerts = control.get("alerts")
    if not isinstance(alerts, Mapping):
        return ["PR3_MONITORING_ALERTS_MISSING"]
    missing = sorted(REQUIRED_MONITORING_SIGNALS - set(alerts))
    unknown = sorted(set(alerts) - REQUIRED_MONITORING_SIGNALS)
    reasons.extend(f"PR3_MONITORING_SIGNAL_MISSING:{signal}" for signal in missing)
    reasons.extend(f"PR3_MONITORING_SIGNAL_UNKNOWN:{signal}" for signal in unknown)
    for signal in sorted(REQUIRED_MONITORING_SIGNALS & set(alerts)):
        alert = alerts.get(signal)
        if not isinstance(alert, Mapping):
            reasons.append(f"PR3_MONITORING_ALERT_MALFORMED:{signal}")
            continue
        if alert.get("covered") is not True and alert.get("severity") == "CRITICAL":
            reasons.append(f"PR3_MONITORING_CRITICAL_COVERAGE_MISSING:{signal}")
        if alert.get("acknowledged") is not True and alert.get("severity") == "CRITICAL":
            reasons.append(f"PR3_MONITORING_CRITICAL_UNACKNOWLEDGED:{signal}")
        if _is_stale(str(alert.get("last_checked", "")), timestamp, hours=MAX_ALERT_AGE_HOURS):
            reasons.append(f"PR3_MONITORING_ALERT_STALE:{signal}")
    return reasons


def _validate_backup(control: Mapping[str, Any], timestamp: str) -> list[str]:
    reasons: list[str] = []
    for field in ("policy_ref", "scope", "frequency", "retention_period", "owner", "integrity_hash_ref", "immutable_storage_evidence_ref"):
        if _is_placeholder(str(control.get(field, ""))):
            reasons.append(f"PR3_BACKUP_{field.upper()}_MISSING")
    if control.get("encryption_status") != "ENCRYPTED":
        reasons.append("PR3_BACKUP_ENCRYPTION_INVALID")
    if control.get("failure_state") not in {False, "NONE", None}:
        reasons.append("PR3_BACKUP_FAILURE_STATE_PRESENT")
    if _is_stale(str(control.get("last_successful_backup_timestamp", "")), timestamp, hours=MAX_BACKUP_AGE_HOURS):
        reasons.append("PR3_BACKUP_EVIDENCE_STALE")
    return reasons


def _validate_restore(control: Mapping[str, Any], timestamp: str) -> list[str]:
    reasons: list[str] = []
    if _is_placeholder(str(control.get("restore_test_ref", ""))):
        reasons.append("PR3_RESTORE_TEST_MISSING")
    if control.get("data_integrity_result") != "PASS":
        reasons.append("PR3_RESTORE_DATA_INTEGRITY_FAILED")
    if control.get("schema_integrity_result") != "PASS":
        reasons.append("PR3_RESTORE_SCHEMA_INTEGRITY_FAILED")
    if control.get("approval_state") != APPROVED:
        reasons.append("PR3_RESTORE_APPROVAL_MISSING")
    if _is_placeholder(str(control.get("evidence_hash", ""))):
        reasons.append("PR3_RESTORE_EVIDENCE_HASH_MISSING")
    if _is_stale(str(control.get("restore_timestamp", "")), timestamp, days=MAX_RESTORE_AGE_DAYS):
        reasons.append("PR3_RESTORE_TEST_STALE")
    return reasons


def _validate_disaster_recovery(control: Mapping[str, Any], timestamp: str) -> list[str]:
    reasons: list[str] = []
    for field in ("plan_ref", "rto", "rpo", "dependency_recovery_order", "human_command_authority", "communication_path", "critical_service_inventory", "rollback_path"):
        if control.get(field) in (None, "", [], ()):
            reasons.append(f"PR3_DR_{field.upper()}_MISSING")
    if not _duration_minutes(control.get("rto")) or not _duration_minutes(control.get("rpo")):
        reasons.append("PR3_DR_RTO_RPO_INVALID")
    if control.get("recovery_validation") != "PASS":
        reasons.append("PR3_DR_RECOVERY_VALIDATION_FAILED")
    if control.get("exercise_outcome") != "PASS":
        reasons.append("PR3_DR_EXERCISE_FAILED")
    if control.get("unresolved_blockers"):
        reasons.append("PR3_DR_UNRESOLVED_BLOCKERS_PRESENT")
    if _is_stale(str(control.get("last_exercise_date", "")), timestamp, days=MAX_DR_EXERCISE_AGE_DAYS):
        reasons.append("PR3_DR_EXERCISE_STALE")
    return reasons


def _validate_incident_response(control: Mapping[str, Any], timestamp: str) -> list[str]:
    reasons: list[str] = []
    if control.get("severity") == "CRITICAL" and control.get("closure_approval") != APPROVED:
        reasons.append("PR3_INCIDENT_CLOSURE_APPROVAL_MISSING")
    if control.get("governance_integrity_affected") is True:
        reasons.append("PR3_INCIDENT_GOVERNANCE_INTEGRITY_BLOCKED")
    if control.get("evidence_preservation_status") != "HASH_REFERENCED":
        reasons.append("PR3_INCIDENT_EVIDENCE_NOT_HASH_REFERENCED")
    if control.get("unresolved_action_items"):
        reasons.append("PR3_INCIDENT_UNRESOLVED_ACTION_ITEMS")
    return reasons


def _validate_runbooks(control: Mapping[str, Any], timestamp: str) -> list[str]:
    reasons: list[str] = []
    runbooks = control.get("runbooks")
    if not isinstance(runbooks, Mapping):
        return ["PR3_RUNBOOKS_MISSING"]
    missing = sorted(REQUIRED_RUNBOOKS - set(runbooks))
    unknown = sorted(set(runbooks) - REQUIRED_RUNBOOKS)
    reasons.extend(f"PR3_RUNBOOK_MISSING:{name}" for name in missing)
    reasons.extend(f"PR3_RUNBOOK_UNKNOWN:{name}" for name in unknown)
    for name in sorted(REQUIRED_RUNBOOKS & set(runbooks)):
        entry = runbooks.get(name)
        if not isinstance(entry, Mapping):
            reasons.append(f"PR3_RUNBOOK_MALFORMED:{name}")
            continue
        for field in sorted(REQUIRED_RUNBOOK_FIELDS):
            if entry.get(field) in (None, "", [], ()):
                reasons.append(f"PR3_RUNBOOK_FIELD_MISSING:{name}:{field}")
        if not str(entry.get("version", "")).startswith("v"):
            reasons.append(f"PR3_RUNBOOK_VERSION_INVALID:{name}")
        if entry.get("required_human_approval") is not True:
            reasons.append(f"PR3_RUNBOOK_APPROVAL_MISSING:{name}")
        if _is_placeholder(str(entry.get("rollback_step", ""))):
            reasons.append(f"PR3_RUNBOOK_ROLLBACK_STEP_MISSING:{name}")
    return reasons


def _validate_release_workflow(control: Mapping[str, Any], timestamp: str) -> list[str]:
    reasons: list[str] = []
    for field in ("release_identifier", "control_manifest_version", "evidence_export_hash"):
        if _is_placeholder(str(control.get(field, ""))):
            reasons.append(f"PR3_RELEASE_WORKFLOW_{field.upper()}_MISSING")
    if control.get("approval_required") is not True:
        reasons.append("PR3_RELEASE_WORKFLOW_APPROVAL_NOT_REQUIRED")
    return reasons


def _validate_change_management(control: Mapping[str, Any], timestamp: str) -> list[str]:
    reasons: list[str] = []
    changes = control.get("changes")
    if not isinstance(changes, list) or not changes:
        return ["PR3_CHANGE_RECORDS_MISSING"]
    for item in changes:
        if not isinstance(item, Mapping):
            reasons.append("PR3_CHANGE_RECORD_MALFORMED")
            continue
        change_id = str(item.get("change_id", "UNKNOWN"))
        if item.get("risk_classification") in {"HIGH", "CRITICAL"} and item.get("approval_state") != APPROVED:
            reasons.append(f"PR3_CHANGE_HIGH_RISK_APPROVAL_MISSING:{change_id}")
        if _is_placeholder(str(item.get("rollback_reference", ""))):
            reasons.append(f"PR3_CHANGE_ROLLBACK_EVIDENCE_MISSING:{change_id}")
        if item.get("emergency_change") is True and item.get("retrospective_approval") != APPROVED:
            reasons.append(f"PR3_CHANGE_EMERGENCY_RETROSPECTIVE_APPROVAL_MISSING:{change_id}")
        if item.get("unresolved_deviation"):
            reasons.append(f"PR3_CHANGE_UNRESOLVED_DEVIATION:{change_id}")
        if item.get("implementation_status") not in {"PLANNED", "VERIFIED"}:
            reasons.append(f"PR3_CHANGE_IMPLEMENTATION_STATUS_INVALID:{change_id}")
    return reasons


def _validate_approval_persistence(control: Mapping[str, Any], timestamp: str) -> list[str]:
    reasons: list[str] = []
    record = control.get("persistence_record")
    if not isinstance(record, Mapping):
        return ["PR3_APPROVAL_PERSISTENCE_RECORD_MISSING"]
    if record.get("schema") != PHASE3_APPROVAL_PERSISTENCE_SCHEMA:
        reasons.append("PR3_APPROVAL_PERSISTENCE_SCHEMA_INVALID")
    if record.get("persistence_status") != "PERSISTED":
        reasons.append("PR3_APPROVAL_PERSISTENCE_STATUS_INVALID")
    if _is_placeholder(str(record.get("evidence_export_hash", ""))):
        reasons.append("PR3_APPROVAL_PERSISTENCE_EVIDENCE_MISSING")
    expected_hash = deterministic_persistence_hash(record)
    if record.get("persistence_hash") != expected_hash:
        reasons.append("PR3_APPROVAL_PERSISTENCE_HASH_INVALID")
    return reasons


CONTROL_VALIDATORS: Mapping[str, Callable[[Mapping[str, Any], str], list[str]]] = {
    "secrets_credential_governance": _validate_secrets,
    "monitoring_alerting_governance": _validate_monitoring,
    "backup_governance": _validate_backup,
    "restore_validation": _validate_restore,
    "disaster_recovery_governance": _validate_disaster_recovery,
    "incident_response_governance": _validate_incident_response,
    "operational_runbooks": _validate_runbooks,
    "release_approval_workflow": _validate_release_workflow,
    "change_management_governance": _validate_change_management,
    "human_approval_persistence": _validate_approval_persistence,
}


def _validate_release_approval(
    approval: Mapping[str, Any] | None,
    *,
    expected_commit_sha: str,
    expected_branch: str,
    expected_evaluation_id: str,
    expected_manifest_version: str,
    expected_policy_version: str,
    now: str,
) -> tuple[str, tuple[str, ...]]:
    if not isinstance(approval, Mapping):
        return "MISSING", ("PR3_RELEASE_APPROVAL_MISSING",)
    reasons: list[str] = []
    expected = {
        "schema": PHASE3_APPROVAL_SCHEMA,
        "commit_sha": expected_commit_sha,
        "branch": expected_branch,
        "production_readiness_evaluation_id": expected_evaluation_id,
        "policy_version": expected_policy_version,
        "control_manifest_version": expected_manifest_version,
        "approval_decision": APPROVED,
    }
    for key, value in expected.items():
        if approval.get(key) != value:
            reasons.append(f"PR3_RELEASE_APPROVAL_{key.upper()}_MISMATCH")
    if _is_placeholder(str(approval.get("approval_actor", ""))) or _is_placeholder(str(approval.get("approval_role", ""))):
        reasons.append("PR3_RELEASE_APPROVAL_ACTOR_OR_ROLE_MISSING")
    if not _is_past_or_equal(str(approval.get("approval_timestamp", "")), now):
        reasons.append("PR3_RELEASE_APPROVAL_TIMESTAMP_INVALID")
    if not _is_future(str(approval.get("approval_expiry", "")), now):
        reasons.append("PR3_RELEASE_APPROVAL_EXPIRED")
    if _contains_sensitive_key(approval):
        reasons.append("PR3_RELEASE_APPROVAL_SENSITIVE_FIELD_PRESENT")
    if approval.get("approval_hash") != deterministic_phase3_approval_hash(approval):
        reasons.append("PR3_RELEASE_APPROVAL_HASH_INVALID")
    return ("BLOCKED", tuple(sorted(set(reasons)))) if reasons else (APPROVED, ())


def _validate_evidence(control: Mapping[str, Any], *, root: Path, timestamp: str) -> tuple[tuple[str, ...], dict[str, str], tuple[str, ...]]:
    refs = control.get("evidence_references")
    if not isinstance(refs, list) or not refs:
        return (), {}, (f"PR3_EVIDENCE_MISSING:{control.get('control_id', 'UNKNOWN')}",)
    references: list[str] = []
    hashes: dict[str, str] = {}
    reasons: list[str] = []
    expected_hashes = control.get("evidence_hashes", {})
    if expected_hashes is not None and not isinstance(expected_hashes, Mapping):
        reasons.append(f"PR3_EVIDENCE_HASHES_MALFORMED:{control.get('control_id', 'UNKNOWN')}")
        expected_hashes = {}
    for ref in refs:
        path_text = str(ref)
        references.append(path_text)
        path = root / path_text
        if not path.is_file():
            reasons.append(f"PR3_EVIDENCE_REFERENCE_MISSING:{control.get('control_id', 'UNKNOWN')}:{path_text}")
            continue
        actual = SHA256_PREFIX + sha256_bytes(path.read_bytes())
        hashes[path_text] = actual
        expected = expected_hashes.get(path_text) if isinstance(expected_hashes, Mapping) else None
        if expected is not None and expected != actual:
            reasons.append(f"PR3_EVIDENCE_HASH_MISMATCH:{control.get('control_id', 'UNKNOWN')}:{path_text}")
    evidence_timestamp = str(control.get("evidence_timestamp", ""))
    if _is_stale(evidence_timestamp, timestamp, days=MAX_EVIDENCE_AGE_DAYS):
        reasons.append(f"PR3_EVIDENCE_STALE:{control.get('control_id', 'UNKNOWN')}")
    return tuple(sorted(set(references))), dict(sorted(hashes.items())), tuple(sorted(set(reasons)))


def _blocked_evaluation(
    *,
    commit_sha: str,
    branch: str,
    timestamp: str,
    reasons: Sequence[str],
    manifest_version: str = "",
) -> Phase3Evaluation:
    blockers = tuple(sorted(set(reasons)))
    seed = {
        "commit_sha": commit_sha,
        "branch": branch,
        "policy_version": PHASE3_POLICY_VERSION,
        "timestamp": timestamp,
        "blockers": list(blockers),
    }
    return Phase3Evaluation(
        readiness_outcome=BLOCKED,
        evaluation_id=sha256_reference(seed),
        manifest_version=manifest_version,
        commit_sha=commit_sha,
        branch=branch,
        policy_version=PHASE3_POLICY_VERSION,
        evaluator_version=PHASE3_EVALUATOR_VERSION,
        timestamp=timestamp,
        approval_state="BLOCKED",
        release_state="NOT_AUTHORIZED",
        blockers=blockers,
        risks=("CRITICAL",),
        evidence_references=(),
        evidence_hashes={},
        control_results=(),
    )


def _control_result(
    control_id: str,
    state: str,
    risk: str,
    blocker_status: bool,
    reasons: Sequence[str],
    evidence_references: Sequence[str],
    evidence_hashes: Mapping[str, str],
) -> Phase3ControlResult:
    return Phase3ControlResult(
        control_id=control_id,
        state=state,
        risk=risk,
        blocker_status=blocker_status,
        reason_codes=tuple(sorted(set(reasons))),
        evidence_references=tuple(sorted(set(evidence_references))),
        evidence_hashes=dict(sorted(evidence_hashes.items())),
    )


def _combined_evidence_hashes(results: Sequence[Phase3ControlResult]) -> dict[str, str]:
    hashes: dict[str, str] = {}
    for result in results:
        hashes.update(result.evidence_hashes)
    return dict(sorted(hashes.items()))


def _contains_sensitive_key(value: Any) -> bool:
    if isinstance(value, Mapping):
        for key, item in value.items():
            normalized = str(key).lower()
            if normalized in SENSITIVE_KEYS:
                return True
            if _contains_sensitive_key(item):
                return True
    if isinstance(value, list):
        return any(_contains_sensitive_key(item) for item in value)
    return False


def _is_placeholder(value: str) -> bool:
    normalized = value.strip()
    return normalized in PLACEHOLDER_VALUES or normalized.upper() in PLACEHOLDER_VALUES


def _parse_timestamp(value: str) -> datetime | None:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _is_stale(value: str, now: str, *, days: int = 0, hours: int = 0) -> bool:
    observed = _parse_timestamp(value)
    current = _parse_timestamp(now)
    if observed is None or current is None:
        return True
    return observed < current - timedelta(days=days, hours=hours)


def _is_future(value: str, now: str) -> bool:
    observed = _parse_timestamp(value)
    current = _parse_timestamp(now)
    return observed is not None and current is not None and observed > current


def _is_past_or_equal(value: str, now: str) -> bool:
    observed = _parse_timestamp(value)
    current = _parse_timestamp(now)
    return observed is not None and current is not None and observed <= current


def _duration_minutes(value: Any) -> int | None:
    if not isinstance(value, str) or not value:
        return None
    unit = value[-1]
    amount = value[:-1]
    if not amount.isdigit():
        return None
    multiplier = {"m": 1, "h": 60, "d": 1440}.get(unit)
    if multiplier is None:
        return None
    parsed = int(amount) * multiplier
    return parsed if parsed > 0 else None
