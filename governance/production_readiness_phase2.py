from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping, Sequence

from governance.hashing import SHA256_PREFIX, canonical_json, sha256_reference


PHASE2_POLICY_VERSION = "usbay.production-readiness.phase2.v1"
PHASE2_SCHEMA = "usbay.production_readiness.phase2.foundation.v1"
PHASE2_EVIDENCE_SCHEMA = "usbay.production_readiness.phase2.evidence_export.v1"
PHASE2_APPROVAL_SCHEMA = "usbay.production_readiness.phase2.release_approval.v1"
PHASE2_EVALUATOR_VERSION = "production-readiness-phase2-evaluator-v1"
DEFAULT_PHASE2_MANIFEST_PATH = Path("governance/evidence/production_readiness_phase2_foundation.json")

READY = "READY"
BLOCKED = "BLOCKED"
REVIEW_REQUIRED = "REVIEW_REQUIRED"

REQUIRED_MONITORING_DOMAINS = frozenset(
    {
        "runtime_health",
        "governance_health",
        "audit_health",
        "evidence_health",
        "dependency_health",
    }
)
REQUIRED_RUNBOOKS = frozenset(
    {
        "deployment_approval",
        "rollback",
        "incident_response",
        "recovery",
        "release_validation",
    }
)
REQUIRED_BACKUP_FIELDS = frozenset(
    {
        "backup_policy_ref",
        "restore_policy_ref",
        "recovery_interval",
        "recovery_owner",
    }
)
REQUIRED_DR_FIELDS = frozenset(
    {
        "recovery_documentation",
        "recovery_owner",
        "recovery_evidence",
        "recovery_checkpoints",
    }
)
SECRET_PLAINTEXT_FIELDS = frozenset(
    {
        "value",
        "secret",
        "secret_value",
        "token",
        "password",
        "private_key",
        "credential",
    }
)
PLACEHOLDER_MARKERS = frozenset(
    {
        "",
        "CHANGE_ME",
        "CHANGEME",
        "PLACEHOLDER",
        "TODO",
        "TBD",
        "example",
        "dummy",
    }
)


@dataclass(frozen=True)
class ComponentResult:
    component: str
    state: str
    reason_codes: tuple[str, ...]
    evidence_references: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "component": self.component,
            "state": self.state,
            "reason_codes": list(self.reason_codes),
            "evidence_references": list(self.evidence_references),
        }


@dataclass(frozen=True)
class Phase2Evaluation:
    readiness_id: str
    evaluation_id: str
    policy_version: str
    evaluator_version: str
    timestamp: str
    release_gate_result: str
    blocker_list: tuple[str, ...]
    evidence_references: tuple[str, ...]
    component_results: tuple[ComponentResult, ...]
    approval_state: str
    approval_metadata: Mapping[str, Any]
    execution_allowed: bool = False
    provider_execution: bool = False
    production_activation: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "readiness_id": self.readiness_id,
            "evaluation_id": self.evaluation_id,
            "policy_version": self.policy_version,
            "evaluator_version": self.evaluator_version,
            "timestamp": self.timestamp,
            "release_gate_result": self.release_gate_result,
            "blocker_list": list(self.blocker_list),
            "evidence_references": list(self.evidence_references),
            "component_results": [result.to_dict() for result in self.component_results],
            "approval_state": self.approval_state,
            "approval_metadata": dict(self.approval_metadata),
            "execution_allowed": self.execution_allowed,
            "provider_execution": self.provider_execution,
            "production_activation": self.production_activation,
        }


def load_phase2_manifest(path: Path = DEFAULT_PHASE2_MANIFEST_PATH) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def deterministic_release_approval_hash(approval: Mapping[str, Any]) -> str:
    return sha256_reference({key: value for key, value in approval.items() if key != "approval_hash"})


def evaluate_phase2_readiness(
    manifest: Mapping[str, Any] | None,
    *,
    approval: Mapping[str, Any] | None = None,
    commit_sha: str,
    timestamp: str,
    root: Path = Path("."),
) -> Phase2Evaluation:
    try:
        return _evaluate_phase2_readiness(
            manifest,
            approval=approval,
            commit_sha=commit_sha,
            timestamp=timestamp,
            root=root,
        )
    except Exception:
        return _blocked_evaluation(
            timestamp=timestamp,
            reasons=("PR2_EVALUATOR_EXCEPTION",),
            approval_state="BLOCKED",
            approval_metadata={},
        )


def export_phase2_evidence(evaluation: Phase2Evaluation) -> dict[str, Any]:
    payload = {
        "schema": PHASE2_EVIDENCE_SCHEMA,
        "readiness_id": evaluation.readiness_id,
        "evaluation_id": evaluation.evaluation_id,
        "policy_version": evaluation.policy_version,
        "release_gate_result": evaluation.release_gate_result,
        "blocker_list": list(evaluation.blocker_list),
        "evidence_references": list(evaluation.evidence_references),
        "timestamp": evaluation.timestamp,
        "approval_metadata": dict(evaluation.approval_metadata),
        "component_results": [result.to_dict() for result in evaluation.component_results],
        "execution_allowed": False,
        "provider_execution": False,
        "production_activation": False,
    }
    return {**payload, "evidence_export_hash": sha256_reference(payload)}


def _evaluate_phase2_readiness(
    manifest: Mapping[str, Any] | None,
    *,
    approval: Mapping[str, Any] | None,
    commit_sha: str,
    timestamp: str,
    root: Path,
) -> Phase2Evaluation:
    if not isinstance(manifest, Mapping):
        return _blocked_evaluation(
            timestamp=timestamp,
            reasons=("PR2_MANIFEST_MISSING",),
            approval_state="BLOCKED",
            approval_metadata={},
        )
    manifest_reasons = _validate_manifest_header(manifest)
    component_results = (
        _evaluate_secrets(manifest.get("secrets_management")),
        _evaluate_monitoring(manifest.get("monitoring_baseline")),
        _evaluate_backup(manifest.get("backup_readiness")),
        _evaluate_disaster_recovery(manifest.get("disaster_recovery")),
        _evaluate_runbooks(manifest.get("operational_runbooks"), root=root),
    )
    blocker_list = sorted({*manifest_reasons, *(reason for result in component_results for reason in result.reason_codes)})
    evidence_references = tuple(
        sorted({reference for result in component_results for reference in result.evidence_references})
    )
    preliminary_state = READY if not blocker_list else BLOCKED
    preliminary_seed = {
        "policy_version": PHASE2_POLICY_VERSION,
        "timestamp": timestamp,
        "component_results": [result.to_dict() for result in component_results],
        "blocker_list": blocker_list,
        "preliminary_state": preliminary_state,
    }
    readiness_id = sha256_reference(preliminary_seed)
    evaluation_id = sha256_reference(
        {
            "readiness_id": readiness_id,
            "policy_version": PHASE2_POLICY_VERSION,
            "timestamp": timestamp,
            "evaluator_version": PHASE2_EVALUATOR_VERSION,
        }
    )
    approval_state, approval_reasons, approval_metadata = _validate_release_approval(
        approval,
        expected_commit_sha=commit_sha,
        expected_readiness_id=readiness_id,
        expected_evaluation_id=evaluation_id,
        expected_policy_version=PHASE2_POLICY_VERSION,
        now=timestamp,
    )
    combined_blockers = tuple(sorted({*blocker_list, *approval_reasons}))
    if preliminary_state == BLOCKED:
        release_gate_result = BLOCKED
    elif approval_state == "APPROVED":
        release_gate_result = READY
    elif approval_state == "MISSING":
        release_gate_result = REVIEW_REQUIRED
    else:
        release_gate_result = BLOCKED
    return Phase2Evaluation(
        readiness_id=readiness_id,
        evaluation_id=evaluation_id,
        policy_version=PHASE2_POLICY_VERSION,
        evaluator_version=PHASE2_EVALUATOR_VERSION,
        timestamp=timestamp,
        release_gate_result=release_gate_result,
        blocker_list=combined_blockers,
        evidence_references=evidence_references,
        component_results=component_results,
        approval_state=approval_state,
        approval_metadata=approval_metadata,
    )


def _validate_manifest_header(manifest: Mapping[str, Any]) -> tuple[str, ...]:
    reasons: list[str] = []
    if manifest.get("schema") != PHASE2_SCHEMA:
        reasons.append("PR2_MANIFEST_SCHEMA_INVALID")
    if manifest.get("policy_version") != PHASE2_POLICY_VERSION:
        reasons.append("PR2_MANIFEST_POLICY_VERSION_INVALID")
    if _contains_raw_or_secret_field(manifest):
        reasons.append("PR2_MANIFEST_RAW_SECRET_FIELD_PRESENT")
    return tuple(sorted(set(reasons)))


def _evaluate_secrets(section: Any) -> ComponentResult:
    reasons: list[str] = []
    evidence: list[str] = []
    if not isinstance(section, Mapping):
        return _component_blocked("secrets_management", "PR2_SECRETS_SECTION_MISSING")
    required = section.get("required_secrets")
    if not isinstance(required, list) or not required:
        reasons.append("PR2_REQUIRED_SECRET_INVENTORY_MISSING")
        required = []
    observed_ids: list[str] = []
    for entry in required:
        if not isinstance(entry, Mapping):
            reasons.append("PR2_SECRET_ENTRY_MALFORMED")
            continue
        secret_id = str(entry.get("secret_id", "UNKNOWN"))
        observed_ids.append(secret_id)
        if not secret_id or secret_id == "UNKNOWN":
            reasons.append("PR2_SECRET_ID_MISSING")
        if entry.get("required") is not True:
            reasons.append(f"PR2_SECRET_NOT_MARKED_REQUIRED:{secret_id}")
        if entry.get("configured") is not True:
            reasons.append(f"PR2_SECRET_MISSING:{secret_id}")
        storage_ref = str(entry.get("storage_ref", ""))
        if _is_placeholder(storage_ref) or entry.get("placeholder") is True:
            reasons.append(f"PR2_SECRET_PLACEHOLDER_PRESENT:{secret_id}")
        if any(field in entry for field in SECRET_PLAINTEXT_FIELDS):
            reasons.append(f"PR2_SECRET_PLAINTEXT_PRESENT:{secret_id}")
    duplicates = sorted({secret_id for secret_id in observed_ids if observed_ids.count(secret_id) > 1})
    reasons.extend(f"PR2_SECRET_DUPLICATE:{secret_id}" for secret_id in duplicates)
    evidence.extend(_evidence_refs(section))
    return _component("secrets_management", reasons, evidence)


def _evaluate_monitoring(section: Any) -> ComponentResult:
    reasons: list[str] = []
    evidence: list[str] = []
    if not isinstance(section, Mapping):
        return _component_blocked("monitoring_baseline", "PR2_MONITORING_SECTION_MISSING")
    checks = section.get("checks")
    if not isinstance(checks, Mapping):
        return _component_blocked("monitoring_baseline", "PR2_MONITORING_CHECKS_MISSING")
    unknown = sorted(set(checks) - REQUIRED_MONITORING_DOMAINS)
    missing = sorted(REQUIRED_MONITORING_DOMAINS - set(checks))
    reasons.extend(f"PR2_MONITORING_DOMAIN_UNKNOWN:{domain}" for domain in unknown)
    reasons.extend(f"PR2_MONITORING_DOMAIN_MISSING:{domain}" for domain in missing)
    for domain in sorted(REQUIRED_MONITORING_DOMAINS & set(checks)):
        item = checks.get(domain)
        if not isinstance(item, Mapping):
            reasons.append(f"PR2_MONITORING_DOMAIN_MALFORMED:{domain}")
            continue
        if item.get("metadata_only") is not True:
            reasons.append(f"PR2_MONITORING_NOT_METADATA_ONLY:{domain}")
        if item.get("external_provider") not in (False, None):
            reasons.append(f"PR2_MONITORING_EXTERNAL_PROVIDER_ENABLED:{domain}")
        if item.get("status") != READY:
            reasons.append(f"PR2_MONITORING_NOT_READY:{domain}")
    evidence.extend(_evidence_refs(section))
    return _component("monitoring_baseline", reasons, evidence)


def _evaluate_backup(section: Any) -> ComponentResult:
    reasons: list[str] = []
    evidence: list[str] = []
    if not isinstance(section, Mapping):
        return _component_blocked("backup_readiness", "PR2_BACKUP_SECTION_MISSING")
    missing = sorted(field for field in REQUIRED_BACKUP_FIELDS if not section.get(field))
    reasons.extend(f"PR2_BACKUP_{field.upper()}_MISSING" for field in missing)
    if section.get("metadata_only") is not True:
        reasons.append("PR2_BACKUP_NOT_METADATA_ONLY")
    if section.get("backup_execution") not in (False, None):
        reasons.append("PR2_BACKUP_EXECUTION_ENABLED")
    if section.get("restore_execution") not in (False, None):
        reasons.append("PR2_RESTORE_EXECUTION_ENABLED")
    if section.get("status") != READY:
        reasons.append("PR2_BACKUP_NOT_READY")
    evidence.extend(_evidence_refs(section))
    return _component("backup_readiness", reasons, evidence)


def _evaluate_disaster_recovery(section: Any) -> ComponentResult:
    reasons: list[str] = []
    evidence: list[str] = []
    if not isinstance(section, Mapping):
        return _component_blocked("disaster_recovery", "PR2_DR_SECTION_MISSING")
    missing = sorted(field for field in REQUIRED_DR_FIELDS if not section.get(field))
    reasons.extend(f"PR2_DR_{field.upper()}_MISSING" for field in missing)
    checkpoints = section.get("recovery_checkpoints")
    if not isinstance(checkpoints, list) or not checkpoints:
        reasons.append("PR2_DR_RECOVERY_CHECKPOINTS_INVALID")
    if section.get("metadata_only") is not True:
        reasons.append("PR2_DR_NOT_METADATA_ONLY")
    if section.get("recovery_execution") not in (False, None):
        reasons.append("PR2_DR_RECOVERY_EXECUTION_ENABLED")
    if section.get("status") != READY:
        reasons.append("PR2_DR_NOT_READY")
    evidence.extend(_evidence_refs(section))
    return _component("disaster_recovery", reasons, evidence)


def _evaluate_runbooks(section: Any, *, root: Path) -> ComponentResult:
    reasons: list[str] = []
    evidence: list[str] = []
    if not isinstance(section, Mapping):
        return _component_blocked("operational_runbooks", "PR2_RUNBOOK_SECTION_MISSING")
    runbooks = section.get("runbooks")
    if not isinstance(runbooks, Mapping):
        return _component_blocked("operational_runbooks", "PR2_RUNBOOKS_MISSING")
    unknown = sorted(set(runbooks) - REQUIRED_RUNBOOKS)
    missing = sorted(REQUIRED_RUNBOOKS - set(runbooks))
    reasons.extend(f"PR2_RUNBOOK_UNKNOWN:{name}" for name in unknown)
    reasons.extend(f"PR2_RUNBOOK_MISSING:{name}" for name in missing)
    for name in sorted(REQUIRED_RUNBOOKS & set(runbooks)):
        path_value = str(runbooks.get(name, ""))
        if _is_placeholder(path_value):
            reasons.append(f"PR2_RUNBOOK_PATH_PLACEHOLDER:{name}")
            continue
        if not (root / path_value).is_file():
            reasons.append(f"PR2_RUNBOOK_FILE_MISSING:{name}")
        evidence.append(path_value)
    evidence.extend(_evidence_refs(section))
    return _component("operational_runbooks", reasons, evidence)


def _validate_release_approval(
    approval: Mapping[str, Any] | None,
    *,
    expected_commit_sha: str,
    expected_readiness_id: str,
    expected_evaluation_id: str,
    expected_policy_version: str,
    now: str,
) -> tuple[str, tuple[str, ...], Mapping[str, Any]]:
    if not isinstance(approval, Mapping):
        return "MISSING", ("PR2_RELEASE_APPROVAL_MISSING",), {"approval_state": "MISSING"}
    reasons: list[str] = []
    if approval.get("schema") != PHASE2_APPROVAL_SCHEMA:
        reasons.append("PR2_RELEASE_APPROVAL_SCHEMA_INVALID")
    if approval.get("approval_state") != "APPROVED":
        reasons.append("PR2_RELEASE_APPROVAL_NOT_APPROVED")
    if approval.get("commit_sha") != expected_commit_sha:
        reasons.append("PR2_RELEASE_APPROVAL_COMMIT_SHA_MISMATCH")
    if approval.get("readiness_id") != expected_readiness_id:
        reasons.append("PR2_RELEASE_APPROVAL_READINESS_ID_MISMATCH")
    if approval.get("readiness_evaluation_id") != expected_evaluation_id:
        reasons.append("PR2_RELEASE_APPROVAL_EVALUATION_ID_MISMATCH")
    if approval.get("policy_version") != expected_policy_version:
        reasons.append("PR2_RELEASE_APPROVAL_POLICY_VERSION_MISMATCH")
    if not _is_past_or_equal_timestamp(str(approval.get("issued_at", "")), now):
        reasons.append("PR2_RELEASE_APPROVAL_ISSUED_AT_INVALID")
    if not _is_future_timestamp(str(approval.get("expires_at", "")), now):
        reasons.append("PR2_RELEASE_APPROVAL_EXPIRED")
    if _contains_raw_or_secret_field(approval):
        reasons.append("PR2_RELEASE_APPROVAL_RAW_FIELD_PRESENT")
    expected_hash = deterministic_release_approval_hash(approval)
    if approval.get("approval_hash") != expected_hash:
        reasons.append("PR2_RELEASE_APPROVAL_HASH_INVALID")
    metadata = {
        "approval_state": "BLOCKED" if reasons else "APPROVED",
        "approval_hash": str(approval.get("approval_hash", "")),
        "approval_reference_hash": sha256_reference(
            {
                "commit_sha": approval.get("commit_sha"),
                "readiness_id": approval.get("readiness_id"),
                "readiness_evaluation_id": approval.get("readiness_evaluation_id"),
                "policy_version": approval.get("policy_version"),
                "issued_at": approval.get("issued_at"),
                "expires_at": approval.get("expires_at"),
            }
        ),
    }
    return ("BLOCKED", tuple(sorted(set(reasons))), metadata) if reasons else ("APPROVED", (), metadata)


def _component_blocked(component: str, reason: str) -> ComponentResult:
    return ComponentResult(component=component, state=BLOCKED, reason_codes=(reason,), evidence_references=())


def _component(component: str, reasons: Sequence[str], evidence_references: Sequence[str]) -> ComponentResult:
    reason_tuple = tuple(sorted(set(reasons)))
    return ComponentResult(
        component=component,
        state=BLOCKED if reason_tuple else READY,
        reason_codes=reason_tuple,
        evidence_references=tuple(sorted(set(evidence_references))),
    )


def _blocked_evaluation(
    *,
    timestamp: str,
    reasons: Sequence[str],
    approval_state: str,
    approval_metadata: Mapping[str, Any],
) -> Phase2Evaluation:
    blocker_list = tuple(sorted(set(reasons)))
    seed = {
        "policy_version": PHASE2_POLICY_VERSION,
        "timestamp": timestamp,
        "blocker_list": list(blocker_list),
    }
    readiness_id = sha256_reference(seed)
    return Phase2Evaluation(
        readiness_id=readiness_id,
        evaluation_id=sha256_reference({"readiness_id": readiness_id, "blocked": True}),
        policy_version=PHASE2_POLICY_VERSION,
        evaluator_version=PHASE2_EVALUATOR_VERSION,
        timestamp=timestamp,
        release_gate_result=BLOCKED,
        blocker_list=blocker_list,
        evidence_references=(),
        component_results=(),
        approval_state=approval_state,
        approval_metadata=approval_metadata,
    )


def _evidence_refs(section: Mapping[str, Any]) -> tuple[str, ...]:
    refs = section.get("evidence_references", ())
    if not isinstance(refs, list):
        return ()
    return tuple(str(ref) for ref in refs if ref)


def _is_placeholder(value: str) -> bool:
    normalized = value.strip()
    return normalized in PLACEHOLDER_MARKERS or normalized.upper() in PLACEHOLDER_MARKERS


def _contains_raw_or_secret_field(value: Any) -> bool:
    if isinstance(value, Mapping):
        for key, item in value.items():
            normalized = str(key).lower()
            if normalized in SECRET_PLAINTEXT_FIELDS or normalized in {"raw_payload", "secret_value", "approval_contents"}:
                return True
            if _contains_raw_or_secret_field(item):
                return True
    if isinstance(value, list):
        return any(_contains_raw_or_secret_field(item) for item in value)
    return False


def _parse_timestamp(value: str) -> datetime | None:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _is_future_timestamp(expires_at: str, now: str) -> bool:
    expiry = _parse_timestamp(expires_at)
    current = _parse_timestamp(now)
    return expiry is not None and current is not None and expiry > current


def _is_past_or_equal_timestamp(issued_at: str, now: str) -> bool:
    issued = _parse_timestamp(issued_at)
    current = _parse_timestamp(now)
    return issued is not None and current is not None and issued <= current
