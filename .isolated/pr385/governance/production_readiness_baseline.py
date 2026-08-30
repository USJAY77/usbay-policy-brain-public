from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping, Sequence

from governance.hashing import SHA256_PREFIX, canonical_json, sha256_bytes, sha256_reference


PHASE1_POLICY_VERSION = "usbay.production-readiness.phase1.v1"
PHASE1_EVALUATOR_VERSION = "production-readiness-phase1-evaluator-v1"
PHASE1_MANIFEST_SCHEMA = "usbay.production_readiness.phase1.manifest.v1"
PHASE1_EVIDENCE_SCHEMA = "usbay.production_readiness.phase1.evidence_export.v1"
HUMAN_APPROVAL_SCHEMA = "usbay.production_readiness.phase1.human_release_approval.v1"
DEFAULT_MANIFEST_PATH = Path("governance/evidence/production_readiness_phase1_manifest.json")

READY = "READY"
BLOCKED = "BLOCKED"
COMPLETE = "COMPLETE"
MANDATORY_CONTROL_IDS = (
    "PR-001",
    "PR-002",
    "PR-003",
    "PR-004",
    "PR-005",
    "PR-006",
    "PR-007",
    "PR-008",
    "PR-009",
    "PR-010",
    "PR-011",
    "PR-012",
    "PR-013",
    "PR-014",
    "PR-015",
)
REQUIRED_CONTROL_FIELDS = (
    "control_id",
    "control_domain",
    "implementation_status",
    "evidence_references",
    "validation_command",
    "blocker_status",
    "risk_level",
    "owner",
    "last_evaluated_timestamp",
    "readiness_outcome",
)
ALLOWED_RISK_LEVELS = frozenset({"CRITICAL", "HIGH", "MEDIUM", "LOW"})
ALLOWED_OWNERS = frozenset({"Codex", "Replit", "Terminal", "Human governance review", "External specialist"})


@dataclass(frozen=True)
class ControlResult:
    control_id: str
    readiness_outcome: str
    blocker_status: bool
    risk_level: str
    evidence_references: tuple[str, ...]
    evidence_hashes: Mapping[str, str]
    reason_codes: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "control_id": self.control_id,
            "readiness_outcome": self.readiness_outcome,
            "blocker_status": self.blocker_status,
            "risk_level": self.risk_level,
            "evidence_references": list(self.evidence_references),
            "evidence_hashes": dict(self.evidence_hashes),
            "reason_codes": list(self.reason_codes),
        }


@dataclass(frozen=True)
class ReadinessEvaluation:
    readiness_state: str
    evaluation_id: str
    policy_version: str
    evaluator_version: str
    evaluation_timestamp: str
    control_results: tuple[ControlResult, ...]
    failed_control_ids: tuple[str, ...]
    reason_codes: tuple[str, ...]
    evidence_references: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "readiness_state": self.readiness_state,
            "evaluation_id": self.evaluation_id,
            "policy_version": self.policy_version,
            "evaluator_version": self.evaluator_version,
            "evaluation_timestamp": self.evaluation_timestamp,
            "control_results": [result.to_dict() for result in self.control_results],
            "failed_control_ids": list(self.failed_control_ids),
            "reason_codes": list(self.reason_codes),
            "evidence_references": list(self.evidence_references),
        }


@dataclass(frozen=True)
class ReleaseGateDecision:
    readiness_state: str
    evaluation_id: str
    policy_version: str
    evaluation_timestamp: str
    reason_codes: tuple[str, ...]
    failed_control_ids: tuple[str, ...]
    evidence_references: tuple[str, ...]
    human_approval_state: str
    execution_allowed: bool = False
    provider_execution: bool = False
    production_activation: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "readiness_state": self.readiness_state,
            "evaluation_id": self.evaluation_id,
            "policy_version": self.policy_version,
            "evaluation_timestamp": self.evaluation_timestamp,
            "reason_codes": list(self.reason_codes),
            "failed_control_ids": list(self.failed_control_ids),
            "evidence_references": list(self.evidence_references),
            "human_approval_state": self.human_approval_state,
            "execution_allowed": self.execution_allowed,
            "provider_execution": self.provider_execution,
            "production_activation": self.production_activation,
        }


def load_readiness_manifest(path: Path = DEFAULT_MANIFEST_PATH) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def evaluate_readiness_manifest(
    manifest: Mapping[str, Any] | None,
    *,
    root: Path = Path("."),
    evaluation_timestamp: str,
) -> ReadinessEvaluation:
    try:
        return _evaluate_readiness_manifest(manifest, root=root, evaluation_timestamp=evaluation_timestamp)
    except Exception:
        return _blocked_evaluation("PR_EVALUATOR_EXCEPTION", evaluation_timestamp=evaluation_timestamp)


def evaluate_release_readiness(
    manifest: Mapping[str, Any] | None,
    *,
    approval: Mapping[str, Any] | None = None,
    commit_sha: str,
    root: Path = Path("."),
    evaluation_timestamp: str,
) -> ReleaseGateDecision:
    evaluation = evaluate_readiness_manifest(manifest, root=root, evaluation_timestamp=evaluation_timestamp)
    approval_state, approval_reasons = validate_human_release_approval(
        approval,
        expected_commit_sha=commit_sha,
        expected_evaluation_id=evaluation.evaluation_id,
        expected_policy_version=evaluation.policy_version,
        now=evaluation_timestamp,
    )
    reasons = tuple(sorted(set((*evaluation.reason_codes, *approval_reasons))))
    state = READY if evaluation.readiness_state == READY and approval_state == "APPROVED" and not reasons else BLOCKED
    if state == BLOCKED and not reasons:
        reasons = ("PR_RELEASE_GATE_BLOCKED",)
    return ReleaseGateDecision(
        readiness_state=state,
        evaluation_id=evaluation.evaluation_id,
        policy_version=evaluation.policy_version,
        evaluation_timestamp=evaluation.evaluation_timestamp,
        reason_codes=reasons,
        failed_control_ids=evaluation.failed_control_ids,
        evidence_references=evaluation.evidence_references,
        human_approval_state=approval_state,
    )


def export_readiness_evidence(decision: ReleaseGateDecision, control_results: Sequence[ControlResult]) -> dict[str, Any]:
    payload = {
        "schema": PHASE1_EVIDENCE_SCHEMA,
        "evaluation_id": decision.evaluation_id,
        "control_results": [result.to_dict() for result in control_results],
        "overall_readiness_state": decision.readiness_state,
        "blockers": list(decision.reason_codes),
        "referenced_evidence_hashes": _combined_evidence_hashes(control_results),
        "policy_version": decision.policy_version,
        "evaluator_version": PHASE1_EVALUATOR_VERSION,
        "timestamp": decision.evaluation_timestamp,
        "human_approval_state": decision.human_approval_state,
        "execution_allowed": False,
        "provider_execution": False,
        "production_activation": False,
    }
    return {**payload, "evidence_export_hash": sha256_reference(payload)}


def validate_human_release_approval(
    approval: Mapping[str, Any] | None,
    *,
    expected_commit_sha: str,
    expected_evaluation_id: str,
    expected_policy_version: str,
    now: str,
) -> tuple[str, tuple[str, ...]]:
    if not isinstance(approval, Mapping):
        return "MISSING", ("PR_HUMAN_RELEASE_APPROVAL_MISSING",)
    reasons: list[str] = []
    if approval.get("schema") != HUMAN_APPROVAL_SCHEMA:
        reasons.append("PR_HUMAN_RELEASE_APPROVAL_SCHEMA_INVALID")
    if approval.get("approval_state") != "APPROVED":
        reasons.append("PR_HUMAN_RELEASE_APPROVAL_NOT_APPROVED")
    if approval.get("commit_sha") != expected_commit_sha:
        reasons.append("PR_HUMAN_RELEASE_APPROVAL_COMMIT_SHA_MISMATCH")
    if approval.get("readiness_evaluation_id") != expected_evaluation_id:
        reasons.append("PR_HUMAN_RELEASE_APPROVAL_EVALUATION_ID_MISMATCH")
    if approval.get("policy_version") != expected_policy_version:
        reasons.append("PR_HUMAN_RELEASE_APPROVAL_POLICY_VERSION_MISMATCH")
    if not _is_future_timestamp(str(approval.get("expires_at", "")), now):
        reasons.append("PR_HUMAN_RELEASE_APPROVAL_EXPIRED")
    approval_hash = approval.get("approval_hash")
    expected_hash = sha256_reference({key: value for key, value in approval.items() if key != "approval_hash"})
    if approval_hash != expected_hash:
        reasons.append("PR_HUMAN_RELEASE_APPROVAL_HASH_INVALID")
    return ("BLOCKED", tuple(sorted(set(reasons)))) if reasons else ("APPROVED", ())


def _evaluate_readiness_manifest(
    manifest: Mapping[str, Any] | None,
    *,
    root: Path,
    evaluation_timestamp: str,
) -> ReadinessEvaluation:
    if not isinstance(manifest, Mapping):
        return _blocked_evaluation("PR_MANIFEST_MISSING", evaluation_timestamp=evaluation_timestamp)

    manifest_reasons: list[str] = []
    if manifest.get("schema") != PHASE1_MANIFEST_SCHEMA:
        manifest_reasons.append("PR_MANIFEST_SCHEMA_INVALID")
    if manifest.get("policy_version") != PHASE1_POLICY_VERSION:
        manifest_reasons.append("PR_MANIFEST_POLICY_VERSION_INVALID")
    controls = manifest.get("controls")
    if not isinstance(controls, list):
        return _blocked_evaluation(
            "PR_MANIFEST_CONTROLS_INVALID",
            extra_reasons=manifest_reasons,
            evaluation_timestamp=evaluation_timestamp,
        )

    results = tuple(_evaluate_control(control, root=root) for control in controls)
    observed_ids = tuple(result.control_id for result in results)
    missing_ids = tuple(control_id for control_id in MANDATORY_CONTROL_IDS if control_id not in observed_ids)
    unknown_ids = tuple(control_id for control_id in observed_ids if control_id not in MANDATORY_CONTROL_IDS)
    duplicate_ids = tuple(sorted({control_id for control_id in observed_ids if observed_ids.count(control_id) > 1}))
    reasons = list(manifest_reasons)
    reasons.extend(f"PR_REQUIRED_CONTROL_MISSING:{control_id}" for control_id in missing_ids)
    reasons.extend(f"PR_CONTROL_UNKNOWN:{control_id}" for control_id in unknown_ids)
    reasons.extend(f"PR_CONTROL_DUPLICATE:{control_id}" for control_id in duplicate_ids)
    for result in results:
        reasons.extend(result.reason_codes)
    failed_ids = tuple(
        sorted(
            {
                *missing_ids,
                *unknown_ids,
                *duplicate_ids,
                *(result.control_id for result in results if result.reason_codes),
            }
        )
    )
    evidence_refs = tuple(sorted({ref for result in results for ref in result.evidence_references}))
    reason_tuple = tuple(sorted(set(reasons)))
    state = READY if not reason_tuple and observed_ids == MANDATORY_CONTROL_IDS else BLOCKED
    seed = {
        "policy_version": PHASE1_POLICY_VERSION,
        "evaluator_version": PHASE1_EVALUATOR_VERSION,
        "evaluation_timestamp": evaluation_timestamp,
        "readiness_state": state,
        "control_results": [result.to_dict() for result in results],
        "failed_control_ids": list(failed_ids),
        "reason_codes": list(reason_tuple),
    }
    return ReadinessEvaluation(
        readiness_state=state,
        evaluation_id=sha256_reference(seed),
        policy_version=PHASE1_POLICY_VERSION,
        evaluator_version=PHASE1_EVALUATOR_VERSION,
        evaluation_timestamp=evaluation_timestamp,
        control_results=results,
        failed_control_ids=failed_ids,
        reason_codes=reason_tuple,
        evidence_references=evidence_refs,
    )


def _evaluate_control(control: Any, *, root: Path) -> ControlResult:
    if not isinstance(control, Mapping):
        return ControlResult(
            control_id="UNKNOWN",
            readiness_outcome=BLOCKED,
            blocker_status=True,
            risk_level="CRITICAL",
            evidence_references=(),
            evidence_hashes={},
            reason_codes=("PR_CONTROL_MALFORMED",),
        )
    control_id = str(control.get("control_id", "UNKNOWN"))
    reasons: list[str] = []
    for field in REQUIRED_CONTROL_FIELDS:
        if control.get(field) in ("", None, [], ()):
            reasons.append(f"PR_CONTROL_{field.upper()}_MISSING:{control_id}")
    if control.get("implementation_status") != COMPLETE:
        reasons.append(f"PR_CONTROL_NOT_COMPLETE:{control_id}")
    if control.get("readiness_outcome") != READY:
        reasons.append(f"PR_CONTROL_NOT_READY:{control_id}")
    if control.get("blocker_status") is not False:
        reasons.append(f"PR_CONTROL_BLOCKER_PRESENT:{control_id}")
    if control.get("risk_level") in {"CRITICAL", "HIGH"} and control.get("blocker_status") is not False:
        reasons.append(f"PR_CONTROL_HIGH_BLOCKER_PRESENT:{control_id}")
    if control.get("risk_level") not in ALLOWED_RISK_LEVELS:
        reasons.append(f"PR_CONTROL_RISK_LEVEL_INVALID:{control_id}")
    if control.get("owner") not in ALLOWED_OWNERS:
        reasons.append(f"PR_CONTROL_OWNER_INVALID:{control_id}")
    evidence_references = tuple(str(ref) for ref in control.get("evidence_references", ()) if ref)
    evidence_hashes: dict[str, str] = {}
    for reference in evidence_references:
        path = root / reference
        if not path.is_file():
            reasons.append(f"PR_CONTROL_EVIDENCE_MISSING:{control_id}:{reference}")
            continue
        evidence_hashes[reference] = SHA256_PREFIX + sha256_bytes(path.read_bytes())
    return ControlResult(
        control_id=control_id,
        readiness_outcome=str(control.get("readiness_outcome", BLOCKED)),
        blocker_status=control.get("blocker_status") is not False,
        risk_level=str(control.get("risk_level", "CRITICAL")),
        evidence_references=tuple(sorted(evidence_references)),
        evidence_hashes=dict(sorted(evidence_hashes.items())),
        reason_codes=tuple(sorted(set(reasons))),
    )


def _blocked_evaluation(
    reason: str,
    *,
    evaluation_timestamp: str,
    extra_reasons: Sequence[str] = (),
) -> ReadinessEvaluation:
    reasons = tuple(sorted(set((reason, *extra_reasons))))
    seed = {
        "policy_version": PHASE1_POLICY_VERSION,
        "evaluator_version": PHASE1_EVALUATOR_VERSION,
        "evaluation_timestamp": evaluation_timestamp,
        "readiness_state": BLOCKED,
        "reason_codes": list(reasons),
    }
    return ReadinessEvaluation(
        readiness_state=BLOCKED,
        evaluation_id=sha256_reference(seed),
        policy_version=PHASE1_POLICY_VERSION,
        evaluator_version=PHASE1_EVALUATOR_VERSION,
        evaluation_timestamp=evaluation_timestamp,
        control_results=(),
        failed_control_ids=(),
        reason_codes=reasons,
        evidence_references=(),
    )


def _combined_evidence_hashes(control_results: Sequence[ControlResult]) -> dict[str, str]:
    hashes: dict[str, str] = {}
    for result in control_results:
        hashes.update(result.evidence_hashes)
    return dict(sorted(hashes.items()))


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
