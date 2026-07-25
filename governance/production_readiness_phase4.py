from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping, Sequence

from governance.hashing import SHA256_PREFIX, sha256_reference


PHASE4_SCHEMA = "usbay.production_readiness.phase4.authorization_boundary.v1"
PHASE4_POLICY_VERSION = "usbay.production-readiness.phase4.v1"
PHASE4_EVALUATOR_VERSION = "production-readiness-phase4-evaluator-v1"
DEFAULT_PHASE4_MANIFEST_PATH = Path("governance/evidence/production_readiness_phase4_manifest.json")

READY_METADATA_ONLY = "READY_METADATA_ONLY"
BLOCKED = "BLOCKED"
INVALID = "INVALID"

FALSE_FLAGS = {
    "execution_allowed": False,
    "provider_execution": False,
    "production_activation": False,
    "deployment_authorized": False,
    "release_authorized": False,
}

CAPABILITY_STATES = frozenset({"CONFIGURED", "VERIFIED_METADATA", "VERIFIED_INTERFACE", "MISSING", "INVALID", "UNAVAILABLE", "NOT_APPLICABLE"})
MANDATORY_CAPABILITIES = frozenset({"rfc3161", "worm", "external_signing"})
MANDATORY_CAPABILITY_READY_STATES = {
    "external_signing": "VERIFIED_INTERFACE",
    "rfc3161": "VERIFIED_METADATA",
    "worm": "VERIFIED_METADATA",
}
OPTIONAL_CAPABILITIES = frozenset({"regulator_submission", "production_deployment_evidence"})
REQUIRED_CAPABILITIES = tuple(sorted(MANDATORY_CAPABILITIES | OPTIONAL_CAPABILITIES))
SUPPORTED_SCHEMA_VERSIONS = frozenset({PHASE4_SCHEMA})
SUPPORTED_SIGNATURE_ALGORITHMS = frozenset({"TEST_DETERMINISTIC_SHA256"})
SUPPORTED_ENVIRONMENTS = frozenset({"internal_controlled", "limited_pilot", "enterprise_production"})
SUPPORTED_ACTION_TYPES = frozenset({"production_readiness_boundary"})
REQUIRED_FIELDS = frozenset(
    {
        "phase",
        "schema_version",
        "policy_id",
        "policy_version",
        "policy_digest",
        "evidence_manifest_digest",
        "source_commit_sha",
        "source_branch",
        "environment_class",
        "requested_action_type",
        "requested_target",
        "parameters_digest",
        "requester_identity_reference",
        "approver_identity_references",
        "approval_policy_reference",
        "required_approval_count",
        "recorded_approval_count",
        "approval_quorum_satisfied",
        "authorized_approver_identity_references",
        "revoked_approver_identity_references",
        "self_approval_prohibited",
        "approval_issued_at",
        "approval_expires_at",
        "approval_evidence_digest",
        "signer_identity_reference",
        "allowed_signer_identity_references",
        "signature_algorithm",
        "signature_reference",
        "signature_verified",
        "trust_root_reference",
        "trusted_root_references",
        "trust_root_verified",
        "timestamp_reference",
        "timestamp_verified",
        "evidence_freshness_seconds",
        "evidence_not_before",
        "evidence_expires_at",
        "evidence_fresh",
        "anti_replay_reference",
        "used_anti_replay_references",
        "replay_check_passed",
        "anti_rollback_reference",
        "rollback_check_passed",
        "minimum_policy_version",
        "change_ticket_reference",
        "rollback_plan_reference",
        "capabilities",
        "action_contract",
    }
)
PROTECTED_FLAG_FIELDS = frozenset(FALSE_FLAGS)
ALLOWED_FIELDS = REQUIRED_FIELDS | PROTECTED_FLAG_FIELDS | frozenset({"production_boundary_ready", "decision", "blocking_reasons"})

SENSITIVE_KEYS = frozenset(
    {
        "secret",
        "secret_value",
        "token",
        "password",
        "private_key",
        "credential",
        "raw_payload",
        "payload",
        "prompt",
        "signature_material",
        "personal_data",
    }
)


@dataclass(frozen=True)
class Phase4Evaluation:
    decision: str
    blocking_reasons: tuple[str, ...]
    production_boundary_ready: bool
    evaluation_id: str
    policy_version: str
    evaluator_version: str
    source_commit_sha: str
    source_branch: str
    evidence_digest: str
    capability_states: Mapping[str, str]
    execution_allowed: bool = False
    provider_execution: bool = False
    production_activation: bool = False
    deployment_authorized: bool = False
    release_authorized: bool = False

    def to_dict(self) -> dict[str, Any]:
        payload = {
            "decision": self.decision,
            "blocking_reasons": list(self.blocking_reasons),
            "production_boundary_ready": self.production_boundary_ready,
            "evaluation_id": self.evaluation_id,
            "policy_version": self.policy_version,
            "evaluator_version": self.evaluator_version,
            "source_commit_sha": self.source_commit_sha,
            "source_branch": self.source_branch,
            "evidence_digest": self.evidence_digest,
            "capability_states": dict(self.capability_states),
            **FALSE_FLAGS,
        }
        return {**payload, "phase4_evaluation_hash": sha256_reference(payload)}


def load_phase4_manifest(path: Path = DEFAULT_PHASE4_MANIFEST_PATH) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def load_phase4_manifest_safely(path: Path = DEFAULT_PHASE4_MANIFEST_PATH) -> Mapping[str, Any] | None:
    try:
        return load_phase4_manifest(path)
    except (OSError, json.JSONDecodeError):
        return None


def deterministic_phase4_signature_reference(payload: Mapping[str, Any]) -> str:
    return sha256_reference(
        {
            "algorithm": "TEST_DETERMINISTIC_SHA256",
            "policy_digest": payload.get("policy_digest"),
            "evidence_manifest_digest": payload.get("evidence_manifest_digest"),
            "source_commit_sha": payload.get("source_commit_sha"),
            "requested_action_type": payload.get("requested_action_type"),
            "requested_target": payload.get("requested_target"),
            "parameters_digest": payload.get("parameters_digest"),
            "signer_identity_reference": payload.get("signer_identity_reference"),
            "trust_root_reference": payload.get("trust_root_reference"),
        }
    )


def evaluate_phase4_authorization_boundary(manifest: Mapping[str, Any] | None, *, timestamp: str) -> Phase4Evaluation:
    try:
        return _evaluate_phase4_authorization_boundary(manifest, timestamp=timestamp)
    except Exception:
        return _blocked(
            reasons=("PR4_EVALUATOR_EXCEPTION",),
            source_commit_sha="",
            source_branch="",
            evidence_digest="",
            capability_states={},
        )


def export_phase4_evidence(evaluation: Phase4Evaluation) -> dict[str, Any]:
    payload = {
        "schema_version": "usbay.production_readiness.phase4.evidence_export.v1",
        "decision": evaluation.decision,
        "blocking_reasons": list(evaluation.blocking_reasons),
        "production_boundary_ready": evaluation.production_boundary_ready,
        "evaluation_id": evaluation.evaluation_id,
        "policy_version": evaluation.policy_version,
        "evaluator_version": evaluation.evaluator_version,
        "source_commit_sha": evaluation.source_commit_sha,
        "source_branch": evaluation.source_branch,
        "evidence_digest": evaluation.evidence_digest,
        "capability_states": dict(evaluation.capability_states),
        **FALSE_FLAGS,
    }
    if _contains_sensitive_key(payload):
        raise ValueError("phase4 evidence export contains sensitive field")
    return {**payload, "evidence_export_hash": sha256_reference(payload)}


def _evaluate_phase4_authorization_boundary(manifest: Mapping[str, Any] | None, *, timestamp: str) -> Phase4Evaluation:
    if not isinstance(manifest, Mapping):
        return _blocked(reasons=("PR4_MANIFEST_MISSING",), source_commit_sha="", source_branch="", evidence_digest="", capability_states={})

    reasons: list[str] = []
    unknown_fields = sorted(set(manifest) - ALLOWED_FIELDS)
    reasons.extend(f"PR4_UNKNOWN_FIELD:{field}" for field in unknown_fields)
    missing_fields = sorted(REQUIRED_FIELDS - set(manifest))
    reasons.extend(f"PR4_REQUIRED_FIELD_MISSING:{field}" for field in missing_fields)
    if _contains_sensitive_key(manifest):
        reasons.append("PR4_SENSITIVE_FIELD_PRESENT")
    for flag, expected in FALSE_FLAGS.items():
        if manifest.get(flag, expected) is not False:
            reasons.append(f"PR4_PROTECTED_FLAG_TRUE:{flag}")

    if manifest.get("phase") != "phase4":
        reasons.append("PR4_PHASE_INVALID")
    if manifest.get("schema_version") not in SUPPORTED_SCHEMA_VERSIONS:
        reasons.append("PR4_SCHEMA_VERSION_UNSUPPORTED")
    if manifest.get("policy_version") != PHASE4_POLICY_VERSION:
        reasons.append("PR4_POLICY_VERSION_MISMATCH")
    if not _is_hash(manifest.get("policy_digest")):
        reasons.append("PR4_POLICY_DIGEST_INVALID")
    if not _is_hash(manifest.get("evidence_manifest_digest")):
        reasons.append("PR4_EVIDENCE_MANIFEST_DIGEST_INVALID")
    if not _is_hash(manifest.get("approval_evidence_digest")):
        reasons.append("PR4_APPROVAL_EVIDENCE_DIGEST_INVALID")
    if not _is_commit_sha(manifest.get("source_commit_sha")):
        reasons.append("PR4_SOURCE_COMMIT_SHA_INVALID")
    if not _is_nonempty_string(manifest.get("source_branch")):
        reasons.append("PR4_SOURCE_BRANCH_MISSING")
    if manifest.get("environment_class") not in SUPPORTED_ENVIRONMENTS:
        reasons.append("PR4_ENVIRONMENT_UNSUPPORTED")
    if manifest.get("requested_action_type") not in SUPPORTED_ACTION_TYPES:
        reasons.append("PR4_ACTION_TYPE_UNSUPPORTED")
    if not _is_nonempty_string(manifest.get("requested_target")):
        reasons.append("PR4_TARGET_MISSING")
    if not _is_hash(manifest.get("parameters_digest")):
        reasons.append("PR4_PARAMETERS_DIGEST_INVALID")
    if not _has_prefix(manifest.get("requester_identity_reference"), "identity:"):
        reasons.append("PR4_REQUESTER_IDENTITY_MALFORMED")
    if not _has_prefix(manifest.get("approval_policy_reference"), "policy:"):
        reasons.append("PR4_APPROVAL_POLICY_REFERENCE_MALFORMED")

    reasons.extend(_validate_signature(manifest))
    reasons.extend(_validate_capabilities(manifest))
    reasons.extend(_validate_approvals(manifest, now=timestamp))
    reasons.extend(_validate_freshness_and_replay(manifest, now=timestamp))
    reasons.extend(_validate_action_contract(manifest))

    invalid_prefixes = ("PR4_UNKNOWN_FIELD", "PR4_REQUIRED_FIELD_MISSING", "PR4_SCHEMA_VERSION_UNSUPPORTED", "PR4_SENSITIVE_FIELD_PRESENT")
    decision = INVALID if any(reason.startswith(invalid_prefixes) for reason in reasons) else BLOCKED if reasons else READY_METADATA_ONLY
    capability_states = {
        str(name): str(value.get("state")) if isinstance(value, Mapping) else "INVALID"
        for name, value in sorted((manifest.get("capabilities") or {}).items())
    }
    payload_digest = sha256_reference(_redacted_manifest(manifest))
    evaluation_id = sha256_reference(
        {
            "decision": decision,
            "blocking_reasons": sorted(set(reasons)),
            "policy_version": PHASE4_POLICY_VERSION,
            "evidence_digest": payload_digest,
            "timestamp": timestamp,
        }
    )
    return Phase4Evaluation(
        decision=decision,
        blocking_reasons=tuple(sorted(set(reasons))),
        production_boundary_ready=decision == READY_METADATA_ONLY,
        evaluation_id=evaluation_id,
        policy_version=PHASE4_POLICY_VERSION,
        evaluator_version=PHASE4_EVALUATOR_VERSION,
        source_commit_sha=str(manifest.get("source_commit_sha", "")),
        source_branch=str(manifest.get("source_branch", "")),
        evidence_digest=payload_digest,
        capability_states=capability_states,
    )


def _validate_signature(manifest: Mapping[str, Any]) -> list[str]:
    reasons: list[str] = []
    signer = manifest.get("signer_identity_reference")
    allowed_signers = manifest.get("allowed_signer_identity_references")
    trust_root = manifest.get("trust_root_reference")
    trusted_roots = manifest.get("trusted_root_references")
    algorithm = manifest.get("signature_algorithm")
    if not _is_nonempty_string(signer):
        reasons.append("PR4_SIGNER_MISSING")
    elif not _has_prefix(signer, "signer:"):
        reasons.append("PR4_SIGNER_IDENTITY_MALFORMED")
    if not isinstance(allowed_signers, Sequence) or isinstance(allowed_signers, (str, bytes)) or not allowed_signers:
        reasons.append("PR4_ALLOWED_SIGNERS_MISSING")
    elif signer not in allowed_signers:
        reasons.append("PR4_SIGNER_UNKNOWN")
    if algorithm not in SUPPORTED_SIGNATURE_ALGORITHMS:
        reasons.append("PR4_SIGNATURE_ALGORITHM_UNSUPPORTED")
    if not _is_nonempty_string(trust_root):
        reasons.append("PR4_TRUST_ROOT_MISSING")
    elif not _has_prefix(trust_root, "trust-root:"):
        reasons.append("PR4_TRUST_ROOT_MALFORMED")
    if not isinstance(trusted_roots, Sequence) or isinstance(trusted_roots, (str, bytes)) or not trusted_roots:
        reasons.append("PR4_TRUSTED_ROOTS_MISSING")
    elif trust_root not in trusted_roots:
        reasons.append("PR4_TRUST_ROOT_UNKNOWN")
    if manifest.get("trust_root_verified") is not True:
        reasons.append("PR4_TRUST_ROOT_UNVERIFIED")
    if not _is_hash(manifest.get("signature_reference")):
        reasons.append("PR4_SIGNATURE_MISSING")
    elif manifest.get("signature_reference") != deterministic_phase4_signature_reference(manifest):
        reasons.append("PR4_SIGNATURE_INVALID")
    if manifest.get("signature_verified") is not True:
        reasons.append("PR4_SIGNATURE_UNVERIFIED")
    return reasons


def _validate_capabilities(manifest: Mapping[str, Any]) -> list[str]:
    reasons: list[str] = []
    capabilities = manifest.get("capabilities")
    if not isinstance(capabilities, Mapping):
        return ["PR4_CAPABILITIES_MISSING"]
    for capability in REQUIRED_CAPABILITIES:
        if capability not in capabilities:
            reasons.append(f"PR4_CAPABILITY_MISSING:{capability}")
            continue
        record = capabilities[capability]
        if not isinstance(record, Mapping):
            reasons.append(f"PR4_CAPABILITY_MALFORMED:{capability}")
            continue
        state = record.get("state")
        if state not in CAPABILITY_STATES:
            reasons.append(f"PR4_CAPABILITY_STATE_INVALID:{capability}")
        expected_ready_state = MANDATORY_CAPABILITY_READY_STATES.get(capability)
        if expected_ready_state is not None and state != expected_ready_state:
            reasons.append(f"PR4_CAPABILITY_NOT_METADATA_READY:{capability}:{state}")
        if state in {"VERIFIED_METADATA", "VERIFIED_INTERFACE"} and not _is_hash(record.get("evidence_reference")):
            reasons.append(f"PR4_CAPABILITY_READY_WITHOUT_EVIDENCE:{capability}")
    for capability in sorted(set(capabilities) - set(REQUIRED_CAPABILITIES)):
        reasons.append(f"PR4_CAPABILITY_UNKNOWN:{capability}")
    return reasons


def _validate_approvals(manifest: Mapping[str, Any], *, now: str) -> list[str]:
    reasons: list[str] = []
    approvers = manifest.get("approver_identity_references")
    authorized = manifest.get("authorized_approver_identity_references")
    revoked = set(manifest.get("revoked_approver_identity_references") or ())
    if not isinstance(approvers, Sequence) or isinstance(approvers, (str, bytes)):
        return ["PR4_APPROVERS_MALFORMED"]
    if not isinstance(authorized, Sequence) or isinstance(authorized, (str, bytes)) or not authorized:
        reasons.append("PR4_AUTHORIZED_APPROVERS_MISSING")
        authorized_set: set[Any] = set()
    else:
        authorized_set = set(authorized)
    approver_set = set(approvers)
    if len(approver_set) != len(approvers):
        reasons.append("PR4_APPROVER_DUPLICATE")
    if revoked & approver_set:
        reasons.append("PR4_APPROVER_REVOKED")
    unauthorized = sorted(str(approver) for approver in approver_set - authorized_set)
    reasons.extend(f"PR4_APPROVER_UNAUTHORIZED:{approver}" for approver in unauthorized)
    malformed = sorted(str(approver) for approver in approver_set if not _has_prefix(approver, "identity:"))
    reasons.extend(f"PR4_APPROVER_IDENTITY_MALFORMED:{approver}" for approver in malformed)
    if manifest.get("self_approval_prohibited") is True and manifest.get("requester_identity_reference") in approver_set:
        reasons.append("PR4_SELF_APPROVAL_PROHIBITED")
    required = manifest.get("required_approval_count")
    recorded = manifest.get("recorded_approval_count")
    if not isinstance(required, int) or required <= 0:
        reasons.append("PR4_REQUIRED_APPROVAL_COUNT_INVALID")
    if recorded != len(approver_set):
        reasons.append("PR4_RECORDED_APPROVAL_COUNT_MISMATCH")
    if isinstance(required, int) and len(approver_set - revoked) < required:
        reasons.append("PR4_APPROVAL_QUORUM_INSUFFICIENT")
    if manifest.get("approval_quorum_satisfied") is not True:
        reasons.append("PR4_APPROVAL_QUORUM_NOT_SATISFIED")
    issued = _parse_time(manifest.get("approval_issued_at"))
    expires = _parse_time(manifest.get("approval_expires_at"))
    current = _parse_time(now)
    if issued is None or expires is None or current is None:
        reasons.append("PR4_APPROVAL_TIMESTAMP_INVALID")
    elif issued > current or expires <= current:
        reasons.append("PR4_APPROVAL_EXPIRED_OR_NOT_YET_VALID")
    return reasons


def _validate_freshness_and_replay(manifest: Mapping[str, Any], *, now: str) -> list[str]:
    reasons: list[str] = []
    if manifest.get("timestamp_verified") is not True:
        reasons.append("PR4_TIMESTAMP_UNVERIFIED")
    if not _is_hash(manifest.get("timestamp_reference")):
        reasons.append("PR4_TIMESTAMP_MISSING")
    current = _parse_time(now)
    not_before = _parse_time(manifest.get("evidence_not_before"))
    expires = _parse_time(manifest.get("evidence_expires_at"))
    if current is None or not_before is None or expires is None:
        reasons.append("PR4_EVIDENCE_TIMESTAMP_INVALID")
    elif not_before > current:
        reasons.append("PR4_EVIDENCE_FUTURE_DATED")
    elif expires <= current:
        reasons.append("PR4_EVIDENCE_EXPIRED")
    if manifest.get("evidence_fresh") is not True:
        reasons.append("PR4_EVIDENCE_NOT_FRESH")
    if not isinstance(manifest.get("evidence_freshness_seconds"), int) or manifest.get("evidence_freshness_seconds") <= 0:
        reasons.append("PR4_EVIDENCE_FRESHNESS_INVALID")
    anti_replay = manifest.get("anti_replay_reference")
    if not _is_hash(anti_replay):
        reasons.append("PR4_ANTI_REPLAY_REFERENCE_INVALID")
    if anti_replay in set(manifest.get("used_anti_replay_references") or ()):
        reasons.append("PR4_REPLAY_DETECTED")
    if manifest.get("replay_check_passed") is not True:
        reasons.append("PR4_REPLAY_CHECK_FAILED")
    if not _is_hash(manifest.get("anti_rollback_reference")):
        reasons.append("PR4_ANTI_ROLLBACK_REFERENCE_INVALID")
    if manifest.get("rollback_check_passed") is not True:
        reasons.append("PR4_ROLLBACK_CHECK_FAILED")
    if manifest.get("minimum_policy_version") != PHASE4_POLICY_VERSION:
        reasons.append("PR4_POLICY_ROLLBACK_DETECTED")
    if not _is_nonempty_string(manifest.get("change_ticket_reference")):
        reasons.append("PR4_CHANGE_TICKET_MISSING")
    elif not _has_prefix(manifest.get("change_ticket_reference"), "change:"):
        reasons.append("PR4_CHANGE_TICKET_MALFORMED")
    if not _is_nonempty_string(manifest.get("rollback_plan_reference")):
        reasons.append("PR4_ROLLBACK_PLAN_MISSING")
    elif not _has_prefix(manifest.get("rollback_plan_reference"), "rollback:"):
        reasons.append("PR4_ROLLBACK_PLAN_MALFORMED")
    return reasons


def _validate_action_contract(manifest: Mapping[str, Any]) -> list[str]:
    contract = manifest.get("action_contract")
    if not isinstance(contract, Mapping):
        return ["PR4_ACTION_CONTRACT_MISSING"]
    expected = {
        "action_type": manifest.get("requested_action_type"),
        "target": manifest.get("requested_target"),
        "environment": manifest.get("environment_class"),
        "policy_version": manifest.get("policy_version"),
        "parameters_digest": manifest.get("parameters_digest"),
        "evidence_digest": manifest.get("evidence_manifest_digest"),
        "requester": manifest.get("requester_identity_reference"),
        "approvers": list(manifest.get("approver_identity_references") or ()),
        "source_commit": manifest.get("source_commit_sha"),
    }
    reasons = []
    for key, value in expected.items():
        if contract.get(key) != value:
            reasons.append(f"PR4_ACTION_CONTRACT_MISMATCH:{key}")
    return reasons


def _blocked(
    *,
    reasons: Sequence[str],
    source_commit_sha: str,
    source_branch: str,
    evidence_digest: str,
    capability_states: Mapping[str, str],
) -> Phase4Evaluation:
    evaluation_id = sha256_reference({"decision": BLOCKED, "blocking_reasons": sorted(reasons)})
    return Phase4Evaluation(
        decision=BLOCKED,
        blocking_reasons=tuple(sorted(set(reasons))),
        production_boundary_ready=False,
        evaluation_id=evaluation_id,
        policy_version=PHASE4_POLICY_VERSION,
        evaluator_version=PHASE4_EVALUATOR_VERSION,
        source_commit_sha=source_commit_sha,
        source_branch=source_branch,
        evidence_digest=evidence_digest,
        capability_states=capability_states,
    )


def _redacted_manifest(manifest: Mapping[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in manifest.items() if key not in {"signature_reference"}}


def _contains_sensitive_key(value: Any) -> bool:
    if isinstance(value, Mapping):
        for key, child in value.items():
            if str(key).lower() in SENSITIVE_KEYS:
                return True
            if _contains_sensitive_key(child):
                return True
    elif isinstance(value, Sequence) and not isinstance(value, (str, bytes)):
        return any(_contains_sensitive_key(item) for item in value)
    return False


def _is_hash(value: Any) -> bool:
    return isinstance(value, str) and value.startswith(SHA256_PREFIX) and len(value) == len(SHA256_PREFIX) + 64 and all(char in "0123456789abcdef" for char in value[len(SHA256_PREFIX) :])


def _is_commit_sha(value: Any) -> bool:
    return isinstance(value, str) and len(value) == 40 and all(char in "0123456789abcdef" for char in value)


def _is_nonempty_string(value: Any) -> bool:
    return isinstance(value, str) and bool(value.strip())


def _has_prefix(value: Any, prefix: str) -> bool:
    return isinstance(value, str) and value.startswith(prefix) and len(value) > len(prefix)


def _parse_time(value: Any) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(timezone.utc)
    except ValueError:
        return None
