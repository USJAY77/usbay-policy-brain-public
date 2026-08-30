from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping, Sequence

from governance.hashing import canonical_json, is_sha256_reference, sha256_reference
from runtime.computer_use.pb_1i_chain_closure_verification import (
    BLOCKED,
    READY,
    READY_WITH_RESTRICTIONS,
)


CAPABILITY_NAME = "PB-1J Governance Chain Release Readiness Contract"
ALLOWED_DECISIONS = frozenset({READY, READY_WITH_RESTRICTIONS, BLOCKED})
ALLOWED_TOP_LEVEL_FIELDS = frozenset(
    {
        "pb_1i",
        "release_intent",
        "approval_chain",
        "audit_chain",
        "evidence_chain",
        "regression_evidence",
        "rollback_evidence",
        "replay_protection",
        "validation_metadata",
        "safety_flags",
        "restriction_metadata",
        "expected_contract_hash",
        "expected_evidence_hash",
        "expected_package_hash",
    }
)
FALSE_SAFETY_FLAGS = (
    "execution_allowed",
    "provider_execution",
    "production_activation",
    "deployment_authorized",
    "runtime_mutation",
    "policy_mutation",
)
SENSITIVE_KEYS = frozenset(
    {
        "api_key",
        "authorization",
        "cookie",
        "credential",
        "environment",
        "password",
        "personal_data",
        "pii",
        "private_key",
        "prompt",
        "provider_response",
        "raw_payload",
        "secret",
        "token",
    }
)
EXECUTION_KEYS = frozenset(
    {
        "command",
        "deploy",
        "deployment_authorized",
        "direct_execution_requested",
        "execute",
        "network_access",
        "policy_mutation",
        "production_activation",
        "provider_execution",
        "runtime_mutation",
        "socket",
        "subprocess",
    }
)
REQUIRED_VALIDATION_CHECKS = (
    "focused_pb_1j_tests",
    "pb_1b_regression",
    "pb_1c_regression",
    "pb_1d_regression",
    "pb_1e_regression",
    "pb_1f_regression",
    "pb_1g_regression",
    "pb_1h_regression",
    "pb_1i_regression",
    "governance_regression",
    "json_validation",
    "python_validation",
    "markdown_validation",
    "boundary_validation",
    "conflict_marker_scan",
    "sensitive_data_scan",
    "credential_scan",
    "execution_surface_scan",
    "deterministic_output_validation",
    "fail_closed_validation",
)


@dataclass(frozen=True)
class PB1JReleaseReadinessDecision:
    final_decision: str
    reason_codes: tuple[str, ...]
    contract_hash: str
    evidence_hash: str
    package_hash: str
    execution_allowed: bool = False
    provider_execution: bool = False
    production_activation: bool = False
    deployment_authorized: bool = False
    runtime_mutation: bool = False
    policy_mutation: bool = False
    metadata_only: bool = True
    human_approval_required: bool = True

    def to_dict(self) -> dict[str, Any]:
        payload = {
            "final_decision": self.final_decision,
            "reason_codes": list(self.reason_codes),
            "contract_hash": self.contract_hash,
            "evidence_hash": self.evidence_hash,
            "package_hash": self.package_hash,
            "execution_allowed": self.execution_allowed,
            "provider_execution": self.provider_execution,
            "production_activation": self.production_activation,
            "deployment_authorized": self.deployment_authorized,
            "runtime_mutation": self.runtime_mutation,
            "policy_mutation": self.policy_mutation,
            "metadata_only": self.metadata_only,
            "human_approval_required": self.human_approval_required,
        }
        payload["decision_hash"] = sha256_reference(payload)
        return payload


def evaluate_pb_1j_release_readiness_contract(metadata: Mapping[str, Any] | None) -> PB1JReleaseReadinessDecision:
    try:
        return _evaluate_pb_1j_release_readiness_contract(metadata)
    except Exception:
        return _blocked(["INTERNAL_ERROR"])


def expected_pb_1j_contract_hash(metadata: Mapping[str, Any] | None) -> str:
    try:
        if not isinstance(metadata, Mapping):
            return sha256_reference({"blocked": "MALFORMED_PB_1J_METADATA"})
        return _contract_hash(metadata)
    except Exception:
        return sha256_reference({"blocked": "INTERNAL_ERROR"})


def expected_pb_1j_evidence_hash(metadata: Mapping[str, Any] | None) -> str:
    try:
        if not isinstance(metadata, Mapping):
            return sha256_reference({"blocked": "MALFORMED_PB_1J_METADATA"})
        return _evidence_hash(metadata)
    except Exception:
        return sha256_reference({"blocked": "INTERNAL_ERROR"})


def expected_pb_1j_package_hash(metadata: Mapping[str, Any] | None) -> str:
    try:
        if not isinstance(metadata, Mapping):
            return sha256_reference({"blocked": "MALFORMED_PB_1J_METADATA"})
        return _package_hash(metadata)
    except Exception:
        return sha256_reference({"blocked": "INTERNAL_ERROR"})


def canonical_pb_1j_json(decision: PB1JReleaseReadinessDecision) -> str:
    return canonical_json(decision.to_dict())


def _evaluate_pb_1j_release_readiness_contract(metadata: Mapping[str, Any] | None) -> PB1JReleaseReadinessDecision:
    if not isinstance(metadata, Mapping):
        return _blocked(["MALFORMED_PB_1J_METADATA"])

    surface_reasons = _surface_reasons(metadata)
    if surface_reasons:
        return _blocked(surface_reasons)

    unknown_fields = sorted(set(metadata) - ALLOWED_TOP_LEVEL_FIELDS)
    if unknown_fields:
        return _blocked(["UNSUPPORTED_CAPABILITY_METADATA"])

    reasons = [
        *_pb_1i_reasons(metadata.get("pb_1i")),
        *_release_intent_reasons(metadata.get("release_intent")),
        *_approval_reasons(metadata.get("approval_chain"), metadata),
        *_audit_reasons(metadata.get("audit_chain"), metadata),
        *_evidence_reasons(metadata.get("evidence_chain")),
        *_regression_reasons(metadata.get("regression_evidence")),
        *_rollback_reasons(metadata.get("rollback_evidence")),
        *_replay_reasons(metadata.get("replay_protection"), metadata),
        *_validation_reasons(metadata.get("validation_metadata")),
        *_safety_flag_reasons(metadata.get("safety_flags")),
        *_restriction_reasons(metadata),
        *_hash_reasons(metadata),
    ]
    if reasons:
        return _blocked(reasons)

    final_decision = READY_WITH_RESTRICTIONS if _has_governed_restrictions(metadata) else READY
    return _decision(
        final_decision,
        [],
        contract_hash=_contract_hash(metadata),
        evidence_hash=_evidence_hash(metadata),
        package_hash=_package_hash(metadata),
    )


def _surface_reasons(value: Any) -> tuple[str, ...]:
    reasons: list[str] = []
    _collect_surface_reasons(value, reasons)
    return tuple(sorted(dict.fromkeys(reasons)))


def _collect_surface_reasons(value: Any, reasons: list[str]) -> None:
    if isinstance(value, Mapping):
        for key, item in value.items():
            normalized_key = str(key).lower()
            if normalized_key in SENSITIVE_KEYS:
                reasons.append("SENSITIVE_DATA_REJECTED")
            if normalized_key in EXECUTION_KEYS:
                if normalized_key in FALSE_SAFETY_FLAGS:
                    pass
                else:
                    reasons.append("EXECUTION_SURFACE_REJECTED")
            _collect_surface_reasons(item, reasons)
        return
    if isinstance(value, str):
        if _looks_like_credential(value):
            reasons.append("CREDENTIAL_LITERAL_REJECTED")
        return
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes)):
        for item in value:
            _collect_surface_reasons(item, reasons)


def _looks_like_credential(value: str) -> bool:
    access_key = "A" + "KIA"
    github_classic = "g" + "hp_"
    github_fine_grained = "github" + "_pat_"
    slack_bot = "x" + "oxb-"
    private_key_marker = "PRIVATE" + " KEY"
    return any(marker in value for marker in (access_key, github_classic, github_fine_grained, slack_bot, private_key_marker))


def _pb_1i_reasons(pb_1i: Any) -> tuple[str, ...]:
    if not isinstance(pb_1i, Mapping):
        return ("PB_1I_METADATA_MISSING",)
    reasons: list[str] = []
    decision = pb_1i.get("final_decision")
    if decision not in ALLOWED_DECISIONS:
        reasons.append("INVALID_PB_1I_DECISION")
    if decision == BLOCKED:
        reasons.append("UPSTREAM_BLOCKED")
    for field, reason in (
        ("chain_hash", "PB_1I_CHAIN_HASH_MISSING"),
        ("evidence_hash", "PB_1I_EVIDENCE_HASH_MISSING"),
        ("package_hash", "PB_1I_PACKAGE_HASH_MISSING"),
        ("decision_hash", "PB_1I_DECISION_HASH_MISSING"),
        ("audit_hash", "PB_1I_AUDIT_HASH_MISSING"),
    ):
        if not is_sha256_reference(pb_1i.get(field)):
            reasons.append(reason)
    if not isinstance(pb_1i.get("policy_version"), str) or not pb_1i.get("policy_version"):
        reasons.append("POLICY_VERSION_MISSING")
    if pb_1i.get("metadata_stale") is True:
        reasons.append("STALE_METADATA")
    return tuple(reasons)


def _release_intent_reasons(release_intent: Any) -> tuple[str, ...]:
    if not isinstance(release_intent, Mapping):
        return ("RELEASE_INTENT_MISSING",)
    reasons: list[str] = []
    if not is_sha256_reference(release_intent.get("release_intent_reference")):
        reasons.append("RELEASE_INTENT_MISSING")
    if release_intent.get("capability") != CAPABILITY_NAME:
        reasons.append("UNSUPPORTED_CAPABILITY_METADATA")
    if not isinstance(release_intent.get("policy_version"), str) or not release_intent.get("policy_version"):
        reasons.append("POLICY_VERSION_MISSING")
    if release_intent.get("metadata_stale") is True:
        reasons.append("STALE_METADATA")
    return tuple(reasons)


def _approval_reasons(approval: Any, metadata: Mapping[str, Any]) -> tuple[str, ...]:
    if not isinstance(approval, Mapping):
        return ("APPROVAL_REFERENCE_MISSING",)
    reasons: list[str] = []
    if approval.get("status") != "VALID":
        reasons.append("APPROVAL_INVALID")
    for field in (
        "approval_reference",
        "pb_1i_decision_hash",
        "release_intent_reference",
        "regression_evidence_reference",
        "rollback_evidence_reference",
        "chronology_reference",
    ):
        if not is_sha256_reference(approval.get(field)):
            reasons.append("APPROVAL_REFERENCE_MISSING")
    if approval.get("capability") != CAPABILITY_NAME:
        reasons.append("APPROVAL_INVALID")
    if approval.get("pb_1i_decision_hash") != _mapping_value(metadata.get("pb_1i"), "decision_hash"):
        reasons.append("APPROVAL_INVALID")
    if approval.get("release_intent_reference") != _mapping_value(metadata.get("release_intent"), "release_intent_reference"):
        reasons.append("APPROVAL_INVALID")
    if approval.get("policy_version") != _policy_version(metadata):
        reasons.append("POLICY_VERSION_MISMATCH")
    if approval.get("expired") is True or approval.get("metadata_stale") is True:
        reasons.append("STALE_METADATA")
    return tuple(reasons)


def _audit_reasons(audit: Any, metadata: Mapping[str, Any]) -> tuple[str, ...]:
    if not isinstance(audit, Mapping):
        return ("AUDIT_CHAIN_MISSING",)
    reasons: list[str] = []
    for field in (
        "pb_1i_audit_reference",
        "pb_1j_validation_audit_reference",
        "previous_audit_hash",
        "current_audit_hash",
        "expected_current_audit_hash",
        "correlation_reference",
        "human_approval_reference",
    ):
        if not is_sha256_reference(audit.get(field)):
            reasons.append("AUDIT_CHAIN_MISSING")
    if audit.get("current_audit_hash") != audit.get("expected_current_audit_hash"):
        reasons.append("AUDIT_HASH_MISMATCH")
    if audit.get("pb_1i_audit_reference") != _mapping_value(metadata.get("pb_1i"), "audit_hash"):
        reasons.append("AUDIT_HASH_MISMATCH")
    if audit.get("human_approval_reference") != _mapping_value(metadata.get("approval_chain"), "approval_reference"):
        reasons.append("AUDIT_HASH_MISMATCH")
    if audit.get("policy_version") != _policy_version(metadata):
        reasons.append("POLICY_VERSION_MISMATCH")
    if not _valid_chronology(audit.get("chronology_marker")):
        reasons.append("CHRONOLOGY_MISMATCH")
    if audit.get("duplicate") is True or audit.get("metadata_stale") is True:
        reasons.append("STALE_METADATA")
    return tuple(reasons)


def _evidence_reasons(evidence: Any) -> tuple[str, ...]:
    if not isinstance(evidence, Mapping):
        return ("EVIDENCE_CHAIN_MISSING",)
    reasons: list[str] = []
    required = (
        "pb_1i_evidence_reference",
        "regression_test_evidence_reference",
        "governance_regression_evidence_reference",
        "approval_evidence_reference",
        "audit_chain_evidence_reference",
        "rollback_evidence_reference",
        "boundary_verification_evidence_reference",
        "sensitive_data_scan_evidence_reference",
        "execution_surface_scan_evidence_reference",
        "current_evidence_hash",
        "expected_current_evidence_hash",
    )
    for field in required:
        if not is_sha256_reference(evidence.get(field)):
            reasons.append("EVIDENCE_CHAIN_MISSING")
    if evidence.get("current_evidence_hash") != evidence.get("expected_current_evidence_hash"):
        reasons.append("EVIDENCE_HASH_MISMATCH")
    if evidence.get("metadata_stale") is True:
        reasons.append("STALE_METADATA")
    return tuple(reasons)


def _regression_reasons(regression: Any) -> tuple[str, ...]:
    if not isinstance(regression, Mapping):
        return ("REGRESSION_EVIDENCE_MISSING",)
    reasons: list[str] = []
    if not is_sha256_reference(regression.get("regression_evidence_reference")):
        reasons.append("REGRESSION_EVIDENCE_MISSING")
    if regression.get("status") != "PASS":
        reasons.append("REGRESSION_EVIDENCE_MISSING")
    if regression.get("metadata_stale") is True:
        reasons.append("STALE_METADATA")
    return tuple(reasons)


def _rollback_reasons(rollback: Any) -> tuple[str, ...]:
    if not isinstance(rollback, Mapping):
        return ("ROLLBACK_EVIDENCE_MISSING",)
    reasons: list[str] = []
    if not is_sha256_reference(rollback.get("rollback_evidence_reference")):
        reasons.append("ROLLBACK_EVIDENCE_MISSING")
    if rollback.get("status") != "VERIFIED":
        reasons.append("ROLLBACK_EVIDENCE_MISSING")
    if rollback.get("metadata_stale") is True:
        reasons.append("STALE_METADATA")
    return tuple(reasons)


def _replay_reasons(replay: Any, metadata: Mapping[str, Any]) -> tuple[str, ...]:
    if not isinstance(replay, Mapping):
        return ("REPLAY_METADATA_MISSING",)
    reasons: list[str] = []
    for field in ("nonce_reference", "timestamp_reference", "previous_package_hash", "current_package_hash"):
        if not is_sha256_reference(replay.get(field)):
            reasons.append("REPLAY_METADATA_MISSING")
    if replay.get("current_package_hash") != metadata.get("expected_package_hash"):
        reasons.append("REPLAY_PACKAGE_HASH_MISMATCH")
    if replay.get("duplicate_package_detected") is not False:
        reasons.append("DUPLICATE_PACKAGE_METADATA")
    if not isinstance(replay.get("replay_window_seconds"), int) or replay.get("replay_window_seconds") <= 0:
        reasons.append("REPLAY_METADATA_MISSING")
    if not _valid_chronology(replay.get("chronology_marker")):
        reasons.append("CHRONOLOGY_MISMATCH")
    if replay.get("expired") is True or replay.get("metadata_stale") is True:
        reasons.append("STALE_METADATA")
    return tuple(reasons)


def _validation_reasons(validation: Any) -> tuple[str, ...]:
    if not isinstance(validation, Mapping):
        return ("VALIDATION_METADATA_MISSING",)
    reasons: list[str] = []
    for check in REQUIRED_VALIDATION_CHECKS:
        record = validation.get(check)
        if not isinstance(record, Mapping):
            reasons.append("VALIDATION_METADATA_MISSING")
            continue
        if record.get("status") != "PASS" or not is_sha256_reference(record.get("evidence_reference")):
            reasons.append("VALIDATION_METADATA_MISSING")
    return tuple(reasons)


def _safety_flag_reasons(flags: Any) -> tuple[str, ...]:
    if not isinstance(flags, Mapping):
        return ("SAFETY_FLAGS_MISSING",)
    reasons = []
    for flag in FALSE_SAFETY_FLAGS:
        if flags.get(flag) is not False:
            reasons.append("EXECUTION_FLAG_NOT_FALSE")
    return tuple(reasons)


def _restriction_reasons(metadata: Mapping[str, Any]) -> tuple[str, ...]:
    pb_1i = metadata.get("pb_1i")
    pb_1i_restricted = isinstance(pb_1i, Mapping) and pb_1i.get("final_decision") == READY_WITH_RESTRICTIONS
    restrictions = metadata.get("restriction_metadata", ())
    if pb_1i_restricted and not _has_governed_restrictions(metadata):
        return ("GOVERNED_RESTRICTION_METADATA_MISSING",)
    if restrictions and (
        not isinstance(restrictions, Sequence)
        or isinstance(restrictions, (str, bytes))
        or any(not isinstance(item, Mapping) or not is_sha256_reference(item.get("restriction_reference")) for item in restrictions)
    ):
        return ("GOVERNED_RESTRICTION_METADATA_MISSING",)
    return ()


def _hash_reasons(metadata: Mapping[str, Any]) -> tuple[str, ...]:
    reasons: list[str] = []
    for field, expected, mismatch in (
        ("expected_contract_hash", _contract_hash(metadata), "CONTRACT_HASH_MISMATCH"),
        ("expected_evidence_hash", _evidence_hash(metadata), "EVIDENCE_HASH_MISMATCH"),
        ("expected_package_hash", _package_hash(metadata), "PACKAGE_HASH_MISMATCH"),
    ):
        value = metadata.get(field)
        if not is_sha256_reference(value):
            reasons.append("HASH_REFERENCE_MISSING")
        elif value != expected:
            reasons.append(mismatch)
    return tuple(reasons)


def _contract_hash(metadata: Mapping[str, Any]) -> str:
    return sha256_reference({"schema": "usbay.pb_1j.release_readiness_contract.v1", "metadata": _redacted_metadata(metadata)})


def _evidence_hash(metadata: Mapping[str, Any]) -> str:
    return sha256_reference(
        {
            "schema": "usbay.pb_1j.release_readiness_contract.evidence.v1",
            "contract_hash": _contract_hash(metadata),
            "evidence_chain": _redacted_mapping(metadata.get("evidence_chain")),
            "audit_chain": _redacted_mapping(metadata.get("audit_chain")),
        }
    )


def _package_hash(metadata: Mapping[str, Any]) -> str:
    return sha256_reference(
        {
            "schema": "usbay.pb_1j.release_readiness_contract.package.v1",
            "contract_hash": _contract_hash(metadata),
            "evidence_hash": _evidence_hash(metadata),
        }
    )


def _redacted_metadata(metadata: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "pb_1i": _redacted_mapping(metadata.get("pb_1i")),
        "release_intent": _redacted_mapping(metadata.get("release_intent")),
        "approval_chain": _redacted_mapping(metadata.get("approval_chain")),
        "audit_chain": _redacted_mapping(metadata.get("audit_chain")),
        "evidence_chain": _redacted_mapping(metadata.get("evidence_chain")),
        "regression_evidence": _redacted_mapping(metadata.get("regression_evidence")),
        "rollback_evidence": _redacted_mapping(metadata.get("rollback_evidence")),
        "replay_protection": _redacted_replay(metadata.get("replay_protection")),
        "validation_metadata": _redacted_validation(metadata.get("validation_metadata")),
        "safety_flags": _redacted_mapping(metadata.get("safety_flags")),
        "restriction_metadata": _redacted_restrictions(metadata),
    }


def _redacted_mapping(value: Any) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        return {}
    return {
        key: item
        for key, item in sorted(value.items())
        if key not in {"raw_payload", "secret", "token", "credential", "current_package_hash"}
    }


def _redacted_replay(value: Any) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        return {}
    return {key: item for key, item in sorted(value.items()) if key != "current_package_hash"}


def _redacted_validation(value: Any) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        return {}
    return {
        key: {
            "status": item.get("status"),
            "evidence_reference": item.get("evidence_reference"),
        }
        for key, item in sorted(value.items())
        if isinstance(item, Mapping)
    }


def _redacted_restrictions(metadata: Mapping[str, Any]) -> list[dict[str, Any]]:
    restrictions = metadata.get("restriction_metadata", ())
    if not isinstance(restrictions, Sequence) or isinstance(restrictions, (str, bytes)):
        return []
    return [
        {"restriction_reference": item.get("restriction_reference")}
        for item in restrictions
        if isinstance(item, Mapping) and is_sha256_reference(item.get("restriction_reference"))
    ]


def _has_governed_restrictions(metadata: Mapping[str, Any]) -> bool:
    restrictions = metadata.get("restriction_metadata", ())
    return isinstance(restrictions, Sequence) and not isinstance(restrictions, (str, bytes)) and len(restrictions) > 0


def _policy_version(metadata: Mapping[str, Any]) -> str | None:
    release = metadata.get("release_intent")
    if isinstance(release, Mapping):
        return release.get("policy_version")
    return None


def _mapping_value(value: Any, key: str) -> Any:
    if isinstance(value, Mapping):
        return value.get(key)
    return None


def _valid_chronology(value: Any) -> bool:
    return isinstance(value, int) and value > 0


def _decision(
    final_decision: str,
    reason_codes: Sequence[str],
    *,
    contract_hash: str | None = None,
    evidence_hash: str | None = None,
    package_hash: str | None = None,
) -> PB1JReleaseReadinessDecision:
    normalized_reasons = tuple(sorted(dict.fromkeys(reason_codes)))
    resolved_contract_hash = contract_hash or sha256_reference({"final_decision": final_decision, "reason_codes": normalized_reasons})
    resolved_evidence_hash = evidence_hash or sha256_reference(
        {"contract_hash": resolved_contract_hash, "final_decision": final_decision, "reason_codes": normalized_reasons}
    )
    resolved_package_hash = package_hash or sha256_reference(
        {
            "contract_hash": resolved_contract_hash,
            "evidence_hash": resolved_evidence_hash,
            "final_decision": final_decision,
            "reason_codes": normalized_reasons,
        }
    )
    return PB1JReleaseReadinessDecision(
        final_decision=final_decision,
        reason_codes=normalized_reasons,
        contract_hash=resolved_contract_hash,
        evidence_hash=resolved_evidence_hash,
        package_hash=resolved_package_hash,
    )


def _blocked(reason_codes: Sequence[str]) -> PB1JReleaseReadinessDecision:
    return _decision(BLOCKED, reason_codes)
