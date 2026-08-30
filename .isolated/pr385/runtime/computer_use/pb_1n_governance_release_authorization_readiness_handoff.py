from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping, Sequence

from governance.hashing import canonical_json, is_sha256_reference, sha256_reference
from runtime.computer_use.pb_1j_governance_chain_release_readiness_contract import (
    BLOCKED,
    READY,
    READY_WITH_RESTRICTIONS,
)


CAPABILITY_NAME = "PB-1N Governance Release Authorization Readiness Handoff"
ALLOWED_DECISIONS = frozenset({READY, READY_WITH_RESTRICTIONS, BLOCKED})
ALLOWED_TOP_LEVEL_FIELDS = frozenset(
    {
        "pb_1m",
        "release_authorization_readiness",
        "approval_chain",
        "approval_evidence",
        "audit_chain",
        "evidence_chain",
        "rollback_references",
        "replay_protection",
        "validation_metadata",
        "policy_reference",
        "tenant_reference",
        "correlation_reference",
        "safety_flags",
        "restriction_metadata",
        "expected_release_authorization_readiness_handoff_hash",
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
        "approval_contents",
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
REDACTED_HASH_FIELDS = frozenset(
    {
        "approval_contents",
        "credential",
        "current_package_hash",
        "current_release_authorization_readiness_handoff_hash",
        "raw_payload",
        "secret",
        "token",
    }
)
REQUIRED_VALIDATION_CHECKS = (
    "focused_pb_1n_tests",
    "pb_1b_regression",
    "pb_1c_regression",
    "pb_1d_regression",
    "pb_1e_regression",
    "pb_1f_regression",
    "pb_1g_regression",
    "pb_1h_regression",
    "pb_1i_regression",
    "pb_1j_regression",
    "pb_1k_regression",
    "pb_1m_regression",
    "governance_regression",
    "evidence_hash_regression",
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
class PB1NReleaseAuthorizationReadinessHandoffDecision:
    final_decision: str
    reason_codes: tuple[str, ...]
    release_authorization_readiness_handoff_hash: str
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
            "release_authorization_readiness_handoff_hash": self.release_authorization_readiness_handoff_hash,
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


def evaluate_pb_1n_release_authorization_readiness_handoff(
    metadata: Mapping[str, Any] | None,
) -> PB1NReleaseAuthorizationReadinessHandoffDecision:
    try:
        return _evaluate_pb_1n_release_authorization_readiness_handoff(metadata)
    except Exception:
        return _blocked(["INTERNAL_ERROR"])


def expected_pb_1n_release_authorization_readiness_handoff_hash(metadata: Mapping[str, Any] | None) -> str:
    try:
        if not isinstance(metadata, Mapping):
            return sha256_reference({"blocked": "MALFORMED_PB_1N_METADATA"})
        return _release_authorization_readiness_handoff_hash(metadata)
    except Exception:
        return sha256_reference({"blocked": "INTERNAL_ERROR"})


def expected_pb_1n_evidence_hash(metadata: Mapping[str, Any] | None) -> str:
    try:
        if not isinstance(metadata, Mapping):
            return sha256_reference({"blocked": "MALFORMED_PB_1N_METADATA"})
        return _evidence_hash(metadata)
    except Exception:
        return sha256_reference({"blocked": "INTERNAL_ERROR"})


def expected_pb_1n_package_hash(metadata: Mapping[str, Any] | None) -> str:
    try:
        if not isinstance(metadata, Mapping):
            return sha256_reference({"blocked": "MALFORMED_PB_1N_METADATA"})
        return _package_hash(metadata)
    except Exception:
        return sha256_reference({"blocked": "INTERNAL_ERROR"})


def canonical_pb_1n_release_authorization_readiness_handoff_json(decision: PB1NReleaseAuthorizationReadinessHandoffDecision) -> str:
    return canonical_json(decision.to_dict())


def _evaluate_pb_1n_release_authorization_readiness_handoff(
    metadata: Mapping[str, Any] | None,
) -> PB1NReleaseAuthorizationReadinessHandoffDecision:
    if not isinstance(metadata, Mapping):
        return _blocked(["MALFORMED_PB_1N_METADATA"])

    surface_reasons = _surface_reasons(metadata)
    if surface_reasons:
        return _blocked(surface_reasons)

    if sorted(set(metadata) - ALLOWED_TOP_LEVEL_FIELDS):
        return _blocked(["UNSUPPORTED_CAPABILITY_METADATA"])

    reasons = [
        *_pb_1m_reasons(metadata.get("pb_1m")),
        *_release_authorization_readiness_reasons(metadata.get("release_authorization_readiness"), metadata),
        *_policy_reasons(metadata),
        *_tenant_reasons(metadata),
        *_correlation_reasons(metadata),
        *_approval_reasons(metadata.get("approval_chain"), metadata),
        *_approval_evidence_reasons(metadata.get("approval_evidence"), metadata),
        *_audit_reasons(metadata.get("audit_chain"), metadata),
        *_evidence_reasons(metadata.get("evidence_chain"), metadata),
        *_rollback_reasons(metadata.get("rollback_references"), metadata),
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
        release_authorization_readiness_handoff_hash=_release_authorization_readiness_handoff_hash(metadata),
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
            if normalized_key in EXECUTION_KEYS and normalized_key not in FALSE_SAFETY_FLAGS:
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


def _pb_1m_reasons(pb_1m: Any) -> tuple[str, ...]:
    if not isinstance(pb_1m, Mapping):
        return ("PB_1M_METADATA_MISSING",)
    reasons: list[str] = []
    decision = pb_1m.get("final_decision")
    if decision not in ALLOWED_DECISIONS:
        reasons.append("INVALID_PB_1M_DECISION")
    if decision == BLOCKED:
        reasons.append("UPSTREAM_BLOCKED")
    for field, reason in (
        ("final_review_package_hash", "PB_1M_FINAL_REVIEW_PACKAGE_HASH_MISSING"),
        ("evidence_hash", "PB_1M_EVIDENCE_HASH_MISSING"),
        ("package_hash", "PB_1M_PACKAGE_HASH_MISSING"),
        ("decision_hash", "PB_1M_DECISION_HASH_MISSING"),
        ("audit_hash", "PB_1M_AUDIT_HASH_MISSING"),
    ):
        if not is_sha256_reference(pb_1m.get(field)):
            reasons.append(reason)
    if pb_1m.get("metadata_stale") is True:
        reasons.append("STALE_METADATA")
    return tuple(reasons)


def _release_authorization_readiness_reasons(candidate: Any, metadata: Mapping[str, Any]) -> tuple[str, ...]:
    if not isinstance(candidate, Mapping):
        return ("RELEASE_AUTHORIZATION_READINESS_REFERENCE_MISSING",)
    reasons: list[str] = []
    for field in (
        "release_authorization_readiness_reference",
        "release_authorization_readiness_evidence_hash",
        "expected_release_authorization_readiness_evidence_hash",
        "pb_1m_decision_hash",
        "pb_1m_package_hash",
        "policy_reference",
        "tenant_reference",
        "correlation_reference",
        "chronology_reference",
    ):
        if not is_sha256_reference(candidate.get(field)):
            reasons.append("RELEASE_AUTHORIZATION_READINESS_REFERENCE_MISSING")
    if candidate.get("release_authorization_readiness_evidence_hash") != candidate.get("expected_release_authorization_readiness_evidence_hash"):
        reasons.append("RELEASE_AUTHORIZATION_READINESS_EVIDENCE_MISSING")
    if candidate.get("pb_1m_decision_hash") != _mapping_value(metadata.get("pb_1m"), "decision_hash"):
        reasons.append("RELEASE_AUTHORIZATION_READINESS_EVIDENCE_MISSING")
    if candidate.get("pb_1m_package_hash") != _mapping_value(metadata.get("pb_1m"), "package_hash"):
        reasons.append("RELEASE_AUTHORIZATION_READINESS_EVIDENCE_MISSING")
    if candidate.get("policy_reference") != _mapping_value(metadata.get("policy_reference"), "policy_reference"):
        reasons.append("POLICY_VERSION_MISMATCH")
    if candidate.get("tenant_reference") != _mapping_value(metadata.get("tenant_reference"), "tenant_reference"):
        reasons.append("TENANT_REFERENCE_MISMATCH")
    if candidate.get("correlation_reference") != _mapping_value(metadata.get("correlation_reference"), "correlation_reference"):
        reasons.append("CORRELATION_REFERENCE_MISSING")
    if candidate.get("duplicate") is True:
        reasons.append("DUPLICATE_RELEASE_AUTHORIZATION_READINESS_METADATA")
    if candidate.get("metadata_stale") is True:
        reasons.append("STALE_METADATA")
    return tuple(reasons)


def _policy_reasons(metadata: Mapping[str, Any]) -> tuple[str, ...]:
    policy = metadata.get("policy_reference")
    pb_1m = metadata.get("pb_1m")
    if not isinstance(policy, Mapping):
        return ("POLICY_VERSION_MISSING",)
    reasons: list[str] = []
    if not is_sha256_reference(policy.get("policy_reference")):
        reasons.append("POLICY_VERSION_MISSING")
    if not isinstance(policy.get("policy_version"), str) or not policy.get("policy_version"):
        reasons.append("POLICY_VERSION_MISSING")
    if isinstance(pb_1m, Mapping) and policy.get("policy_version") != pb_1m.get("policy_version"):
        reasons.append("POLICY_VERSION_MISMATCH")
    if policy.get("metadata_stale") is True:
        reasons.append("STALE_METADATA")
    return tuple(reasons)


def _tenant_reasons(metadata: Mapping[str, Any]) -> tuple[str, ...]:
    tenant = metadata.get("tenant_reference")
    if not isinstance(tenant, Mapping):
        return ("TENANT_REFERENCE_MISSING",)
    reasons: list[str] = []
    if not is_sha256_reference(tenant.get("tenant_reference")):
        reasons.append("TENANT_REFERENCE_MISSING")
    if tenant.get("expected_tenant_reference") != tenant.get("tenant_reference"):
        reasons.append("TENANT_REFERENCE_MISMATCH")
    if tenant.get("metadata_stale") is True:
        reasons.append("STALE_METADATA")
    return tuple(reasons)


def _correlation_reasons(metadata: Mapping[str, Any]) -> tuple[str, ...]:
    correlation = metadata.get("correlation_reference")
    if not isinstance(correlation, Mapping):
        return ("CORRELATION_REFERENCE_MISSING",)
    if not is_sha256_reference(correlation.get("correlation_reference")):
        return ("CORRELATION_REFERENCE_MISSING",)
    return ()


def _approval_reasons(approval: Any, metadata: Mapping[str, Any]) -> tuple[str, ...]:
    if not isinstance(approval, Mapping):
        return ("APPROVAL_REFERENCE_MISSING",)
    reasons: list[str] = []
    if approval.get("status") != "VALID":
        reasons.append("APPROVAL_INVALID")
    if approval.get("duplicate") is True:
        reasons.append("DUPLICATE_RELEASE_AUTHORIZATION_READINESS_METADATA")
    for field in (
        "approval_reference",
        "approval_evidence_hash",
        "pb_1m_decision_hash",
        "pb_1m_package_hash",
        "release_authorization_readiness_reference",
        "release_authorization_readiness_evidence_hash",
        "rollback_evidence_reference",
        "policy_reference",
        "tenant_reference",
        "correlation_reference",
        "replay_metadata_reference",
        "chronology_reference",
    ):
        if not is_sha256_reference(approval.get(field)):
            reasons.append("APPROVAL_REFERENCE_MISSING")
    if approval.get("capability") != CAPABILITY_NAME:
        reasons.append("APPROVAL_INVALID")
    if approval.get("pb_1m_decision_hash") != _mapping_value(metadata.get("pb_1m"), "decision_hash"):
        reasons.append("APPROVAL_INVALID")
    if approval.get("pb_1m_package_hash") != _mapping_value(metadata.get("pb_1m"), "package_hash"):
        reasons.append("APPROVAL_INVALID")
    if approval.get("release_authorization_readiness_reference") != _mapping_value(metadata.get("release_authorization_readiness"), "release_authorization_readiness_reference"):
        reasons.append("APPROVAL_INVALID")
    if approval.get("release_authorization_readiness_evidence_hash") != _mapping_value(metadata.get("release_authorization_readiness"), "release_authorization_readiness_evidence_hash"):
        reasons.append("APPROVAL_INVALID")
    if approval.get("rollback_evidence_reference") != _mapping_value(metadata.get("rollback_references"), "rollback_evidence_reference"):
        reasons.append("ROLLBACK_EVIDENCE_MISSING")
    if approval.get("policy_reference") != _mapping_value(metadata.get("policy_reference"), "policy_reference"):
        reasons.append("POLICY_VERSION_MISMATCH")
    if approval.get("tenant_reference") != _mapping_value(metadata.get("tenant_reference"), "tenant_reference"):
        reasons.append("TENANT_REFERENCE_MISMATCH")
    if approval.get("correlation_reference") != _mapping_value(metadata.get("correlation_reference"), "correlation_reference"):
        reasons.append("CORRELATION_REFERENCE_MISSING")
    if approval.get("expired") is True or approval.get("metadata_stale") is True:
        reasons.append("STALE_METADATA")
    return tuple(reasons)


def _approval_evidence_reasons(approval_evidence: Any, metadata: Mapping[str, Any]) -> tuple[str, ...]:
    if not isinstance(approval_evidence, Mapping):
        return ("APPROVAL_EVIDENCE_MISSING",)
    reasons: list[str] = []
    for field in ("approval_evidence_hash", "expected_approval_evidence_hash", "human_approval_reference"):
        if not is_sha256_reference(approval_evidence.get(field)):
            reasons.append("APPROVAL_EVIDENCE_MISSING")
    if approval_evidence.get("approval_evidence_hash") != approval_evidence.get("expected_approval_evidence_hash"):
        reasons.append("APPROVAL_INVALID")
    if approval_evidence.get("human_approval_reference") != _mapping_value(metadata.get("approval_chain"), "approval_reference"):
        reasons.append("APPROVAL_INVALID")
    if approval_evidence.get("metadata_stale") is True:
        reasons.append("STALE_METADATA")
    return tuple(reasons)


def _audit_reasons(audit: Any, metadata: Mapping[str, Any]) -> tuple[str, ...]:
    if not isinstance(audit, Mapping):
        return ("AUDIT_CHAIN_MISSING",)
    reasons: list[str] = []
    for field in (
        "pb_1m_audit_hash",
        "pb_1n_validation_audit_hash",
        "previous_audit_hash",
        "current_audit_hash",
        "expected_current_audit_hash",
        "approval_audit_reference",
        "release_authorization_readiness_audit_reference",
        "correlation_reference",
        "policy_reference",
        "tenant_reference",
    ):
        if not is_sha256_reference(audit.get(field)):
            reasons.append("AUDIT_CHAIN_MISSING")
    if audit.get("current_audit_hash") != audit.get("expected_current_audit_hash"):
        reasons.append("AUDIT_HASH_MISMATCH")
    if audit.get("pb_1m_audit_hash") != _mapping_value(metadata.get("pb_1m"), "audit_hash"):
        reasons.append("AUDIT_HASH_MISMATCH")
    if audit.get("approval_audit_reference") != _mapping_value(metadata.get("approval_chain"), "approval_reference"):
        reasons.append("AUDIT_HASH_MISMATCH")
    if audit.get("release_authorization_readiness_audit_reference") != _mapping_value(metadata.get("release_authorization_readiness"), "release_authorization_readiness_reference"):
        reasons.append("AUDIT_HASH_MISMATCH")
    if audit.get("policy_reference") != _mapping_value(metadata.get("policy_reference"), "policy_reference"):
        reasons.append("POLICY_VERSION_MISMATCH")
    if audit.get("tenant_reference") != _mapping_value(metadata.get("tenant_reference"), "tenant_reference"):
        reasons.append("TENANT_REFERENCE_MISMATCH")
    if not _valid_chronology(audit.get("chronology_marker")):
        reasons.append("CHRONOLOGY_MISMATCH")
    if audit.get("duplicate") is True or audit.get("metadata_stale") is True:
        reasons.append("STALE_METADATA")
    return tuple(reasons)


def _evidence_reasons(evidence: Any, metadata: Mapping[str, Any]) -> tuple[str, ...]:
    if not isinstance(evidence, Mapping):
        return ("EVIDENCE_CHAIN_MISSING",)
    reasons: list[str] = []
    for field in (
        "pb_1m_final_review_package_reference",
        "pb_1m_evidence_reference",
        "pb_1m_audit_reference",
        "release_authorization_readiness_evidence_reference",
        "approval_evidence_reference",
        "human_approval_reference",
        "audit_chain_evidence_reference",
        "evidence_chain_reference",
        "rollback_evidence_reference",
        "rollback_plan_evidence_reference",
        "replay_metadata_evidence_reference",
        "validation_evidence_reference",
        "boundary_verification_evidence_reference",
        "sensitive_data_scan_evidence_reference",
        "execution_surface_scan_evidence_reference",
        "current_evidence_hash",
        "expected_current_evidence_hash",
    ):
        if not is_sha256_reference(evidence.get(field)):
            reasons.append("EVIDENCE_CHAIN_MISSING")
    if evidence.get("pb_1m_final_review_package_reference") != _mapping_value(metadata.get("pb_1m"), "final_review_package_hash"):
        reasons.append("EVIDENCE_HASH_MISMATCH")
    if evidence.get("pb_1m_evidence_reference") != _mapping_value(metadata.get("pb_1m"), "evidence_hash"):
        reasons.append("EVIDENCE_HASH_MISMATCH")
    if evidence.get("pb_1m_audit_reference") != _mapping_value(metadata.get("pb_1m"), "audit_hash"):
        reasons.append("EVIDENCE_HASH_MISMATCH")
    if evidence.get("release_authorization_readiness_evidence_reference") != _mapping_value(metadata.get("release_authorization_readiness"), "release_authorization_readiness_evidence_hash"):
        reasons.append("EVIDENCE_HASH_MISMATCH")
    if evidence.get("current_evidence_hash") != evidence.get("expected_current_evidence_hash"):
        reasons.append("EVIDENCE_HASH_MISMATCH")
    if not _valid_chronology(evidence.get("chronology_marker")):
        reasons.append("CHRONOLOGY_MISMATCH")
    if evidence.get("metadata_stale") is True:
        reasons.append("STALE_METADATA")
    return tuple(reasons)


def _rollback_reasons(rollback: Any, metadata: Mapping[str, Any]) -> tuple[str, ...]:
    if not isinstance(rollback, Mapping):
        return ("ROLLBACK_REFERENCE_MISSING",)
    reasons: list[str] = []
    for field in (
        "rollback_plan_reference",
        "rollback_evidence_reference",
        "previous_release_authorization_readiness_handoff_hash",
        "current_release_authorization_readiness_handoff_hash",
        "rollback_owner_reference",
        "rollback_chronology_reference",
    ):
        if not is_sha256_reference(rollback.get(field)):
            reasons.append("ROLLBACK_REFERENCE_MISSING")
    if rollback.get("status") != "VERIFIED":
        reasons.append("ROLLBACK_EVIDENCE_MISSING")
    if rollback.get("current_release_authorization_readiness_handoff_hash") != metadata.get("expected_package_hash"):
        reasons.append("PACKAGE_HASH_MISMATCH")
    if rollback.get("duplicate") is True:
        reasons.append("DUPLICATE_RELEASE_AUTHORIZATION_READINESS_METADATA")
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
        reasons.append("PACKAGE_HASH_MISMATCH")
    if replay.get("duplicate_approval_detected") is not False:
        reasons.append("DUPLICATE_RELEASE_AUTHORIZATION_READINESS_METADATA")
    if replay.get("duplicate_release_authorization_readiness_detected") is not False:
        reasons.append("DUPLICATE_RELEASE_AUTHORIZATION_READINESS_METADATA")
    if replay.get("duplicate_package_detected") is not False:
        reasons.append("DUPLICATE_RELEASE_AUTHORIZATION_READINESS_METADATA")
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
        return ("EXECUTION_FLAG_NOT_FALSE",)
    reasons: list[str] = []
    for flag in FALSE_SAFETY_FLAGS:
        if flags.get(flag) is not False:
            reasons.append("EXECUTION_FLAG_NOT_FALSE")
    return tuple(reasons)


def _restriction_reasons(metadata: Mapping[str, Any]) -> tuple[str, ...]:
    pb_1m = metadata.get("pb_1m")
    pb_1m_restricted = isinstance(pb_1m, Mapping) and pb_1m.get("final_decision") == READY_WITH_RESTRICTIONS
    restrictions = metadata.get("restriction_metadata", ())
    if pb_1m_restricted and not _has_governed_restrictions(metadata):
        return ("UNSUPPORTED_CAPABILITY_METADATA",)
    if restrictions and (
        not isinstance(restrictions, Sequence)
        or isinstance(restrictions, (str, bytes))
        or any(not isinstance(item, Mapping) or not is_sha256_reference(item.get("restriction_reference")) for item in restrictions)
    ):
        return ("UNSUPPORTED_CAPABILITY_METADATA",)
    return ()


def _hash_reasons(metadata: Mapping[str, Any]) -> tuple[str, ...]:
    reasons: list[str] = []
    for field, expected, mismatch in (
        (
            "expected_release_authorization_readiness_handoff_hash",
            _release_authorization_readiness_handoff_hash(metadata),
            "RELEASE_AUTHORIZATION_READINESS_HANDOFF_HASH_MISMATCH",
        ),
        ("expected_evidence_hash", _evidence_hash(metadata), "EVIDENCE_HASH_MISMATCH"),
        ("expected_package_hash", _package_hash(metadata), "PACKAGE_HASH_MISMATCH"),
    ):
        value = metadata.get(field)
        if not is_sha256_reference(value):
            reasons.append("HASH_REFERENCE_MISSING")
        elif value != expected:
            reasons.append(mismatch)
    return tuple(reasons)


def _release_authorization_readiness_handoff_hash(metadata: Mapping[str, Any]) -> str:
    return sha256_reference({"schema": "usbay.pb_1n.release_authorization_readiness_handoff.v1", "metadata": _redacted_metadata(metadata)})


def _evidence_hash(metadata: Mapping[str, Any]) -> str:
    return sha256_reference(
        {
            "schema": "usbay.pb_1n.release_authorization_readiness_handoff.evidence.v1",
            "release_authorization_readiness_handoff_hash": _release_authorization_readiness_handoff_hash(metadata),
            "audit_chain": _redacted_mapping(metadata.get("audit_chain")),
            "evidence_chain": _redacted_mapping(metadata.get("evidence_chain")),
            "rollback_references": _redacted_mapping(metadata.get("rollback_references")),
        }
    )


def _package_hash(metadata: Mapping[str, Any]) -> str:
    return sha256_reference(
        {
            "schema": "usbay.pb_1n.release_authorization_readiness_handoff.package.v1",
            "evidence_hash": _evidence_hash(metadata),
            "release_authorization_readiness_handoff_hash": _release_authorization_readiness_handoff_hash(metadata),
        }
    )


def _redacted_metadata(metadata: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "pb_1m": _redacted_mapping(metadata.get("pb_1m")),
        "release_authorization_readiness": _redacted_mapping(metadata.get("release_authorization_readiness")),
        "approval_chain": _redacted_mapping(metadata.get("approval_chain")),
        "approval_evidence": _redacted_mapping(metadata.get("approval_evidence")),
        "audit_chain": _redacted_mapping(metadata.get("audit_chain")),
        "evidence_chain": _redacted_mapping(metadata.get("evidence_chain")),
        "rollback_references": _redacted_mapping(metadata.get("rollback_references")),
        "replay_protection": _redacted_replay(metadata.get("replay_protection")),
        "validation_metadata": _redacted_validation(metadata.get("validation_metadata")),
        "policy_reference": _redacted_mapping(metadata.get("policy_reference")),
        "tenant_reference": _redacted_mapping(metadata.get("tenant_reference")),
        "correlation_reference": _redacted_mapping(metadata.get("correlation_reference")),
        "safety_flags": _redacted_mapping(metadata.get("safety_flags")),
        "restriction_metadata": _redacted_restrictions(metadata),
    }


def _redacted_mapping(value: Any) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        return {}
    return {key: item for key, item in sorted(value.items()) if key not in REDACTED_HASH_FIELDS}


def _redacted_replay(value: Any) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        return {}
    return {key: item for key, item in sorted(value.items()) if key != "current_package_hash"}


def _redacted_validation(value: Any) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        return {}
    return {
        key: {"status": item.get("status"), "evidence_reference": item.get("evidence_reference")}
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
    release_authorization_readiness_handoff_hash: str | None = None,
    evidence_hash: str | None = None,
    package_hash: str | None = None,
) -> PB1NReleaseAuthorizationReadinessHandoffDecision:
    normalized_reasons = tuple(sorted(dict.fromkeys(reason_codes)))
    resolved_lock_hash = release_authorization_readiness_handoff_hash or sha256_reference(
        {"final_decision": final_decision, "reason_codes": normalized_reasons}
    )
    resolved_evidence_hash = evidence_hash or sha256_reference(
        {"final_decision": final_decision, "reason_codes": normalized_reasons, "release_authorization_readiness_handoff_hash": resolved_lock_hash}
    )
    resolved_package_hash = package_hash or sha256_reference(
        {
            "evidence_hash": resolved_evidence_hash,
            "final_decision": final_decision,
            "reason_codes": normalized_reasons,
            "release_authorization_readiness_handoff_hash": resolved_lock_hash,
        }
    )
    return PB1NReleaseAuthorizationReadinessHandoffDecision(
        final_decision=final_decision,
        reason_codes=normalized_reasons,
        release_authorization_readiness_handoff_hash=resolved_lock_hash,
        evidence_hash=resolved_evidence_hash,
        package_hash=resolved_package_hash,
    )


def _blocked(reason_codes: Sequence[str]) -> PB1NReleaseAuthorizationReadinessHandoffDecision:
    return _decision(BLOCKED, reason_codes)
