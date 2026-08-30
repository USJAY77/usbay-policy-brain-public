from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Mapping, Sequence

from governance.hashing import sha256_reference


EXTERNAL_TRUST_SCHEMA = "usbay.production_readiness.external_trust.v1"
EXTERNAL_TRUST_POLICY_VERSION = "usbay.production-readiness.external-trust.v1"
EXTERNAL_TRUST_CONTRACT_VERSION = "production-external-trust-v1"

NOT_CONFIGURED = "NOT_CONFIGURED"
CONFIGURED = "CONFIGURED"
CONNECTIVITY_VERIFIED = "CONNECTIVITY_VERIFIED"
EVIDENCE_VERIFIED = "EVIDENCE_VERIFIED"
BLOCKED = "BLOCKED"
INVALID = "INVALID"
UNAVAILABLE = "UNAVAILABLE"

CONFIGURATION_STATES = frozenset({NOT_CONFIGURED, CONFIGURED, UNAVAILABLE, INVALID})
VERIFICATION_STATES = frozenset(
    {
        NOT_CONFIGURED,
        CONFIGURED,
        CONNECTIVITY_VERIFIED,
        EVIDENCE_VERIFIED,
        BLOCKED,
        INVALID,
        UNAVAILABLE,
    }
)
CAPABILITY_TYPES = frozenset(
    {
        "rfc3161",
        "worm_object_lock",
        "external_signing",
        "regulator_transport",
        "deployment_evidence",
    }
)
MANDATORY_EXTERNAL_CAPABILITIES = frozenset(
    {"rfc3161", "worm_object_lock", "external_signing", "deployment_evidence"}
)
REGULATOR_CAPABILITY = "regulator_transport"
SUPPORTED_PROVIDER_TYPES = {
    "rfc3161": frozenset({"tsa"}),
    "worm_object_lock": frozenset({"s3_object_lock"}),
    "external_signing": frozenset({"cloud_kms", "hsm_pkcs11", "external_signing_service"}),
    "regulator_transport": frozenset({"governed_outbox"}),
    "deployment_evidence": frozenset({"deployment_evidence_provider"}),
}
SUPPORTED_ENVIRONMENTS = frozenset({"internal_controlled", "limited_pilot", "enterprise_production"})
SUPPORTED_DIGEST_ALGORITHMS = frozenset({"sha256", "sha384", "sha512"})
SUPPORTED_SIGNATURE_ALGORITHMS = frozenset({"ECDSA_SHA256", "RSA_PSS_SHA256", "ED25519"})
SUPPORTED_RETENTION_MODES = frozenset({"GOVERNANCE", "COMPLIANCE"})
SUPPORTED_SUBMISSION_STATES = frozenset(
    {"DRAFT", "VALIDATED", "HUMAN_APPROVED", "QUEUED", "SUBMITTED", "ACKNOWLEDGED", "REJECTED", "BLOCKED", "EXPIRED"}
)
SUPPORTED_DEPLOYMENT_RESULTS = frozenset({"SUCCEEDED", "FAILED", "CANCELLED", "ROLLED_BACK"})
FALSE_FLAGS = {
    "execution_allowed": False,
    "provider_execution": False,
    "production_activation": False,
    "deployment_authorized": False,
    "release_authorized": False,
}

CONTRACT_FIELDS = frozenset(
    {
        "capability_id",
        "capability_type",
        "provider_id",
        "provider_type",
        "environment",
        "configuration_state",
        "verification_state",
        "verified_at",
        "expires_at",
        "evidence_reference",
        "evidence_hash",
        "policy_version",
        "source_commit_sha",
        "request_id",
        "correlation_id",
        "failure_code",
        "failure_reason",
        "contains_sensitive_data",
        "production_eligible",
    }
)
COMMON_FIELDS = CONTRACT_FIELDS | frozenset(FALSE_FLAGS)
RFC3161_FIELDS = COMMON_FIELDS | frozenset(
    {
        "tsa_endpoint_id",
        "trust_anchor_reference",
        "timeout_ms",
        "allowed_digest_algorithms",
        "request_digest",
        "response_digest",
        "nonce_reference",
        "response_nonce_reference",
        "certificate_chain_hash",
        "timestamp_signature_hash",
        "message_imprint_hash",
        "expected_message_imprint_hash",
        "policy_oid",
        "expected_policy_oid",
        "replay_reference",
        "used_replay_references",
        "certificate_fingerprint",
    }
)
WORM_FIELDS = COMMON_FIELDS | frozenset(
    {
        "bucket_reference",
        "object_reference",
        "object_lock_enabled",
        "retention_mode",
        "retention_until",
        "minimum_retention_until",
        "legal_hold_enabled",
        "version_id",
        "immutable_object_checksum",
        "readback_checksum",
        "overwrite_attempt_blocked",
        "delete_attempt_blocked",
        "retention_downgrade_blocked",
        "provider_response_hash",
    }
)
SIGNING_FIELDS = COMMON_FIELDS | frozenset(
    {
        "signer_identity",
        "key_identifier",
        "key_version",
        "algorithm",
        "allowed_algorithms",
        "trust_root_reference",
        "payload_hash",
        "signed_payload_hash",
        "environment_binding",
        "request_nonce",
        "signature_hash",
        "signature_verified",
        "key_revoked",
        "key_expired",
        "signer_authorized",
        "verification_evidence_hash",
    }
)
REGULATOR_FIELDS = COMMON_FIELDS | frozenset(
    {
        "submission_state",
        "regulator_jurisdiction",
        "regulator_endpoint_id",
        "approved_regulator_destinations",
        "submission_type",
        "schema_version",
        "source_evidence_references",
        "evidence_hashes",
        "human_approver_identity",
        "requester_identity",
        "approval_timestamp",
        "approval_expires_at",
        "payload_minimized",
        "sensitive_field_classification",
        "encryption_required",
        "signing_required",
        "external_signature_reference",
        "rfc3161_reference",
        "worm_reference",
        "idempotency_key",
        "anti_replay_nonce",
        "used_anti_replay_nonces",
        "submission_receipt_hash",
        "acknowledgement_receipt_hash",
        "retry_policy_reference",
        "permanent_failure",
        "policy_not_applicable_proof",
    }
)
DEPLOYMENT_FIELDS = COMMON_FIELDS | frozenset(
    {
        "deployment_id",
        "repository",
        "artifact_digest",
        "build_provenance_reference",
        "sbom_reference",
        "workflow_identity",
        "authorized_workflow_identities",
        "runner_identity",
        "deployment_target",
        "deployment_start",
        "deployment_end",
        "deployment_result",
        "rollback_reference",
        "human_authorization_reference",
        "external_signature_reference",
        "rfc3161_reference",
        "worm_reference",
        "commit_exists",
        "artifact_matches_provenance",
        "environment_approved",
        "human_authorization_current",
        "signature_evidence_valid",
        "timestamp_evidence_valid",
        "worm_evidence_valid",
        "rollback_reference_exists",
        "evidence_fresh",
        "replay_reference",
        "used_replay_references",
        "target_binding",
    }
)
FIELDS_BY_CAPABILITY = {
    "rfc3161": RFC3161_FIELDS,
    "worm_object_lock": WORM_FIELDS,
    "external_signing": SIGNING_FIELDS,
    "regulator_transport": REGULATOR_FIELDS,
    "deployment_evidence": DEPLOYMENT_FIELDS,
}

FAILURE_CODES = (
    "EXTERNAL_TRUST_METADATA_MISSING",
    "EXTERNAL_TRUST_UNKNOWN_FIELD",
    "EXTERNAL_TRUST_CAPABILITY_UNKNOWN",
    "EXTERNAL_TRUST_CAPABILITY_MISMATCH",
    "EXTERNAL_TRUST_PROVIDER_ID_MISSING",
    "EXTERNAL_TRUST_PROVIDER_TYPE_UNSUPPORTED",
    "EXTERNAL_TRUST_ENVIRONMENT_UNSUPPORTED",
    "EXTERNAL_TRUST_CONFIGURATION_STATE_INVALID",
    "EXTERNAL_TRUST_VERIFICATION_STATE_INVALID",
    "EXTERNAL_TRUST_VERIFICATION_EXPIRED",
    "EXTERNAL_TRUST_EVIDENCE_REFERENCE_INVALID",
    "EXTERNAL_TRUST_EVIDENCE_HASH_INVALID",
    "EXTERNAL_TRUST_POLICY_VERSION_MISSING",
    "EXTERNAL_TRUST_SOURCE_COMMIT_MISSING",
    "EXTERNAL_TRUST_REQUEST_ID_INVALID",
    "EXTERNAL_TRUST_CORRELATION_ID_INVALID",
    "EXTERNAL_TRUST_SENSITIVE_DATA_PRESENT",
    "EXTERNAL_TRUST_PRODUCTION_ELIGIBLE_WITHOUT_EVIDENCE",
    "EXTERNAL_TRUST_PROTECTED_FLAG_TRUE",
    "RFC3161_NOT_CONFIGURED",
    "RFC3161_ENDPOINT_UNAVAILABLE",
    "RFC3161_TIMEOUT",
    "RFC3161_RESPONSE_MALFORMED",
    "RFC3161_SIGNATURE_INVALID",
    "RFC3161_CERTIFICATE_UNTRUSTED",
    "RFC3161_MESSAGE_IMPRINT_MISMATCH",
    "RFC3161_NONCE_MISMATCH",
    "RFC3161_POLICY_MISMATCH",
    "RFC3161_TIMESTAMP_EXPIRED",
    "RFC3161_REPLAY_DETECTED",
    "WORM_NOT_CONFIGURED",
    "WORM_PROVIDER_UNAVAILABLE",
    "WORM_OBJECT_LOCK_DISABLED",
    "WORM_RETENTION_MISSING",
    "WORM_RETENTION_TOO_SHORT",
    "WORM_RETENTION_MODE_INVALID",
    "WORM_CHECKSUM_MISMATCH",
    "WORM_VERSION_MISSING",
    "WORM_OVERWRITE_POSSIBLE",
    "WORM_DELETE_POSSIBLE",
    "WORM_READBACK_FAILED",
    "WORM_EVIDENCE_INVALID",
    "SIGNING_NOT_CONFIGURED",
    "SIGNER_UNKNOWN",
    "SIGNER_UNAUTHORIZED",
    "SIGNING_KEY_REVOKED",
    "SIGNING_KEY_EXPIRED",
    "SIGNATURE_MISSING",
    "SIGNATURE_INVALID",
    "SIGNATURE_ALGORITHM_UNSUPPORTED",
    "SIGNATURE_PAYLOAD_MISMATCH",
    "SIGNATURE_CONTEXT_MISMATCH",
    "SIGNING_PROVIDER_UNAVAILABLE",
    "SIGNING_EVIDENCE_INVALID",
    "REGULATOR_TRANSPORT_NOT_CONFIGURED",
    "REGULATOR_DESTINATION_UNKNOWN",
    "REGULATOR_DESTINATION_UNAUTHORIZED",
    "REGULATOR_SCHEMA_INVALID",
    "REGULATOR_APPROVAL_MISSING",
    "REGULATOR_APPROVAL_EXPIRED",
    "REGULATOR_SELF_APPROVAL_BLOCKED",
    "REGULATOR_SIGNATURE_MISSING",
    "REGULATOR_TIMESTAMP_MISSING",
    "REGULATOR_WORM_EVIDENCE_MISSING",
    "REGULATOR_REPLAY_DETECTED",
    "REGULATOR_SUBMISSION_FAILED",
    "REGULATOR_ACKNOWLEDGEMENT_INVALID",
    "DEPLOYMENT_EVIDENCE_NOT_CONFIGURED",
    "DEPLOYMENT_EVIDENCE_MISSING",
    "DEPLOYMENT_COMMIT_MISMATCH",
    "DEPLOYMENT_ARTIFACT_MISMATCH",
    "DEPLOYMENT_PROVENANCE_INVALID",
    "DEPLOYMENT_WORKFLOW_UNAUTHORIZED",
    "DEPLOYMENT_ENVIRONMENT_UNAUTHORIZED",
    "DEPLOYMENT_HUMAN_APPROVAL_MISSING",
    "DEPLOYMENT_SIGNATURE_INVALID",
    "DEPLOYMENT_TIMESTAMP_INVALID",
    "DEPLOYMENT_WORM_REFERENCE_INVALID",
    "DEPLOYMENT_REPLAY_DETECTED",
    "DEPLOYMENT_ROLLBACK_REFERENCE_MISSING",
    "DEPLOYMENT_EVIDENCE_EXPIRED",
    "EXTERNAL_TRUST_REQUIRED_CAPABILITY_MISSING",
    "EXTERNAL_TRUST_REGULATOR_POLICY_PROOF_MISSING",
    "EXTERNAL_TRUST_DUPLICATE_CAPABILITY",
)
SENSITIVE_KEYS = frozenset(
    {
        "secret",
        "token",
        "password",
        "credential",
        "credentials",
        "private_key",
        "raw_payload",
        "raw_provider_response",
        "timestamp_token",
        "certificate_body",
        "access_key",
        "access_token",
    }
)


@dataclass(frozen=True)
class ExternalCapabilityResult:
    capability_id: str
    capability_type: str
    provider_id: str
    provider_type: str
    environment: str
    configuration_state: str
    verification_state: str
    failure_codes: tuple[str, ...]
    evidence_reference: str
    evidence_hash: str
    policy_version: str
    source_commit_sha: str
    request_id: str
    correlation_id: str
    production_eligible: bool
    capability_hash: str
    execution_allowed: bool = False
    provider_execution: bool = False
    production_activation: bool = False
    deployment_authorized: bool = False
    release_authorized: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema": EXTERNAL_TRUST_SCHEMA,
            "capability_id": self.capability_id,
            "capability_type": self.capability_type,
            "provider_id": self.provider_id,
            "provider_type": self.provider_type,
            "environment": self.environment,
            "configuration_state": self.configuration_state,
            "verification_state": self.verification_state,
            "failure_codes": list(self.failure_codes),
            "evidence_reference": self.evidence_reference,
            "evidence_hash": self.evidence_hash,
            "policy_version": self.policy_version,
            "source_commit_sha": self.source_commit_sha,
            "request_id": self.request_id,
            "correlation_id": self.correlation_id,
            "production_eligible": self.production_eligible,
            "capability_hash": self.capability_hash,
            **FALSE_FLAGS,
        }


@dataclass(frozen=True)
class ExternalTrustAggregate:
    decision: str
    failure_codes: tuple[str, ...]
    capability_states: dict[str, str]
    aggregate_hash: str
    regulator_required: bool
    production_boundary_ready: bool = False
    execution_allowed: bool = False
    provider_execution: bool = False
    production_activation: bool = False
    deployment_authorized: bool = False
    release_authorized: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema": EXTERNAL_TRUST_SCHEMA + ".aggregate",
            "decision": self.decision,
            "failure_codes": list(self.failure_codes),
            "capability_states": dict(sorted(self.capability_states.items())),
            "regulator_required": self.regulator_required,
            "production_boundary_ready": self.production_boundary_ready,
            "aggregate_hash": self.aggregate_hash,
            **FALSE_FLAGS,
        }


class UnavailableExternalCapabilityAdapter:
    def __init__(self, capability_type: str) -> None:
        if capability_type not in CAPABILITY_TYPES:
            raise ValueError("EXTERNAL_TRUST_CAPABILITY_UNKNOWN")
        self.capability_type = capability_type

    def evaluate(self, metadata: Mapping[str, Any] | None, *, timestamp: str) -> ExternalCapabilityResult:
        payload = dict(metadata or {})
        payload.setdefault("capability_type", self.capability_type)
        payload.setdefault("configuration_state", UNAVAILABLE)
        payload.setdefault("verification_state", UNAVAILABLE)
        return evaluate_external_capability(payload, timestamp=timestamp)


def evaluate_external_capability(metadata: Mapping[str, Any] | None, *, timestamp: str) -> ExternalCapabilityResult:
    if not isinstance(metadata, Mapping):
        return _result({}, timestamp=timestamp, failure_codes=("EXTERNAL_TRUST_METADATA_MISSING",))

    payload = dict(metadata)
    capability_type = str(payload.get("capability_type", ""))
    allowed_fields = FIELDS_BY_CAPABILITY.get(capability_type, COMMON_FIELDS)
    errors: list[str] = []
    unknown = sorted(set(payload) - allowed_fields)
    errors.extend("EXTERNAL_TRUST_UNKNOWN_FIELD" for _ in unknown)
    errors.extend(_validate_common(payload, timestamp=timestamp))
    if not errors:
        if capability_type == "rfc3161":
            errors.extend(_validate_rfc3161(payload, timestamp=timestamp))
        elif capability_type == "worm_object_lock":
            errors.extend(_validate_worm(payload, timestamp=timestamp))
        elif capability_type == "external_signing":
            errors.extend(_validate_signing(payload))
        elif capability_type == "regulator_transport":
            errors.extend(_validate_regulator(payload, timestamp=timestamp))
        elif capability_type == "deployment_evidence":
            errors.extend(_validate_deployment(payload, timestamp=timestamp))

    ordered = _ordered_unique(errors)
    return _result(payload, timestamp=timestamp, failure_codes=ordered)


def export_external_capability_evidence(result: ExternalCapabilityResult) -> dict[str, Any]:
    payload = result.to_dict()
    if _contains_sensitive_key(payload):
        raise ValueError("EXTERNAL_TRUST_SENSITIVE_DATA_PRESENT")
    return {
        "schema": EXTERNAL_TRUST_SCHEMA + ".evidence",
        "capability_type": result.capability_type,
        "verification_state": result.verification_state,
        "failure_codes": list(result.failure_codes),
        "evidence_reference": result.evidence_reference,
        "evidence_hash": result.evidence_hash,
        "capability_hash": result.capability_hash,
        **FALSE_FLAGS,
    }


def aggregate_external_trust(
    results: Sequence[ExternalCapabilityResult | Mapping[str, Any]],
    *,
    regulator_required: bool,
) -> ExternalTrustAggregate:
    failures: list[str] = []
    states: dict[str, str] = {}
    for item in results:
        payload = item.to_dict() if isinstance(item, ExternalCapabilityResult) else dict(item)
        capability_type = str(payload.get("capability_type", ""))
        if capability_type in states:
            failures.append("EXTERNAL_TRUST_DUPLICATE_CAPABILITY")
            continue
        states[capability_type] = str(payload.get("verification_state", INVALID))
        failures.extend(str(code) for code in payload.get("failure_codes", ()))
    for capability in sorted(MANDATORY_EXTERNAL_CAPABILITIES):
        if states.get(capability) != EVIDENCE_VERIFIED:
            failures.append(f"EXTERNAL_TRUST_REQUIRED_CAPABILITY_MISSING:{capability}")
    regulator_state = states.get(REGULATOR_CAPABILITY)
    if regulator_required and regulator_state != EVIDENCE_VERIFIED:
        failures.append("EXTERNAL_TRUST_REQUIRED_CAPABILITY_MISSING:regulator_transport")
    if not regulator_required and regulator_state not in {None, EVIDENCE_VERIFIED, BLOCKED, INVALID, UNAVAILABLE, NOT_CONFIGURED, CONFIGURED, CONNECTIVITY_VERIFIED}:
        failures.append("EXTERNAL_TRUST_REGULATOR_POLICY_PROOF_MISSING")

    ordered = tuple(sorted(set(failures)))
    decision = "EXTERNAL_TRUST_EVIDENCE_VERIFIED" if not ordered else BLOCKED
    payload = {
        "decision": decision,
        "failure_codes": list(ordered),
        "capability_states": dict(sorted(states.items())),
        "regulator_required": regulator_required,
        "production_boundary_ready": False,
        **FALSE_FLAGS,
    }
    return ExternalTrustAggregate(
        decision=decision,
        failure_codes=ordered,
        capability_states=dict(sorted(states.items())),
        aggregate_hash=sha256_reference(payload),
        regulator_required=regulator_required,
    )


def external_trust_contract() -> dict[str, Any]:
    return {
        "schema": EXTERNAL_TRUST_SCHEMA,
        "contract_version": EXTERNAL_TRUST_CONTRACT_VERSION,
        "capability_states": sorted(VERIFICATION_STATES),
        "capability_types": sorted(CAPABILITY_TYPES),
        "mandatory_capabilities": sorted(MANDATORY_EXTERNAL_CAPABILITIES),
        "failure_codes": list(FAILURE_CODES),
        **FALSE_FLAGS,
    }


def _validate_common(payload: Mapping[str, Any], *, timestamp: str) -> list[str]:
    errors: list[str] = []
    capability_type = str(payload.get("capability_type", ""))
    if capability_type not in CAPABILITY_TYPES:
        errors.append("EXTERNAL_TRUST_CAPABILITY_UNKNOWN")
    if not _nonempty(payload.get("capability_id")):
        errors.append("EXTERNAL_TRUST_CAPABILITY_MISMATCH")
    if not _nonempty(payload.get("provider_id")):
        errors.append("EXTERNAL_TRUST_PROVIDER_ID_MISSING")
    if payload.get("provider_type") not in SUPPORTED_PROVIDER_TYPES.get(capability_type, frozenset()):
        errors.append("EXTERNAL_TRUST_PROVIDER_TYPE_UNSUPPORTED")
    if payload.get("environment") not in SUPPORTED_ENVIRONMENTS:
        errors.append("EXTERNAL_TRUST_ENVIRONMENT_UNSUPPORTED")
    if payload.get("configuration_state") not in CONFIGURATION_STATES:
        errors.append("EXTERNAL_TRUST_CONFIGURATION_STATE_INVALID")
    if payload.get("verification_state") not in VERIFICATION_STATES:
        errors.append("EXTERNAL_TRUST_VERIFICATION_STATE_INVALID")
    if not _is_hash(payload.get("evidence_reference")):
        errors.append("EXTERNAL_TRUST_EVIDENCE_REFERENCE_INVALID")
    if not _is_hash(payload.get("evidence_hash")):
        errors.append("EXTERNAL_TRUST_EVIDENCE_HASH_INVALID")
    if not _nonempty(payload.get("policy_version")):
        errors.append("EXTERNAL_TRUST_POLICY_VERSION_MISSING")
    if not _is_commit_sha(payload.get("source_commit_sha")):
        errors.append("EXTERNAL_TRUST_SOURCE_COMMIT_MISSING")
    if not _is_hash(payload.get("request_id")):
        errors.append("EXTERNAL_TRUST_REQUEST_ID_INVALID")
    if not _is_hash(payload.get("correlation_id")):
        errors.append("EXTERNAL_TRUST_CORRELATION_ID_INVALID")
    if _contains_sensitive_key(payload) or payload.get("contains_sensitive_data") is not False:
        errors.append("EXTERNAL_TRUST_SENSITIVE_DATA_PRESENT")
    if any(payload.get(flag) is not False for flag in FALSE_FLAGS):
        errors.append("EXTERNAL_TRUST_PROTECTED_FLAG_TRUE")
    if payload.get("production_eligible") is True and payload.get("verification_state") != EVIDENCE_VERIFIED:
        errors.append("EXTERNAL_TRUST_PRODUCTION_ELIGIBLE_WITHOUT_EVIDENCE")
    if payload.get("configuration_state") in {NOT_CONFIGURED, UNAVAILABLE}:
        errors.append(_not_configured_code(capability_type))
    if _parse_time(payload.get("expires_at")) is None or _parse_time(timestamp) is None:
        errors.append("EXTERNAL_TRUST_VERIFICATION_EXPIRED")
    elif _parse_time(payload.get("expires_at")) <= _parse_time(timestamp):
        errors.append("EXTERNAL_TRUST_VERIFICATION_EXPIRED")
    if payload.get("verification_state") == EVIDENCE_VERIFIED and payload.get("environment") == "enterprise_production":
        # Production evidence must have explicit external proof. Test fixtures use non-production environments.
        if str(payload.get("provider_id", "")).startswith("fixture:"):
            errors.append("EXTERNAL_TRUST_PRODUCTION_ELIGIBLE_WITHOUT_EVIDENCE")
    return errors


def _validate_rfc3161(payload: Mapping[str, Any], *, timestamp: str) -> list[str]:
    errors: list[str] = []
    if not _nonempty(payload.get("tsa_endpoint_id")):
        errors.append("RFC3161_ENDPOINT_UNAVAILABLE")
    if not _is_hash(payload.get("trust_anchor_reference")):
        errors.append("RFC3161_CERTIFICATE_UNTRUSTED")
    if not _timeout_valid(payload.get("timeout_ms")):
        errors.append("RFC3161_TIMEOUT")
    algorithms = payload.get("allowed_digest_algorithms")
    if not isinstance(algorithms, Sequence) or isinstance(algorithms, (str, bytes)) or not set(algorithms).issubset(SUPPORTED_DIGEST_ALGORITHMS):
        errors.append("RFC3161_RESPONSE_MALFORMED")
    for field in ("request_digest", "response_digest", "certificate_chain_hash", "timestamp_signature_hash"):
        if not _is_hash(payload.get(field)):
            errors.append("RFC3161_RESPONSE_MALFORMED")
    if payload.get("message_imprint_hash") != payload.get("expected_message_imprint_hash") or not _is_hash(payload.get("message_imprint_hash")):
        errors.append("RFC3161_MESSAGE_IMPRINT_MISMATCH")
    if payload.get("nonce_reference") != payload.get("response_nonce_reference") or not _is_hash(payload.get("nonce_reference")):
        errors.append("RFC3161_NONCE_MISMATCH")
    if payload.get("policy_oid") != payload.get("expected_policy_oid"):
        errors.append("RFC3161_POLICY_MISMATCH")
    if payload.get("replay_reference") in set(payload.get("used_replay_references") or ()):
        errors.append("RFC3161_REPLAY_DETECTED")
    if _parse_time(payload.get("verified_at")) is None or _parse_time(payload.get("verified_at")) > _parse_time(timestamp):
        errors.append("RFC3161_TIMESTAMP_EXPIRED")
    return errors


def _validate_worm(payload: Mapping[str, Any], *, timestamp: str) -> list[str]:
    errors: list[str] = []
    if not _nonempty(payload.get("bucket_reference")) or not _nonempty(payload.get("object_reference")):
        errors.append("WORM_PROVIDER_UNAVAILABLE")
    if payload.get("object_lock_enabled") is not True:
        errors.append("WORM_OBJECT_LOCK_DISABLED")
    if payload.get("retention_mode") not in SUPPORTED_RETENTION_MODES:
        errors.append("WORM_RETENTION_MODE_INVALID")
    if payload.get("environment") == "enterprise_production" and payload.get("retention_mode") != "COMPLIANCE":
        errors.append("WORM_RETENTION_MODE_INVALID")
    retention_until = _parse_time(payload.get("retention_until"))
    minimum = _parse_time(payload.get("minimum_retention_until"))
    now = _parse_time(timestamp)
    if retention_until is None or minimum is None or now is None:
        errors.append("WORM_RETENTION_MISSING")
    elif retention_until <= now or retention_until < minimum:
        errors.append("WORM_RETENTION_TOO_SHORT")
    if not _nonempty(payload.get("version_id")):
        errors.append("WORM_VERSION_MISSING")
    if not _is_hash(payload.get("immutable_object_checksum")) or payload.get("immutable_object_checksum") != payload.get("readback_checksum"):
        errors.append("WORM_CHECKSUM_MISMATCH")
    if payload.get("overwrite_attempt_blocked") is not True:
        errors.append("WORM_OVERWRITE_POSSIBLE")
    if payload.get("delete_attempt_blocked") is not True:
        errors.append("WORM_DELETE_POSSIBLE")
    if not _is_hash(payload.get("provider_response_hash")):
        errors.append("WORM_EVIDENCE_INVALID")
    return errors


def _validate_signing(payload: Mapping[str, Any]) -> list[str]:
    errors: list[str] = []
    for field, code in (
        ("signer_identity", "SIGNER_UNKNOWN"),
        ("key_identifier", "SIGNING_EVIDENCE_INVALID"),
        ("key_version", "SIGNING_EVIDENCE_INVALID"),
        ("trust_root_reference", "SIGNING_EVIDENCE_INVALID"),
        ("request_nonce", "SIGNING_EVIDENCE_INVALID"),
    ):
        if not _nonempty(payload.get(field)):
            errors.append(code)
    if payload.get("algorithm") not in SUPPORTED_SIGNATURE_ALGORITHMS or payload.get("algorithm") not in set(payload.get("allowed_algorithms") or ()):
        errors.append("SIGNATURE_ALGORITHM_UNSUPPORTED")
    if not _is_hash(payload.get("payload_hash")) or payload.get("payload_hash") != payload.get("signed_payload_hash"):
        errors.append("SIGNATURE_PAYLOAD_MISMATCH")
    if payload.get("environment_binding") != payload.get("environment"):
        errors.append("SIGNATURE_CONTEXT_MISMATCH")
    if not _is_hash(payload.get("signature_hash")):
        errors.append("SIGNATURE_MISSING")
    if payload.get("signature_verified") is not True:
        errors.append("SIGNATURE_INVALID")
    if payload.get("key_revoked") is True:
        errors.append("SIGNING_KEY_REVOKED")
    if payload.get("key_expired") is True:
        errors.append("SIGNING_KEY_EXPIRED")
    if payload.get("signer_authorized") is not True:
        errors.append("SIGNER_UNAUTHORIZED")
    if not _is_hash(payload.get("verification_evidence_hash")):
        errors.append("SIGNING_EVIDENCE_INVALID")
    return errors


def _validate_regulator(payload: Mapping[str, Any], *, timestamp: str) -> list[str]:
    errors: list[str] = []
    state = payload.get("submission_state")
    if state not in SUPPORTED_SUBMISSION_STATES:
        errors.append("REGULATOR_SCHEMA_INVALID")
    if not _nonempty(payload.get("regulator_endpoint_id")):
        errors.append("REGULATOR_DESTINATION_UNKNOWN")
    if payload.get("regulator_endpoint_id") not in set(payload.get("approved_regulator_destinations") or ()):
        errors.append("REGULATOR_DESTINATION_UNAUTHORIZED")
    if not _nonempty(payload.get("schema_version")):
        errors.append("REGULATOR_SCHEMA_INVALID")
    if not _nonempty(payload.get("human_approver_identity")):
        errors.append("REGULATOR_APPROVAL_MISSING")
    if payload.get("human_approver_identity") == payload.get("requester_identity"):
        errors.append("REGULATOR_SELF_APPROVAL_BLOCKED")
    approval_expires = _parse_time(payload.get("approval_expires_at"))
    now = _parse_time(timestamp)
    if approval_expires is None or now is None or approval_expires <= now:
        errors.append("REGULATOR_APPROVAL_EXPIRED")
    if not _is_hash(payload.get("external_signature_reference")):
        errors.append("REGULATOR_SIGNATURE_MISSING")
    if not _is_hash(payload.get("rfc3161_reference")):
        errors.append("REGULATOR_TIMESTAMP_MISSING")
    if not _is_hash(payload.get("worm_reference")):
        errors.append("REGULATOR_WORM_EVIDENCE_MISSING")
    if payload.get("anti_replay_nonce") in set(payload.get("used_anti_replay_nonces") or ()):
        errors.append("REGULATOR_REPLAY_DETECTED")
    if state in {"REJECTED", "BLOCKED", "EXPIRED"} or payload.get("permanent_failure") is True:
        errors.append("REGULATOR_SUBMISSION_FAILED")
    if state == "ACKNOWLEDGED" and not _is_hash(payload.get("acknowledgement_receipt_hash")):
        errors.append("REGULATOR_ACKNOWLEDGEMENT_INVALID")
    return errors


def _validate_deployment(payload: Mapping[str, Any], *, timestamp: str) -> list[str]:
    errors: list[str] = []
    if not _nonempty(payload.get("deployment_id")):
        errors.append("DEPLOYMENT_EVIDENCE_MISSING")
    if payload.get("source_commit_sha") != payload.get("target_binding") or not _is_commit_sha(payload.get("source_commit_sha")):
        errors.append("DEPLOYMENT_COMMIT_MISMATCH")
    if not _is_hash(payload.get("artifact_digest")) or payload.get("artifact_matches_provenance") is not True:
        errors.append("DEPLOYMENT_ARTIFACT_MISMATCH")
    if not _nonempty(payload.get("build_provenance_reference")) or not _nonempty(payload.get("sbom_reference")):
        errors.append("DEPLOYMENT_PROVENANCE_INVALID")
    if payload.get("workflow_identity") not in set(payload.get("authorized_workflow_identities") or ()):
        errors.append("DEPLOYMENT_WORKFLOW_UNAUTHORIZED")
    if payload.get("environment") not in SUPPORTED_ENVIRONMENTS or payload.get("environment_approved") is not True:
        errors.append("DEPLOYMENT_ENVIRONMENT_UNAUTHORIZED")
    if not _is_hash(payload.get("human_authorization_reference")) or payload.get("human_authorization_current") is not True:
        errors.append("DEPLOYMENT_HUMAN_APPROVAL_MISSING")
    if not _is_hash(payload.get("external_signature_reference")) or payload.get("signature_evidence_valid") is not True:
        errors.append("DEPLOYMENT_SIGNATURE_INVALID")
    if not _is_hash(payload.get("rfc3161_reference")) or payload.get("timestamp_evidence_valid") is not True:
        errors.append("DEPLOYMENT_TIMESTAMP_INVALID")
    if not _is_hash(payload.get("worm_reference")) or payload.get("worm_evidence_valid") is not True:
        errors.append("DEPLOYMENT_WORM_REFERENCE_INVALID")
    if payload.get("deployment_result") not in SUPPORTED_DEPLOYMENT_RESULTS:
        errors.append("DEPLOYMENT_EVIDENCE_MISSING")
    if not _nonempty(payload.get("rollback_reference")) or payload.get("rollback_reference_exists") is not True:
        errors.append("DEPLOYMENT_ROLLBACK_REFERENCE_MISSING")
    if payload.get("evidence_fresh") is not True:
        errors.append("DEPLOYMENT_EVIDENCE_EXPIRED")
    if payload.get("replay_reference") in set(payload.get("used_replay_references") or ()):
        errors.append("DEPLOYMENT_REPLAY_DETECTED")
    return errors


def _result(payload: Mapping[str, Any], *, timestamp: str, failure_codes: Sequence[str]) -> ExternalCapabilityResult:
    capability_type = str(payload.get("capability_type", ""))
    ordered = _ordered_unique(list(failure_codes))
    verification_state = EVIDENCE_VERIFIED if not ordered and payload.get("verification_state") == EVIDENCE_VERIFIED else BLOCKED if ordered else str(payload.get("verification_state", BLOCKED))
    production_eligible = verification_state == EVIDENCE_VERIFIED and payload.get("production_eligible") is True and not ordered
    evidence_reference = str(payload.get("evidence_reference", ""))
    evidence_hash = str(payload.get("evidence_hash", ""))
    record = {
        "schema": EXTERNAL_TRUST_SCHEMA,
        "capability_id": str(payload.get("capability_id", "")),
        "capability_type": capability_type,
        "provider_id": str(payload.get("provider_id", "")),
        "provider_type": str(payload.get("provider_type", "")),
        "environment": str(payload.get("environment", "")),
        "configuration_state": str(payload.get("configuration_state", "")),
        "verification_state": verification_state,
        "failure_codes": list(ordered),
        "evidence_reference": evidence_reference,
        "evidence_hash": evidence_hash,
        "policy_version": str(payload.get("policy_version", "")),
        "source_commit_sha": str(payload.get("source_commit_sha", "")),
        "request_id": str(payload.get("request_id", "")),
        "correlation_id": str(payload.get("correlation_id", "")),
        "production_eligible": production_eligible,
        "timestamp": timestamp,
        **FALSE_FLAGS,
    }
    return ExternalCapabilityResult(
        capability_id=record["capability_id"],
        capability_type=capability_type,
        provider_id=record["provider_id"],
        provider_type=record["provider_type"],
        environment=record["environment"],
        configuration_state=record["configuration_state"],
        verification_state=verification_state,
        failure_codes=ordered,
        evidence_reference=evidence_reference,
        evidence_hash=evidence_hash,
        policy_version=record["policy_version"],
        source_commit_sha=record["source_commit_sha"],
        request_id=record["request_id"],
        correlation_id=record["correlation_id"],
        production_eligible=production_eligible,
        capability_hash=sha256_reference(record),
    )


def _not_configured_code(capability_type: str) -> str:
    return {
        "rfc3161": "RFC3161_NOT_CONFIGURED",
        "worm_object_lock": "WORM_NOT_CONFIGURED",
        "external_signing": "SIGNING_NOT_CONFIGURED",
        "regulator_transport": "REGULATOR_TRANSPORT_NOT_CONFIGURED",
        "deployment_evidence": "DEPLOYMENT_EVIDENCE_NOT_CONFIGURED",
    }.get(capability_type, "EXTERNAL_TRUST_CAPABILITY_UNKNOWN")


def _ordered_unique(errors: Sequence[str]) -> tuple[str, ...]:
    known = []
    extras = []
    for code in errors:
        if code in FAILURE_CODES:
            known.append(code)
        else:
            extras.append(code)
    return tuple(code for code in FAILURE_CODES if code in known) + tuple(sorted(set(extras)))


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


def _timeout_valid(value: Any) -> bool:
    return isinstance(value, int) and 0 < value <= 300_000


def _is_hash(value: Any) -> bool:
    return isinstance(value, str) and value.startswith("sha256:") and len(value) == 71 and all(char in "0123456789abcdef" for char in value[7:])


def _is_commit_sha(value: Any) -> bool:
    return isinstance(value, str) and len(value) == 40 and all(char in "0123456789abcdef" for char in value)


def _nonempty(value: Any) -> bool:
    return isinstance(value, str) and bool(value.strip())


def _parse_time(value: Any) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(timezone.utc)
    except ValueError:
        return None
