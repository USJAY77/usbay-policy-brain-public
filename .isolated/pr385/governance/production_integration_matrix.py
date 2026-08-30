from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from governance.audit_evidence import canonical_audit_json, sha256_audit_hash
from governance.rfc3161_timestamp import DEFAULT_POLICY_OID_PLACEHOLDER
from governance.regulator_export_profile import REGULATOR_EXPORT_MODE
from governance.worm_immutable_storage import WORM_IMMUTABLE_STORAGE_MODE


PRODUCTION_INTEGRATION_MATRIX_SCHEMA = "usbay.governance.production_integration_matrix.v1"
PRODUCTION_INTEGRATION_MATRIX_VERSION = "production-integration-matrix-v1"
LOCAL_ONLY_MODE = "LOCAL_ONLY"
NOT_REQUESTED = "NOT_REQUESTED"
NOT_CONFIGURED = "NOT_CONFIGURED"
DEFERRED = "DEFERRED"
FAIL_CLOSED = "FAIL_CLOSED"

RFC3161_INTEGRATION = "rfc3161_timestamp_authority"
WORM_INTEGRATION = "worm_storage_provider"
REGULATOR_EXPORT_INTEGRATION = "regulator_submission"
EXTERNAL_SIGNING_INTEGRATION = "external_signing_authority"
OBJECT_LOCK_INTEGRATION = "object_lock_persistence"
TIMESTAMP_AUTHORITY_INTEGRATION = "timestamp_authority_chain"

DEFERRED_INTEGRATION_ORDER = (
    RFC3161_INTEGRATION,
    TIMESTAMP_AUTHORITY_INTEGRATION,
    EXTERNAL_SIGNING_INTEGRATION,
    WORM_INTEGRATION,
    OBJECT_LOCK_INTEGRATION,
    REGULATOR_EXPORT_INTEGRATION,
)
EXECUTION_FLAGS = (
    "execution_allowed",
    "provider_execution",
    "production_activation",
    "network_access",
    "live_signing",
    "worm_provider_enabled",
    "regulator_submission_enabled",
)


@dataclass(frozen=True)
class ProductionIntegration:
    integration_id: str
    purpose: str
    current_placeholder: str
    required_interface: str
    dependencies: tuple[str, ...]
    blocking_risks: tuple[str, ...]
    implementation_order: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "integration_id": self.integration_id,
            "purpose": self.purpose,
            "current_placeholder": self.current_placeholder,
            "required_interface": self.required_interface,
            "dependencies": list(self.dependencies),
            "blocking_risks": list(self.blocking_risks),
            "implementation_order": self.implementation_order,
            **fail_closed_execution_flags(),
        }


def fail_closed_execution_flags() -> dict[str, bool]:
    return {flag: False for flag in EXECUTION_FLAGS}


def deferred_production_integrations() -> tuple[ProductionIntegration, ...]:
    return (
        ProductionIntegration(
            integration_id=RFC3161_INTEGRATION,
            purpose="Submit deterministic message-imprint material to a governed RFC3161 timestamp authority.",
            current_placeholder=DEFAULT_POLICY_OID_PLACEHOLDER,
            required_interface="hash-only TSA request/response verifier with certificate, policy OID, revocation, and imprint checks",
            dependencies=("proof_timestamp_anchor", "signed_bundle_timestamp"),
            blocking_risks=("unverified TSA token", "policy OID mismatch", "timestamp chronology drift"),
            implementation_order=1,
        ),
        ProductionIntegration(
            integration_id=TIMESTAMP_AUTHORITY_INTEGRATION,
            purpose="Bind timestamp authority chain readiness to governance evidence without trusting local receipt claims.",
            current_placeholder=NOT_CONFIGURED,
            required_interface="read-only timestamp authority chain verifier using hash-only chain metadata",
            dependencies=(RFC3161_INTEGRATION, "timestamp_chain_schema"),
            blocking_risks=("authority duplication", "chain schema mismatch", "revocation data unavailable"),
            implementation_order=2,
        ),
        ProductionIntegration(
            integration_id=EXTERNAL_SIGNING_INTEGRATION,
            purpose="Attach externally verifiable signatures to signed auditor bundles without repository key material.",
            current_placeholder=NOT_CONFIGURED,
            required_interface="detached signing envelope verifier with public-key fingerprint binding and no private-key logging",
            dependencies=("signed_auditor_bundle", RFC3161_INTEGRATION),
            blocking_risks=("private key exposure", "signature envelope mismatch", "untrusted signer fingerprint"),
            implementation_order=3,
        ),
        ProductionIntegration(
            integration_id=WORM_INTEGRATION,
            purpose="Persist sealed audit archive references into governed immutable storage.",
            current_placeholder=WORM_IMMUTABLE_STORAGE_MODE,
            required_interface="provider-neutral WORM write receipt verifier using hash-only object references",
            dependencies=("sealed_audit_archive", "evidence_record_chain", TIMESTAMP_AUTHORITY_INTEGRATION),
            blocking_risks=("mutable storage output", "missing legal hold", "retention mismatch"),
            implementation_order=4,
        ),
        ProductionIntegration(
            integration_id=OBJECT_LOCK_INTEGRATION,
            purpose="Verify object-lock retention, legal hold, and immutability metadata from storage-provider receipts.",
            current_placeholder=LOCAL_ONLY_MODE,
            required_interface="object-lock receipt verifier with retention mode, retain-until timestamp, and legal-hold status",
            dependencies=(WORM_INTEGRATION,),
            blocking_risks=("provider receipt spoofing", "clock skew", "object version mismatch"),
            implementation_order=5,
        ),
        ProductionIntegration(
            integration_id=REGULATOR_EXPORT_INTEGRATION,
            purpose="Submit regulator export bundles only after evidence, WORM, timestamp, and signing gates verify.",
            current_placeholder=REGULATOR_EXPORT_MODE,
            required_interface="regulator submission adapter with dry-run proof, delivery receipt verification, and no raw payload export",
            dependencies=(OBJECT_LOCK_INTEGRATION, EXTERNAL_SIGNING_INTEGRATION, "attestation_export_registry"),
            blocking_risks=("raw payload leakage", "jurisdiction mismatch", "unverified delivery receipt"),
            implementation_order=6,
        ),
    )


def production_integration_matrix() -> dict[str, Any]:
    integrations = tuple(sorted(deferred_production_integrations(), key=lambda item: item.implementation_order))
    payload = {
        "schema": PRODUCTION_INTEGRATION_MATRIX_SCHEMA,
        "version": PRODUCTION_INTEGRATION_MATRIX_VERSION,
        "status": DEFERRED,
        "fail_closed_default": True,
        "integrations": [integration.to_dict() for integration in integrations],
        "integration_order": [integration.integration_id for integration in integrations],
        **fail_closed_execution_flags(),
    }
    return {**payload, "matrix_hash": sha256_audit_hash(payload)}


def verify_production_integration_matrix(matrix: dict[str, Any]) -> tuple[str, ...]:
    errors: list[str] = []
    if not isinstance(matrix, dict):
        return ("PRODUCTION_INTEGRATION_MATRIX_MALFORMED",)
    if matrix.get("schema") != PRODUCTION_INTEGRATION_MATRIX_SCHEMA:
        errors.append("PRODUCTION_INTEGRATION_MATRIX_SCHEMA_INVALID")
    if matrix.get("status") != DEFERRED or matrix.get("fail_closed_default") is not True:
        errors.append("PRODUCTION_INTEGRATION_MATRIX_FAIL_CLOSED_INVALID")
    if any(matrix.get(flag) is not False for flag in EXECUTION_FLAGS):
        errors.append("PRODUCTION_INTEGRATION_MATRIX_EXECUTION_FLAG_INVALID")
    integrations = matrix.get("integrations")
    if not isinstance(integrations, list) or len(integrations) != len(DEFERRED_INTEGRATION_ORDER):
        errors.append("PRODUCTION_INTEGRATION_MATRIX_ORDER_INVALID")
        integrations = []
    observed_order = tuple(item.get("integration_id") for item in integrations if isinstance(item, dict))
    if observed_order != DEFERRED_INTEGRATION_ORDER or tuple(matrix.get("integration_order", ())) != DEFERRED_INTEGRATION_ORDER:
        errors.append("PRODUCTION_INTEGRATION_MATRIX_ORDER_INVALID")
    seen: set[str] = set()
    for index, integration in enumerate(integrations, start=1):
        if not isinstance(integration, dict):
            errors.append("PRODUCTION_INTEGRATION_MATRIX_MALFORMED")
            continue
        integration_id = integration.get("integration_id")
        if integration_id in seen:
            errors.append("PRODUCTION_INTEGRATION_MATRIX_DUPLICATE")
        seen.add(str(integration_id))
        if integration.get("implementation_order") != index:
            errors.append("PRODUCTION_INTEGRATION_MATRIX_ORDER_INVALID")
        if any(integration.get(flag) is not False for flag in EXECUTION_FLAGS):
            errors.append("PRODUCTION_INTEGRATION_MATRIX_EXECUTION_FLAG_INVALID")
        for field in ("purpose", "current_placeholder", "required_interface", "dependencies", "blocking_risks"):
            if integration.get(field) in ("", None, [], ()):
                errors.append("PRODUCTION_INTEGRATION_MATRIX_MALFORMED")
    expected_hash = sha256_audit_hash({key: value for key, value in matrix.items() if key != "matrix_hash"})
    if matrix.get("matrix_hash") != expected_hash:
        errors.append("PRODUCTION_INTEGRATION_MATRIX_HASH_INVALID")
    serialized = canonical_audit_json(matrix).lower()
    if any(marker in serialized for marker in ("private_key", "credential", "secret", "raw_payload", "approval_content")):
        errors.append("PRODUCTION_INTEGRATION_MATRIX_UNSAFE")
    return tuple(
        code
        for code in (
            "PRODUCTION_INTEGRATION_MATRIX_MALFORMED",
            "PRODUCTION_INTEGRATION_MATRIX_SCHEMA_INVALID",
            "PRODUCTION_INTEGRATION_MATRIX_FAIL_CLOSED_INVALID",
            "PRODUCTION_INTEGRATION_MATRIX_EXECUTION_FLAG_INVALID",
            "PRODUCTION_INTEGRATION_MATRIX_ORDER_INVALID",
            "PRODUCTION_INTEGRATION_MATRIX_DUPLICATE",
            "PRODUCTION_INTEGRATION_MATRIX_HASH_INVALID",
            "PRODUCTION_INTEGRATION_MATRIX_UNSAFE",
        )
        if code in errors
    )
