from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Mapping

from governance.hashing import canonical_json, is_sha256_reference, sha256_reference


CONTRACT_ROOT = Path("governance/contracts")
SUPPORTED_REGISTRY_SCHEMA_VERSION = "usbay.cross_repo.registry.v1"
SUPPORTED_MATRIX_SCHEMA_VERSION = "usbay.cross_repo.compatibility_matrix.v1"
SUPPORTED_REPOSITORY_IDENTITY_VERSION = "usbay.repository_identity.v1"
SUPPORTED_HASH_ALGORITHM = "sha256"
SUPPORTED_HASH_ENCODING = "sha256_reference"
COMPATIBLE_STATES = {"compatible", "compatible_with_translation", "development_only"}
BLOCKING_STATES = {"incompatible", "unknown"}


class CrossRepositoryContractError(ValueError):
    """Structured internal validation error for cross-repository contracts."""

    def __init__(self, code: str, message: str):
        self.code = code
        self.message = message
        super().__init__(f"{code}: {message}")


def _load_json(root: Path, relative: str) -> dict[str, Any]:
    path = root / relative
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:  # pragma: no cover - surfaced as fail-closed error
        raise CrossRepositoryContractError("JSON_INVALID", f"{relative} is not valid JSON") from exc
    if not isinstance(payload, dict):
        raise CrossRepositoryContractError("JSON_INVALID", f"{relative} must be a JSON object")
    return payload


def canonical_contract_hash(payload: Mapping[str, Any]) -> str:
    return sha256_reference(payload)


def canonical_contract_json(payload: Mapping[str, Any]) -> str:
    return canonical_json(payload)


def validate_repository_identity(identity: Mapping[str, Any]) -> None:
    required = {
        "repository_id",
        "canonical_repository_owner",
        "canonical_repository_name",
        "canonical_remote_identifier",
        "repository_role",
        "protected_default_branch",
        "identity_schema_version",
        "contract_registry_version",
        "status",
    }
    _require_exact_fields(identity, required, "REPOSITORY_IDENTITY_FIELD_DRIFT")
    if identity["identity_schema_version"] != SUPPORTED_REPOSITORY_IDENTITY_VERSION:
        raise CrossRepositoryContractError("REPOSITORY_IDENTITY_VERSION_UNSUPPORTED", "Repository identity version is unsupported")
    if identity["repository_role"] != "governance_policy_authority":
        raise CrossRepositoryContractError("REPOSITORY_ROLE_INVALID", "Policy Brain must be governance policy authority only")
    if "execution" in identity["repository_role"]:
        raise CrossRepositoryContractError("REPOSITORY_ROLE_INVALID", "Policy Brain must not declare runtime execution authority")
    if identity["status"] != "canonical":
        raise CrossRepositoryContractError("REPOSITORY_IDENTITY_NOT_CANONICAL", "Repository identity is not canonical")
    if identity["canonical_repository_owner"] != "USJAY77":
        raise CrossRepositoryContractError("REPOSITORY_OWNER_MISMATCH", "Canonical Policy Brain owner mismatch")
    if identity["canonical_repository_name"] != "usbay-policy-brain-public":
        raise CrossRepositoryContractError("REPOSITORY_NAME_MISMATCH", "Canonical Policy Brain name mismatch")


def validate_registry(root: Path = Path(".")) -> dict[str, Any]:
    identity = _load_json(root, "governance/contracts/repository_identity.json")
    registry = _load_json(root, "governance/contracts/cross_repository_contract_registry.json")
    matrix = _load_json(root, "governance/contracts/cross_repository_compatibility_matrix.json")
    validate_repository_identity(identity)
    _validate_registry_payload(root, registry, identity)
    _validate_matrix_payload(matrix, registry)
    _validate_hash_vectors(root)
    return {
        "status": "PASS",
        "registry_hash": canonical_contract_hash(registry),
        "identity_hash": canonical_contract_hash(identity),
        "matrix_hash": canonical_contract_hash(matrix),
        "production_ready": False,
    }


def validate_approval_reference(reference: Mapping[str, Any], *, production: bool = False) -> dict[str, Any]:
    required = {
        "schema_version",
        "approval_request_id",
        "approval_decision_id",
        "policy_decision_reference",
        "human_authority_reference",
        "decision",
        "issued_at",
        "expires_at",
        "evidence_hash",
        "subject_action_reference",
        "revocation_reference",
        "supersession_reference",
        "ai_generated_only",
    }
    _require_exact_fields(reference, required, "APPROVAL_REFERENCE_FIELD_DRIFT")
    if reference["schema_version"] != "usbay.cross_repo.approval_reference.v1":
        raise CrossRepositoryContractError("APPROVAL_SCHEMA_UNSUPPORTED", "Approval reference schema is unsupported")
    if reference["ai_generated_only"] is not False:
        raise CrossRepositoryContractError("APPROVAL_NOT_HUMAN", "AI-only output cannot satisfy human approval")
    if reference["decision"] != "approved":
        raise CrossRepositoryContractError("APPROVAL_NOT_APPROVED", "Approval decision is not approved")
    for field in (
        "policy_decision_reference",
        "human_authority_reference",
        "evidence_hash",
        "subject_action_reference",
        "revocation_reference",
        "supersession_reference",
    ):
        if not is_sha256_reference(reference[field]):
            raise CrossRepositoryContractError("APPROVAL_HASH_INVALID", f"{field} must be a sha256 reference")
    if production and reference["expires_at"] <= reference["issued_at"]:
        raise CrossRepositoryContractError("APPROVAL_EXPIRED", "Approval expiry must be after issuance")
    return {"status": "PASS", "approval_reference_hash": canonical_contract_hash(reference)}


def validate_evidence_reference(reference: Mapping[str, Any]) -> dict[str, Any]:
    required = {
        "schema_version",
        "decision_evidence",
        "approval_evidence",
        "execution_evidence",
        "audit_chain_reference",
        "policy_package_hash",
        "chronology_reference",
        "runtime_attestation_reference",
        "integrity_manifest_reference",
        "hash_algorithm",
        "hash_encoding",
        "hex_case",
    }
    _require_exact_fields(reference, required, "EVIDENCE_REFERENCE_FIELD_DRIFT")
    if reference["schema_version"] != "usbay.cross_repo.evidence_reference.v1":
        raise CrossRepositoryContractError("EVIDENCE_SCHEMA_UNSUPPORTED", "Evidence reference schema is unsupported")
    _require_hash_contract(reference)
    for field in required - {"schema_version", "hash_algorithm", "hash_encoding", "hex_case"}:
        if not is_sha256_reference(reference[field]):
            raise CrossRepositoryContractError("EVIDENCE_HASH_INVALID", f"{field} must be a sha256 reference")
    return {"status": "PASS", "evidence_reference_hash": canonical_contract_hash(reference)}


def validate_production_attestation(attestation: Mapping[str, Any]) -> dict[str, Any]:
    required = {
        "schema_version",
        "repository_identity_hash",
        "source_commit_sha",
        "contract_registry_hash",
        "schema_hashes_hash",
        "validator_version",
        "validation_result",
        "time_reference",
        "environment_classification",
        "production_readiness_decision",
        "human_approval_reference",
        "self_issued",
    }
    _require_exact_fields(attestation, required, "ATTESTATION_FIELD_DRIFT")
    if attestation["schema_version"] != "usbay.cross_repo.production_attestation.v1":
        raise CrossRepositoryContractError("ATTESTATION_SCHEMA_UNSUPPORTED", "Production attestation schema is unsupported")
    if attestation["environment_classification"] != "production":
        raise CrossRepositoryContractError("ATTESTATION_NOT_PRODUCTION", "Development attestation cannot satisfy production")
    if attestation["validation_result"] != "PASS" or attestation["production_readiness_decision"] != "READY":
        raise CrossRepositoryContractError("ATTESTATION_NOT_READY", "Production attestation is not ready")
    if attestation["self_issued"] is not False:
        raise CrossRepositoryContractError("ATTESTATION_SELF_ISSUED", "Self-issued attestation cannot satisfy production")
    for field in (
        "repository_identity_hash",
        "contract_registry_hash",
        "schema_hashes_hash",
        "human_approval_reference",
    ):
        if not is_sha256_reference(attestation[field]):
            raise CrossRepositoryContractError("ATTESTATION_HASH_INVALID", f"{field} must be a sha256 reference")
    return {"status": "PASS", "attestation_hash": canonical_contract_hash(attestation)}


def production_compatibility_decision(root: Path = Path("."), attestation: Mapping[str, Any] | None = None) -> dict[str, Any]:
    try:
        registry_result = validate_registry(root)
        if attestation is None:
            raise CrossRepositoryContractError("PRODUCTION_ATTESTATION_MISSING", "Production attestation is required")
        attestation_result = validate_production_attestation(attestation)
    except CrossRepositoryContractError as exc:
        return {
            "status": "BLOCKED",
            "reason_code": exc.code,
            "production_ready": False,
            "runtime_execution_authorized": False,
        }
    return {
        "status": "PASS",
        "production_ready": True,
        "runtime_execution_authorized": False,
        "registry_hash": registry_result["registry_hash"],
        "attestation_hash": attestation_result["attestation_hash"],
    }


def _validate_registry_payload(root: Path, registry: Mapping[str, Any], identity: Mapping[str, Any]) -> None:
    required = {
        "registry_schema_version",
        "registry_id",
        "policy_brain_identity",
        "enforcement_gateway_identity",
        "versions",
        "hash_contract",
        "canonical_schema_hashes",
        "compatibility",
        "production_readiness",
    }
    _require_exact_fields(registry, required, "REGISTRY_FIELD_DRIFT")
    if registry["registry_schema_version"] != SUPPORTED_REGISTRY_SCHEMA_VERSION:
        raise CrossRepositoryContractError("REGISTRY_VERSION_UNSUPPORTED", "Registry schema version is unsupported")
    if registry["policy_brain_identity"] != identity:
        raise CrossRepositoryContractError("REGISTRY_IDENTITY_MISMATCH", "Registry identity does not match repository identity")
    _require_hash_contract(registry["hash_contract"])
    schema_hashes = registry["canonical_schema_hashes"]
    if not isinstance(schema_hashes, dict) or not schema_hashes:
        raise CrossRepositoryContractError("SCHEMA_HASHES_MISSING", "Canonical schema hashes are required")
    for name, item in schema_hashes.items():
        if not isinstance(item, dict):
            raise CrossRepositoryContractError("SCHEMA_HASH_INVALID", f"{name} schema hash entry is malformed")
        path = item.get("path")
        expected = item.get("hash")
        verified = item.get("verification")
        if verified != "verified":
            raise CrossRepositoryContractError("SCHEMA_HASH_UNVERIFIED", f"{name} schema hash is not verified")
        if not isinstance(path, str) or not is_sha256_reference(expected):
            raise CrossRepositoryContractError("SCHEMA_HASH_INVALID", f"{name} schema hash is invalid")
        actual = canonical_contract_hash(_load_json(root, path))
        if actual != expected:
            raise CrossRepositoryContractError("SCHEMA_HASH_MISMATCH", f"{name} schema hash mismatch")
    compatibility = registry["compatibility"]
    if compatibility.get("production_status") in BLOCKING_STATES:
        raise CrossRepositoryContractError("REGISTRY_PRODUCTION_BLOCKED", "Registry production status is blocked")
    if compatibility.get("runtime_execution_authorized") is not False:
        raise CrossRepositoryContractError("REGISTRY_EXECUTION_AUTHORITY_INVALID", "Compatibility metadata cannot authorize execution")


def _validate_matrix_payload(matrix: Mapping[str, Any], registry: Mapping[str, Any]) -> None:
    required = {"matrix_schema_version", "matrix_id", "relations", "default_state", "production_rule"}
    _require_exact_fields(matrix, required, "MATRIX_FIELD_DRIFT")
    if matrix["matrix_schema_version"] != SUPPORTED_MATRIX_SCHEMA_VERSION:
        raise CrossRepositoryContractError("MATRIX_VERSION_UNSUPPORTED", "Compatibility matrix version is unsupported")
    if matrix["default_state"] != "unknown":
        raise CrossRepositoryContractError("MATRIX_DEFAULT_NOT_UNKNOWN", "Unknown must be the default compatibility state")
    relations = matrix["relations"]
    if not isinstance(relations, list) or not relations:
        raise CrossRepositoryContractError("MATRIX_RELATIONS_MISSING", "Compatibility relations are required")
    allowed = COMPATIBLE_STATES | BLOCKING_STATES
    for relation in relations:
        if not isinstance(relation, dict) or relation.get("state") not in allowed:
            raise CrossRepositoryContractError("MATRIX_RELATION_INVALID", "Compatibility relation is invalid")
        if relation.get("state") == "compatible_with_translation" and not relation.get("adapter"):
            raise CrossRepositoryContractError("MATRIX_TRANSLATION_UNBOUND", "Translation requires an explicit adapter")
    registry_versions = registry["versions"]
    if not any(
        relation.get("policy_contract_version") == registry_versions["policy_contract_version"]
        and relation.get("published_api_contract_version") == registry_versions["published_api_contract_version"]
        for relation in relations
    ):
        raise CrossRepositoryContractError("MATRIX_REGISTRY_UNMAPPED", "Registry versions are not mapped")


def _validate_hash_vectors(root: Path) -> None:
    vectors = _load_json(root, "governance/contracts/cross_repository_hash_vectors.json")
    if vectors.get("schema_version") != "usbay.cross_repo.hash_vectors.v1":
        raise CrossRepositoryContractError("HASH_VECTOR_VERSION_UNSUPPORTED", "Hash vector version is unsupported")
    _require_hash_contract(vectors)
    for vector in vectors.get("vectors", []):
        if vector.get("algorithm") != SUPPORTED_HASH_ALGORITHM or vector.get("encoding") != SUPPORTED_HASH_ENCODING:
            raise CrossRepositoryContractError("HASH_VECTOR_ALGORITHM_UNSUPPORTED", "Unsupported hash vector algorithm")
        payload = vector.get("payload")
        if not isinstance(payload, dict) or canonical_contract_hash(payload) != vector.get("expected_hash"):
            raise CrossRepositoryContractError("HASH_VECTOR_MISMATCH", "Hash vector mismatch")
    for value in vectors.get("legacy_unverified_values", []):
        if is_sha256_reference(value):
            raise CrossRepositoryContractError("LEGACY_HASH_UNVERIFIED", "Unverified legacy value cannot be a verified reference")


def _require_hash_contract(payload: Mapping[str, Any]) -> None:
    if payload.get("hash_algorithm") != SUPPORTED_HASH_ALGORITHM:
        raise CrossRepositoryContractError("HASH_ALGORITHM_UNSUPPORTED", "Unsupported hash algorithm")
    if payload.get("hash_encoding") != SUPPORTED_HASH_ENCODING:
        raise CrossRepositoryContractError("HASH_ENCODING_UNSUPPORTED", "Unsupported hash encoding")
    if payload.get("hex_case") != "lowercase":
        raise CrossRepositoryContractError("HASH_HEX_CASE_UNSUPPORTED", "Hash hex case must be lowercase")


def _require_exact_fields(payload: Mapping[str, Any], required: set[str], code: str) -> None:
    fields = set(payload.keys())
    if fields != required:
        raise CrossRepositoryContractError(code, f"Field set mismatch: missing={sorted(required-fields)} extra={sorted(fields-required)}")
