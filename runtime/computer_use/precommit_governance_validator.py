from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping, Sequence

from governance.hashing import sha256_reference


READY = "READY"
READY_WITH_RESTRICTIONS = "READY_WITH_RESTRICTIONS"
BLOCKED = "BLOCKED"
ALLOWED_RESULTS = frozenset({READY, READY_WITH_RESTRICTIONS, BLOCKED})
REQUIRED_BOOLEAN_CONTROLS = (
    "policy_schema_valid",
    "execution_contract_valid",
    "approval_contract_valid",
    "dependency_readiness_valid",
    "runtime_readiness_valid",
    "adapter_readiness_valid",
    "evidence_manifest_valid",
    "package_hash_valid",
    "evidence_hash_valid",
    "rollback_record_valid",
    "required_approvals_present",
    "branch_protection_valid",
    "production_readiness_export_valid",
    "timestamp_fresh",
    "nonce_valid",
    "replay_protection_valid",
    "json_valid",
    "python_syntax_valid",
    "git_diff_valid",
    "forbidden_files_absent",
    "sensitive_data_absent",
    "secrets_absent",
    "unsupported_files_absent",
    "duplicate_manifests_absent",
    "duplicate_hashes_absent",
    "references_present",
    "references_well_formed",
)
REQUIRED_COLLECTIONS = ("required_ci_checks", "required_tests")
SENSITIVE_KEYS = frozenset(
    {
        "token",
        "password",
        "private_key",
        "cookie",
        "credential",
        "prompt",
        "raw_payload",
        "provider_response",
        "pii",
        "environment_dump",
    }
)


@dataclass(frozen=True)
class PrecommitGovernanceValidation:
    result: str
    reason_codes: tuple[str, ...]
    validation_hash: str
    execution_allowed: bool = False
    provider_execution: bool = False
    production_activation: bool = False
    deployment_authorized: bool = False

    def to_dict(self) -> dict[str, Any]:
        payload = {
            "result": self.result,
            "reason_codes": list(self.reason_codes),
            "validation_hash": self.validation_hash,
            "execution_allowed": self.execution_allowed,
            "provider_execution": self.provider_execution,
            "production_activation": self.production_activation,
            "deployment_authorized": self.deployment_authorized,
        }
        return {**payload, "decision_hash": sha256_reference(payload)}


def validate_precommit_governance(metadata: Mapping[str, Any] | None) -> PrecommitGovernanceValidation:
    try:
        return _validate_precommit_governance(metadata)
    except Exception:
        return _blocked(("INTERNAL_ERROR",))


def _validate_precommit_governance(metadata: Mapping[str, Any] | None) -> PrecommitGovernanceValidation:
    reasons = _validation_reasons(metadata)
    if reasons:
        return _blocked(tuple(sorted(set(reasons))))
    assert isinstance(metadata, Mapping)
    result = str(metadata["expected_result"])
    validation_hash = sha256_reference(_redacted_metadata(metadata))
    return PrecommitGovernanceValidation(result=result, reason_codes=(), validation_hash=validation_hash)


def _validation_reasons(metadata: Mapping[str, Any] | None) -> list[str]:
    if not isinstance(metadata, Mapping):
        return ["MALFORMED_METADATA"]
    if _contains_sensitive_key(metadata):
        return ["SENSITIVE_DATA_REJECTED"]
    reasons: list[str] = []
    expected = metadata.get("expected_result")
    if expected not in ALLOWED_RESULTS:
        reasons.append("UNKNOWN_RESULT")
    for field in REQUIRED_BOOLEAN_CONTROLS:
        if metadata.get(field) is not True:
            reasons.append(_reason_for_boolean(field))
    for field in REQUIRED_COLLECTIONS:
        reasons.extend(_collection_reasons(metadata.get(field), field))
    if metadata.get("governance_status") not in {"VALID", "RESTRICTED"}:
        reasons.append("UNKNOWN_GOVERNANCE_STATUS")
    if expected == READY and metadata.get("restrictions"):
        reasons.append("READY_WITH_RESTRICTIONS_REQUIRED")
    if expected == READY_WITH_RESTRICTIONS:
        reasons.extend(_restriction_reasons(metadata.get("restrictions")))
    if metadata.get("manifest_hash") != metadata.get("computed_manifest_hash"):
        reasons.append("HASH_MISMATCH")
    return reasons


def _collection_reasons(value: Any, field: str) -> list[str]:
    label = "CI" if field == "required_ci_checks" else "TEST"
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes)) or not value:
        return [f"MISSING_{label}"]
    reasons: list[str] = []
    seen = set()
    for item in value:
        if not isinstance(item, Mapping):
            reasons.append(f"MALFORMED_{label}")
            continue
        item_id = item.get("id")
        if not isinstance(item_id, str) or not item_id:
            reasons.append(f"MALFORMED_{label}")
        if item_id in seen:
            reasons.append(f"DUPLICATE_{label}")
        seen.add(item_id)
        if item.get("required") is True and item.get("status") != "PASS":
            reasons.append(f"MISSING_{label}" if item.get("status") == "MISSING" else f"FAILED_{label}")
    return reasons


def _restriction_reasons(restrictions: Any) -> list[str]:
    if not isinstance(restrictions, Sequence) or isinstance(restrictions, (str, bytes)) or not restrictions:
        return ["RESTRICTION_MISSING"]
    reasons: list[str] = []
    for restriction in restrictions:
        if not isinstance(restriction, Mapping) or restriction.get("policy_authorized") is not True:
            reasons.append("RESTRICTION_INVALID")
    return reasons


def _reason_for_boolean(field: str) -> str:
    return {
        "policy_schema_valid": "MISSING_POLICY",
        "execution_contract_valid": "MISSING_CONTRACT",
        "approval_contract_valid": "MISSING_APPROVAL",
        "dependency_readiness_valid": "MISSING_DEPENDENCY",
        "runtime_readiness_valid": "MISSING_RUNTIME",
        "adapter_readiness_valid": "MISSING_ADAPTER",
        "evidence_manifest_valid": "MISSING_EVIDENCE",
        "package_hash_valid": "PACKAGE_HASH_INVALID",
        "evidence_hash_valid": "EVIDENCE_HASH_INVALID",
        "rollback_record_valid": "MISSING_ROLLBACK",
        "required_approvals_present": "MISSING_APPROVAL",
        "branch_protection_valid": "BRANCH_PROTECTION_INVALID",
        "production_readiness_export_valid": "PRODUCTION_READINESS_EXPORT_INVALID",
        "timestamp_fresh": "TIMESTAMP_EXPIRED",
        "nonce_valid": "NONCE_INVALID",
        "replay_protection_valid": "REPLAY_DETECTED",
        "json_valid": "INVALID_JSON",
        "python_syntax_valid": "PYTHON_SYNTAX_INVALID",
        "git_diff_valid": "GIT_DIFF_INVALID",
        "forbidden_files_absent": "FORBIDDEN_FILES_PRESENT",
        "sensitive_data_absent": "SENSITIVE_DATA_REJECTED",
        "secrets_absent": "SECRET_DETECTED",
        "unsupported_files_absent": "UNSUPPORTED_FILES_PRESENT",
        "duplicate_manifests_absent": "DUPLICATE_MANIFEST",
        "duplicate_hashes_absent": "DUPLICATE_HASH",
        "references_present": "MISSING_REFERENCES",
        "references_well_formed": "MALFORMED_REFERENCES",
    }[field]


def _contains_sensitive_key(value: Any) -> bool:
    if isinstance(value, Mapping):
        return any(str(key).lower() in SENSITIVE_KEYS or _contains_sensitive_key(child) for key, child in value.items())
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes)):
        return any(_contains_sensitive_key(item) for item in value)
    return False


def _redacted_metadata(metadata: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "expected_result": metadata.get("expected_result", ""),
        "governance_status": metadata.get("governance_status", ""),
        "required_ci_checks": sorted(
            [{"id": item.get("id", ""), "status": item.get("status", "")} for item in metadata.get("required_ci_checks", [])],
            key=lambda item: item["id"],
        ),
        "required_tests": sorted(
            [{"id": item.get("id", ""), "status": item.get("status", "")} for item in metadata.get("required_tests", [])],
            key=lambda item: item["id"],
        ),
        "manifest_hash": metadata.get("manifest_hash", ""),
        "computed_manifest_hash": metadata.get("computed_manifest_hash", ""),
    }


def _blocked(reason_codes: Sequence[str]) -> PrecommitGovernanceValidation:
    reasons = tuple(sorted(set(reason_codes or ("BLOCKED",))))
    return PrecommitGovernanceValidation(result=BLOCKED, reason_codes=reasons, validation_hash=sha256_reference({"reason_codes": reasons}))
