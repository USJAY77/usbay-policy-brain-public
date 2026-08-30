from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Mapping, Sequence

from governance.hashing import sha256_reference


READY = "READY"
READY_WITH_RESTRICTIONS = "READY_WITH_RESTRICTIONS"
BLOCKED = "BLOCKED"
ALLOWED_DECISIONS = frozenset({READY, READY_WITH_RESTRICTIONS, BLOCKED})
REQUIRED_FIELDS = (
    "schema",
    "manifest_id",
    "generated_at",
    "repository_revision",
    "source_branch",
    "policy_version",
    "policy_hash",
    "execution_contract_version",
    "execution_contract_hash",
    "approval_contract_version",
    "approval_reference",
    "runtime_gate_version",
    "runtime_readiness_reference",
    "dependency_readiness_version",
    "dependency_readiness_reference",
    "adapter_contract_version",
    "adapter_readiness_reference",
    "evidence_chain_reference",
    "evidence_chain_integrity",
    "timestamp_reference",
    "timestamp_verification",
    "test_summary",
    "required_test_results",
    "ci_check_summary",
    "required_ci_results",
    "rollback_reference",
    "rollback_verified",
    "known_gaps",
    "critical_gap_count",
    "restrictions",
    "evidence_hash",
    "final_readiness_decision",
)
HASH_FIELDS = (
    "policy_hash",
    "execution_contract_hash",
    "approval_reference",
    "runtime_readiness_reference",
    "dependency_readiness_reference",
    "adapter_readiness_reference",
    "evidence_chain_reference",
    "timestamp_reference",
    "rollback_reference",
    "evidence_hash",
)
REFERENCE_FIELDS = (
    "repository_revision",
    "policy_version",
    "execution_contract_version",
    "approval_contract_version",
    "runtime_gate_version",
    "dependency_readiness_version",
    "adapter_contract_version",
)
SENSITIVE_KEYS = frozenset(
    {
        "prompt",
        "raw_prompt",
        "raw_model_response",
        "raw_payload",
        "payload",
        "token",
        "api_key",
        "password",
        "credential",
        "private_key",
        "session_cookie",
        "personal_data",
        "medical_data",
        "environment_dump",
        "stack_trace",
        "provider_request_body",
        "provider_response_body",
    }
)


@dataclass(frozen=True)
class ProductionReadinessExport:
    final_readiness_decision: str
    blocked_reasons: tuple[str, ...]
    canonical_json: str
    markdown_summary: str
    manifest_hash: str
    package_hash: str
    execution_allowed: bool = False
    provider_execution: bool = False
    production_activation: bool = False
    deployment_authorized: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "final_readiness_decision": self.final_readiness_decision,
            "blocked_reasons": list(self.blocked_reasons),
            "canonical_json": self.canonical_json,
            "markdown_summary": self.markdown_summary,
            "manifest_hash": self.manifest_hash,
            "package_hash": self.package_hash,
            "execution_allowed": self.execution_allowed,
            "provider_execution": self.provider_execution,
            "production_activation": self.production_activation,
            "deployment_authorized": self.deployment_authorized,
        }


def generate_production_readiness_export(manifest: Mapping[str, Any] | None) -> ProductionReadinessExport:
    try:
        return _generate_production_readiness_export(manifest)
    except Exception:
        return _blocked(("INTERNAL_ERROR",))


def verify_production_readiness_export(canonical_json: str, expected_package_hash: str) -> ProductionReadinessExport:
    try:
        manifest = json.loads(canonical_json)
        result = generate_production_readiness_export(manifest)
        if result.package_hash != expected_package_hash:
            return _blocked(("PACKAGE_HASH_MISMATCH",))
        return result
    except Exception:
        return _blocked(("MALFORMED_MANIFEST",))


def _generate_production_readiness_export(manifest: Mapping[str, Any] | None) -> ProductionReadinessExport:
    reasons = _validation_reasons(manifest)
    if reasons:
        return _blocked(tuple(sorted(set(reasons))))
    assert isinstance(manifest, Mapping)
    decision = str(manifest["final_readiness_decision"])
    canonical_manifest = _canonical_manifest(manifest, decision=decision, blocked_reasons=())
    if decision == READY_WITH_RESTRICTIONS:
        canonical_manifest = _canonical_manifest(manifest, decision=decision, blocked_reasons=())
    canonical_json = _canonical_json(canonical_manifest)
    markdown = _markdown_summary(canonical_manifest)
    manifest_hash = sha256_reference(canonical_manifest)
    package_hash = sha256_reference({"canonical_json": canonical_json, "markdown_summary": markdown, "manifest_hash": manifest_hash})
    return ProductionReadinessExport(
        final_readiness_decision=decision,
        blocked_reasons=(),
        canonical_json=canonical_json,
        markdown_summary=markdown,
        manifest_hash=manifest_hash,
        package_hash=package_hash,
    )


def _validation_reasons(manifest: Mapping[str, Any] | None) -> list[str]:
    reasons: list[str] = []
    if not isinstance(manifest, Mapping):
        return ["MALFORMED_MANIFEST"]
    if _contains_sensitive_key(manifest):
        return ["SENSITIVE_DATA_REJECTED"]
    for field in REQUIRED_FIELDS:
        if field not in manifest:
            reasons.append(f"MISSING_{field.upper()}")
    if reasons:
        return reasons
    if manifest.get("schema") != "usbay.production_readiness.evidence_export.v1":
        reasons.append("UNSUPPORTED_SCHEMA")
    if not _repository_revision_valid(manifest.get("repository_revision")):
        reasons.append("REPOSITORY_REVISION_INVALID")
    for field in HASH_FIELDS:
        if not _is_hash(manifest.get(field)):
            reasons.append(f"INVALID_{field.upper()}")
    for field in REFERENCE_FIELDS:
        if not isinstance(manifest.get(field), str) or not manifest.get(field):
            reasons.append(f"MISSING_{field.upper()}")
    decision = manifest.get("final_readiness_decision")
    if decision not in ALLOWED_DECISIONS:
        reasons.append("UNSUPPORTED_DECISION")
    if manifest.get("evidence_chain_integrity") != "VERIFIED":
        reasons.append("EVIDENCE_CHAIN_BROKEN")
    if manifest.get("timestamp_verification") != "VALID_FRESH":
        reasons.append("TIMESTAMP_STALE_OR_INVALID")
    reasons.extend(_result_reasons(manifest.get("required_test_results"), "TEST"))
    reasons.extend(_result_reasons(manifest.get("required_ci_results"), "CI"))
    if manifest.get("rollback_verified") is not True:
        reasons.append("ROLLBACK_NOT_VERIFIED")
    if not _is_hash(manifest.get("rollback_reference")):
        reasons.append("ROLLBACK_MISSING")
    gaps = manifest.get("known_gaps")
    if not isinstance(gaps, Sequence) or isinstance(gaps, (str, bytes)):
        reasons.append("KNOWN_GAPS_MALFORMED")
    else:
        critical_count = sum(1 for gap in gaps if isinstance(gap, Mapping) and gap.get("severity") == "CRITICAL")
        if critical_count:
            reasons.append("CRITICAL_GAP_UNRESOLVED")
        if manifest.get("critical_gap_count") != critical_count:
            reasons.append("CRITICAL_GAP_COUNT_MISMATCH")
    restrictions = manifest.get("restrictions")
    restriction_reasons = _restriction_reasons(restrictions, manifest.get("generated_at"))
    reasons.extend(restriction_reasons)
    if decision == READY and restrictions:
        reasons.append("READY_WITH_RESTRICTIONS_REQUIRED")
    if decision == READY_WITH_RESTRICTIONS and (not restrictions or restriction_reasons):
        reasons.append("RESTRICTIONS_INVALID")
    return reasons


def _result_reasons(results: Any, prefix: str) -> list[str]:
    if not isinstance(results, Sequence) or isinstance(results, (str, bytes)) or not results:
        return [f"MISSING_REQUIRED_{prefix}"]
    reasons: list[str] = []
    seen = set()
    for result in results:
        if not isinstance(result, Mapping):
            reasons.append(f"MALFORMED_{prefix}_RESULT")
            continue
        result_id = result.get("id")
        if not isinstance(result_id, str) or not result_id:
            reasons.append(f"MALFORMED_{prefix}_RESULT")
        if result_id in seen:
            reasons.append(f"DUPLICATE_{prefix}_RESULT")
        seen.add(result_id)
        if result.get("required") is True and result.get("status") != "PASS":
            reasons.append(f"FAILED_REQUIRED_{prefix}")
    return reasons


def _restriction_reasons(restrictions: Any, generated_at: Any) -> list[str]:
    if restrictions in (None, []):
        return []
    generated = _parse_time(generated_at)
    if generated is None or not isinstance(restrictions, Sequence) or isinstance(restrictions, (str, bytes)):
        return ["MALFORMED_RESTRICTION"]
    reasons: list[str] = []
    for restriction in restrictions:
        if not isinstance(restriction, Mapping):
            reasons.append("MALFORMED_RESTRICTION")
            continue
        required = ("restriction_id", "reason", "owner", "approval_reference", "expires_at", "evidence_hash", "policy_authorized")
        if any(field not in restriction for field in required):
            reasons.append("MALFORMED_RESTRICTION")
            continue
        if restriction.get("policy_authorized") is not True:
            reasons.append("RESTRICTION_UNAUTHORIZED")
        if not _is_hash(restriction.get("approval_reference")) or not _is_hash(restriction.get("evidence_hash")):
            reasons.append("MALFORMED_RESTRICTION")
        expires = _parse_time(restriction.get("expires_at"))
        if expires is None or expires <= generated:
            reasons.append("RESTRICTION_EXPIRED")
    return reasons


def _canonical_manifest(manifest: Mapping[str, Any], *, decision: str, blocked_reasons: Sequence[str]) -> dict[str, Any]:
    payload = {field: manifest[field] for field in REQUIRED_FIELDS}
    payload["required_test_results"] = sorted(payload["required_test_results"], key=lambda item: item["id"])
    payload["required_ci_results"] = sorted(payload["required_ci_results"], key=lambda item: item["id"])
    payload["known_gaps"] = sorted(payload["known_gaps"], key=lambda item: item.get("gap_id", ""))
    payload["restrictions"] = sorted(payload["restrictions"], key=lambda item: item.get("restriction_id", ""))
    payload["blocked_reasons"] = list(blocked_reasons)
    payload["final_readiness_decision"] = decision
    payload["package_hash"] = ""
    return payload


def _blocked(reasons: Sequence[str]) -> ProductionReadinessExport:
    blocked_reasons = tuple(sorted(set(reasons or ("BLOCKED",))))
    manifest = {
        "final_readiness_decision": BLOCKED,
        "blocked_reasons": list(blocked_reasons),
        "package_hash": "",
    }
    canonical_json = _canonical_json(manifest)
    markdown = _markdown_summary(manifest)
    manifest_hash = sha256_reference(manifest)
    package_hash = sha256_reference({"canonical_json": canonical_json, "markdown_summary": markdown, "manifest_hash": manifest_hash})
    return ProductionReadinessExport(
        final_readiness_decision=BLOCKED,
        blocked_reasons=blocked_reasons,
        canonical_json=canonical_json,
        markdown_summary=markdown,
        manifest_hash=manifest_hash,
        package_hash=package_hash,
    )


def _canonical_json(payload: Mapping[str, Any]) -> str:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _markdown_summary(payload: Mapping[str, Any]) -> str:
    reasons = payload.get("blocked_reasons", [])
    reason_text = ", ".join(reasons) if reasons else "None"
    return "\n".join(
        [
            "# Production Readiness Evidence Export",
            "",
            f"Decision: {payload.get('final_readiness_decision', BLOCKED)}",
            f"Blocked reasons: {reason_text}",
            "Execution authorized: false",
            "Production activation: false",
        ]
    )


def _contains_sensitive_key(value: Any) -> bool:
    if isinstance(value, Mapping):
        return any(str(key).lower() in SENSITIVE_KEYS or _contains_sensitive_key(child) for key, child in value.items())
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes)):
        return any(_contains_sensitive_key(item) for item in value)
    return False


def _is_hash(value: Any) -> bool:
    return isinstance(value, str) and value.startswith("sha256:") and len(value) == 71 and all(char in "0123456789abcdef" for char in value[7:])


def _repository_revision_valid(value: Any) -> bool:
    return isinstance(value, str) and len(value) == 40 and all(char in "0123456789abcdef" for char in value)


def _parse_time(value: Any) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(timezone.utc)
    except ValueError:
        return None
