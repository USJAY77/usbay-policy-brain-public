from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Mapping, Sequence

from governance.hashing import canonical_json, is_sha256_reference, sha256_reference
from runtime.computer_use.dependency_readiness_gate import evaluate_dependency_readiness
from runtime.computer_use.execution_adapter_contract import evaluate_execution_adapter_contract
from runtime.computer_use.precommit_governance_validator import validate_precommit_governance
from runtime.computer_use.production_readiness_evidence_export import generate_production_readiness_export


READY = "READY"
READY_WITH_RESTRICTIONS = "READY_WITH_RESTRICTIONS"
BLOCKED = "BLOCKED"
ALLOWED_DECISIONS = frozenset({READY, READY_WITH_RESTRICTIONS, BLOCKED})
ALLOWED_CHECK_STATES = frozenset({"PASS", "FAIL", "MISSING"})
DEPENDENCY_STATUSES = frozenset({"READY", "DEGRADED", "MISSING", "STALE", "INCOMPATIBLE", "UNVERIFIED", "BLOCKED"})
SENSITIVE_KEYS = frozenset(
    {
        "api_key",
        "authorization",
        "cookie",
        "credential",
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


@dataclass(frozen=True)
class IntegratedGovernanceChainDecision:
    final_decision: str
    reason_codes: tuple[str, ...]
    stage_hashes: Mapping[str, str]
    evidence_hash: str
    package_hash: str
    execution_allowed: bool = False
    provider_execution: bool = False
    production_activation: bool = False
    deployment_authorized: bool = False
    human_approval_required: bool = True
    metadata_only: bool = True

    def to_dict(self) -> dict[str, Any]:
        payload = {
            "final_decision": self.final_decision,
            "reason_codes": list(self.reason_codes),
            "stage_hashes": dict(sorted(self.stage_hashes.items())),
            "evidence_hash": self.evidence_hash,
            "package_hash": self.package_hash,
            "execution_allowed": self.execution_allowed,
            "provider_execution": self.provider_execution,
            "production_activation": self.production_activation,
            "deployment_authorized": self.deployment_authorized,
            "human_approval_required": self.human_approval_required,
            "metadata_only": self.metadata_only,
        }
        payload["decision_hash"] = sha256_reference(payload)
        return payload


def evaluate_integrated_governance_chain(metadata: Mapping[str, Any] | None) -> IntegratedGovernanceChainDecision:
    try:
        return _evaluate_integrated_governance_chain(metadata)
    except Exception:
        return _blocked(["INTERNAL_ERROR"])


def expected_integrated_evidence_hash(metadata: Mapping[str, Any] | None) -> str:
    try:
        if not isinstance(metadata, Mapping):
            return sha256_reference({"blocked": "MALFORMED_INTEGRATED_METADATA"})
        return _chain_evidence_hash(metadata)
    except Exception:
        return sha256_reference({"blocked": "INTERNAL_ERROR"})


def _evaluate_integrated_governance_chain(metadata: Mapping[str, Any] | None) -> IntegratedGovernanceChainDecision:
    if not isinstance(metadata, Mapping):
        return _blocked(["MALFORMED_INTEGRATED_METADATA"])
    if _contains_sensitive_key(metadata):
        return _blocked(["SENSITIVE_DATA_REJECTED"])
    if metadata.get("direct_execution_requested") is True or metadata.get("execute") is True or "command" in metadata:
        return _blocked(["DIRECT_EXECUTION_BYPASS"])

    unsupported = _unsupported_expected_decision(metadata)
    if unsupported:
        return _blocked([unsupported])

    policy_reason = _policy_reason(metadata.get("policy"))
    if policy_reason:
        return _blocked([policy_reason])

    approval_reason = _approval_reason(metadata.get("approval"))
    if approval_reason:
        return _blocked([approval_reason])

    check_reason = _required_check_reason(metadata.get("precommit_metadata"))
    if check_reason:
        return _blocked([check_reason])

    dependency = evaluate_dependency_readiness(
        metadata.get("dependencies"),
        observed_at=metadata.get("observed_at"),
        degraded_operation_permitted=metadata.get("degraded_operation_permitted") is True,
    )
    if dependency.final_decision != "ALLOW":
        return _blocked(
            [
                "DEPENDENCY_NOT_READY",
                dependency.reason_code,
                *_dependency_detail_reasons(metadata.get("dependencies"), observed_at=metadata.get("observed_at")),
            ],
            _stage_hashes(dependency=dependency.to_dict()),
        )

    adapter = evaluate_execution_adapter_contract(metadata.get("adapter_contract"), prechecks=metadata.get("adapter_prechecks"))
    if adapter.decision != "ALLOWED":
        return _blocked(["ADAPTER_CONTRACT_INVALID", adapter.reason_code], _stage_hashes(dependency=dependency.to_dict(), adapter=adapter.to_dict()))

    export = generate_production_readiness_export(metadata.get("evidence_manifest"))
    if export.final_readiness_decision == BLOCKED:
        return _blocked(
            ["EVIDENCE_EXPORT_FAILED", *export.blocked_reasons],
            _stage_hashes(dependency=dependency.to_dict(), adapter=adapter.to_dict(), export=export.to_dict()),
        )

    precommit = validate_precommit_governance(metadata.get("precommit_metadata"))
    if precommit.result == BLOCKED:
        return _blocked(
            ["PRECOMMIT_VALIDATION_FAILED", *precommit.reason_codes],
            _stage_hashes(
                dependency=dependency.to_dict(),
                adapter=adapter.to_dict(),
                export=export.to_dict(),
                precommit=precommit.to_dict(),
            ),
        )

    evidence_hash = _chain_evidence_hash(metadata)
    expected_hash = metadata.get("expected_evidence_hash")
    if not is_sha256_reference(expected_hash):
        return _blocked(["EVIDENCE_HASH_MISSING"])
    if expected_hash != evidence_hash:
        return _blocked(["EVIDENCE_HASH_MISMATCH"])

    final_decision = READY
    if export.final_readiness_decision == READY_WITH_RESTRICTIONS or precommit.result == READY_WITH_RESTRICTIONS:
        final_decision = READY_WITH_RESTRICTIONS

    stage_hashes = _stage_hashes(
        dependency=dependency.to_dict(),
        adapter=adapter.to_dict(),
        export=export.to_dict(),
        precommit=precommit.to_dict(),
    )
    return _decision(final_decision, [], stage_hashes, evidence_hash)


def _chain_evidence_hash(metadata: Mapping[str, Any]) -> str:
    dependency = evaluate_dependency_readiness(
        metadata.get("dependencies"),
        observed_at=metadata.get("observed_at"),
        degraded_operation_permitted=metadata.get("degraded_operation_permitted") is True,
    )
    adapter = evaluate_execution_adapter_contract(metadata.get("adapter_contract"), prechecks=metadata.get("adapter_prechecks"))
    export = generate_production_readiness_export(metadata.get("evidence_manifest"))
    precommit = validate_precommit_governance(metadata.get("precommit_metadata"))
    evidence = {
        "schema": "usbay.integrated_governance_chain.v1",
        "policy_hash": _hash_from(metadata.get("policy"), "policy_hash"),
        "approval_reference": _hash_from(metadata.get("approval"), "approval_reference"),
        "dependency_decision_hash": dependency.to_dict()["decision_hash"],
        "adapter_decision_hash": adapter.to_dict()["decision_hash"],
        "evidence_export_package_hash": export.package_hash,
        "precommit_validation_hash": precommit.validation_hash,
    }
    return sha256_reference(evidence)


def _stage_hashes(**stage_payloads: Mapping[str, Any]) -> dict[str, str]:
    return {stage: sha256_reference(payload) for stage, payload in sorted(stage_payloads.items()) if payload}


def _decision(
    final_decision: str,
    reason_codes: Sequence[str],
    stage_hashes: Mapping[str, str] | None = None,
    evidence_hash: str | None = None,
) -> IntegratedGovernanceChainDecision:
    normalized_reasons = tuple(sorted(dict.fromkeys(reason_codes)))
    normalized_stage_hashes = dict(sorted((stage_hashes or {}).items()))
    resolved_evidence_hash = evidence_hash or sha256_reference(
        {"final_decision": final_decision, "reason_codes": normalized_reasons, "stage_hashes": normalized_stage_hashes}
    )
    package_hash = sha256_reference(
        {
            "evidence_hash": resolved_evidence_hash,
            "final_decision": final_decision,
            "reason_codes": normalized_reasons,
            "stage_hashes": normalized_stage_hashes,
        }
    )
    return IntegratedGovernanceChainDecision(
        final_decision=final_decision,
        reason_codes=normalized_reasons,
        stage_hashes=normalized_stage_hashes,
        evidence_hash=resolved_evidence_hash,
        package_hash=package_hash,
    )


def _blocked(reason_codes: Sequence[str], stage_hashes: Mapping[str, str] | None = None) -> IntegratedGovernanceChainDecision:
    return _decision(BLOCKED, reason_codes, stage_hashes)


def _policy_reason(policy: Any) -> str:
    if not isinstance(policy, Mapping):
        return "POLICY_MISSING"
    if not policy.get("policy_version"):
        return "POLICY_MISSING"
    if not is_sha256_reference(policy.get("policy_hash")):
        return "POLICY_MISSING"
    if policy.get("final_decision") != "ALLOW":
        return "POLICY_DENIED"
    return ""


def _approval_reason(approval: Any) -> str:
    if not isinstance(approval, Mapping):
        return "APPROVAL_MISSING"
    if approval.get("status") != "VALID":
        return "APPROVAL_MISSING"
    if approval.get("expired") is True:
        return "APPROVAL_EXPIRED"
    if not is_sha256_reference(approval.get("approval_reference")):
        return "APPROVAL_MISSING"
    return ""


def _required_check_reason(precommit_metadata: Any) -> str:
    if not isinstance(precommit_metadata, Mapping):
        return "REQUIRED_CHECK_MISSING"
    for field in ("required_ci_checks", "required_tests"):
        checks = precommit_metadata.get(field)
        if not checks:
            return "REQUIRED_CHECK_MISSING"
        if not isinstance(checks, Sequence) or isinstance(checks, (str, bytes)):
            return "REQUIRED_CHECK_MISSING"
        for check in checks:
            if not isinstance(check, Mapping):
                return "REQUIRED_CHECK_MISSING"
            if check.get("status") not in ALLOWED_CHECK_STATES:
                return "REQUIRED_CHECK_UNKNOWN"
    return ""


def _dependency_detail_reasons(dependencies: Any, *, observed_at: Any) -> tuple[str, ...]:
    if not isinstance(dependencies, Sequence) or isinstance(dependencies, (str, bytes)):
        return ()
    reasons: list[str] = []
    for dependency in dependencies:
        if not isinstance(dependency, Mapping):
            reasons.append("MALFORMED_READINESS_RECORD")
            continue
        if dependency.get("readiness_status") not in DEPENDENCY_STATUSES:
            reasons.append("UNKNOWN_DEPENDENCY_STATUS")
        if dependency.get("readiness_status") == "DEGRADED" and dependency.get("required") is True:
            reasons.append("REQUIRED_DEPENDENCY_DEGRADED")
        if not _dependency_fresh(dependency, observed_at=observed_at) and dependency.get("readiness_status") == "READY":
            reasons.append("DEPENDENCY_STALE")
        if dependency.get("expected_version") != dependency.get("observed_version"):
            reasons.append("VERSION_MISMATCH")
    return tuple(reasons)


def _dependency_fresh(dependency: Mapping[str, Any], *, observed_at: Any) -> bool:
    observed = _parse_time(observed_at)
    verified = _parse_time(dependency.get("last_verified_at"))
    window = dependency.get("freshness_window_seconds")
    if observed is None or verified is None or not isinstance(window, int):
        return False
    return (observed - verified).total_seconds() <= window


def _parse_time(value: Any) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(timezone.utc)
    except ValueError:
        return None


def _unsupported_expected_decision(metadata: Mapping[str, Any]) -> str:
    if "expected_final_decision" not in metadata:
        return ""
    return "" if metadata.get("expected_final_decision") in ALLOWED_DECISIONS else "UNKNOWN_INTEGRATED_DECISION"


def _hash_from(value: Any, field: str) -> str:
    if isinstance(value, Mapping) and is_sha256_reference(value.get(field)):
        return value[field]
    return ""


def _contains_sensitive_key(value: Any) -> bool:
    if isinstance(value, Mapping):
        for key, item in value.items():
            if str(key).lower() in SENSITIVE_KEYS:
                return True
            if _contains_sensitive_key(item):
                return True
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes)):
        return any(_contains_sensitive_key(item) for item in value)
    return False


def canonical_integrated_chain_json(decision: IntegratedGovernanceChainDecision) -> str:
    return canonical_json(decision.to_dict())
