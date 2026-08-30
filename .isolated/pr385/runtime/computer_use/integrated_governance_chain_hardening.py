from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping, Sequence

from governance.hashing import canonical_json, is_sha256_reference, sha256_reference
from runtime.computer_use.integrated_governance_chain_validator import (
    BLOCKED,
    READY,
    READY_WITH_RESTRICTIONS,
    evaluate_integrated_governance_chain,
)


ALLOWED_DECISIONS = frozenset({READY, READY_WITH_RESTRICTIONS, BLOCKED})
REQUIRED_STAGE_ORDER = (
    "PB-1C_DEPENDENCY_READINESS",
    "PB-1D_EXECUTION_ADAPTER_CONTRACT",
    "PB-1E_PRODUCTION_READINESS_EVIDENCE_EXPORT",
    "PB-1F_PRECOMMIT_GOVERNANCE_VALIDATION",
    "PB-1G_INTEGRATED_GOVERNANCE_CHAIN_VALIDATION",
)
REQUIRED_CONTROL_FLAGS = (
    "policy_complete",
    "audit_complete",
    "evidence_available",
    "execution_contract_complete",
    "replay_protection_present",
    "timestamp_window_present",
    "nonce_validation_present",
    "approval_chain_present",
    "fail_closed_propagation",
    "metadata_consistent",
)
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
class IntegratedGovernanceChainHardeningDecision:
    final_decision: str
    reason_codes: tuple[str, ...]
    chain_hash: str
    evidence_hash: str
    package_hash: str
    execution_allowed: bool = False
    provider_execution: bool = False
    production_activation: bool = False
    deployment_authorized: bool = False
    metadata_only: bool = True

    def to_dict(self) -> dict[str, Any]:
        payload = {
            "final_decision": self.final_decision,
            "reason_codes": list(self.reason_codes),
            "chain_hash": self.chain_hash,
            "evidence_hash": self.evidence_hash,
            "package_hash": self.package_hash,
            "execution_allowed": self.execution_allowed,
            "provider_execution": self.provider_execution,
            "production_activation": self.production_activation,
            "deployment_authorized": self.deployment_authorized,
            "metadata_only": self.metadata_only,
        }
        payload["decision_hash"] = sha256_reference(payload)
        return payload


def evaluate_integrated_governance_chain_hardening(
    metadata: Mapping[str, Any] | None,
) -> IntegratedGovernanceChainHardeningDecision:
    try:
        return _evaluate_integrated_governance_chain_hardening(metadata)
    except Exception:
        return _blocked(["INTERNAL_ERROR"])


def expected_hardening_evidence_hash(metadata: Mapping[str, Any] | None) -> str:
    try:
        if not isinstance(metadata, Mapping):
            return sha256_reference({"blocked": "MALFORMED_HARDENING_METADATA"})
        return _hardening_evidence_hash(metadata)
    except Exception:
        return sha256_reference({"blocked": "INTERNAL_ERROR"})


def _evaluate_integrated_governance_chain_hardening(
    metadata: Mapping[str, Any] | None,
) -> IntegratedGovernanceChainHardeningDecision:
    if not isinstance(metadata, Mapping):
        return _blocked(["MALFORMED_HARDENING_METADATA"])
    if _contains_sensitive_key(metadata):
        return _blocked(["SENSITIVE_DATA_REJECTED"])
    if metadata.get("direct_execution_requested") is True or metadata.get("execute") is True or "command" in metadata:
        return _blocked(["DIRECT_EXECUTION_BYPASS"])

    reasons = [
        *_ordering_reasons(metadata.get("chain_order")),
        *_stage_reasons(metadata.get("stage_metadata")),
        *_control_reasons(metadata.get("controls")),
        *_hash_reasons(metadata),
    ]
    if reasons:
        return _blocked(reasons)

    integrated = evaluate_integrated_governance_chain(metadata.get("integrated_chain_metadata"))
    if integrated.final_decision == BLOCKED:
        return _blocked(["PB_1G_BLOCKED", *integrated.reason_codes])
    if integrated.final_decision not in ALLOWED_DECISIONS:
        return _blocked(["UNKNOWN_INTEGRATED_DECISION"])

    hardening_hash = _hardening_evidence_hash(metadata)
    expected_hash = metadata.get("expected_hardening_evidence_hash")
    if not is_sha256_reference(expected_hash):
        return _blocked(["HARDENING_EVIDENCE_HASH_MISSING"])
    if expected_hash != hardening_hash:
        return _blocked(["HARDENING_EVIDENCE_HASH_MISMATCH"])

    final_decision = READY_WITH_RESTRICTIONS if integrated.final_decision == READY_WITH_RESTRICTIONS else READY
    return _decision(final_decision, [], chain_hash=_chain_hash(metadata), evidence_hash=hardening_hash)


def _ordering_reasons(chain_order: Any) -> tuple[str, ...]:
    if not isinstance(chain_order, Sequence) or isinstance(chain_order, (str, bytes)):
        return ("INVALID_DEPENDENCY_ORDER",)
    observed = tuple(chain_order)
    if observed != REQUIRED_STAGE_ORDER:
        return ("INVALID_DEPENDENCY_ORDER",)
    return ()


def _stage_reasons(stage_metadata: Any) -> tuple[str, ...]:
    if not isinstance(stage_metadata, Mapping):
        return ("MALFORMED_STAGE_METADATA",)
    reasons: list[str] = []
    for stage in REQUIRED_STAGE_ORDER:
        stage_record = stage_metadata.get(stage)
        if not isinstance(stage_record, Mapping):
            reasons.append("MISSING_DEPENDENCY")
            continue
        status = stage_record.get("status")
        if status not in ALLOWED_DECISIONS:
            reasons.append("UNSUPPORTED_CAPABILITY")
        if status == BLOCKED:
            reasons.append("FAIL_CLOSED_PROPAGATION")
        if not is_sha256_reference(stage_record.get("evidence_hash")):
            reasons.append("MISSING_EVIDENCE")
        if not is_sha256_reference(stage_record.get("audit_hash")):
            reasons.append("AUDIT_INCOMPLETE")
        if stage_record.get("capability_supported") is not True:
            reasons.append("UNSUPPORTED_CAPABILITY")
    return tuple(reasons)


def _control_reasons(controls: Any) -> tuple[str, ...]:
    if not isinstance(controls, Mapping):
        return ("MALFORMED_CONTROL_METADATA",)
    reasons: list[str] = []
    for flag in REQUIRED_CONTROL_FLAGS:
        if controls.get(flag) is not True:
            reasons.append(_reason_for_control(flag))
    return tuple(reasons)


def _hash_reasons(metadata: Mapping[str, Any]) -> tuple[str, ...]:
    reasons: list[str] = []
    if not is_sha256_reference(metadata.get("chain_evidence_hash")):
        reasons.append("EVIDENCE_HASH_MISSING")
    if metadata.get("chain_evidence_hash") != _chain_hash(metadata):
        reasons.append("CORRUPTED_EVIDENCE")
    return tuple(reasons)


def _hardening_evidence_hash(metadata: Mapping[str, Any]) -> str:
    evidence = {
        "schema": "usbay.integrated_governance_chain_hardening.v1",
        "chain_hash": _chain_hash(metadata),
        "stage_order": list(REQUIRED_STAGE_ORDER),
        "integrated_decision_hash": _integrated_decision_hash(metadata.get("integrated_chain_metadata")),
    }
    return sha256_reference(evidence)


def _chain_hash(metadata: Mapping[str, Any]) -> str:
    stage_metadata = metadata.get("stage_metadata")
    if not isinstance(stage_metadata, Mapping):
        return sha256_reference({"blocked": "MALFORMED_STAGE_METADATA"})
    redacted = {
        stage: {
            "status": record.get("status"),
            "evidence_hash": record.get("evidence_hash"),
            "audit_hash": record.get("audit_hash"),
            "capability_supported": record.get("capability_supported"),
        }
        for stage, record in sorted(stage_metadata.items())
        if isinstance(record, Mapping)
    }
    return sha256_reference({"chain_order": list(metadata.get("chain_order", ())), "stage_metadata": redacted})


def _integrated_decision_hash(integrated_metadata: Any) -> str:
    if not isinstance(integrated_metadata, Mapping):
        return sha256_reference({"blocked": "MISSING_INTEGRATED_METADATA"})
    return evaluate_integrated_governance_chain(integrated_metadata).to_dict()["decision_hash"]


def _reason_for_control(flag: str) -> str:
    return {
        "policy_complete": "POLICY_INCOMPLETE",
        "audit_complete": "AUDIT_INCOMPLETE",
        "evidence_available": "MISSING_EVIDENCE",
        "execution_contract_complete": "EXECUTION_CONTRACT_INCOMPLETE",
        "replay_protection_present": "REPLAY_PROTECTION_MISSING",
        "timestamp_window_present": "TIMESTAMP_WINDOW_MISSING",
        "nonce_validation_present": "NONCE_VALIDATION_MISSING",
        "approval_chain_present": "APPROVAL_CHAIN_MISSING",
        "fail_closed_propagation": "FAIL_CLOSED_PROPAGATION_MISSING",
        "metadata_consistent": "METADATA_INCONSISTENT",
    }[flag]


def _decision(
    final_decision: str,
    reason_codes: Sequence[str],
    *,
    chain_hash: str | None = None,
    evidence_hash: str | None = None,
) -> IntegratedGovernanceChainHardeningDecision:
    normalized_reasons = tuple(sorted(dict.fromkeys(reason_codes)))
    resolved_chain_hash = chain_hash or sha256_reference({"final_decision": final_decision, "reason_codes": normalized_reasons})
    resolved_evidence_hash = evidence_hash or sha256_reference(
        {"chain_hash": resolved_chain_hash, "final_decision": final_decision, "reason_codes": normalized_reasons}
    )
    package_hash = sha256_reference(
        {
            "chain_hash": resolved_chain_hash,
            "evidence_hash": resolved_evidence_hash,
            "final_decision": final_decision,
            "reason_codes": normalized_reasons,
        }
    )
    return IntegratedGovernanceChainHardeningDecision(
        final_decision=final_decision,
        reason_codes=normalized_reasons,
        chain_hash=resolved_chain_hash,
        evidence_hash=resolved_evidence_hash,
        package_hash=package_hash,
    )


def _blocked(reason_codes: Sequence[str]) -> IntegratedGovernanceChainHardeningDecision:
    return _decision(BLOCKED, reason_codes)


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


def canonical_hardening_json(decision: IntegratedGovernanceChainHardeningDecision) -> str:
    return canonical_json(decision.to_dict())
