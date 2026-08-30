from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping, Sequence

from governance.hashing import canonical_json, is_sha256_reference, sha256_reference


READY = "READY"
READY_WITH_RESTRICTIONS = "READY_WITH_RESTRICTIONS"
BLOCKED = "BLOCKED"

ALLOWED_DECISIONS = frozenset({READY, READY_WITH_RESTRICTIONS, BLOCKED})
REQUIRED_STAGE_ORDER = (
    "PB-1B_RUNTIME_FAIL_CLOSED_EXECUTION_GATE",
    "PB-1C_RUNTIME_DEPENDENCY_READINESS_GATE",
    "PB-1D_GOVERNED_EXECUTION_ADAPTER_CONTRACT",
    "PB-1E_PRODUCTION_READINESS_EVIDENCE_EXPORT",
    "PB-1F_PRECOMMIT_GOVERNANCE_VALIDATION",
    "PB-1G_INTEGRATED_GOVERNANCE_CHAIN_VALIDATION",
    "PB-1H_INTEGRATED_GOVERNANCE_CHAIN_HARDENING",
)
REQUIRED_STAGE_FIELDS = (
    "status",
    "evidence_hash",
    "audit_hash",
    "decision_hash",
    "merge_commit",
    "pull_request",
    "approval_reference",
    "policy_version",
    "chronology_marker",
    "fail_closed_propagation",
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
        "production_activation",
        "provider_execution",
        "runtime_mutation",
        "subprocess",
    }
)
FALSE_SAFETY_FLAGS = (
    "execution_allowed",
    "provider_execution",
    "production_activation",
    "deployment_authorized",
    "runtime_mutation",
)


@dataclass(frozen=True)
class PB1IChainClosureDecision:
    final_decision: str
    reason_codes: tuple[str, ...]
    chain_hash: str
    evidence_hash: str
    package_hash: str
    execution_allowed: bool = False
    provider_execution: bool = False
    production_activation: bool = False
    deployment_authorized: bool = False
    runtime_mutation: bool = False
    metadata_only: bool = True
    human_approval_required: bool = True

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
            "runtime_mutation": self.runtime_mutation,
            "metadata_only": self.metadata_only,
            "human_approval_required": self.human_approval_required,
        }
        payload["decision_hash"] = sha256_reference(payload)
        return payload


def evaluate_pb_1i_chain_closure_verification(metadata: Mapping[str, Any] | None) -> PB1IChainClosureDecision:
    try:
        return _evaluate_pb_1i_chain_closure_verification(metadata)
    except Exception:
        return _blocked(["INTERNAL_ERROR"])


def expected_pb_1i_chain_hash(metadata: Mapping[str, Any] | None) -> str:
    try:
        if not isinstance(metadata, Mapping):
            return sha256_reference({"blocked": "MALFORMED_PB_1I_METADATA"})
        return _chain_hash(metadata)
    except Exception:
        return sha256_reference({"blocked": "INTERNAL_ERROR"})


def expected_pb_1i_evidence_hash(metadata: Mapping[str, Any] | None) -> str:
    try:
        if not isinstance(metadata, Mapping):
            return sha256_reference({"blocked": "MALFORMED_PB_1I_METADATA"})
        return _evidence_hash(metadata)
    except Exception:
        return sha256_reference({"blocked": "INTERNAL_ERROR"})


def expected_pb_1i_package_hash(metadata: Mapping[str, Any] | None) -> str:
    try:
        if not isinstance(metadata, Mapping):
            return sha256_reference({"blocked": "MALFORMED_PB_1I_METADATA"})
        return _package_hash(metadata)
    except Exception:
        return sha256_reference({"blocked": "INTERNAL_ERROR"})


def canonical_pb_1i_json(decision: PB1IChainClosureDecision) -> str:
    return canonical_json(decision.to_dict())


def _evaluate_pb_1i_chain_closure_verification(metadata: Mapping[str, Any] | None) -> PB1IChainClosureDecision:
    if not isinstance(metadata, Mapping):
        return _blocked(["MALFORMED_PB_1I_METADATA"])

    surface_reasons = _surface_reasons(metadata)
    if surface_reasons:
        return _blocked(surface_reasons)

    reasons = [
        *_order_reasons(metadata.get("chain_order")),
        *_stage_reasons(metadata.get("stage_metadata")),
        *_hash_reasons(metadata),
        *_restriction_reasons(metadata),
        *_safety_flag_reasons(metadata),
    ]
    if reasons:
        return _blocked(reasons)

    final_decision = READY_WITH_RESTRICTIONS if _has_governed_restrictions(metadata) else READY
    return _decision(
        final_decision,
        [],
        chain_hash=_chain_hash(metadata),
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
                if normalized_key in FALSE_SAFETY_FLAGS and item is False:
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


def _order_reasons(chain_order: Any) -> tuple[str, ...]:
    if not isinstance(chain_order, Sequence) or isinstance(chain_order, (str, bytes)):
        return ("INVALID_CHAIN_ORDER",)
    if tuple(chain_order) != REQUIRED_STAGE_ORDER:
        return ("INVALID_CHAIN_ORDER",)
    return ()


def _stage_reasons(stage_metadata: Any) -> tuple[str, ...]:
    if not isinstance(stage_metadata, Mapping):
        return ("MALFORMED_STAGE_METADATA",)

    reasons: list[str] = []
    if set(stage_metadata) != set(REQUIRED_STAGE_ORDER):
        for stage in REQUIRED_STAGE_ORDER:
            if stage not in stage_metadata:
                reasons.append(_missing_stage_reason(stage))
        for stage in stage_metadata:
            if stage not in REQUIRED_STAGE_ORDER:
                reasons.append("UNSUPPORTED_CAPABILITY_METADATA")

    chronology: list[int] = []
    policy_versions: set[str] = set()
    for stage in REQUIRED_STAGE_ORDER:
        record = stage_metadata.get(stage)
        if not isinstance(record, Mapping):
            continue
        reasons.extend(_stage_record_reasons(stage, record))
        marker = record.get("chronology_marker")
        if isinstance(marker, int) and marker > 0:
            chronology.append(marker)
        policy_version = record.get("policy_version")
        if isinstance(policy_version, str) and policy_version:
            policy_versions.add(policy_version)

    if chronology != sorted(chronology) or len(chronology) != len(REQUIRED_STAGE_ORDER):
        reasons.append("CHRONOLOGY_MISMATCH")
    if len(set(chronology)) != len(chronology):
        reasons.append("CHRONOLOGY_MISMATCH")
    if len(policy_versions) != 1:
        reasons.append("POLICY_VERSION_MISMATCH")

    return tuple(reasons)


def _stage_record_reasons(stage: str, record: Mapping[str, Any]) -> tuple[str, ...]:
    reasons: list[str] = []
    for field in REQUIRED_STAGE_FIELDS:
        if field not in record:
            reasons.append(_missing_field_reason(field))

    status = record.get("status")
    if status not in ALLOWED_DECISIONS:
        reasons.append("UNKNOWN_DECISION")
    if status == BLOCKED:
        reasons.append("UPSTREAM_BLOCKED")
    if status == READY_WITH_RESTRICTIONS and not is_sha256_reference(record.get("restriction_reference")):
        reasons.append("GOVERNED_RESTRICTION_REFERENCE_MISSING")

    if not is_sha256_reference(record.get("evidence_hash")):
        reasons.append("EVIDENCE_HASH_MISSING")
    if not is_sha256_reference(record.get("audit_hash")):
        reasons.append("AUDIT_HASH_MISSING")
    if not is_sha256_reference(record.get("decision_hash")):
        reasons.append("DECISION_HASH_MISSING")
    if not is_sha256_reference(record.get("approval_reference")):
        reasons.append("APPROVAL_REFERENCE_MISSING")
    if not _is_commit_reference(record.get("merge_commit")):
        reasons.append("MERGE_METADATA_MISSING")
    if not _is_pull_request_reference(record.get("pull_request")):
        reasons.append("PULL_REQUEST_METADATA_MISSING")
    if not isinstance(record.get("policy_version"), str) or not record.get("policy_version"):
        reasons.append("POLICY_VERSION_MISSING")
    if record.get("fail_closed_propagation") is not True:
        reasons.append("FAIL_CLOSED_PROPAGATION_MISSING")
    if record.get("capability_supported") is not True:
        reasons.append("UNSUPPORTED_CAPABILITY_METADATA")
    if record.get("metadata_stale") is True:
        reasons.append("STALE_METADATA")
    if record.get("stage_id") not in (None, stage):
        reasons.append("METADATA_INCONSISTENT")

    return tuple(reasons)


def _hash_reasons(metadata: Mapping[str, Any]) -> tuple[str, ...]:
    reasons: list[str] = []
    expected_chain_hash = metadata.get("expected_chain_hash")
    expected_evidence_hash = metadata.get("expected_evidence_hash")
    expected_package_hash = metadata.get("expected_package_hash")
    if not is_sha256_reference(expected_chain_hash):
        reasons.append("CHAIN_HASH_MISSING")
    elif expected_chain_hash != _chain_hash(metadata):
        reasons.append("CHAIN_HASH_MISMATCH")
    if not is_sha256_reference(expected_evidence_hash):
        reasons.append("EVIDENCE_HASH_MISSING")
    elif expected_evidence_hash != _evidence_hash(metadata):
        reasons.append("EVIDENCE_HASH_MISMATCH")
    if not is_sha256_reference(expected_package_hash):
        reasons.append("PACKAGE_HASH_MISSING")
    elif expected_package_hash != _package_hash(metadata):
        reasons.append("PACKAGE_HASH_MISMATCH")
    return tuple(reasons)


def _restriction_reasons(metadata: Mapping[str, Any]) -> tuple[str, ...]:
    stage_metadata = metadata.get("stage_metadata")
    if not isinstance(stage_metadata, Mapping):
        return ()
    restricted = any(isinstance(record, Mapping) and record.get("status") == READY_WITH_RESTRICTIONS for record in stage_metadata.values())
    restrictions = metadata.get("restriction_metadata", ())
    if restricted and not _has_governed_restrictions(metadata):
        return ("GOVERNED_RESTRICTION_METADATA_MISSING",)
    if restrictions and (
        not isinstance(restrictions, Sequence)
        or isinstance(restrictions, (str, bytes))
        or any(not isinstance(item, Mapping) or not is_sha256_reference(item.get("restriction_reference")) for item in restrictions)
    ):
        return ("GOVERNED_RESTRICTION_METADATA_MISSING",)
    return ()


def _safety_flag_reasons(metadata: Mapping[str, Any]) -> tuple[str, ...]:
    flags = metadata.get("safety_flags")
    if not isinstance(flags, Mapping):
        return ("SAFETY_FLAGS_MISSING",)
    reasons = []
    for flag in FALSE_SAFETY_FLAGS:
        if flags.get(flag) is not False:
            reasons.append("EXECUTION_FLAG_NOT_FALSE")
    return tuple(reasons)


def _has_governed_restrictions(metadata: Mapping[str, Any]) -> bool:
    restrictions = metadata.get("restriction_metadata", ())
    return isinstance(restrictions, Sequence) and not isinstance(restrictions, (str, bytes)) and len(restrictions) > 0


def _chain_hash(metadata: Mapping[str, Any]) -> str:
    return sha256_reference({"schema": "usbay.pb_1i.chain_closure.v1", "stages": _redacted_stages(metadata)})


def _evidence_hash(metadata: Mapping[str, Any]) -> str:
    return sha256_reference(
        {
            "schema": "usbay.pb_1i.chain_closure.evidence.v1",
            "chain_hash": _chain_hash(metadata),
            "stage_order": list(REQUIRED_STAGE_ORDER),
            "restriction_metadata": _redacted_restrictions(metadata),
        }
    )


def _package_hash(metadata: Mapping[str, Any]) -> str:
    return sha256_reference(
        {
            "schema": "usbay.pb_1i.chain_closure.package.v1",
            "chain_hash": _chain_hash(metadata),
            "evidence_hash": _evidence_hash(metadata),
        }
    )


def _redacted_stages(metadata: Mapping[str, Any]) -> list[dict[str, Any]]:
    stage_metadata = metadata.get("stage_metadata")
    if not isinstance(stage_metadata, Mapping):
        return []
    redacted: list[dict[str, Any]] = []
    for stage in REQUIRED_STAGE_ORDER:
        record = stage_metadata.get(stage)
        if not isinstance(record, Mapping):
            continue
        redacted.append(
            {
                "stage": stage,
                "status": record.get("status"),
                "evidence_hash": record.get("evidence_hash"),
                "audit_hash": record.get("audit_hash"),
                "decision_hash": record.get("decision_hash"),
                "merge_commit": record.get("merge_commit"),
                "pull_request": record.get("pull_request"),
                "approval_reference": record.get("approval_reference"),
                "policy_version": record.get("policy_version"),
                "chronology_marker": record.get("chronology_marker"),
                "restriction_reference": record.get("restriction_reference"),
            }
        )
    return redacted


def _redacted_restrictions(metadata: Mapping[str, Any]) -> list[dict[str, Any]]:
    restrictions = metadata.get("restriction_metadata", ())
    if not isinstance(restrictions, Sequence) or isinstance(restrictions, (str, bytes)):
        return []
    return [
        {"restriction_reference": item.get("restriction_reference")}
        for item in restrictions
        if isinstance(item, Mapping) and is_sha256_reference(item.get("restriction_reference"))
    ]


def _decision(
    final_decision: str,
    reason_codes: Sequence[str],
    *,
    chain_hash: str | None = None,
    evidence_hash: str | None = None,
    package_hash: str | None = None,
) -> PB1IChainClosureDecision:
    normalized_reasons = tuple(sorted(dict.fromkeys(reason_codes)))
    resolved_chain_hash = chain_hash or sha256_reference({"final_decision": final_decision, "reason_codes": normalized_reasons})
    resolved_evidence_hash = evidence_hash or sha256_reference(
        {"chain_hash": resolved_chain_hash, "final_decision": final_decision, "reason_codes": normalized_reasons}
    )
    resolved_package_hash = package_hash or sha256_reference(
        {
            "chain_hash": resolved_chain_hash,
            "evidence_hash": resolved_evidence_hash,
            "final_decision": final_decision,
            "reason_codes": normalized_reasons,
        }
    )
    return PB1IChainClosureDecision(
        final_decision=final_decision,
        reason_codes=normalized_reasons,
        chain_hash=resolved_chain_hash,
        evidence_hash=resolved_evidence_hash,
        package_hash=resolved_package_hash,
    )


def _blocked(reason_codes: Sequence[str]) -> PB1IChainClosureDecision:
    return _decision(BLOCKED, reason_codes)


def _missing_stage_reason(stage: str) -> str:
    return {
        "PB-1B_RUNTIME_FAIL_CLOSED_EXECUTION_GATE": "PB_1B_METADATA_MISSING",
        "PB-1C_RUNTIME_DEPENDENCY_READINESS_GATE": "PB_1C_METADATA_MISSING",
        "PB-1D_GOVERNED_EXECUTION_ADAPTER_CONTRACT": "PB_1D_METADATA_MISSING",
        "PB-1E_PRODUCTION_READINESS_EVIDENCE_EXPORT": "PB_1E_METADATA_MISSING",
        "PB-1F_PRECOMMIT_GOVERNANCE_VALIDATION": "PB_1F_METADATA_MISSING",
        "PB-1G_INTEGRATED_GOVERNANCE_CHAIN_VALIDATION": "PB_1G_METADATA_MISSING",
        "PB-1H_INTEGRATED_GOVERNANCE_CHAIN_HARDENING": "PB_1H_METADATA_MISSING",
    }[stage]


def _missing_field_reason(field: str) -> str:
    return {
        "status": "UNKNOWN_DECISION",
        "evidence_hash": "EVIDENCE_HASH_MISSING",
        "audit_hash": "AUDIT_HASH_MISSING",
        "decision_hash": "DECISION_HASH_MISSING",
        "merge_commit": "MERGE_METADATA_MISSING",
        "pull_request": "PULL_REQUEST_METADATA_MISSING",
        "approval_reference": "APPROVAL_REFERENCE_MISSING",
        "policy_version": "POLICY_VERSION_MISSING",
        "chronology_marker": "CHRONOLOGY_MISMATCH",
        "fail_closed_propagation": "FAIL_CLOSED_PROPAGATION_MISSING",
    }[field]


def _is_commit_reference(value: Any) -> bool:
    return isinstance(value, str) and len(value) == 40 and all(char in "0123456789abcdef" for char in value)


def _is_pull_request_reference(value: Any) -> bool:
    return isinstance(value, str) and value.startswith("PR-") and value.removeprefix("PR-").isdigit()
