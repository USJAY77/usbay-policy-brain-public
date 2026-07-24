from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Any


AUDIT_EVIDENCE_SCHEMA = "usbay.governance.audit_evidence.v1"
AUDIT_EVIDENCE_VALIDATOR_VERSION = "audit-evidence-v1"
AUDIT_EVIDENCE_FIELDS = (
    "schema",
    "validator",
    "timestamp",
    "policy_version",
    "tenant",
    "evidence_id",
    "validator_version",
    "result",
    "failure_code",
    "canonical_payload_hash",
    "audit_hash",
)
AUDIT_VALIDATOR_DOMAINS = (
    "approvals",
    "evidence",
    "evidence_chain",
    "manifests",
    "policy_validation",
    "production_readiness",
    "regulator_exports",
    "signatures",
    "signed_bundles",
    "worm",
)
AUDIT_RESULTS = ("PASS", "FAIL_CLOSED")
ZERO_AUDIT_CHAIN_HASH = "sha256:" + ("0" * 64)
AUDIT_PIPELINE_SCHEMA = AUDIT_EVIDENCE_SCHEMA + ".pipeline.v1"
AUDIT_PIPELINE_STAGE_SEQUENCE = (
    "policy_validation",
    "approvals",
    "signatures",
    "manifests",
    "evidence",
    "evidence_chain",
    "worm",
    "regulator_exports",
    "signed_bundles",
    "production_readiness",
)
AUDIT_PIPELINE_ERROR_CODES = (
    "AUDIT_PIPELINE_STAGE_MISSING",
    "AUDIT_PIPELINE_STAGE_DUPLICATE",
    "AUDIT_PIPELINE_STAGE_ORDER_INVALID",
    "AUDIT_PIPELINE_TENANT_MISMATCH",
    "AUDIT_PIPELINE_POLICY_VERSION_MISMATCH",
    "AUDIT_PIPELINE_EVIDENCE_INVALID",
)


class AuditEvidenceError(RuntimeError):
    pass


@dataclass(frozen=True)
class AuditEvidence:
    validator: str
    timestamp: str
    policy_version: str
    tenant: str
    evidence_id: str
    validator_version: str
    result: str
    failure_code: str
    canonical_payload_hash: str
    audit_hash: str

    def to_dict(self) -> dict[str, str]:
        return {
            "schema": AUDIT_EVIDENCE_SCHEMA,
            "validator": self.validator,
            "timestamp": self.timestamp,
            "policy_version": self.policy_version,
            "tenant": self.tenant,
            "evidence_id": self.evidence_id,
            "validator_version": self.validator_version,
            "result": self.result,
            "failure_code": self.failure_code,
            "canonical_payload_hash": self.canonical_payload_hash,
            "audit_hash": self.audit_hash,
        }


@dataclass(frozen=True)
class AuditEvidenceContext:
    validator: str
    timestamp: str
    policy_version: str
    tenant: str
    evidence_id: str
    validator_version: str = AUDIT_EVIDENCE_VALIDATOR_VERSION


@dataclass(frozen=True)
class AuditEvidenceAttachment:
    validation_output: Any
    audit_evidence: AuditEvidence | None
    audit_generation_error: str


@dataclass(frozen=True)
class AuditPipelineSummary:
    valid: bool
    errors: tuple[str, ...]
    correlation_id: str
    tenant: str
    policy_version: str
    stage_count: int
    stage_hashes: tuple[str, ...]
    canonical_payload_hashes: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema": AUDIT_PIPELINE_SCHEMA,
            "valid": self.valid,
            "errors": list(self.errors),
            "correlation_id": self.correlation_id,
            "tenant": self.tenant,
            "policy_version": self.policy_version,
            "stage_count": self.stage_count,
            "stage_hashes": list(self.stage_hashes),
            "canonical_payload_hashes": list(self.canonical_payload_hashes),
        }


def audit_evidence_schema() -> dict[str, Any]:
    return {
        "schema": AUDIT_EVIDENCE_SCHEMA,
        "fields": list(AUDIT_EVIDENCE_FIELDS),
        "validator_domains": list(AUDIT_VALIDATOR_DOMAINS),
        "results": list(AUDIT_RESULTS),
        "hash_algorithm": "SHA256",
        "serialization": "json.dumps(sort_keys=True,separators=(',',':'))",
        "payload_policy": "hash-only",
        "pipeline_stage_sequence": list(AUDIT_PIPELINE_STAGE_SEQUENCE),
    }


def attach_audit_evidence(
    validation_output: Any,
    *,
    canonical_payload: Any,
    context: AuditEvidenceContext,
) -> AuditEvidenceAttachment:
    try:
        _validate_context(context)
        evidence = build_audit_evidence(
            validator=context.validator,
            validation_output=validation_output,
            canonical_payload=canonical_payload,
            timestamp=context.timestamp,
            policy_version=context.policy_version,
            tenant=context.tenant,
            evidence_id=context.evidence_id,
            validator_version=context.validator_version,
        )
    except AuditEvidenceError as exc:
        return AuditEvidenceAttachment(
            validation_output=validation_output,
            audit_evidence=None,
            audit_generation_error=str(exc),
        )
    return AuditEvidenceAttachment(
        validation_output=validation_output,
        audit_evidence=evidence,
        audit_generation_error="",
    )


def canonical_audit_json(payload: Any) -> str:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def sha256_audit_hash(payload: Any) -> str:
    return "sha256:" + hashlib.sha256(canonical_audit_json(payload).encode("utf-8")).hexdigest()


def build_audit_evidence(
    *,
    validator: str,
    validation_output: Any,
    canonical_payload: Any,
    timestamp: str,
    policy_version: str,
    tenant: str,
    evidence_id: str,
    validator_version: str = AUDIT_EVIDENCE_VALIDATOR_VERSION,
) -> AuditEvidence:
    _require_domain(validator)
    failure_code = _first_failure_code(validation_output)
    result = "PASS" if _is_valid(validation_output) else "FAIL_CLOSED"
    if result == "PASS":
        failure_code = ""
    canonical_payload_hash = sha256_audit_hash(canonical_payload)
    payload = {
        "schema": AUDIT_EVIDENCE_SCHEMA,
        "validator": validator,
        "timestamp": timestamp,
        "policy_version": policy_version,
        "tenant": tenant,
        "evidence_id": evidence_id,
        "validator_version": validator_version,
        "result": result,
        "failure_code": failure_code,
        "canonical_payload_hash": canonical_payload_hash,
    }
    return AuditEvidence(
        validator=validator,
        timestamp=timestamp,
        policy_version=policy_version,
        tenant=tenant,
        evidence_id=evidence_id,
        validator_version=validator_version,
        result=result,
        failure_code=failure_code,
        canonical_payload_hash=canonical_payload_hash,
        audit_hash=sha256_audit_hash(payload),
    )


def serialize_audit_evidence(evidence: AuditEvidence | dict[str, Any]) -> str:
    payload = evidence.to_dict() if isinstance(evidence, AuditEvidence) else dict(evidence)
    validate_audit_evidence(payload)
    return canonical_audit_json(payload)


def build_audit_pipeline_summary(
    evidences: tuple[AuditEvidence | dict[str, Any], ...] | list[AuditEvidence | dict[str, Any]],
    *,
    expected_stages: tuple[str, ...] = AUDIT_PIPELINE_STAGE_SEQUENCE,
) -> AuditPipelineSummary:
    payloads = tuple(_audit_payload(evidence) for evidence in evidences)
    errors: list[str] = []
    stage_names = tuple(str(payload.get("validator", "")) for payload in payloads)
    expected_positions = {stage: index for index, stage in enumerate(expected_stages)}

    for payload in payloads:
        try:
            validate_audit_evidence(payload)
        except AuditEvidenceError:
            errors.append("AUDIT_PIPELINE_EVIDENCE_INVALID")

    for stage in expected_stages:
        count = stage_names.count(stage)
        if count == 0:
            errors.append("AUDIT_PIPELINE_STAGE_MISSING")
        elif count > 1:
            errors.append("AUDIT_PIPELINE_STAGE_DUPLICATE")

    observed_positions = tuple(expected_positions.get(stage, -1) for stage in stage_names)
    if any(position < 0 for position in observed_positions) or observed_positions != tuple(sorted(observed_positions)):
        errors.append("AUDIT_PIPELINE_STAGE_ORDER_INVALID")

    tenants = tuple(str(payload.get("tenant", "")) for payload in payloads)
    policy_versions = tuple(str(payload.get("policy_version", "")) for payload in payloads)
    if len(set(tenants)) > 1:
        errors.append("AUDIT_PIPELINE_TENANT_MISMATCH")
    if len(set(policy_versions)) > 1:
        errors.append("AUDIT_PIPELINE_POLICY_VERSION_MISMATCH")

    stage_hashes = tuple(str(payload.get("audit_hash", "")) for payload in payloads)
    canonical_payload_hashes = tuple(str(payload.get("canonical_payload_hash", "")) for payload in payloads)
    tenant = tenants[0] if tenants else ""
    policy_version = policy_versions[0] if policy_versions else ""
    correlation_payload = {
        "schema": AUDIT_PIPELINE_SCHEMA,
        "tenant": tenant,
        "policy_version": policy_version,
        "stages": [
            {
                "validator": payload.get("validator", ""),
                "evidence_id": payload.get("evidence_id", ""),
                "audit_hash": payload.get("audit_hash", ""),
                "canonical_payload_hash": payload.get("canonical_payload_hash", ""),
            }
            for payload in payloads
        ],
    }
    ordered_errors = _ordered_unique_errors(errors)
    return AuditPipelineSummary(
        valid=not ordered_errors,
        errors=ordered_errors,
        correlation_id=sha256_audit_hash(correlation_payload),
        tenant=tenant,
        policy_version=policy_version,
        stage_count=len(payloads),
        stage_hashes=stage_hashes,
        canonical_payload_hashes=canonical_payload_hashes,
    )


def build_audit_chain_record(
    evidence: AuditEvidence | dict[str, Any],
    *,
    previous_hash: str = ZERO_AUDIT_CHAIN_HASH,
    position: int = 0,
) -> dict[str, Any]:
    payload = evidence.to_dict() if isinstance(evidence, AuditEvidence) else dict(evidence)
    validate_audit_evidence(payload)
    if not _is_sha256_reference(previous_hash):
        raise AuditEvidenceError("AUDIT_CHAIN_PREVIOUS_HASH_INVALID")
    if not isinstance(position, int) or position < 0:
        raise AuditEvidenceError("AUDIT_CHAIN_POSITION_INVALID")
    record = {
        "schema": AUDIT_EVIDENCE_SCHEMA + ".chain_record",
        "position": position,
        "previous_hash": previous_hash,
        "audit_hash": payload["audit_hash"],
    }
    return {**record, "record_hash": sha256_audit_hash(record)}


def verify_audit_chain_records(records: tuple[dict[str, Any], ...] | list[dict[str, Any]]) -> tuple[str, ...]:
    previous_hash = ZERO_AUDIT_CHAIN_HASH
    seen: set[str] = set()
    errors: list[str] = []
    for expected_position, record in enumerate(records):
        if not isinstance(record, dict):
            errors.append("AUDIT_CHAIN_RECORD_INVALID")
            continue
        if record.get("schema") != AUDIT_EVIDENCE_SCHEMA + ".chain_record":
            errors.append("AUDIT_CHAIN_SCHEMA_INVALID")
        if record.get("position") != expected_position:
            errors.append("AUDIT_CHAIN_POSITION_INVALID")
        if record.get("previous_hash") != previous_hash:
            errors.append("AUDIT_CHAIN_PREVIOUS_HASH_MISMATCH")
        audit_hash = str(record.get("audit_hash", ""))
        if not _is_sha256_reference(audit_hash):
            errors.append("AUDIT_CHAIN_AUDIT_HASH_INVALID")
        if audit_hash in seen:
            errors.append("AUDIT_CHAIN_DUPLICATE_RECORD")
        seen.add(audit_hash)
        expected_hash = sha256_audit_hash(
            {
                "schema": record.get("schema"),
                "position": record.get("position"),
                "previous_hash": record.get("previous_hash"),
                "audit_hash": record.get("audit_hash"),
            }
        )
        if record.get("record_hash") != expected_hash:
            errors.append("AUDIT_CHAIN_RECORD_HASH_MISMATCH")
        previous_hash = str(record.get("record_hash", ""))
    return tuple(errors)


def serialize_audit_pipeline_summary(summary: AuditPipelineSummary | dict[str, Any]) -> str:
    payload = summary.to_dict() if isinstance(summary, AuditPipelineSummary) else dict(summary)
    return canonical_audit_json(payload)


def validate_audit_evidence(payload: dict[str, Any]) -> None:
    if tuple(payload) != AUDIT_EVIDENCE_FIELDS:
        raise AuditEvidenceError("AUDIT_EVIDENCE_FIELD_ORDER_INVALID")
    if payload.get("schema") != AUDIT_EVIDENCE_SCHEMA:
        raise AuditEvidenceError("AUDIT_EVIDENCE_SCHEMA_INVALID")
    _require_domain(str(payload.get("validator", "")))
    if payload.get("result") not in AUDIT_RESULTS:
        raise AuditEvidenceError("AUDIT_EVIDENCE_RESULT_INVALID")
    for field in ("canonical_payload_hash", "audit_hash"):
        if not _is_sha256_reference(payload.get(field)):
            raise AuditEvidenceError("AUDIT_EVIDENCE_HASH_INVALID")
    if payload["result"] == "PASS" and payload.get("failure_code") != "":
        raise AuditEvidenceError("AUDIT_EVIDENCE_FAILURE_CODE_INVALID")
    if payload["result"] == "FAIL_CLOSED" and not payload.get("failure_code"):
        raise AuditEvidenceError("AUDIT_EVIDENCE_FAILURE_CODE_MISSING")
    expected_hash = sha256_audit_hash({key: payload[key] for key in AUDIT_EVIDENCE_FIELDS if key != "audit_hash"})
    if payload["audit_hash"] != expected_hash:
        raise AuditEvidenceError("AUDIT_EVIDENCE_HASH_MISMATCH")


def _validate_context(context: AuditEvidenceContext) -> None:
    _require_domain(context.validator)
    required = {
        "timestamp": context.timestamp,
        "policy_version": context.policy_version,
        "tenant": context.tenant,
        "evidence_id": context.evidence_id,
        "validator_version": context.validator_version,
    }
    for field, value in required.items():
        if not isinstance(value, str) or not value.strip():
            raise AuditEvidenceError("AUDIT_EVIDENCE_CONTEXT_" + field.upper() + "_MISSING")


def _require_domain(validator: str) -> None:
    if validator not in AUDIT_VALIDATOR_DOMAINS:
        raise AuditEvidenceError("AUDIT_EVIDENCE_VALIDATOR_UNSUPPORTED")


def _is_valid(validation_output: Any) -> bool:
    if hasattr(validation_output, "valid"):
        return bool(validation_output.valid)
    if isinstance(validation_output, dict):
        if "valid" in validation_output:
            return bool(validation_output["valid"])
        if "result" in validation_output:
            return str(validation_output["result"]) == "PASS"
        if "decision" in validation_output:
            return str(validation_output["decision"]) in {"ALLOW", "PASS", "VERIFIED"}
    return False


def _first_failure_code(validation_output: Any) -> str:
    for value in _failure_values(validation_output):
        if hasattr(value, "code"):
            return str(value.code)
        if isinstance(value, dict) and "code" in value:
            return str(value["code"])
        return str(value)
    return "UNKNOWN_FAIL_CLOSED"


def _failure_values(validation_output: Any) -> tuple[Any, ...]:
    for attr in ("errors", "failures", "reason_codes", "denial_reasons"):
        if hasattr(validation_output, attr):
            values = getattr(validation_output, attr)
            if values:
                return tuple(values)
    if isinstance(validation_output, dict):
        for key in ("errors", "failures", "reason_codes", "denial_reasons"):
            values = validation_output.get(key)
            if values:
                return tuple(values)
    return ()


def _is_sha256_reference(value: Any) -> bool:
    if not isinstance(value, str) or not value.startswith("sha256:"):
        return False
    digest = value.removeprefix("sha256:")
    return len(digest) == 64 and all(char in "0123456789abcdef" for char in digest)


def _audit_payload(evidence: AuditEvidence | dict[str, Any]) -> dict[str, Any]:
    return evidence.to_dict() if isinstance(evidence, AuditEvidence) else dict(evidence)


def _ordered_unique_errors(errors: list[str]) -> tuple[str, ...]:
    return tuple(code for code in AUDIT_PIPELINE_ERROR_CODES if code in errors)
