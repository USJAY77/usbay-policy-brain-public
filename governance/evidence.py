from __future__ import annotations

from typing import Any

from governance.interfaces import EvidenceManifest, GovernanceValidationResult

EVIDENCE_SCHEMA = "usbay.production_readiness_ci_evidence_chain.v1"


def validate_evidence_manifest_interface(payload: dict[str, Any]) -> GovernanceValidationResult:
    """Validate evidence manifest shape at the evidence boundary.

    Governance scope: structural checks only; cryptographic hash and signature
    verification remains in the evidence verification engine.
    Fail-closed expectation: any failure must deny evidence acceptance.
    Sensitive-data handling: does not inspect or log secret-bearing fields.
    """

    failures: list[str] = []
    if not isinstance(payload, dict):
        return GovernanceValidationResult(False, ("EVIDENCE_MANIFEST_INTERFACE_INVALID",))
    if payload.get("evidence_schema") != EVIDENCE_SCHEMA:
        failures.append("EVIDENCE_SCHEMA_INVALID")
    records = payload.get("records")
    if not isinstance(records, list) or not records:
        failures.append("EVIDENCE_CHAIN_EMPTY")
        records = []
    for index, record in enumerate(records):
        if not isinstance(record, dict):
            failures.append(f"EVIDENCE_RECORD_INVALID:{index}")
            continue
        for field in ("record_id", "evidence_path", "evidence_type", "evidence_sha256", "previous_record_hash", "current_record_hash", "timestamp"):
            if not record.get(field):
                failures.append(f"EVIDENCE_RECORD_FIELD_MISSING:{index}:{field}")
    if not payload.get("workflow_version"):
        failures.append("EVIDENCE_WORKFLOW_VERSION_MISSING")
    if not payload.get("generated_at"):
        failures.append("EVIDENCE_GENERATED_AT_MISSING")
    if not payload.get("chain_head"):
        failures.append("EVIDENCE_CHAIN_HEAD_MISSING")
    return GovernanceValidationResult(not failures, tuple(sorted(set(failures))))


def evidence_manifest_from_payload(payload: dict[str, Any]) -> EvidenceManifest:
    result = validate_evidence_manifest_interface(payload)
    if not result.valid:
        raise ValueError(",".join(result.failures))
    return EvidenceManifest(
        schema=str(payload["evidence_schema"]),
        workflow_version=str(payload["workflow_version"]),
        generated_at=str(payload["generated_at"]),
        chain_head=str(payload["chain_head"]),
        records=tuple(payload["records"]),
    )

