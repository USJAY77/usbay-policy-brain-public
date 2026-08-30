from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from governance.evidence_contracts import EVIDENCE_POLICY_VERSION, EVIDENCE_VERIFICATION_SCHEMA, validate_artifact_record, validate_evidence_manifest
from governance.evidence_manifest import artifact_hash_from_payload, canonical_manifest_hash
from governance.evidence_signing import validate_evidence_signature
from governance.evidence_timestamp import TIMESTAMP_INTEGRATION_STATUS, validate_evidence_timestamp
from governance.execution_contracts import sha256_json


@dataclass(frozen=True)
class EvidenceVerificationResult:
    verification_status: str
    reason_codes: tuple[str, ...]
    verification_record: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return {
            "verification_status": self.verification_status,
            "reason_codes": list(self.reason_codes),
            "verification_record": self.verification_record,
        }


def _now_text(now: datetime | None) -> str:
    effective_now = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    return effective_now.isoformat().replace("+00:00", "Z")


def _append_reason(reasons: list[str], code: str) -> None:
    if code not in reasons:
        reasons.append(code)


def _status_from_reasons(reasons: list[str]) -> str:
    if any("TAMPER" in reason or "HASH_MISMATCH" in reason or "INVALID" in reason for reason in reasons):
        return "TAMPERED"
    if any("POLICY" in reason for reason in reasons):
        return "POLICY_MISMATCH"
    if any("MISSING_SIGNATURE" in reason or "SIGNATURE_MISSING" in reason for reason in reasons):
        return "MISSING_SIGNATURE"
    if any("MISSING_TIMESTAMP" in reason or "TIMESTAMP_MISSING" in reason for reason in reasons):
        return "MISSING_TIMESTAMP"
    if any("MISSING_ARTIFACT" in reason or "ARTIFACT_MISSING" in reason for reason in reasons):
        return "MISSING_ARTIFACT"
    return "BLOCKED" if reasons else "VERIFIED"


def verify_evidence_trust(
    *,
    manifest: dict[str, Any] | None,
    artifact_payloads: dict[str, Any] | None,
    signature: dict[str, Any] | None,
    timestamp: dict[str, Any] | None,
    expected_previous_manifest_hash: str = "",
    expected_policy_version: str = EVIDENCE_POLICY_VERSION,
    now: datetime | None = None,
) -> EvidenceVerificationResult:
    generated_at = _now_text(now)
    effective_now = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    reasons: list[str] = []
    safe_manifest = manifest if isinstance(manifest, dict) else {}

    manifest_validation = validate_evidence_manifest(manifest)
    if not manifest_validation.valid:
        reasons.extend(manifest_validation.reason_codes)
    if isinstance(manifest, dict) and safe_manifest.get("policy_version") and safe_manifest.get("policy_version") != expected_policy_version:
        _append_reason(reasons, "EVIDENCE_POLICY_MISMATCH")
    if safe_manifest.get("previous_manifest_hash", "") != expected_previous_manifest_hash:
        _append_reason(reasons, "EVIDENCE_PREVIOUS_MANIFEST_MISMATCH")
    if safe_manifest and safe_manifest.get("manifest_hash") != canonical_manifest_hash(safe_manifest):
        _append_reason(reasons, "EVIDENCE_MANIFEST_HASH_MISMATCH")

    payloads = artifact_payloads if isinstance(artifact_payloads, dict) else {}
    manifest_artifacts = safe_manifest.get("artifacts", [])
    if not isinstance(manifest_artifacts, list):
        manifest_artifacts = []
        _append_reason(reasons, "EVIDENCE_ARTIFACTS_MALFORMED")

    artifact_created_at_values: list[str] = []
    seen_ids: set[str] = set()
    for artifact in manifest_artifacts:
        validation = validate_artifact_record(artifact if isinstance(artifact, dict) else None)
        if not validation.valid:
            reasons.extend(validation.reason_codes)
        if not isinstance(artifact, dict):
            continue
        artifact_id = str(artifact.get("artifact_id", ""))
        if artifact_id in seen_ids:
            _append_reason(reasons, f"EVIDENCE_DUPLICATE_ARTIFACT_ID:{artifact_id}")
        seen_ids.add(artifact_id)
        artifact_created_at_values.append(str(artifact.get("created_at", "")))
        if artifact.get("policy_version") != safe_manifest.get("policy_version"):
            _append_reason(reasons, f"EVIDENCE_ARTIFACT_POLICY_MISMATCH:{artifact_id}")
        if artifact_id not in payloads:
            _append_reason(reasons, f"EVIDENCE_MISSING_ARTIFACT:{artifact_id}")
            continue
        if artifact_hash_from_payload(payloads[artifact_id]) != artifact.get("artifact_hash"):
            _append_reason(reasons, f"EVIDENCE_ARTIFACT_HASH_MISMATCH:{artifact_id}")

    signature_valid, signature_reasons = validate_evidence_signature(signature, manifest_hash=str(safe_manifest.get("manifest_hash", "")))
    if not signature_valid:
        reasons.extend(signature_reasons)
    timestamp_valid, timestamp_reasons = validate_evidence_timestamp(
        timestamp,
        manifest_hash=str(safe_manifest.get("manifest_hash", "")),
        artifact_created_at_values=artifact_created_at_values,
        now=effective_now,
    )
    if not timestamp_valid:
        reasons.extend(timestamp_reasons)

    status = _status_from_reasons(reasons)
    verification_record = {
        "schema": EVIDENCE_VERIFICATION_SCHEMA,
        "verification_id": f"evidence-verification-{sha256_json({'manifest': safe_manifest.get('manifest_hash', ''), 'generated_at': generated_at})[:24]}",
        "manifest_id": str(safe_manifest.get("manifest_id", "")),
        "manifest_hash": str(safe_manifest.get("manifest_hash", "")),
        "artifact_count": int(safe_manifest.get("artifact_count", 0)) if isinstance(safe_manifest.get("artifact_count", 0), int) else 0,
        "verification_status": status,
        "signature_status": "VERIFIED" if signature_valid else "BLOCKED",
        "timestamp_status": "VERIFIED" if timestamp_valid else "BLOCKED",
        "timestamp_integration_status": TIMESTAMP_INTEGRATION_STATUS,
        "tamper_status": "TAMPERED" if status == "TAMPERED" else "NOT_DETECTED",
        "last_verified_at": generated_at,
        "policy_version": str(safe_manifest.get("policy_version", expected_policy_version)),
        "reason_codes": sorted(set(reasons)),
        "fail_closed": status != "VERIFIED",
        "auto_verified": False,
        "auto_signed": False,
        "auto_timestamped": False,
        "auto_repaired": False,
        "trusted_without_signature": False,
        "trusted_without_timestamp": False,
    }
    return EvidenceVerificationResult(
        verification_status=status,
        reason_codes=tuple(sorted(set(reasons))),
        verification_record=verification_record,
    )


def empty_evidence_trust_dashboard_state() -> dict[str, Any]:
    result = verify_evidence_trust(
        manifest=None,
        artifact_payloads=None,
        signature=None,
        timestamp=None,
    )
    record = result.verification_record
    return {
        "schema_version": "usbay.evidence_trust.demo_dashboard_state.v1",
        "evidence_manifest_id": record["manifest_id"],
        "artifact_count": record["artifact_count"],
        "verification_status": record["verification_status"],
        "signature_status": record["signature_status"],
        "timestamp_status": record["timestamp_status"],
        "tamper_status": record["tamper_status"],
        "last_verified_at": record["last_verified_at"],
        "policy_version": record["policy_version"],
        "reason_codes": record["reason_codes"],
        "timestamp_integration_status": TIMESTAMP_INTEGRATION_STATUS,
        "auto_verified": False,
        "auto_signed": False,
        "auto_timestamped": False,
        "auto_repaired": False,
        "trusted_without_signature": False,
        "trusted_without_timestamp": False,
    }
