from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any


EVIDENCE_MANIFEST_SCHEMA = "usbay.evidence.manifest.v1"
EVIDENCE_ARTIFACT_SCHEMA = "usbay.evidence.artifact.v1"
EVIDENCE_SIGNATURE_SCHEMA = "usbay.evidence.signature.v1"
EVIDENCE_TIMESTAMP_SCHEMA = "usbay.evidence.timestamp.v1"
EVIDENCE_VERIFICATION_SCHEMA = "usbay.evidence.verification.v1"
EVIDENCE_POLICY_VERSION = "usbay.pb-evidence.cryptographic-evidence-trust.v1"

VERIFICATION_STATUSES = frozenset(
    {
        "VERIFIED",
        "BLOCKED",
        "TAMPERED",
        "MISSING_ARTIFACT",
        "MISSING_SIGNATURE",
        "MISSING_TIMESTAMP",
        "HASH_MISMATCH",
        "POLICY_MISMATCH",
    }
)

REQUIRED_MANIFEST_FIELDS = (
    "manifest_id",
    "generated_at",
    "policy_version",
    "artifact_count",
    "artifact_hashes",
    "manifest_hash",
    "previous_manifest_hash",
    "signature_hash",
    "timestamp_token_hash",
    "verification_status",
    "fail_closed",
    "reason_codes",
)

REQUIRED_ARTIFACT_FIELDS = (
    "artifact_id",
    "artifact_path",
    "artifact_schema",
    "artifact_hash",
    "created_at",
    "source_pb",
    "policy_version",
)


@dataclass(frozen=True)
class EvidenceValidation:
    valid: bool
    reason_codes: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return {"valid": self.valid, "reason_codes": list(self.reason_codes)}


def parse_timestamp(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def missing_fields(payload: dict[str, Any], required: tuple[str, ...]) -> list[str]:
    return [field for field in required if payload.get(field) in ("", None)]


def validate_artifact_record(artifact: dict[str, Any] | None) -> EvidenceValidation:
    if not isinstance(artifact, dict):
        return EvidenceValidation(False, ("EVIDENCE_ARTIFACT_MISSING",))
    reasons: list[str] = []
    for field in missing_fields(artifact, REQUIRED_ARTIFACT_FIELDS):
        reasons.append(f"EVIDENCE_ARTIFACT_{field.upper()}_MISSING")
    if artifact.get("schema") != EVIDENCE_ARTIFACT_SCHEMA:
        reasons.append("EVIDENCE_ARTIFACT_SCHEMA_INVALID")
    if parse_timestamp(artifact.get("created_at")) is None:
        reasons.append("EVIDENCE_ARTIFACT_CREATED_AT_INVALID")
    if not str(artifact.get("policy_version", "")).strip():
        reasons.append("EVIDENCE_ARTIFACT_POLICY_VERSION_MISSING")
    return EvidenceValidation(not reasons, tuple(sorted(set(reasons))))


def validate_evidence_manifest(manifest: dict[str, Any] | None) -> EvidenceValidation:
    if not isinstance(manifest, dict):
        return EvidenceValidation(False, ("EVIDENCE_MANIFEST_MISSING",))
    reasons: list[str] = []
    for field in missing_fields(manifest, REQUIRED_MANIFEST_FIELDS):
        reasons.append(f"EVIDENCE_MANIFEST_{field.upper()}_MISSING")
    if manifest.get("schema") != EVIDENCE_MANIFEST_SCHEMA:
        reasons.append("EVIDENCE_MANIFEST_SCHEMA_INVALID")
    if manifest.get("verification_status") not in VERIFICATION_STATUSES:
        reasons.append(f"EVIDENCE_VERIFICATION_STATUS_UNKNOWN:{manifest.get('verification_status') or 'MISSING'}")
    if not isinstance(manifest.get("artifact_hashes"), dict):
        reasons.append("EVIDENCE_MANIFEST_ARTIFACT_HASHES_INVALID")
    if parse_timestamp(manifest.get("generated_at")) is None:
        reasons.append("EVIDENCE_MANIFEST_GENERATED_AT_INVALID")
    if not str(manifest.get("policy_version", "")).strip():
        reasons.append("EVIDENCE_MANIFEST_POLICY_VERSION_MISSING")
    return EvidenceValidation(not reasons, tuple(sorted(set(reasons))))
