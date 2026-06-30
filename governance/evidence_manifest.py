from __future__ import annotations

from typing import Any

from governance.evidence_contracts import (
    EVIDENCE_ARTIFACT_SCHEMA,
    EVIDENCE_MANIFEST_SCHEMA,
    EVIDENCE_POLICY_VERSION,
    validate_artifact_record,
    validate_evidence_manifest,
)
from governance.execution_contracts import canonical_json, sha256_json


SECRET_MARKERS = ("password", "secret", "token", "cookie", "authorization", "api_key", "private_key", "session")
RAW_SCREENSHOT_MARKERS = ("raw_screenshot", "raw_payload", "screenshot_payload", "screenshot_bytes", "image_bytes")


def _contains_forbidden_metadata(value: Any) -> bool:
    encoded = canonical_json(value).lower()
    return any(marker in encoded for marker in SECRET_MARKERS + RAW_SCREENSHOT_MARKERS)


def artifact_hash_from_payload(payload: Any) -> str:
    return sha256_json(payload)


def build_artifact_record(
    *,
    artifact_id: str,
    artifact_path: str,
    artifact_schema: str,
    artifact_payload: Any,
    created_at: str,
    source_pb: str,
    policy_version: str = EVIDENCE_POLICY_VERSION,
) -> dict[str, Any]:
    return {
        "schema": EVIDENCE_ARTIFACT_SCHEMA,
        "artifact_id": str(artifact_id),
        "artifact_path": str(artifact_path),
        "artifact_schema": str(artifact_schema),
        "artifact_hash": artifact_hash_from_payload(artifact_payload),
        "created_at": str(created_at),
        "source_pb": str(source_pb),
        "policy_version": str(policy_version),
    }


def canonical_manifest_hash(manifest: dict[str, Any]) -> str:
    excluded = {"manifest_hash", "signature_hash", "timestamp_token_hash", "verification_status", "fail_closed", "reason_codes"}
    return sha256_json({key: value for key, value in manifest.items() if key not in excluded})


def build_evidence_manifest(
    artifacts: list[dict[str, Any]] | None,
    *,
    generated_at: str,
    previous_manifest_hash: str = "",
    policy_version: str = EVIDENCE_POLICY_VERSION,
    signature_hash: str = "",
    timestamp_token_hash: str = "",
) -> dict[str, Any]:
    reasons: list[str] = []
    safe_artifacts = artifacts if isinstance(artifacts, list) else []
    if not isinstance(artifacts, list):
        reasons.append("EVIDENCE_ARTIFACT_LIST_MISSING")

    artifact_hashes: dict[str, str] = {}
    artifact_records: list[dict[str, Any]] = []
    seen: set[str] = set()
    for artifact in safe_artifacts:
        if not isinstance(artifact, dict):
            reasons.append("EVIDENCE_ARTIFACT_MALFORMED")
            continue
        validation = validate_artifact_record(artifact)
        if not validation.valid:
            reasons.extend(validation.reason_codes)
        artifact_id = str(artifact.get("artifact_id", ""))
        if artifact_id in seen:
            reasons.append(f"EVIDENCE_DUPLICATE_ARTIFACT_ID:{artifact_id}")
        seen.add(artifact_id)
        if _contains_forbidden_metadata(artifact):
            reasons.append(f"EVIDENCE_FORBIDDEN_METADATA:{artifact_id or 'MISSING'}")
        artifact_hashes[artifact_id] = str(artifact.get("artifact_hash", ""))
        artifact_records.append({key: artifact[key] for key in artifact if key != "artifact_payload"})

    manifest = {
        "schema": EVIDENCE_MANIFEST_SCHEMA,
        "manifest_id": "",
        "generated_at": str(generated_at),
        "policy_version": str(policy_version),
        "artifact_count": len(artifact_records),
        "artifact_hashes": artifact_hashes,
        "artifacts": artifact_records,
        "manifest_hash": "",
        "previous_manifest_hash": str(previous_manifest_hash),
        "signature_hash": str(signature_hash),
        "timestamp_token_hash": str(timestamp_token_hash),
        "verification_status": "BLOCKED" if reasons else "VERIFIED",
        "fail_closed": bool(reasons),
        "reason_codes": sorted(set(reasons)),
    }
    manifest["manifest_id"] = f"evidence-manifest-{sha256_json({'artifact_hashes': artifact_hashes, 'generated_at': generated_at})[:24]}"
    manifest["manifest_hash"] = canonical_manifest_hash(manifest)
    validation = validate_evidence_manifest(manifest)
    if not validation.valid:
        reasons.extend(validation.reason_codes)
        manifest["verification_status"] = "BLOCKED"
        manifest["fail_closed"] = True
        manifest["reason_codes"] = sorted(set(reasons))
    return manifest
