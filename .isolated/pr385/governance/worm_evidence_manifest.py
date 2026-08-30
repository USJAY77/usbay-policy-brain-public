from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from governance.policy_pack import assert_cached_validation_safe, assert_policy_diagnostics_safe, redacted_policy_payload
from governance.policy_parity import assert_parity_diagnostics_safe
from governance.policy_proof_bundle import assert_proof_bundle_safe, verify_policy_proof_bundle
from governance.policy_simulation import assert_simulation_diagnostics_safe
from governance.proof_timestamp_anchor import assert_timestamp_anchor_safe, verify_proof_timestamp_anchor
from governance.rfc3161_timestamp import (
    MODULE_VERSIONS as RFC3161_MODULE_VERSIONS,
    assert_rfc3161_safe,
    verify_rfc3161_request_material,
)

WORM_MANIFEST_SCHEMA = "usbay.governance_worm_evidence_manifest.v1"
WORM_ERROR_REGISTRY_PATH = Path("governance/worm_evidence_manifest_errors.json")
WORM_ERROR_SCHEMA = "usbay.governance_worm_evidence_manifest_error_registry.v1"
WORM_ERROR_CODES = (
    "WORM_PROOF_BUNDLE_HASH_MISSING",
    "WORM_TIMESTAMP_ANCHOR_MISSING",
    "WORM_RFC3161_DIGEST_MISSING",
    "WORM_MANIFEST_INVALID",
    "WORM_RETENTION_POLICY_MISSING",
    "WORM_DIAGNOSTICS_UNSAFE",
)
MODULE_VERSIONS = {
    **RFC3161_MODULE_VERSIONS,
    "worm_evidence_manifest": WORM_MANIFEST_SCHEMA,
}


class WORMEvidenceManifestError(RuntimeError):
    pass


@dataclass(frozen=True)
class WORMManifestVerificationResult:
    valid: bool
    errors: tuple[str, ...]
    proof_bundle_hash: str
    timestamp_anchor_hash: str
    rfc3161_request_digest: str
    manifest_hash: str
    retention_policy_label: str
    validation_status: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "valid": self.valid,
            "errors": list(self.errors),
            "proof_bundle_hash": self.proof_bundle_hash,
            "timestamp_anchor_hash": self.timestamp_anchor_hash,
            "rfc3161_request_digest": self.rfc3161_request_digest,
            "manifest_hash": self.manifest_hash,
            "retention_policy_label": self.retention_policy_label,
            "validation_status": self.validation_status,
        }


def load_worm_error_registry(root: Path) -> dict[str, dict[str, str]]:
    path = root / WORM_ERROR_REGISTRY_PATH
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        raise WORMEvidenceManifestError("worm_error_registry_missing") from exc
    if not isinstance(payload, dict) or payload.get("schema") != WORM_ERROR_SCHEMA:
        raise WORMEvidenceManifestError("worm_error_registry_invalid")
    raw_errors = payload.get("errors")
    if not isinstance(raw_errors, list):
        raise WORMEvidenceManifestError("worm_error_registry_invalid")
    registry: dict[str, dict[str, str]] = {}
    for entry in raw_errors:
        if not isinstance(entry, dict) or not entry.get("code"):
            raise WORMEvidenceManifestError("worm_error_registry_invalid")
        registry[str(entry["code"])] = {
            "description": str(entry.get("description", "")),
            "fail_closed_reason": str(entry.get("fail_closed_reason", "")),
        }
    missing = sorted(set(WORM_ERROR_CODES) - set(registry))
    if missing:
        raise WORMEvidenceManifestError("worm_error_registry_incomplete:" + ",".join(missing))
    return registry


def prepare_worm_manifest(
    proof_bundle: dict[str, Any],
    timestamp_anchor: dict[str, Any],
    rfc3161_request: dict[str, Any],
    *,
    retention_policy_label: str,
    created_at: str | None = None,
    artifact_type: str = "governance_policy_proof_bundle",
) -> dict[str, Any]:
    if not retention_policy_label:
        raise WORMEvidenceManifestError("WORM_RETENTION_POLICY_MISSING")
    proof_verification = verify_policy_proof_bundle(proof_bundle)
    if not proof_verification.valid:
        raise WORMEvidenceManifestError("WORM_PROOF_BUNDLE_HASH_MISSING")
    anchor_verification = verify_proof_timestamp_anchor(timestamp_anchor, proof_bundle=proof_bundle)
    if not anchor_verification.valid:
        raise WORMEvidenceManifestError("WORM_TIMESTAMP_ANCHOR_MISSING")
    rfc3161_verification = verify_rfc3161_request_material(rfc3161_request)
    if not rfc3161_verification.valid:
        raise WORMEvidenceManifestError("WORM_RFC3161_DIGEST_MISSING")
    if rfc3161_verification.proof_bundle_hash != proof_verification.bundle_hash:
        raise WORMEvidenceManifestError("WORM_MANIFEST_INVALID")
    if rfc3161_verification.timestamp_anchor_hash != anchor_verification.anchor_hash:
        raise WORMEvidenceManifestError("WORM_MANIFEST_INVALID")
    created_at_value = created_at or _utc_now()
    if not _timestamp_is_valid(created_at_value):
        raise WORMEvidenceManifestError("WORM_MANIFEST_INVALID")
    entry = _manifest_entry(
        proof_bundle_hash=proof_verification.bundle_hash,
        timestamp_anchor_hash=anchor_verification.anchor_hash,
        rfc3161_request_digest=rfc3161_verification.canonical_request_digest,
        retention_policy_label=retention_policy_label,
        artifact_type=artifact_type,
        created_at=created_at_value,
        validation_status="VERIFIED",
    )
    manifest = {
        "schema": WORM_MANIFEST_SCHEMA,
        "entries": [entry],
        "governance_module_versions": dict(MODULE_VERSIONS),
        "validation_status": "VERIFIED",
        "manifest_hash": _sha256_hex(_canonical_json({"entries": [entry], "schema": WORM_MANIFEST_SCHEMA}).encode("utf-8")),
    }
    _assert_worm_safe(manifest)
    return manifest


def prepare_worm_manifest_file(
    proof_bundle_path: Path,
    timestamp_anchor_path: Path,
    rfc3161_request_path: Path,
    output_path: Path,
    *,
    retention_policy_label: str,
    created_at: str | None = None,
    artifact_type: str = "governance_policy_proof_bundle",
) -> dict[str, Any]:
    manifest = prepare_worm_manifest(
        _load_json_object(proof_bundle_path, "worm_proof_bundle_invalid"),
        _load_json_object(timestamp_anchor_path, "worm_timestamp_anchor_invalid"),
        _load_json_object(rfc3161_request_path, "worm_rfc3161_request_invalid"),
        retention_policy_label=retention_policy_label,
        created_at=created_at,
        artifact_type=artifact_type,
    )
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(_canonical_json(manifest) + "\n", encoding="utf-8")
    return manifest


def verify_worm_manifest(
    manifest: dict[str, Any],
    *,
    proof_bundle: dict[str, Any] | None = None,
    timestamp_anchor: dict[str, Any] | None = None,
    rfc3161_request: dict[str, Any] | None = None,
) -> WORMManifestVerificationResult:
    errors: list[str] = []
    if not isinstance(manifest, dict) or manifest.get("schema") != WORM_MANIFEST_SCHEMA:
        errors.append("WORM_MANIFEST_INVALID")
    entries = manifest.get("entries") if isinstance(manifest, dict) else None
    entry = entries[0] if isinstance(entries, list) and len(entries) == 1 and isinstance(entries[0], dict) else {}
    if not entry:
        errors.append("WORM_MANIFEST_INVALID")
    proof_bundle_hash = str(entry.get("proof_bundle_hash", ""))
    timestamp_anchor_hash = str(entry.get("timestamp_anchor_hash", ""))
    rfc3161_request_digest = str(entry.get("rfc3161_request_digest", ""))
    retention_policy_label = str(entry.get("retention_policy_label", ""))
    validation_status = str(entry.get("validation_status", ""))
    manifest_hash = str(manifest.get("manifest_hash", "")) if isinstance(manifest, dict) else ""
    if not _is_sha256_hex(proof_bundle_hash):
        errors.append("WORM_PROOF_BUNDLE_HASH_MISSING")
    if not _is_sha256_hex(timestamp_anchor_hash):
        errors.append("WORM_TIMESTAMP_ANCHOR_MISSING")
    if not _is_sha256_hex(rfc3161_request_digest):
        errors.append("WORM_RFC3161_DIGEST_MISSING")
    if not retention_policy_label:
        errors.append("WORM_RETENTION_POLICY_MISSING")
    if validation_status != "VERIFIED":
        errors.append("WORM_MANIFEST_INVALID")
    if entry and (not _timestamp_is_valid(str(entry.get("created_at", ""))) or not str(entry.get("artifact_type", ""))):
        errors.append("WORM_MANIFEST_INVALID")
    expected_hash = _sha256_hex(_canonical_json({"entries": entries, "schema": WORM_MANIFEST_SCHEMA}).encode("utf-8")) if entry else ""
    if not _is_sha256_hex(manifest_hash) or manifest_hash != expected_hash:
        errors.append("WORM_MANIFEST_INVALID")
    if proof_bundle is not None:
        proof_verification = verify_policy_proof_bundle(proof_bundle)
        if not proof_verification.valid or proof_verification.bundle_hash != proof_bundle_hash:
            errors.append("WORM_MANIFEST_INVALID")
    if timestamp_anchor is not None:
        anchor_verification = verify_proof_timestamp_anchor(timestamp_anchor, proof_bundle=proof_bundle)
        if not anchor_verification.valid or anchor_verification.anchor_hash != timestamp_anchor_hash:
            errors.append("WORM_MANIFEST_INVALID")
    if rfc3161_request is not None:
        rfc3161_verification = verify_rfc3161_request_material(rfc3161_request)
        if not rfc3161_verification.valid or rfc3161_verification.canonical_request_digest != rfc3161_request_digest:
            errors.append("WORM_MANIFEST_INVALID")
    try:
        _assert_worm_safe(manifest)
    except WORMEvidenceManifestError:
        errors.append("WORM_DIAGNOSTICS_UNSAFE")
    return WORMManifestVerificationResult(
        valid=not errors,
        errors=tuple(dict.fromkeys(errors)),
        proof_bundle_hash=proof_bundle_hash,
        timestamp_anchor_hash=timestamp_anchor_hash,
        rfc3161_request_digest=rfc3161_request_digest,
        manifest_hash=manifest_hash,
        retention_policy_label=retention_policy_label,
        validation_status=validation_status,
    )


def verify_worm_manifest_file(
    manifest_path: Path,
    *,
    proof_bundle_path: Path | None = None,
    timestamp_anchor_path: Path | None = None,
    rfc3161_request_path: Path | None = None,
) -> WORMManifestVerificationResult:
    proof_bundle = _load_json_object(proof_bundle_path, "worm_proof_bundle_invalid") if proof_bundle_path else None
    timestamp_anchor = _load_json_object(timestamp_anchor_path, "worm_timestamp_anchor_invalid") if timestamp_anchor_path else None
    rfc3161_request = _load_json_object(rfc3161_request_path, "worm_rfc3161_request_invalid") if rfc3161_request_path else None
    return verify_worm_manifest(
        _load_json_object(manifest_path, "worm_manifest_invalid"),
        proof_bundle=proof_bundle,
        timestamp_anchor=timestamp_anchor,
        rfc3161_request=rfc3161_request,
    )


def explain_worm_manifest(root: Path, code: str) -> dict[str, str]:
    registry = load_worm_error_registry(root)
    if code not in registry:
        raise WORMEvidenceManifestError("worm_error_unknown:" + code)
    return {"code": code, **registry[code]}


def worm_manifest_summary(manifest: dict[str, Any]) -> dict[str, Any]:
    verification = verify_worm_manifest(manifest)
    return {
        "valid": verification.valid,
        "error_codes": list(verification.errors),
        "proof_bundle_hash": verification.proof_bundle_hash,
        "timestamp_anchor_hash": verification.timestamp_anchor_hash,
        "rfc3161_request_digest": verification.rfc3161_request_digest,
        "manifest_hash": verification.manifest_hash,
        "retention_policy_label": verification.retention_policy_label,
        "validation_status": verification.validation_status,
    }


def redacted_worm_payload(payload: Any) -> Any:
    return redacted_policy_payload(payload)


def assert_worm_safe(payload: Any) -> None:
    assert_cached_validation_safe(WORM_MANIFEST_SCHEMA, payload, _assert_worm_safe)


def _manifest_entry(
    *,
    proof_bundle_hash: str,
    timestamp_anchor_hash: str,
    rfc3161_request_digest: str,
    retention_policy_label: str,
    artifact_type: str,
    created_at: str,
    validation_status: str,
) -> dict[str, Any]:
    return {
        "artifact_type": artifact_type,
        "created_at": created_at,
        "governance_module_versions": dict(MODULE_VERSIONS),
        "proof_bundle_hash": proof_bundle_hash,
        "retention_policy_label": retention_policy_label,
        "rfc3161_request_digest": rfc3161_request_digest,
        "timestamp_anchor_hash": timestamp_anchor_hash,
        "validation_status": validation_status,
    }


def _assert_worm_safe(payload: Any) -> None:
    try:
        redacted = redacted_policy_payload(payload)
        assert_policy_diagnostics_safe(redacted)
        assert_simulation_diagnostics_safe(redacted)
        assert_parity_diagnostics_safe(redacted)
        assert_proof_bundle_safe(redacted)
        assert_timestamp_anchor_safe(redacted)
        assert_rfc3161_safe(redacted)
        if redacted != payload:
            raise WORMEvidenceManifestError("WORM_DIAGNOSTICS_UNSAFE")
    except Exception as exc:
        if isinstance(exc, WORMEvidenceManifestError):
            raise
        raise WORMEvidenceManifestError("WORM_DIAGNOSTICS_UNSAFE") from exc


def _load_json_object(path: Path | None, failure_code: str) -> dict[str, Any]:
    if path is None:
        raise WORMEvidenceManifestError(failure_code)
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        raise WORMEvidenceManifestError(failure_code) from exc
    if not isinstance(payload, dict):
        raise WORMEvidenceManifestError(failure_code)
    return payload


def _canonical_json(payload: Any) -> str:
    try:
        return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    except (TypeError, ValueError) as exc:
        raise WORMEvidenceManifestError("WORM_MANIFEST_INVALID") from exc


def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _is_sha256_hex(value: str) -> bool:
    return len(value) == 64 and all(character in "0123456789abcdef" for character in value)


def _timestamp_is_valid(value: str) -> bool:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return False
    return value.endswith("Z") and parsed.tzinfo is not None and parsed.utcoffset() == timezone.utc.utcoffset(parsed)


def _utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
