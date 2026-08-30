from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from governance.policy_pack import redacted_policy_payload
from governance.signed_bundle_ltv import (
    MODULE_VERSIONS as SIGNED_BUNDLE_LTV_MODULE_VERSIONS,
    assert_signed_bundle_ltv_safe,
    verify_signed_bundle_ltv_evidence,
)

REVOCATION_PREFLIGHT_SCHEMA = "usbay.governance_signed_bundle_revocation_preflight.v1"
REVOCATION_PREFLIGHT_ERROR_REGISTRY_PATH = Path("governance/signed_bundle_revocation_preflight_errors.json")
REVOCATION_PREFLIGHT_ERROR_SCHEMA = "usbay.governance_signed_bundle_revocation_preflight_error_registry.v1"
REVOCATION_PREFLIGHT_ERROR_CODES = (
    "REVOCATION_PREFLIGHT_LTV_MISSING",
    "REVOCATION_PREFLIGHT_CERT_MISSING",
    "REVOCATION_PREFLIGHT_SOURCE_MISSING",
    "REVOCATION_PREFLIGHT_SOURCE_INVALID",
    "REVOCATION_PREFLIGHT_FRESHNESS_INVALID",
    "REVOCATION_PREFLIGHT_HASH_MISMATCH",
    "REVOCATION_PREFLIGHT_REPLAY_DETECTED",
    "REVOCATION_PREFLIGHT_DIAGNOSTICS_UNSAFE",
)
ALLOWED_REVOCATION_SOURCE_TYPES = {"OCSP", "CRL"}
MAX_FRESHNESS_WINDOW_SECONDS = 31_536_000
MODULE_VERSIONS = {
    **SIGNED_BUNDLE_LTV_MODULE_VERSIONS,
    "signed_bundle_revocation_preflight": REVOCATION_PREFLIGHT_SCHEMA,
}


class SignedBundleRevocationPreflightError(RuntimeError):
    pass


@dataclass(frozen=True)
class RevocationPreflightVerificationResult:
    valid: bool
    errors: tuple[str, ...]
    preflight_id: str
    ltv_evidence_id: str
    timestamp_attachment_id: str
    tsa_certificate_fingerprint: str
    trust_anchor_fingerprint: str
    revocation_source_type: str
    revocation_source_uri_hash: str
    retention_policy_label: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "valid": self.valid,
            "errors": list(self.errors),
            "preflight_id": self.preflight_id,
            "ltv_evidence_id": self.ltv_evidence_id,
            "timestamp_attachment_id": self.timestamp_attachment_id,
            "tsa_certificate_fingerprint": self.tsa_certificate_fingerprint,
            "trust_anchor_fingerprint": self.trust_anchor_fingerprint,
            "revocation_source_type": self.revocation_source_type,
            "revocation_source_uri_hash": self.revocation_source_uri_hash,
            "retention_policy_label": self.retention_policy_label,
        }


def load_revocation_preflight_error_registry(root: Path) -> dict[str, dict[str, str]]:
    path = root / REVOCATION_PREFLIGHT_ERROR_REGISTRY_PATH
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        raise SignedBundleRevocationPreflightError("revocation_preflight_error_registry_missing") from exc
    if not isinstance(payload, dict) or payload.get("schema") != REVOCATION_PREFLIGHT_ERROR_SCHEMA:
        raise SignedBundleRevocationPreflightError("revocation_preflight_error_registry_invalid")
    raw_errors = payload.get("errors")
    if not isinstance(raw_errors, list):
        raise SignedBundleRevocationPreflightError("revocation_preflight_error_registry_invalid")
    registry: dict[str, dict[str, str]] = {}
    for entry in raw_errors:
        if not isinstance(entry, dict) or not entry.get("code"):
            raise SignedBundleRevocationPreflightError("revocation_preflight_error_registry_invalid")
        registry[str(entry["code"])] = {
            "description": str(entry.get("description", "")),
            "fail_closed_reason": str(entry.get("fail_closed_reason", "")),
        }
    missing = sorted(set(REVOCATION_PREFLIGHT_ERROR_CODES) - set(registry))
    if missing:
        raise SignedBundleRevocationPreflightError("revocation_preflight_error_registry_incomplete:" + ",".join(missing))
    return registry


def create_revocation_preflight(
    ltv_evidence: dict[str, Any],
    *,
    revocation_source_type: str,
    revocation_source_uri_hash: str,
    expected_freshness_window_seconds: int,
    checked_at_utc: str | None = None,
    validation_policy_id: str,
) -> dict[str, Any]:
    ltv_verification = verify_signed_bundle_ltv_evidence(ltv_evidence)
    if not ltv_verification.valid:
        raise SignedBundleRevocationPreflightError("REVOCATION_PREFLIGHT_LTV_MISSING")
    source_type = _normalize_source_type(revocation_source_type)
    if not source_type:
        raise SignedBundleRevocationPreflightError("REVOCATION_PREFLIGHT_SOURCE_MISSING")
    if source_type not in ALLOWED_REVOCATION_SOURCE_TYPES:
        raise SignedBundleRevocationPreflightError("REVOCATION_PREFLIGHT_SOURCE_INVALID")
    if not revocation_source_uri_hash:
        raise SignedBundleRevocationPreflightError("REVOCATION_PREFLIGHT_SOURCE_MISSING")
    if not _fingerprint_valid(revocation_source_uri_hash):
        raise SignedBundleRevocationPreflightError("REVOCATION_PREFLIGHT_SOURCE_INVALID")
    if not _freshness_valid(expected_freshness_window_seconds):
        raise SignedBundleRevocationPreflightError("REVOCATION_PREFLIGHT_FRESHNESS_INVALID")
    checked_at = checked_at_utc or _utc_now()
    if not _timestamp_is_valid(checked_at):
        raise SignedBundleRevocationPreflightError("REVOCATION_PREFLIGHT_FRESHNESS_INVALID")
    if validation_policy_id != str(ltv_evidence.get("validation_policy_id", "")):
        raise SignedBundleRevocationPreflightError("REVOCATION_PREFLIGHT_HASH_MISMATCH")
    payload = {
        "checked_at_utc": checked_at,
        "expected_freshness_window_seconds": expected_freshness_window_seconds,
        "governance_module_versions": dict(MODULE_VERSIONS),
        "ltv_evidence_id": ltv_verification.ltv_evidence_id,
        "retention_policy_label": ltv_verification.retention_policy_label,
        "revocation_source_type": source_type,
        "revocation_source_uri_hash": revocation_source_uri_hash,
        "timestamp_attachment_id": ltv_verification.timestamp_attachment_id,
        "trust_anchor_fingerprint": ltv_verification.trust_anchor_fingerprint,
        "tsa_certificate_fingerprint": str(ltv_evidence.get("tsa_certificate_fingerprint", "")),
        "validation_policy_id": validation_policy_id,
    }
    preflight = {
        "schema": REVOCATION_PREFLIGHT_SCHEMA,
        "preflight_id": _sha256_hex(_canonical_json(payload).encode("utf-8")),
        **payload,
    }
    _assert_preflight_safe(preflight)
    return preflight


def create_revocation_preflight_file(
    ltv_evidence_path: Path,
    output_path: Path,
    *,
    revocation_source_type: str,
    revocation_source_uri_hash: str,
    expected_freshness_window_seconds: int,
    checked_at_utc: str | None = None,
    validation_policy_id: str,
) -> dict[str, Any]:
    preflight = create_revocation_preflight(
        _load_json_object(ltv_evidence_path, "REVOCATION_PREFLIGHT_LTV_MISSING"),
        revocation_source_type=revocation_source_type,
        revocation_source_uri_hash=revocation_source_uri_hash,
        expected_freshness_window_seconds=expected_freshness_window_seconds,
        checked_at_utc=checked_at_utc,
        validation_policy_id=validation_policy_id,
    )
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(_canonical_json(preflight) + "\n", encoding="utf-8")
    return preflight


def verify_revocation_preflight(
    preflight: dict[str, Any],
    *,
    ltv_evidence: dict[str, Any] | None = None,
    existing_preflights: list[dict[str, Any]] | None = None,
) -> RevocationPreflightVerificationResult:
    errors: list[str] = []
    if not isinstance(preflight, dict) or preflight.get("schema") != REVOCATION_PREFLIGHT_SCHEMA:
        errors.append("REVOCATION_PREFLIGHT_LTV_MISSING")
    preflight_id = str(preflight.get("preflight_id", "")) if isinstance(preflight, dict) else ""
    ltv_evidence_id = str(preflight.get("ltv_evidence_id", "")) if isinstance(preflight, dict) else ""
    timestamp_attachment_id = str(preflight.get("timestamp_attachment_id", "")) if isinstance(preflight, dict) else ""
    tsa_certificate_fingerprint = str(preflight.get("tsa_certificate_fingerprint", "")) if isinstance(preflight, dict) else ""
    trust_anchor_fingerprint = str(preflight.get("trust_anchor_fingerprint", "")) if isinstance(preflight, dict) else ""
    source_type = _normalize_source_type(str(preflight.get("revocation_source_type", "")) if isinstance(preflight, dict) else "")
    source_hash = str(preflight.get("revocation_source_uri_hash", "")) if isinstance(preflight, dict) else ""
    freshness_window = preflight.get("expected_freshness_window_seconds") if isinstance(preflight, dict) else None
    checked_at = str(preflight.get("checked_at_utc", "")) if isinstance(preflight, dict) else ""
    validation_policy_id = str(preflight.get("validation_policy_id", "")) if isinstance(preflight, dict) else ""
    retention_policy_label = str(preflight.get("retention_policy_label", "")) if isinstance(preflight, dict) else ""
    if not _fingerprint_valid(ltv_evidence_id) or not _fingerprint_valid(timestamp_attachment_id):
        errors.append("REVOCATION_PREFLIGHT_LTV_MISSING")
    if not _fingerprint_valid(tsa_certificate_fingerprint) or not _fingerprint_valid(trust_anchor_fingerprint):
        errors.append("REVOCATION_PREFLIGHT_CERT_MISSING")
    if not source_type or not source_hash:
        errors.append("REVOCATION_PREFLIGHT_SOURCE_MISSING")
    elif source_type not in ALLOWED_REVOCATION_SOURCE_TYPES or not _fingerprint_valid(source_hash):
        errors.append("REVOCATION_PREFLIGHT_SOURCE_INVALID")
    if not _freshness_valid(freshness_window) or not _timestamp_is_valid(checked_at):
        errors.append("REVOCATION_PREFLIGHT_FRESHNESS_INVALID")
    payload = _preflight_payload(preflight)
    if not _fingerprint_valid(preflight_id) or preflight_id != _sha256_hex(_canonical_json(payload).encode("utf-8")):
        errors.append("REVOCATION_PREFLIGHT_HASH_MISMATCH")
    if ltv_evidence is not None:
        ltv_verification = verify_signed_bundle_ltv_evidence(ltv_evidence)
        if (
            not ltv_verification.valid
            or ltv_verification.ltv_evidence_id != ltv_evidence_id
            or ltv_verification.timestamp_attachment_id != timestamp_attachment_id
            or ltv_verification.trust_anchor_fingerprint != trust_anchor_fingerprint
            or ltv_verification.retention_policy_label != retention_policy_label
            or str(ltv_evidence.get("tsa_certificate_fingerprint", "")) != tsa_certificate_fingerprint
            or str(ltv_evidence.get("validation_policy_id", "")) != validation_policy_id
        ):
            errors.append("REVOCATION_PREFLIGHT_HASH_MISMATCH")
    for existing in existing_preflights or []:
        if isinstance(existing, dict) and existing.get("preflight_id") == preflight_id:
            errors.append("REVOCATION_PREFLIGHT_REPLAY_DETECTED")
    try:
        _assert_preflight_safe(preflight)
    except SignedBundleRevocationPreflightError:
        errors.append("REVOCATION_PREFLIGHT_DIAGNOSTICS_UNSAFE")
    return RevocationPreflightVerificationResult(
        valid=not errors,
        errors=tuple(dict.fromkeys(errors)),
        preflight_id=preflight_id,
        ltv_evidence_id=ltv_evidence_id,
        timestamp_attachment_id=timestamp_attachment_id,
        tsa_certificate_fingerprint=tsa_certificate_fingerprint,
        trust_anchor_fingerprint=trust_anchor_fingerprint,
        revocation_source_type=source_type,
        revocation_source_uri_hash=source_hash,
        retention_policy_label=retention_policy_label,
    )


def verify_revocation_preflight_file(
    preflight_path: Path,
    *,
    ltv_evidence_path: Path | None = None,
    existing_preflight_paths: list[Path] | None = None,
) -> RevocationPreflightVerificationResult:
    ltv_evidence = _load_json_object(ltv_evidence_path, "REVOCATION_PREFLIGHT_LTV_MISSING") if ltv_evidence_path else None
    existing = [_load_json_object(path, "revocation_preflight_existing_invalid") for path in existing_preflight_paths or []]
    return verify_revocation_preflight(
        _load_json_object(preflight_path, "revocation_preflight_invalid"),
        ltv_evidence=ltv_evidence,
        existing_preflights=existing,
    )


def explain_revocation_preflight_failure(root: Path, code: str) -> dict[str, str]:
    registry = load_revocation_preflight_error_registry(root)
    if code not in registry:
        raise SignedBundleRevocationPreflightError("revocation_preflight_error_unknown:" + code)
    return {"code": code, **registry[code]}


def revocation_preflight_summary(preflight: dict[str, Any]) -> dict[str, Any]:
    return verify_revocation_preflight(preflight).to_dict()


def redacted_revocation_preflight_payload(payload: Any) -> Any:
    return redacted_policy_payload(payload)


def assert_revocation_preflight_safe(payload: Any) -> None:
    _assert_preflight_safe(payload)


def _preflight_payload(preflight: dict[str, Any]) -> dict[str, Any]:
    return {
        "checked_at_utc": preflight.get("checked_at_utc", ""),
        "expected_freshness_window_seconds": preflight.get("expected_freshness_window_seconds", 0),
        "governance_module_versions": preflight.get("governance_module_versions", {}),
        "ltv_evidence_id": preflight.get("ltv_evidence_id", ""),
        "retention_policy_label": preflight.get("retention_policy_label", ""),
        "revocation_source_type": _normalize_source_type(str(preflight.get("revocation_source_type", ""))),
        "revocation_source_uri_hash": preflight.get("revocation_source_uri_hash", ""),
        "timestamp_attachment_id": preflight.get("timestamp_attachment_id", ""),
        "trust_anchor_fingerprint": preflight.get("trust_anchor_fingerprint", ""),
        "tsa_certificate_fingerprint": preflight.get("tsa_certificate_fingerprint", ""),
        "validation_policy_id": preflight.get("validation_policy_id", ""),
    }


def _normalize_source_type(value: str) -> str:
    return value.strip().upper()


def _freshness_valid(value: Any) -> bool:
    return isinstance(value, int) and 0 < value <= MAX_FRESHNESS_WINDOW_SECONDS


def _fingerprint_valid(value: str) -> bool:
    return len(value) == 64 and all(character in "0123456789abcdef" for character in value)


def _assert_preflight_safe(payload: Any) -> None:
    try:
        redacted = redacted_policy_payload(payload)
        assert_signed_bundle_ltv_safe(redacted)
        if redacted != payload:
            raise SignedBundleRevocationPreflightError("REVOCATION_PREFLIGHT_DIAGNOSTICS_UNSAFE")
    except Exception as exc:
        if isinstance(exc, SignedBundleRevocationPreflightError):
            raise
        raise SignedBundleRevocationPreflightError("REVOCATION_PREFLIGHT_DIAGNOSTICS_UNSAFE") from exc


def _load_json_object(path: Path | None, failure_code: str) -> dict[str, Any]:
    if path is None:
        raise SignedBundleRevocationPreflightError(failure_code)
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        raise SignedBundleRevocationPreflightError(failure_code) from exc
    if not isinstance(payload, dict):
        raise SignedBundleRevocationPreflightError(failure_code)
    return payload


def _canonical_json(payload: Any) -> str:
    try:
        return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    except (TypeError, ValueError) as exc:
        raise SignedBundleRevocationPreflightError("REVOCATION_PREFLIGHT_HASH_MISMATCH") from exc


def _utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _timestamp_is_valid(value: str) -> bool:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return False
    return value.endswith("Z") and parsed.tzinfo is not None and parsed.utcoffset() == timezone.utc.utcoffset(parsed)


def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()
