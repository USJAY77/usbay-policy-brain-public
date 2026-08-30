from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from governance.policy_pack import redacted_policy_payload
from governance.signed_bundle_ltv import assert_signed_bundle_ltv_safe, verify_signed_bundle_ltv_evidence
from governance.signed_bundle_revocation_preflight import (
    MODULE_VERSIONS as REVOCATION_PREFLIGHT_MODULE_VERSIONS,
    assert_revocation_preflight_safe,
    verify_revocation_preflight,
)

REVOCATION_RESPONSE_SCHEMA = "usbay.governance_signed_bundle_revocation_response.v1"
REVOCATION_RESPONSE_ERROR_REGISTRY_PATH = Path("governance/signed_bundle_revocation_response_errors.json")
REVOCATION_RESPONSE_ERROR_SCHEMA = "usbay.governance_signed_bundle_revocation_response_error_registry.v1"
REVOCATION_RESPONSE_ERROR_CODES = (
    "REVOCATION_RESPONSE_PREFLIGHT_MISSING",
    "REVOCATION_RESPONSE_LTV_MISSING",
    "REVOCATION_RESPONSE_SOURCE_MISMATCH",
    "REVOCATION_RESPONSE_STATUS_UNKNOWN",
    "REVOCATION_RESPONSE_STATUS_REVOKED",
    "REVOCATION_RESPONSE_STALE",
    "REVOCATION_RESPONSE_TIME_INVALID",
    "REVOCATION_RESPONSE_SIGNATURE_INVALID",
    "REVOCATION_RESPONSE_NONCE_MISMATCH",
    "REVOCATION_RESPONSE_HASH_MISMATCH",
    "REVOCATION_RESPONSE_REPLAY_DETECTED",
    "REVOCATION_RESPONSE_DIAGNOSTICS_UNSAFE",
)
ALLOWED_SOURCE_TYPES = {"OCSP", "CRL"}
ALLOWED_RESPONSE_STATUSES = {"GOOD", "REVOKED", "UNKNOWN"}
MODULE_VERSIONS = {
    **REVOCATION_PREFLIGHT_MODULE_VERSIONS,
    "signed_bundle_revocation_response": REVOCATION_RESPONSE_SCHEMA,
}


class SignedBundleRevocationResponseError(RuntimeError):
    pass


@dataclass(frozen=True)
class RevocationResponseVerificationResult:
    valid: bool
    errors: tuple[str, ...]
    revocation_response_id: str
    preflight_id: str
    ltv_evidence_id: str
    timestamp_attachment_id: str
    revocation_source_type: str
    response_status: str
    responder_key_fingerprint: str
    response_signature_fingerprint: str
    retention_policy_label: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "valid": self.valid,
            "errors": list(self.errors),
            "revocation_response_id": self.revocation_response_id,
            "preflight_id": self.preflight_id,
            "ltv_evidence_id": self.ltv_evidence_id,
            "timestamp_attachment_id": self.timestamp_attachment_id,
            "revocation_source_type": self.revocation_source_type,
            "response_status": self.response_status,
            "responder_key_fingerprint": self.responder_key_fingerprint,
            "response_signature_fingerprint": self.response_signature_fingerprint,
            "retention_policy_label": self.retention_policy_label,
        }


def load_revocation_response_error_registry(root: Path) -> dict[str, dict[str, str]]:
    path = root / REVOCATION_RESPONSE_ERROR_REGISTRY_PATH
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        raise SignedBundleRevocationResponseError("revocation_response_error_registry_missing") from exc
    if not isinstance(payload, dict) or payload.get("schema") != REVOCATION_RESPONSE_ERROR_SCHEMA:
        raise SignedBundleRevocationResponseError("revocation_response_error_registry_invalid")
    raw_errors = payload.get("errors")
    if not isinstance(raw_errors, list):
        raise SignedBundleRevocationResponseError("revocation_response_error_registry_invalid")
    registry: dict[str, dict[str, str]] = {}
    for entry in raw_errors:
        if not isinstance(entry, dict) or not entry.get("code"):
            raise SignedBundleRevocationResponseError("revocation_response_error_registry_invalid")
        registry[str(entry["code"])] = {
            "description": str(entry.get("description", "")),
            "fail_closed_reason": str(entry.get("fail_closed_reason", "")),
        }
    missing = sorted(set(REVOCATION_RESPONSE_ERROR_CODES) - set(registry))
    if missing:
        raise SignedBundleRevocationResponseError("revocation_response_error_registry_incomplete:" + ",".join(missing))
    return registry


def create_revocation_response(
    preflight: dict[str, Any],
    *,
    response_status: str,
    response_this_update_utc: str,
    response_next_update_utc: str,
    responder_key_fingerprint: str,
    checked_at_utc: str | None = None,
    validation_policy_id: str,
) -> dict[str, Any]:
    preflight_verification = verify_revocation_preflight(preflight)
    if not preflight_verification.valid:
        raise SignedBundleRevocationResponseError("REVOCATION_RESPONSE_PREFLIGHT_MISSING")
    status = _normalize_response_status(response_status)
    if status == "REVOKED":
        raise SignedBundleRevocationResponseError("REVOCATION_RESPONSE_STATUS_REVOKED")
    if status != "GOOD":
        raise SignedBundleRevocationResponseError("REVOCATION_RESPONSE_STATUS_UNKNOWN")
    checked_at = checked_at_utc or _utc_now()
    if not _response_times_valid(response_this_update_utc, response_next_update_utc, checked_at):
        raise SignedBundleRevocationResponseError("REVOCATION_RESPONSE_TIME_INVALID")
    if _response_is_stale(response_this_update_utc, response_next_update_utc, checked_at, preflight.get("expected_freshness_window_seconds")):
        raise SignedBundleRevocationResponseError("REVOCATION_RESPONSE_STALE")
    if not _fingerprint_valid(responder_key_fingerprint):
        raise SignedBundleRevocationResponseError("REVOCATION_RESPONSE_SIGNATURE_INVALID")
    if validation_policy_id != str(preflight.get("validation_policy_id", "")):
        raise SignedBundleRevocationResponseError("REVOCATION_RESPONSE_HASH_MISMATCH")
    nonce_hash = expected_response_nonce_hash(preflight)
    signature_fingerprint = expected_response_signature_fingerprint(
        preflight_id=preflight_verification.preflight_id,
        response_status=status,
        response_this_update_utc=response_this_update_utc,
        response_next_update_utc=response_next_update_utc,
        responder_key_fingerprint=responder_key_fingerprint,
        response_nonce_hash=nonce_hash,
        validation_policy_id=validation_policy_id,
    )
    payload = {
        "checked_at_utc": checked_at,
        "governance_module_versions": dict(MODULE_VERSIONS),
        "ltv_evidence_id": preflight_verification.ltv_evidence_id,
        "preflight_id": preflight_verification.preflight_id,
        "responder_key_fingerprint": responder_key_fingerprint,
        "response_next_update_utc": response_next_update_utc,
        "response_nonce_hash": nonce_hash,
        "response_signature_fingerprint": signature_fingerprint,
        "response_status": status,
        "response_this_update_utc": response_this_update_utc,
        "retention_policy_label": preflight_verification.retention_policy_label,
        "revocation_source_type": preflight_verification.revocation_source_type,
        "revocation_source_uri_hash": preflight_verification.revocation_source_uri_hash,
        "timestamp_attachment_id": preflight_verification.timestamp_attachment_id,
        "trust_anchor_fingerprint": preflight_verification.trust_anchor_fingerprint,
        "tsa_certificate_fingerprint": preflight_verification.tsa_certificate_fingerprint,
        "validation_policy_id": validation_policy_id,
    }
    response = {
        "schema": REVOCATION_RESPONSE_SCHEMA,
        "revocation_response_id": _sha256_hex(_canonical_json(payload).encode("utf-8")),
        **payload,
    }
    _assert_response_safe(response)
    return response


def create_revocation_response_file(
    preflight_path: Path,
    output_path: Path,
    *,
    response_status: str,
    response_this_update_utc: str,
    response_next_update_utc: str,
    responder_key_fingerprint: str,
    checked_at_utc: str | None = None,
    validation_policy_id: str,
) -> dict[str, Any]:
    response = create_revocation_response(
        _load_json_object(preflight_path, "REVOCATION_RESPONSE_PREFLIGHT_MISSING"),
        response_status=response_status,
        response_this_update_utc=response_this_update_utc,
        response_next_update_utc=response_next_update_utc,
        responder_key_fingerprint=responder_key_fingerprint,
        checked_at_utc=checked_at_utc,
        validation_policy_id=validation_policy_id,
    )
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(_canonical_json(response) + "\n", encoding="utf-8")
    return response


def verify_revocation_response(
    response: dict[str, Any],
    *,
    preflight: dict[str, Any] | None = None,
    ltv_evidence: dict[str, Any] | None = None,
    existing_responses: list[dict[str, Any]] | None = None,
) -> RevocationResponseVerificationResult:
    errors: list[str] = []
    if not isinstance(response, dict) or response.get("schema") != REVOCATION_RESPONSE_SCHEMA:
        errors.append("REVOCATION_RESPONSE_PREFLIGHT_MISSING")
    response_id = str(response.get("revocation_response_id", "")) if isinstance(response, dict) else ""
    preflight_id = str(response.get("preflight_id", "")) if isinstance(response, dict) else ""
    ltv_evidence_id = str(response.get("ltv_evidence_id", "")) if isinstance(response, dict) else ""
    timestamp_attachment_id = str(response.get("timestamp_attachment_id", "")) if isinstance(response, dict) else ""
    tsa_certificate_fingerprint = str(response.get("tsa_certificate_fingerprint", "")) if isinstance(response, dict) else ""
    trust_anchor_fingerprint = str(response.get("trust_anchor_fingerprint", "")) if isinstance(response, dict) else ""
    source_type = str(response.get("revocation_source_type", "")) if isinstance(response, dict) else ""
    source_hash = str(response.get("revocation_source_uri_hash", "")) if isinstance(response, dict) else ""
    status = _normalize_response_status(str(response.get("response_status", "")) if isinstance(response, dict) else "")
    this_update = str(response.get("response_this_update_utc", "")) if isinstance(response, dict) else ""
    next_update = str(response.get("response_next_update_utc", "")) if isinstance(response, dict) else ""
    responder_key = str(response.get("responder_key_fingerprint", "")) if isinstance(response, dict) else ""
    signature = str(response.get("response_signature_fingerprint", "")) if isinstance(response, dict) else ""
    nonce_hash = str(response.get("response_nonce_hash", "")) if isinstance(response, dict) else ""
    checked_at = str(response.get("checked_at_utc", "")) if isinstance(response, dict) else ""
    validation_policy_id = str(response.get("validation_policy_id", "")) if isinstance(response, dict) else ""
    retention_policy_label = str(response.get("retention_policy_label", "")) if isinstance(response, dict) else ""
    if not _fingerprint_valid(preflight_id):
        errors.append("REVOCATION_RESPONSE_PREFLIGHT_MISSING")
    if not _fingerprint_valid(ltv_evidence_id) or not _fingerprint_valid(timestamp_attachment_id):
        errors.append("REVOCATION_RESPONSE_LTV_MISSING")
    if source_type not in ALLOWED_SOURCE_TYPES or not _fingerprint_valid(source_hash):
        errors.append("REVOCATION_RESPONSE_SOURCE_MISMATCH")
    if status == "REVOKED":
        errors.append("REVOCATION_RESPONSE_STATUS_REVOKED")
    elif status != "GOOD":
        errors.append("REVOCATION_RESPONSE_STATUS_UNKNOWN")
    if not _response_times_valid(this_update, next_update, checked_at):
        errors.append("REVOCATION_RESPONSE_TIME_INVALID")
    if _fingerprint_valid(preflight_id) and nonce_hash != expected_response_nonce_hash(response):
        errors.append("REVOCATION_RESPONSE_NONCE_MISMATCH")
    if not _fingerprint_valid(responder_key) or signature != expected_response_signature_fingerprint(
        preflight_id=preflight_id,
        response_status=status,
        response_this_update_utc=this_update,
        response_next_update_utc=next_update,
        responder_key_fingerprint=responder_key,
        response_nonce_hash=nonce_hash,
        validation_policy_id=validation_policy_id,
    ):
        errors.append("REVOCATION_RESPONSE_SIGNATURE_INVALID")
    payload = _response_payload(response)
    if not _fingerprint_valid(response_id) or response_id != _sha256_hex(_canonical_json(payload).encode("utf-8")):
        errors.append("REVOCATION_RESPONSE_HASH_MISMATCH")
    if preflight is not None:
        preflight_verification = verify_revocation_preflight(preflight)
        if (
            not preflight_verification.valid
            or preflight_verification.preflight_id != preflight_id
            or preflight_verification.ltv_evidence_id != ltv_evidence_id
            or preflight_verification.timestamp_attachment_id != timestamp_attachment_id
            or preflight_verification.tsa_certificate_fingerprint != tsa_certificate_fingerprint
            or preflight_verification.trust_anchor_fingerprint != trust_anchor_fingerprint
            or preflight_verification.revocation_source_type != source_type
            or preflight_verification.revocation_source_uri_hash != source_hash
            or preflight_verification.retention_policy_label != retention_policy_label
            or str(preflight.get("validation_policy_id", "")) != validation_policy_id
        ):
            errors.append("REVOCATION_RESPONSE_SOURCE_MISMATCH")
        if preflight_verification.valid and _response_is_stale(this_update, next_update, checked_at, preflight.get("expected_freshness_window_seconds")):
            errors.append("REVOCATION_RESPONSE_STALE")
    if ltv_evidence is not None:
        ltv_verification = verify_signed_bundle_ltv_evidence(ltv_evidence)
        if (
            not ltv_verification.valid
            or ltv_verification.ltv_evidence_id != ltv_evidence_id
            or ltv_verification.timestamp_attachment_id != timestamp_attachment_id
            or ltv_verification.trust_anchor_fingerprint != trust_anchor_fingerprint
            or str(ltv_evidence.get("tsa_certificate_fingerprint", "")) != tsa_certificate_fingerprint
            or str(ltv_evidence.get("validation_policy_id", "")) != validation_policy_id
        ):
            errors.append("REVOCATION_RESPONSE_LTV_MISSING")
    for existing in existing_responses or []:
        if isinstance(existing, dict) and existing.get("revocation_response_id") == response_id:
            errors.append("REVOCATION_RESPONSE_REPLAY_DETECTED")
    try:
        _assert_response_safe(response)
    except SignedBundleRevocationResponseError:
        errors.append("REVOCATION_RESPONSE_DIAGNOSTICS_UNSAFE")
    return RevocationResponseVerificationResult(
        valid=not errors,
        errors=tuple(dict.fromkeys(errors)),
        revocation_response_id=response_id,
        preflight_id=preflight_id,
        ltv_evidence_id=ltv_evidence_id,
        timestamp_attachment_id=timestamp_attachment_id,
        revocation_source_type=source_type,
        response_status=status,
        responder_key_fingerprint=responder_key,
        response_signature_fingerprint=signature,
        retention_policy_label=retention_policy_label,
    )


def verify_revocation_response_file(
    response_path: Path,
    *,
    preflight_path: Path | None = None,
    ltv_evidence_path: Path | None = None,
    existing_response_paths: list[Path] | None = None,
) -> RevocationResponseVerificationResult:
    preflight = _load_json_object(preflight_path, "REVOCATION_RESPONSE_PREFLIGHT_MISSING") if preflight_path else None
    ltv_evidence = _load_json_object(ltv_evidence_path, "REVOCATION_RESPONSE_LTV_MISSING") if ltv_evidence_path else None
    existing = [_load_json_object(path, "revocation_response_existing_invalid") for path in existing_response_paths or []]
    return verify_revocation_response(
        _load_json_object(response_path, "revocation_response_invalid"),
        preflight=preflight,
        ltv_evidence=ltv_evidence,
        existing_responses=existing,
    )


def explain_revocation_response_failure(root: Path, code: str) -> dict[str, str]:
    registry = load_revocation_response_error_registry(root)
    if code not in registry:
        raise SignedBundleRevocationResponseError("revocation_response_error_unknown:" + code)
    return {"code": code, **registry[code]}


def revocation_response_summary(response: dict[str, Any]) -> dict[str, Any]:
    return verify_revocation_response(response).to_dict()


def redacted_revocation_response_payload(payload: Any) -> Any:
    return redacted_policy_payload(payload)


def assert_revocation_response_safe(payload: Any) -> None:
    _assert_response_safe(payload)


def expected_response_nonce_hash(preflight_like: dict[str, Any]) -> str:
    payload = {
        "ltv_evidence_id": preflight_like.get("ltv_evidence_id", ""),
        "preflight_id": preflight_like.get("preflight_id", ""),
        "revocation_source_uri_hash": preflight_like.get("revocation_source_uri_hash", ""),
    }
    return _sha256_hex(_canonical_json(payload).encode("utf-8"))


def expected_response_signature_fingerprint(
    *,
    preflight_id: str,
    response_status: str,
    response_this_update_utc: str,
    response_next_update_utc: str,
    responder_key_fingerprint: str,
    response_nonce_hash: str,
    validation_policy_id: str,
) -> str:
    payload = {
        "preflight_id": preflight_id,
        "responder_key_fingerprint": responder_key_fingerprint,
        "response_next_update_utc": response_next_update_utc,
        "response_nonce_hash": response_nonce_hash,
        "response_status": _normalize_response_status(response_status),
        "response_this_update_utc": response_this_update_utc,
        "validation_policy_id": validation_policy_id,
    }
    return _sha256_hex(_canonical_json(payload).encode("utf-8"))


def _response_payload(response: dict[str, Any]) -> dict[str, Any]:
    return {
        "checked_at_utc": response.get("checked_at_utc", ""),
        "governance_module_versions": response.get("governance_module_versions", {}),
        "ltv_evidence_id": response.get("ltv_evidence_id", ""),
        "preflight_id": response.get("preflight_id", ""),
        "responder_key_fingerprint": response.get("responder_key_fingerprint", ""),
        "response_next_update_utc": response.get("response_next_update_utc", ""),
        "response_nonce_hash": response.get("response_nonce_hash", ""),
        "response_signature_fingerprint": response.get("response_signature_fingerprint", ""),
        "response_status": _normalize_response_status(str(response.get("response_status", ""))),
        "response_this_update_utc": response.get("response_this_update_utc", ""),
        "retention_policy_label": response.get("retention_policy_label", ""),
        "revocation_source_type": response.get("revocation_source_type", ""),
        "revocation_source_uri_hash": response.get("revocation_source_uri_hash", ""),
        "timestamp_attachment_id": response.get("timestamp_attachment_id", ""),
        "trust_anchor_fingerprint": response.get("trust_anchor_fingerprint", ""),
        "tsa_certificate_fingerprint": response.get("tsa_certificate_fingerprint", ""),
        "validation_policy_id": response.get("validation_policy_id", ""),
    }


def _normalize_response_status(value: str) -> str:
    return value.strip().upper()


def _fingerprint_valid(value: str) -> bool:
    return len(value) == 64 and all(character in "0123456789abcdef" for character in value)


def _response_times_valid(this_update: str, next_update: str, checked_at: str) -> bool:
    parsed_this = _parse_utc(this_update)
    parsed_next = _parse_utc(next_update)
    parsed_checked = _parse_utc(checked_at)
    if parsed_this is None or parsed_next is None or parsed_checked is None:
        return False
    return parsed_this < parsed_next and parsed_this <= parsed_checked


def _response_is_stale(this_update: str, next_update: str, checked_at: str, freshness_window: Any) -> bool:
    parsed_this = _parse_utc(this_update)
    parsed_next = _parse_utc(next_update)
    parsed_checked = _parse_utc(checked_at)
    if parsed_this is None or parsed_next is None or parsed_checked is None or not isinstance(freshness_window, int) or freshness_window <= 0:
        return True
    return parsed_checked > parsed_next or (parsed_checked - parsed_this).total_seconds() > freshness_window


def _parse_utc(value: str) -> datetime | None:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if not value.endswith("Z") or parsed.tzinfo is None or parsed.utcoffset() != timezone.utc.utcoffset(parsed):
        return None
    return parsed


def _assert_response_safe(payload: Any) -> None:
    try:
        redacted = redacted_policy_payload(payload)
        assert_signed_bundle_ltv_safe(redacted)
        assert_revocation_preflight_safe(redacted)
        if redacted != payload:
            raise SignedBundleRevocationResponseError("REVOCATION_RESPONSE_DIAGNOSTICS_UNSAFE")
    except Exception as exc:
        if isinstance(exc, SignedBundleRevocationResponseError):
            raise
        raise SignedBundleRevocationResponseError("REVOCATION_RESPONSE_DIAGNOSTICS_UNSAFE") from exc


def _load_json_object(path: Path | None, failure_code: str) -> dict[str, Any]:
    if path is None:
        raise SignedBundleRevocationResponseError(failure_code)
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        raise SignedBundleRevocationResponseError(failure_code) from exc
    if not isinstance(payload, dict):
        raise SignedBundleRevocationResponseError(failure_code)
    return payload


def _canonical_json(payload: Any) -> str:
    try:
        return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    except (TypeError, ValueError) as exc:
        raise SignedBundleRevocationResponseError("REVOCATION_RESPONSE_HASH_MISMATCH") from exc


def _utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()
