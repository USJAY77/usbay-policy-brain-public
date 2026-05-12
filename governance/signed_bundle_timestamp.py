from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from governance.auditor_verification_bundle import assert_auditor_bundle_safe
from governance.evidence_chain import assert_evidence_chain_safe
from governance.evidence_merkle_checkpoint import assert_merkle_safe
from governance.evidence_merkle_consistency import assert_consistency_safe
from governance.evidence_merkle_inclusion import assert_inclusion_safe
from governance.policy_pack import assert_policy_diagnostics_safe, redacted_policy_payload
from governance.policy_parity import assert_parity_diagnostics_safe
from governance.policy_proof_bundle import assert_proof_bundle_safe
from governance.policy_simulation import assert_simulation_diagnostics_safe
from governance.proof_timestamp_anchor import assert_timestamp_anchor_safe
from governance.rfc3161_timestamp import DEFAULT_POLICY_OID_PLACEHOLDER, assert_rfc3161_safe
from governance.signed_auditor_bundle import (
    MODULE_VERSIONS as SIGNED_BUNDLE_MODULE_VERSIONS,
    assert_signed_auditor_bundle_safe,
    verify_signed_auditor_bundle,
)
from governance.worm_evidence_manifest import assert_worm_safe

SIGNED_BUNDLE_TIMESTAMP_SCHEMA = "usbay.governance_signed_bundle_timestamp.v1"
SIGNED_BUNDLE_TIMESTAMP_ERROR_REGISTRY_PATH = Path("governance/signed_bundle_timestamp_errors.json")
SIGNED_BUNDLE_TIMESTAMP_ERROR_SCHEMA = "usbay.governance_signed_bundle_timestamp_error_registry.v1"
SIGNED_BUNDLE_TIMESTAMP_ERROR_CODES = (
    "SIGNED_BUNDLE_TIMESTAMP_MISSING",
    "SIGNED_BUNDLE_TIMESTAMP_HASH_MISMATCH",
    "SIGNED_BUNDLE_TIMESTAMP_TOKEN_INVALID",
    "SIGNED_BUNDLE_TIMESTAMP_POLICY_INVALID",
    "SIGNED_BUNDLE_TIMESTAMP_REPLAY_DETECTED",
    "SIGNED_BUNDLE_TIMESTAMP_SCOPE_INVALID",
    "SIGNED_BUNDLE_TIMESTAMP_DIAGNOSTICS_UNSAFE",
)
HASH_ALGORITHM = "SHA256"
MODULE_VERSIONS = {
    **SIGNED_BUNDLE_MODULE_VERSIONS,
    "signed_bundle_timestamp": SIGNED_BUNDLE_TIMESTAMP_SCHEMA,
}


class SignedBundleTimestampError(RuntimeError):
    pass


@dataclass(frozen=True)
class SignedBundleTimestampVerificationResult:
    valid: bool
    errors: tuple[str, ...]
    timestamp_attachment_id: str
    signed_bundle_id: str
    signed_bundle_hash: str
    message_imprint_hash: str
    timestamp_token_hash: str
    retention_policy_label: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "valid": self.valid,
            "errors": list(self.errors),
            "timestamp_attachment_id": self.timestamp_attachment_id,
            "signed_bundle_id": self.signed_bundle_id,
            "signed_bundle_hash": self.signed_bundle_hash,
            "message_imprint_hash": self.message_imprint_hash,
            "timestamp_token_hash": self.timestamp_token_hash,
            "retention_policy_label": self.retention_policy_label,
        }


def load_signed_bundle_timestamp_error_registry(root: Path) -> dict[str, dict[str, str]]:
    path = root / SIGNED_BUNDLE_TIMESTAMP_ERROR_REGISTRY_PATH
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        raise SignedBundleTimestampError("signed_bundle_timestamp_error_registry_missing") from exc
    if not isinstance(payload, dict) or payload.get("schema") != SIGNED_BUNDLE_TIMESTAMP_ERROR_SCHEMA:
        raise SignedBundleTimestampError("signed_bundle_timestamp_error_registry_invalid")
    raw_errors = payload.get("errors")
    if not isinstance(raw_errors, list):
        raise SignedBundleTimestampError("signed_bundle_timestamp_error_registry_invalid")
    registry: dict[str, dict[str, str]] = {}
    for entry in raw_errors:
        if not isinstance(entry, dict) or not entry.get("code"):
            raise SignedBundleTimestampError("signed_bundle_timestamp_error_registry_invalid")
        registry[str(entry["code"])] = {
            "description": str(entry.get("description", "")),
            "fail_closed_reason": str(entry.get("fail_closed_reason", "")),
        }
    missing = sorted(set(SIGNED_BUNDLE_TIMESTAMP_ERROR_CODES) - set(registry))
    if missing:
        raise SignedBundleTimestampError("signed_bundle_timestamp_error_registry_incomplete:" + ",".join(missing))
    return registry


def attach_signed_bundle_timestamp(
    signed_bundle: dict[str, Any],
    *,
    trust_policy: dict[str, Any],
    tsa_policy_id: str = DEFAULT_POLICY_OID_PLACEHOLDER,
    tsa_serial_number: str | None = None,
    tsa_gen_time_utc: str | None = None,
) -> dict[str, Any]:
    signed_verification = verify_signed_auditor_bundle(signed_bundle, trust_policy=trust_policy)
    if not signed_verification.valid:
        raise SignedBundleTimestampError("SIGNED_BUNDLE_TIMESTAMP_MISSING")
    timestamp = tsa_gen_time_utc or _utc_now()
    if not _timestamp_is_valid(timestamp):
        raise SignedBundleTimestampError("SIGNED_BUNDLE_TIMESTAMP_SCOPE_INVALID")
    if not _policy_id_valid(tsa_policy_id):
        raise SignedBundleTimestampError("SIGNED_BUNDLE_TIMESTAMP_POLICY_INVALID")
    signed_bundle_hash = _sha256_hex(_canonical_json(signed_bundle).encode("utf-8"))
    message_imprint_hash = _message_imprint(signed_bundle_hash)
    serial = tsa_serial_number or _deterministic_serial(signed_verification.signed_bundle_id, message_imprint_hash, tsa_policy_id, timestamp)
    if not _serial_valid(serial):
        raise SignedBundleTimestampError("SIGNED_BUNDLE_TIMESTAMP_TOKEN_INVALID")
    token_payload = _token_payload(
        signed_bundle_id=signed_verification.signed_bundle_id,
        message_imprint_hash=message_imprint_hash,
        hash_algorithm=HASH_ALGORITHM,
        tsa_policy_id=tsa_policy_id,
        tsa_serial_number=serial,
        tsa_gen_time_utc=timestamp,
    )
    timestamp_token_hash = _sha256_hex(_canonical_json(token_payload).encode("utf-8"))
    payload = {
        "governance_module_versions": dict(MODULE_VERSIONS),
        "hash_algorithm": HASH_ALGORITHM,
        "message_imprint_hash": message_imprint_hash,
        "retention_policy_label": signed_verification.retention_policy_label,
        "signed_bundle_hash": signed_bundle_hash,
        "signed_bundle_id": signed_verification.signed_bundle_id,
        "timestamp_token_hash": timestamp_token_hash,
        "tsa_gen_time_utc": timestamp,
        "tsa_policy_id": tsa_policy_id,
        "tsa_serial_number": serial,
        "verification_scope": dict(sorted(signed_bundle.get("verification_scope", {}).items())),
    }
    if not _scope_valid(payload["verification_scope"]):
        raise SignedBundleTimestampError("SIGNED_BUNDLE_TIMESTAMP_SCOPE_INVALID")
    attachment = {
        "schema": SIGNED_BUNDLE_TIMESTAMP_SCHEMA,
        "timestamp_attachment_id": _sha256_hex(_canonical_json(payload).encode("utf-8")),
        **payload,
    }
    _assert_signed_bundle_timestamp_safe(attachment)
    return attachment


def attach_signed_bundle_timestamp_file(
    signed_bundle_path: Path,
    output_path: Path,
    *,
    trust_policy: dict[str, Any],
    tsa_policy_id: str = DEFAULT_POLICY_OID_PLACEHOLDER,
    tsa_serial_number: str | None = None,
    tsa_gen_time_utc: str | None = None,
) -> dict[str, Any]:
    attachment = attach_signed_bundle_timestamp(
        _load_json_object(signed_bundle_path, "SIGNED_BUNDLE_TIMESTAMP_MISSING"),
        trust_policy=trust_policy,
        tsa_policy_id=tsa_policy_id,
        tsa_serial_number=tsa_serial_number,
        tsa_gen_time_utc=tsa_gen_time_utc,
    )
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(_canonical_json(attachment) + "\n", encoding="utf-8")
    return attachment


def verify_signed_bundle_timestamp(
    attachment: dict[str, Any],
    *,
    signed_bundle: dict[str, Any] | None = None,
    expected_tsa_policy_id: str = DEFAULT_POLICY_OID_PLACEHOLDER,
    existing_attachments: list[dict[str, Any]] | None = None,
) -> SignedBundleTimestampVerificationResult:
    errors: list[str] = []
    if not isinstance(attachment, dict) or attachment.get("schema") != SIGNED_BUNDLE_TIMESTAMP_SCHEMA:
        errors.append("SIGNED_BUNDLE_TIMESTAMP_MISSING")
    attachment_id = str(attachment.get("timestamp_attachment_id", "")) if isinstance(attachment, dict) else ""
    signed_bundle_id = str(attachment.get("signed_bundle_id", "")) if isinstance(attachment, dict) else ""
    signed_bundle_hash = str(attachment.get("signed_bundle_hash", "")) if isinstance(attachment, dict) else ""
    message_imprint_hash = str(attachment.get("message_imprint_hash", "")) if isinstance(attachment, dict) else ""
    hash_algorithm = str(attachment.get("hash_algorithm", "")) if isinstance(attachment, dict) else ""
    tsa_policy_id = str(attachment.get("tsa_policy_id", "")) if isinstance(attachment, dict) else ""
    tsa_serial_number = str(attachment.get("tsa_serial_number", "")) if isinstance(attachment, dict) else ""
    tsa_gen_time = str(attachment.get("tsa_gen_time_utc", "")) if isinstance(attachment, dict) else ""
    timestamp_token_hash = str(attachment.get("timestamp_token_hash", "")) if isinstance(attachment, dict) else ""
    retention_policy_label = str(attachment.get("retention_policy_label", "")) if isinstance(attachment, dict) else ""
    scope = attachment.get("verification_scope") if isinstance(attachment, dict) else None
    if not _is_sha256_hex(signed_bundle_id) or not _is_sha256_hex(signed_bundle_hash) or not _is_sha256_hex(message_imprint_hash):
        errors.append("SIGNED_BUNDLE_TIMESTAMP_HASH_MISMATCH")
    if hash_algorithm != HASH_ALGORITHM or message_imprint_hash != _message_imprint(signed_bundle_hash):
        errors.append("SIGNED_BUNDLE_TIMESTAMP_HASH_MISMATCH")
    if tsa_policy_id != expected_tsa_policy_id or not _policy_id_valid(tsa_policy_id):
        errors.append("SIGNED_BUNDLE_TIMESTAMP_POLICY_INVALID")
    if not _serial_valid(tsa_serial_number) or not _timestamp_is_valid(tsa_gen_time):
        errors.append("SIGNED_BUNDLE_TIMESTAMP_TOKEN_INVALID")
    token_payload = _token_payload(
        signed_bundle_id=signed_bundle_id,
        message_imprint_hash=message_imprint_hash,
        hash_algorithm=hash_algorithm,
        tsa_policy_id=tsa_policy_id,
        tsa_serial_number=tsa_serial_number,
        tsa_gen_time_utc=tsa_gen_time,
    )
    if not _is_sha256_hex(timestamp_token_hash) or timestamp_token_hash != _sha256_hex(_canonical_json(token_payload).encode("utf-8")):
        errors.append("SIGNED_BUNDLE_TIMESTAMP_TOKEN_INVALID")
    if not _scope_valid(scope) or not retention_policy_label:
        errors.append("SIGNED_BUNDLE_TIMESTAMP_SCOPE_INVALID")
    payload = _attachment_payload(attachment)
    if not _is_sha256_hex(attachment_id) or attachment_id != _sha256_hex(_canonical_json(payload).encode("utf-8")):
        errors.append("SIGNED_BUNDLE_TIMESTAMP_HASH_MISMATCH")
    if signed_bundle is not None:
        if (
            not isinstance(signed_bundle, dict)
            or signed_bundle.get("signed_bundle_id") != signed_bundle_id
            or signed_bundle.get("retention_policy_label") != retention_policy_label
            or _sha256_hex(_canonical_json(signed_bundle).encode("utf-8")) != signed_bundle_hash
        ):
            errors.append("SIGNED_BUNDLE_TIMESTAMP_HASH_MISMATCH")
    for existing in existing_attachments or []:
        if isinstance(existing, dict) and existing.get("timestamp_attachment_id") == attachment_id:
            errors.append("SIGNED_BUNDLE_TIMESTAMP_REPLAY_DETECTED")
    try:
        _assert_signed_bundle_timestamp_safe(attachment)
    except SignedBundleTimestampError:
        errors.append("SIGNED_BUNDLE_TIMESTAMP_DIAGNOSTICS_UNSAFE")
    return SignedBundleTimestampVerificationResult(
        valid=not errors,
        errors=tuple(dict.fromkeys(errors)),
        timestamp_attachment_id=attachment_id,
        signed_bundle_id=signed_bundle_id,
        signed_bundle_hash=signed_bundle_hash,
        message_imprint_hash=message_imprint_hash,
        timestamp_token_hash=timestamp_token_hash,
        retention_policy_label=retention_policy_label,
    )


def verify_signed_bundle_timestamp_file(
    attachment_path: Path,
    *,
    signed_bundle_path: Path | None = None,
    expected_tsa_policy_id: str = DEFAULT_POLICY_OID_PLACEHOLDER,
    existing_attachment_paths: list[Path] | None = None,
) -> SignedBundleTimestampVerificationResult:
    signed_bundle = _load_json_object(signed_bundle_path, "SIGNED_BUNDLE_TIMESTAMP_MISSING") if signed_bundle_path else None
    existing = [_load_json_object(path, "signed_bundle_timestamp_existing_invalid") for path in existing_attachment_paths or []]
    return verify_signed_bundle_timestamp(
        _load_json_object(attachment_path, "signed_bundle_timestamp_invalid"),
        signed_bundle=signed_bundle,
        expected_tsa_policy_id=expected_tsa_policy_id,
        existing_attachments=existing,
    )


def explain_signed_bundle_timestamp_failure(root: Path, code: str) -> dict[str, str]:
    registry = load_signed_bundle_timestamp_error_registry(root)
    if code not in registry:
        raise SignedBundleTimestampError("signed_bundle_timestamp_error_unknown:" + code)
    return {"code": code, **registry[code]}


def signed_bundle_timestamp_summary(attachment: dict[str, Any]) -> dict[str, Any]:
    verification = verify_signed_bundle_timestamp(attachment)
    return verification.to_dict()


def redacted_signed_bundle_timestamp_payload(payload: Any) -> Any:
    return redacted_policy_payload(payload)


def assert_signed_bundle_timestamp_safe(payload: Any) -> None:
    _assert_signed_bundle_timestamp_safe(payload)


def _attachment_payload(attachment: dict[str, Any]) -> dict[str, Any]:
    return {
        "governance_module_versions": attachment.get("governance_module_versions", {}),
        "hash_algorithm": attachment.get("hash_algorithm", ""),
        "message_imprint_hash": attachment.get("message_imprint_hash", ""),
        "retention_policy_label": attachment.get("retention_policy_label", ""),
        "signed_bundle_hash": attachment.get("signed_bundle_hash", ""),
        "signed_bundle_id": attachment.get("signed_bundle_id", ""),
        "timestamp_token_hash": attachment.get("timestamp_token_hash", ""),
        "tsa_gen_time_utc": attachment.get("tsa_gen_time_utc", ""),
        "tsa_policy_id": attachment.get("tsa_policy_id", ""),
        "tsa_serial_number": attachment.get("tsa_serial_number", ""),
        "verification_scope": attachment.get("verification_scope", {}),
    }


def _token_payload(
    *,
    signed_bundle_id: str,
    message_imprint_hash: str,
    hash_algorithm: str,
    tsa_policy_id: str,
    tsa_serial_number: str,
    tsa_gen_time_utc: str,
) -> dict[str, str]:
    return {
        "hash_algorithm": hash_algorithm,
        "message_imprint_hash": message_imprint_hash,
        "signed_bundle_id": signed_bundle_id,
        "tsa_gen_time_utc": tsa_gen_time_utc,
        "tsa_policy_id": tsa_policy_id,
        "tsa_serial_number": tsa_serial_number,
    }


def _message_imprint(signed_bundle_hash: str) -> str:
    return _sha256_hex(signed_bundle_hash.encode("utf-8")) if _is_sha256_hex(signed_bundle_hash) else ""


def _deterministic_serial(signed_bundle_id: str, message_imprint_hash: str, tsa_policy_id: str, timestamp: str) -> str:
    return _sha256_hex(_canonical_json({
        "message_imprint_hash": message_imprint_hash,
        "signed_bundle_id": signed_bundle_id,
        "tsa_gen_time_utc": timestamp,
        "tsa_policy_id": tsa_policy_id,
    }).encode("utf-8"))[:32]


def _scope_valid(scope: Any) -> bool:
    if not isinstance(scope, dict) or not scope:
        return False
    allowed = {"tenant_id", "environment", "purpose", "auditor_id"}
    if any(key not in allowed or not isinstance(value, str) or not value.strip() for key, value in scope.items()):
        return False
    return "purpose" in scope


def _policy_id_valid(value: str) -> bool:
    parts = value.split(".")
    return bool(value) and len(parts) >= 3 and all(part.isdigit() for part in parts)


def _serial_valid(value: str) -> bool:
    return bool(value) and len(value) <= 64 and all(character in "0123456789abcdef" for character in value)


def _assert_signed_bundle_timestamp_safe(payload: Any) -> None:
    try:
        redacted = redacted_policy_payload(payload)
        assert_policy_diagnostics_safe(redacted)
        assert_simulation_diagnostics_safe(redacted)
        assert_parity_diagnostics_safe(redacted)
        assert_proof_bundle_safe(redacted)
        assert_timestamp_anchor_safe(redacted)
        assert_rfc3161_safe(redacted)
        assert_worm_safe(redacted)
        assert_evidence_chain_safe(redacted)
        assert_merkle_safe(redacted)
        assert_inclusion_safe(redacted)
        assert_consistency_safe(redacted)
        assert_auditor_bundle_safe(redacted)
        assert_signed_auditor_bundle_safe(redacted)
        if redacted != payload:
            raise SignedBundleTimestampError("SIGNED_BUNDLE_TIMESTAMP_DIAGNOSTICS_UNSAFE")
    except Exception as exc:
        if isinstance(exc, SignedBundleTimestampError):
            raise
        raise SignedBundleTimestampError("SIGNED_BUNDLE_TIMESTAMP_DIAGNOSTICS_UNSAFE") from exc


def _load_json_object(path: Path | None, failure_code: str) -> dict[str, Any]:
    if path is None:
        raise SignedBundleTimestampError(failure_code)
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        raise SignedBundleTimestampError(failure_code) from exc
    if not isinstance(payload, dict):
        raise SignedBundleTimestampError(failure_code)
    return payload


def _canonical_json(payload: Any) -> str:
    try:
        return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    except (TypeError, ValueError) as exc:
        raise SignedBundleTimestampError("SIGNED_BUNDLE_TIMESTAMP_HASH_MISMATCH") from exc


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


def _is_sha256_hex(value: str) -> bool:
    return len(value) == 64 and all(character in "0123456789abcdef" for character in value)
