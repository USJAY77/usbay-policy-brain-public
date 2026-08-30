from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from governance.policy_pack import redacted_policy_payload
from governance.rfc3161_timestamp import DEFAULT_POLICY_OID_PLACEHOLDER
from governance.signed_bundle_timestamp import (
    HASH_ALGORITHM,
    MODULE_VERSIONS as SIGNED_BUNDLE_TIMESTAMP_MODULE_VERSIONS,
    assert_signed_bundle_timestamp_safe,
    verify_signed_bundle_timestamp,
)

TSA_LIVE_VERIFICATION_SCHEMA = "usbay.governance_tsa_live_verification.v1"
TSA_LIVE_VERIFICATION_ERROR_REGISTRY_PATH = Path("governance/tsa_live_verification_errors.json")
TSA_LIVE_VERIFICATION_ERROR_SCHEMA = "usbay.governance_tsa_live_verification_error_registry.v1"
TSA_LIVE_VERIFICATION_ERROR_CODES = (
    "TSA_LIVE_TIMESTAMP_ATTACHMENT_MISSING",
    "TSA_LIVE_IMPRINT_MALFORMED",
    "TSA_LIVE_POLICY_UNEXPECTED",
    "TSA_LIVE_TIMESTAMP_METADATA_STALE",
    "TSA_LIVE_SIGNATURE_HASH_MISMATCH",
    "TSA_LIVE_OUTPUT_PATH_MUTABLE",
    "TSA_LIVE_DIAGNOSTICS_UNSAFE",
)
TSA_LIVE_VERIFICATION_MODE = "LOCAL_ONLY"
DEFAULT_MAX_METADATA_AGE_SECONDS = 86_400
MODULE_VERSIONS = {
    **SIGNED_BUNDLE_TIMESTAMP_MODULE_VERSIONS,
    "tsa_live_verification": TSA_LIVE_VERIFICATION_SCHEMA,
}


class TSALiveVerificationError(RuntimeError):
    pass


@dataclass(frozen=True)
class TSALiveVerificationResult:
    valid: bool
    errors: tuple[str, ...]
    tsa_live_verification_id: str
    timestamp_attachment_id: str
    signed_bundle_hash: str
    message_imprint_hash: str
    timestamp_token_hash: str
    tsa_policy_id: str
    tsa_serial_number: str
    tsa_gen_time_utc: str
    verification_mode: str
    retention_policy_label: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "valid": self.valid,
            "errors": list(self.errors),
            "tsa_live_verification_id": self.tsa_live_verification_id,
            "timestamp_attachment_id": self.timestamp_attachment_id,
            "signed_bundle_hash": self.signed_bundle_hash,
            "message_imprint_hash": self.message_imprint_hash,
            "timestamp_token_hash": self.timestamp_token_hash,
            "tsa_policy_id": self.tsa_policy_id,
            "tsa_serial_number": self.tsa_serial_number,
            "tsa_gen_time_utc": self.tsa_gen_time_utc,
            "verification_mode": self.verification_mode,
            "retention_policy_label": self.retention_policy_label,
        }


def load_tsa_live_verification_error_registry(root: Path) -> dict[str, dict[str, str]]:
    path = root / TSA_LIVE_VERIFICATION_ERROR_REGISTRY_PATH
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        raise TSALiveVerificationError("tsa_live_verification_error_registry_missing") from exc
    if not isinstance(payload, dict) or payload.get("schema") != TSA_LIVE_VERIFICATION_ERROR_SCHEMA:
        raise TSALiveVerificationError("tsa_live_verification_error_registry_invalid")
    raw_errors = payload.get("errors")
    if not isinstance(raw_errors, list):
        raise TSALiveVerificationError("tsa_live_verification_error_registry_invalid")
    registry: dict[str, dict[str, str]] = {}
    for entry in raw_errors:
        if not isinstance(entry, dict) or not entry.get("code"):
            raise TSALiveVerificationError("tsa_live_verification_error_registry_invalid")
        registry[str(entry["code"])] = {
            "description": str(entry.get("description", "")),
            "fail_closed_reason": str(entry.get("fail_closed_reason", "")),
        }
    missing = sorted(set(TSA_LIVE_VERIFICATION_ERROR_CODES) - set(registry))
    if missing:
        raise TSALiveVerificationError("tsa_live_verification_error_registry_incomplete:" + ",".join(missing))
    return registry


def prepare_tsa_live_verification_plan(
    timestamp_attachment: dict[str, Any],
    *,
    expected_tsa_policy_id: str = DEFAULT_POLICY_OID_PLACEHOLDER,
    verification_checked_at_utc: str | None = None,
    max_metadata_age_seconds: int = DEFAULT_MAX_METADATA_AGE_SECONDS,
) -> dict[str, Any]:
    timestamp_verification = verify_signed_bundle_timestamp(timestamp_attachment, expected_tsa_policy_id=expected_tsa_policy_id)
    if not timestamp_verification.valid:
        if "SIGNED_BUNDLE_TIMESTAMP_POLICY_INVALID" in timestamp_verification.errors:
            raise TSALiveVerificationError("TSA_LIVE_POLICY_UNEXPECTED")
        if "SIGNED_BUNDLE_TIMESTAMP_HASH_MISMATCH" in timestamp_verification.errors:
            raise TSALiveVerificationError("TSA_LIVE_IMPRINT_MALFORMED")
        if "SIGNED_BUNDLE_TIMESTAMP_TOKEN_INVALID" in timestamp_verification.errors:
            raise TSALiveVerificationError("TSA_LIVE_SIGNATURE_HASH_MISMATCH")
        raise TSALiveVerificationError("TSA_LIVE_TIMESTAMP_ATTACHMENT_MISSING")
    checked_at = verification_checked_at_utc or _utc_now()
    if not _timestamp_is_valid(checked_at):
        raise TSALiveVerificationError("TSA_LIVE_TIMESTAMP_METADATA_STALE")
    if not _freshness_valid(str(timestamp_attachment.get("tsa_gen_time_utc", "")), checked_at, max_metadata_age_seconds):
        raise TSALiveVerificationError("TSA_LIVE_TIMESTAMP_METADATA_STALE")
    policy_id = str(timestamp_attachment.get("tsa_policy_id", ""))
    serial = str(timestamp_attachment.get("tsa_serial_number", ""))
    message_imprint_hash = timestamp_verification.message_imprint_hash
    signed_bundle_hash = timestamp_verification.signed_bundle_hash
    token_hash = timestamp_verification.timestamp_token_hash
    attachment_id = timestamp_verification.timestamp_attachment_id
    path = _local_only_output_path(timestamp_attachment_id=attachment_id, timestamp_token_hash=token_hash)
    payload = {
        "governance_module_versions": dict(MODULE_VERSIONS),
        "hash_algorithm": HASH_ALGORITHM,
        "live_verification_output_path": path,
        "max_metadata_age_seconds": int(max_metadata_age_seconds),
        "message_imprint_hash": message_imprint_hash,
        "retention_policy_label": timestamp_verification.retention_policy_label,
        "signed_bundle_hash": signed_bundle_hash,
        "timestamp_attachment_id": attachment_id,
        "timestamp_token_hash": token_hash,
        "tsa_gen_time_utc": str(timestamp_attachment.get("tsa_gen_time_utc", "")),
        "tsa_live_checked_at_utc": checked_at,
        "tsa_policy_id": policy_id,
        "tsa_serial_number": serial,
        "verification_mode": TSA_LIVE_VERIFICATION_MODE,
    }
    plan = {
        "schema": TSA_LIVE_VERIFICATION_SCHEMA,
        "tsa_live_verification_id": _sha256_hex(_canonical_json(payload).encode("utf-8")),
        **payload,
    }
    _assert_tsa_live_verification_safe(plan)
    return plan


def prepare_tsa_live_verification_plan_file(
    timestamp_attachment_path: Path,
    output_path: Path,
    *,
    expected_tsa_policy_id: str = DEFAULT_POLICY_OID_PLACEHOLDER,
    verification_checked_at_utc: str | None = None,
    max_metadata_age_seconds: int = DEFAULT_MAX_METADATA_AGE_SECONDS,
) -> dict[str, Any]:
    plan = prepare_tsa_live_verification_plan(
        _load_json_object(timestamp_attachment_path, "TSA_LIVE_TIMESTAMP_ATTACHMENT_MISSING"),
        expected_tsa_policy_id=expected_tsa_policy_id,
        verification_checked_at_utc=verification_checked_at_utc,
        max_metadata_age_seconds=max_metadata_age_seconds,
    )
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(_canonical_json(plan) + "\n", encoding="utf-8")
    return plan


def verify_tsa_live_verification_plan(
    plan: dict[str, Any],
    *,
    timestamp_attachment: dict[str, Any] | None = None,
    expected_tsa_policy_id: str = DEFAULT_POLICY_OID_PLACEHOLDER,
) -> TSALiveVerificationResult:
    errors: list[str] = []
    if not isinstance(plan, dict) or plan.get("schema") != TSA_LIVE_VERIFICATION_SCHEMA:
        errors.append("TSA_LIVE_TIMESTAMP_ATTACHMENT_MISSING")
    plan_id = str(plan.get("tsa_live_verification_id", "")) if isinstance(plan, dict) else ""
    attachment_id = str(plan.get("timestamp_attachment_id", "")) if isinstance(plan, dict) else ""
    signed_bundle_hash = str(plan.get("signed_bundle_hash", "")) if isinstance(plan, dict) else ""
    imprint = str(plan.get("message_imprint_hash", "")) if isinstance(plan, dict) else ""
    token_hash = str(plan.get("timestamp_token_hash", "")) if isinstance(plan, dict) else ""
    policy_id = str(plan.get("tsa_policy_id", "")) if isinstance(plan, dict) else ""
    serial = str(plan.get("tsa_serial_number", "")) if isinstance(plan, dict) else ""
    gen_time = str(plan.get("tsa_gen_time_utc", "")) if isinstance(plan, dict) else ""
    checked_at = str(plan.get("tsa_live_checked_at_utc", "")) if isinstance(plan, dict) else ""
    mode = str(plan.get("verification_mode", "")) if isinstance(plan, dict) else ""
    retention = str(plan.get("retention_policy_label", "")) if isinstance(plan, dict) else ""
    max_age = plan.get("max_metadata_age_seconds") if isinstance(plan, dict) else None
    if not _is_sha256_hex(attachment_id):
        errors.append("TSA_LIVE_TIMESTAMP_ATTACHMENT_MISSING")
    if not _is_sha256_hex(attachment_id) or not _is_sha256_hex(signed_bundle_hash) or not _is_sha256_hex(imprint):
        errors.append("TSA_LIVE_IMPRINT_MALFORMED")
    if imprint != _message_imprint(signed_bundle_hash):
        errors.append("TSA_LIVE_IMPRINT_MALFORMED")
    if policy_id != expected_tsa_policy_id or not _policy_id_valid(policy_id):
        errors.append("TSA_LIVE_POLICY_UNEXPECTED")
    if not _serial_valid(serial) or not _timestamp_is_valid(gen_time) or not _timestamp_is_valid(checked_at):
        errors.append("TSA_LIVE_TIMESTAMP_METADATA_STALE")
    if not isinstance(max_age, int) or max_age <= 0 or not _freshness_valid(gen_time, checked_at, max_age):
        errors.append("TSA_LIVE_TIMESTAMP_METADATA_STALE")
    if not _is_sha256_hex(token_hash) or mode != TSA_LIVE_VERIFICATION_MODE:
        errors.append("TSA_LIVE_SIGNATURE_HASH_MISMATCH")
    if plan.get("live_verification_output_path") != _local_only_output_path(timestamp_attachment_id=attachment_id, timestamp_token_hash=token_hash):
        errors.append("TSA_LIVE_OUTPUT_PATH_MUTABLE")
    payload = _plan_payload(plan)
    if not _is_sha256_hex(plan_id) or plan_id != _sha256_hex(_canonical_json(payload).encode("utf-8")):
        errors.append("TSA_LIVE_SIGNATURE_HASH_MISMATCH")
    if timestamp_attachment is not None:
        attachment_verification = verify_signed_bundle_timestamp(timestamp_attachment, expected_tsa_policy_id=expected_tsa_policy_id)
        if not attachment_verification.valid:
            errors.append("TSA_LIVE_TIMESTAMP_ATTACHMENT_MISSING")
        else:
            if attachment_verification.timestamp_attachment_id != attachment_id:
                errors.append("TSA_LIVE_TIMESTAMP_ATTACHMENT_MISSING")
            if attachment_verification.signed_bundle_hash != signed_bundle_hash or attachment_verification.message_imprint_hash != imprint:
                errors.append("TSA_LIVE_IMPRINT_MALFORMED")
            if attachment_verification.timestamp_token_hash != token_hash:
                errors.append("TSA_LIVE_SIGNATURE_HASH_MISMATCH")
    try:
        _assert_tsa_live_verification_safe(plan)
    except TSALiveVerificationError:
        errors.append("TSA_LIVE_DIAGNOSTICS_UNSAFE")
    return TSALiveVerificationResult(
        valid=not errors,
        errors=tuple(dict.fromkeys(errors)),
        tsa_live_verification_id=plan_id,
        timestamp_attachment_id=attachment_id,
        signed_bundle_hash=signed_bundle_hash,
        message_imprint_hash=imprint,
        timestamp_token_hash=token_hash,
        tsa_policy_id=policy_id,
        tsa_serial_number=serial,
        tsa_gen_time_utc=gen_time,
        verification_mode=mode,
        retention_policy_label=retention,
    )


def verify_tsa_live_verification_plan_file(
    tsa_live_verification_path: Path,
    *,
    timestamp_attachment_path: Path | None = None,
    expected_tsa_policy_id: str = DEFAULT_POLICY_OID_PLACEHOLDER,
) -> TSALiveVerificationResult:
    return verify_tsa_live_verification_plan(
        _load_json_object(tsa_live_verification_path, "tsa_live_verification_invalid"),
        timestamp_attachment=_load_json_object(timestamp_attachment_path, "TSA_LIVE_TIMESTAMP_ATTACHMENT_MISSING") if timestamp_attachment_path else None,
        expected_tsa_policy_id=expected_tsa_policy_id,
    )


def explain_tsa_live_verification_failure(root: Path, code: str) -> dict[str, str]:
    registry = load_tsa_live_verification_error_registry(root)
    if code not in registry:
        raise TSALiveVerificationError("tsa_live_verification_error_unknown:" + code)
    return {"code": code, **registry[code]}


def tsa_live_verification_summary(plan: dict[str, Any]) -> dict[str, Any]:
    return verify_tsa_live_verification_plan(plan).to_dict()


def redacted_tsa_live_verification_payload(payload: Any) -> Any:
    return redacted_policy_payload(payload)


def assert_tsa_live_verification_safe(payload: Any) -> None:
    _assert_tsa_live_verification_safe(payload)


def _plan_payload(plan: dict[str, Any]) -> dict[str, Any]:
    return {
        "governance_module_versions": plan.get("governance_module_versions", {}),
        "hash_algorithm": plan.get("hash_algorithm", ""),
        "live_verification_output_path": plan.get("live_verification_output_path", ""),
        "max_metadata_age_seconds": plan.get("max_metadata_age_seconds", 0),
        "message_imprint_hash": plan.get("message_imprint_hash", ""),
        "retention_policy_label": plan.get("retention_policy_label", ""),
        "signed_bundle_hash": plan.get("signed_bundle_hash", ""),
        "timestamp_attachment_id": plan.get("timestamp_attachment_id", ""),
        "timestamp_token_hash": plan.get("timestamp_token_hash", ""),
        "tsa_gen_time_utc": plan.get("tsa_gen_time_utc", ""),
        "tsa_live_checked_at_utc": plan.get("tsa_live_checked_at_utc", ""),
        "tsa_policy_id": plan.get("tsa_policy_id", ""),
        "tsa_serial_number": plan.get("tsa_serial_number", ""),
        "verification_mode": plan.get("verification_mode", ""),
    }


def _local_only_output_path(*, timestamp_attachment_id: str, timestamp_token_hash: str) -> str:
    return f"tsa-live://local-only/sha256/{timestamp_attachment_id}/{timestamp_token_hash}"


def _message_imprint(signed_bundle_hash: str) -> str:
    return _sha256_hex(signed_bundle_hash.encode("utf-8")) if _is_sha256_hex(signed_bundle_hash) else ""


def _freshness_valid(gen_time: str, checked_at: str, max_age_seconds: int) -> bool:
    try:
        generated = datetime.fromisoformat(gen_time.replace("Z", "+00:00"))
        checked = datetime.fromisoformat(checked_at.replace("Z", "+00:00"))
    except ValueError:
        return False
    age = (checked - generated).total_seconds()
    return 0 <= age <= max_age_seconds


def _policy_id_valid(value: str) -> bool:
    parts = value.split(".")
    return bool(value) and len(parts) >= 3 and all(part.isdigit() for part in parts)


def _serial_valid(value: str) -> bool:
    return bool(value) and len(value) <= 64 and all(character in "0123456789abcdef" for character in value)


def _assert_tsa_live_verification_safe(payload: Any) -> None:
    try:
        redacted = redacted_policy_payload(payload)
        assert_signed_bundle_timestamp_safe(redacted)
        if redacted != payload:
            raise TSALiveVerificationError("TSA_LIVE_DIAGNOSTICS_UNSAFE")
    except Exception as exc:
        if isinstance(exc, TSALiveVerificationError):
            raise
        raise TSALiveVerificationError("TSA_LIVE_DIAGNOSTICS_UNSAFE") from exc


def _load_json_object(path: Path | None, failure_code: str) -> dict[str, Any]:
    if path is None:
        raise TSALiveVerificationError(failure_code)
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        raise TSALiveVerificationError(failure_code) from exc
    if not isinstance(payload, dict):
        raise TSALiveVerificationError(failure_code)
    return payload


def _canonical_json(payload: Any) -> str:
    try:
        return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    except (TypeError, ValueError) as exc:
        raise TSALiveVerificationError("TSA_LIVE_SIGNATURE_HASH_MISMATCH") from exc


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
