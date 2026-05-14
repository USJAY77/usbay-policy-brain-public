from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from governance.policy_pack import redacted_policy_payload
from governance.signed_bundle_revocation_preflight import (
    MODULE_VERSIONS as REVOCATION_PREFLIGHT_MODULE_VERSIONS,
    assert_revocation_preflight_safe,
    verify_revocation_preflight,
)
from governance.signed_bundle_revocation_response import (
    assert_revocation_response_safe,
    verify_revocation_response,
)

REVOCATION_LIVE_FETCH_SCHEMA = "usbay.governance_revocation_live_fetch.v1"
REVOCATION_LIVE_FETCH_ERROR_REGISTRY_PATH = Path("governance/revocation_live_fetch_errors.json")
REVOCATION_LIVE_FETCH_ERROR_SCHEMA = "usbay.governance_revocation_live_fetch_error_registry.v1"
REVOCATION_LIVE_FETCH_ERROR_CODES = (
    "REVOCATION_LIVE_FETCH_SOURCE_MISSING",
    "REVOCATION_LIVE_FETCH_SOURCE_MALFORMED",
    "REVOCATION_LIVE_FETCH_SOURCE_STALE",
    "REVOCATION_LIVE_FETCH_RESPONSE_MISSING",
    "REVOCATION_LIVE_FETCH_RESPONSE_UNSIGNED",
    "REVOCATION_LIVE_FETCH_RESPONSE_MISMATCH",
    "REVOCATION_LIVE_FETCH_PATH_MUTABLE",
    "REVOCATION_LIVE_FETCH_RAW_PAYLOAD_LEAKAGE",
    "REVOCATION_LIVE_FETCH_DIAGNOSTICS_UNSAFE",
)
REVOCATION_LIVE_FETCH_MODE = "LOCAL_ONLY"
DEFAULT_MAX_SOURCE_METADATA_AGE_SECONDS = 86_400
MODULE_VERSIONS = {
    **REVOCATION_PREFLIGHT_MODULE_VERSIONS,
    "revocation_live_fetch": REVOCATION_LIVE_FETCH_SCHEMA,
}


class RevocationLiveFetchError(RuntimeError):
    pass


@dataclass(frozen=True)
class RevocationLiveFetchVerificationResult:
    valid: bool
    errors: tuple[str, ...]
    revocation_live_fetch_id: str
    preflight_id: str
    revocation_response_id: str
    revocation_source_type: str
    revocation_source_uri_hash: str
    source_metadata_hash: str
    response_metadata_hash: str
    response_signature_fingerprint: str
    live_fetch_mode: str
    retention_policy_label: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "valid": self.valid,
            "errors": list(self.errors),
            "revocation_live_fetch_id": self.revocation_live_fetch_id,
            "preflight_id": self.preflight_id,
            "revocation_response_id": self.revocation_response_id,
            "revocation_source_type": self.revocation_source_type,
            "revocation_source_uri_hash": self.revocation_source_uri_hash,
            "source_metadata_hash": self.source_metadata_hash,
            "response_metadata_hash": self.response_metadata_hash,
            "response_signature_fingerprint": self.response_signature_fingerprint,
            "live_fetch_mode": self.live_fetch_mode,
            "retention_policy_label": self.retention_policy_label,
        }


def load_revocation_live_fetch_error_registry(root: Path) -> dict[str, dict[str, str]]:
    path = root / REVOCATION_LIVE_FETCH_ERROR_REGISTRY_PATH
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        raise RevocationLiveFetchError("revocation_live_fetch_error_registry_missing") from exc
    if not isinstance(payload, dict) or payload.get("schema") != REVOCATION_LIVE_FETCH_ERROR_SCHEMA:
        raise RevocationLiveFetchError("revocation_live_fetch_error_registry_invalid")
    raw_errors = payload.get("errors")
    if not isinstance(raw_errors, list):
        raise RevocationLiveFetchError("revocation_live_fetch_error_registry_invalid")
    registry: dict[str, dict[str, str]] = {}
    for entry in raw_errors:
        if not isinstance(entry, dict) or not entry.get("code"):
            raise RevocationLiveFetchError("revocation_live_fetch_error_registry_invalid")
        registry[str(entry["code"])] = {
            "description": str(entry.get("description", "")),
            "fail_closed_reason": str(entry.get("fail_closed_reason", "")),
        }
    missing = sorted(set(REVOCATION_LIVE_FETCH_ERROR_CODES) - set(registry))
    if missing:
        raise RevocationLiveFetchError("revocation_live_fetch_error_registry_incomplete:" + ",".join(missing))
    return registry


def prepare_revocation_live_fetch_plan(
    *,
    revocation_preflight: dict[str, Any],
    revocation_response: dict[str, Any],
    planned_at_utc: str | None = None,
    max_source_metadata_age_seconds: int = DEFAULT_MAX_SOURCE_METADATA_AGE_SECONDS,
) -> dict[str, Any]:
    preflight_result = verify_revocation_preflight(revocation_preflight)
    if not preflight_result.valid:
        raise RevocationLiveFetchError("REVOCATION_LIVE_FETCH_SOURCE_MISSING")
    response_result = verify_revocation_response(revocation_response, preflight=revocation_preflight)
    if not response_result.valid:
        if "REVOCATION_RESPONSE_SIGNATURE_INVALID" in response_result.errors:
            raise RevocationLiveFetchError("REVOCATION_LIVE_FETCH_RESPONSE_UNSIGNED")
        if "REVOCATION_RESPONSE_SOURCE_MISMATCH" in response_result.errors:
            raise RevocationLiveFetchError("REVOCATION_LIVE_FETCH_RESPONSE_MISMATCH")
        raise RevocationLiveFetchError("REVOCATION_LIVE_FETCH_RESPONSE_MISSING")
    planned_at = planned_at_utc or _utc_now()
    if not _timestamp_is_valid(planned_at) or not _fresh_source_metadata(revocation_preflight, revocation_response, planned_at, max_source_metadata_age_seconds):
        raise RevocationLiveFetchError("REVOCATION_LIVE_FETCH_SOURCE_STALE")
    source_metadata_hash = _source_metadata_hash(revocation_preflight)
    response_metadata_hash = _response_metadata_hash(revocation_response)
    payload = {
        "governance_module_versions": dict(MODULE_VERSIONS),
        "live_fetch_mode": REVOCATION_LIVE_FETCH_MODE,
        "max_source_metadata_age_seconds": int(max_source_metadata_age_seconds),
        "planned_at_utc": planned_at,
        "preflight_id": preflight_result.preflight_id,
        "response_metadata_hash": response_metadata_hash,
        "response_signature_fingerprint": response_result.response_signature_fingerprint,
        "retention_policy_label": preflight_result.retention_policy_label,
        "revocation_response_id": response_result.revocation_response_id,
        "revocation_source_type": preflight_result.revocation_source_type,
        "revocation_source_uri_hash": preflight_result.revocation_source_uri_hash,
        "source_metadata_hash": source_metadata_hash,
        "validation_policy_id": str(revocation_preflight.get("validation_policy_id", "")),
    }
    live_fetch_id = _sha256_hex(_canonical_json(payload).encode("utf-8"))
    plan = {
        "schema": REVOCATION_LIVE_FETCH_SCHEMA,
        "revocation_live_fetch_id": live_fetch_id,
        "live_fetch_output_path": _live_fetch_output_path(live_fetch_id),
        **payload,
    }
    _assert_live_fetch_safe(plan)
    return plan


def prepare_revocation_live_fetch_plan_file(
    *,
    revocation_preflight_path: Path,
    revocation_response_path: Path,
    output_path: Path,
    planned_at_utc: str | None = None,
    max_source_metadata_age_seconds: int = DEFAULT_MAX_SOURCE_METADATA_AGE_SECONDS,
) -> dict[str, Any]:
    plan = prepare_revocation_live_fetch_plan(
        revocation_preflight=_load_json_object(revocation_preflight_path, "REVOCATION_LIVE_FETCH_SOURCE_MISSING"),
        revocation_response=_load_json_object(revocation_response_path, "REVOCATION_LIVE_FETCH_RESPONSE_MISSING"),
        planned_at_utc=planned_at_utc,
        max_source_metadata_age_seconds=max_source_metadata_age_seconds,
    )
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(_canonical_json(plan) + "\n", encoding="utf-8")
    return plan


def verify_revocation_live_fetch_plan(
    plan: dict[str, Any],
    *,
    revocation_preflight: dict[str, Any] | None = None,
    revocation_response: dict[str, Any] | None = None,
) -> RevocationLiveFetchVerificationResult:
    errors: list[str] = []
    if not isinstance(plan, dict) or plan.get("schema") != REVOCATION_LIVE_FETCH_SCHEMA:
        errors.append("REVOCATION_LIVE_FETCH_SOURCE_MISSING")
    live_fetch_id = str(plan.get("revocation_live_fetch_id", "")) if isinstance(plan, dict) else ""
    preflight_id = str(plan.get("preflight_id", "")) if isinstance(plan, dict) else ""
    response_id = str(plan.get("revocation_response_id", "")) if isinstance(plan, dict) else ""
    source_type = str(plan.get("revocation_source_type", "")) if isinstance(plan, dict) else ""
    source_hash = str(plan.get("revocation_source_uri_hash", "")) if isinstance(plan, dict) else ""
    source_metadata_hash = str(plan.get("source_metadata_hash", "")) if isinstance(plan, dict) else ""
    response_metadata_hash = str(plan.get("response_metadata_hash", "")) if isinstance(plan, dict) else ""
    signature = str(plan.get("response_signature_fingerprint", "")) if isinstance(plan, dict) else ""
    mode = str(plan.get("live_fetch_mode", "")) if isinstance(plan, dict) else ""
    planned_at = str(plan.get("planned_at_utc", "")) if isinstance(plan, dict) else ""
    max_age = plan.get("max_source_metadata_age_seconds") if isinstance(plan, dict) else None
    retention = str(plan.get("retention_policy_label", "")) if isinstance(plan, dict) else ""
    if not _sha256_valid(preflight_id) or not _sha256_valid(source_metadata_hash):
        errors.append("REVOCATION_LIVE_FETCH_SOURCE_MISSING")
    if source_type not in {"OCSP", "CRL"} or not _sha256_valid(source_hash):
        errors.append("REVOCATION_LIVE_FETCH_SOURCE_MALFORMED")
    if not _timestamp_is_valid(planned_at) or not isinstance(max_age, int) or max_age <= 0:
        errors.append("REVOCATION_LIVE_FETCH_SOURCE_STALE")
    if not _sha256_valid(response_id) or not _sha256_valid(response_metadata_hash):
        errors.append("REVOCATION_LIVE_FETCH_RESPONSE_MISSING")
    if not _sha256_valid(signature):
        errors.append("REVOCATION_LIVE_FETCH_RESPONSE_UNSIGNED")
    if mode != REVOCATION_LIVE_FETCH_MODE or plan.get("live_fetch_output_path") != _live_fetch_output_path(live_fetch_id):
        errors.append("REVOCATION_LIVE_FETCH_PATH_MUTABLE")
    payload = _plan_payload(plan)
    if not _sha256_valid(live_fetch_id) or live_fetch_id != _sha256_hex(_canonical_json(payload).encode("utf-8")):
        errors.append("REVOCATION_LIVE_FETCH_RESPONSE_MISMATCH")
    if revocation_preflight is not None:
        preflight_result = verify_revocation_preflight(revocation_preflight)
        if (
            not preflight_result.valid
            or preflight_result.preflight_id != preflight_id
            or preflight_result.revocation_source_type != source_type
            or preflight_result.revocation_source_uri_hash != source_hash
            or preflight_result.retention_policy_label != retention
            or _source_metadata_hash(revocation_preflight) != source_metadata_hash
        ):
            errors.append("REVOCATION_LIVE_FETCH_SOURCE_MALFORMED")
    if revocation_response is not None:
        response_result = verify_revocation_response(revocation_response, preflight=revocation_preflight)
        if not response_result.valid or response_result.revocation_response_id != response_id or _response_metadata_hash(revocation_response) != response_metadata_hash:
            if "REVOCATION_RESPONSE_SIGNATURE_INVALID" in response_result.errors:
                errors.append("REVOCATION_LIVE_FETCH_RESPONSE_UNSIGNED")
            else:
                errors.append("REVOCATION_LIVE_FETCH_RESPONSE_MISMATCH")
        if response_result.valid and response_result.response_signature_fingerprint != signature:
            errors.append("REVOCATION_LIVE_FETCH_RESPONSE_UNSIGNED")
    if revocation_preflight is not None and revocation_response is not None:
        if not _fresh_source_metadata(revocation_preflight, revocation_response, planned_at, int(max_age) if isinstance(max_age, int) else 0):
            errors.append("REVOCATION_LIVE_FETCH_SOURCE_STALE")
    try:
        _assert_live_fetch_safe(plan)
    except RevocationLiveFetchError as exc:
        if str(exc) == "REVOCATION_LIVE_FETCH_RAW_PAYLOAD_LEAKAGE":
            errors.append("REVOCATION_LIVE_FETCH_RAW_PAYLOAD_LEAKAGE")
        else:
            errors.append("REVOCATION_LIVE_FETCH_DIAGNOSTICS_UNSAFE")
    return RevocationLiveFetchVerificationResult(
        valid=not errors,
        errors=tuple(dict.fromkeys(errors)),
        revocation_live_fetch_id=live_fetch_id,
        preflight_id=preflight_id,
        revocation_response_id=response_id,
        revocation_source_type=source_type,
        revocation_source_uri_hash=source_hash,
        source_metadata_hash=source_metadata_hash,
        response_metadata_hash=response_metadata_hash,
        response_signature_fingerprint=signature,
        live_fetch_mode=mode,
        retention_policy_label=retention,
    )


def verify_revocation_live_fetch_plan_file(
    revocation_live_fetch_path: Path,
    *,
    revocation_preflight_path: Path | None = None,
    revocation_response_path: Path | None = None,
) -> RevocationLiveFetchVerificationResult:
    return verify_revocation_live_fetch_plan(
        _load_json_object(revocation_live_fetch_path, "revocation_live_fetch_invalid"),
        revocation_preflight=_load_json_object(revocation_preflight_path, "REVOCATION_LIVE_FETCH_SOURCE_MISSING") if revocation_preflight_path else None,
        revocation_response=_load_json_object(revocation_response_path, "REVOCATION_LIVE_FETCH_RESPONSE_MISSING") if revocation_response_path else None,
    )


def explain_revocation_live_fetch_failure(root: Path, code: str) -> dict[str, str]:
    registry = load_revocation_live_fetch_error_registry(root)
    if code not in registry:
        raise RevocationLiveFetchError("revocation_live_fetch_error_unknown:" + code)
    return {"code": code, **registry[code]}


def revocation_live_fetch_summary(plan: dict[str, Any]) -> dict[str, Any]:
    return verify_revocation_live_fetch_plan(plan).to_dict()


def redacted_revocation_live_fetch_payload(payload: Any) -> Any:
    return redacted_policy_payload(payload)


def assert_revocation_live_fetch_safe(payload: Any) -> None:
    _assert_live_fetch_safe(payload)


def _plan_payload(plan: dict[str, Any]) -> dict[str, Any]:
    return {
        "governance_module_versions": plan.get("governance_module_versions", {}),
        "live_fetch_mode": plan.get("live_fetch_mode", ""),
        "max_source_metadata_age_seconds": plan.get("max_source_metadata_age_seconds", ""),
        "planned_at_utc": plan.get("planned_at_utc", ""),
        "preflight_id": plan.get("preflight_id", ""),
        "response_metadata_hash": plan.get("response_metadata_hash", ""),
        "response_signature_fingerprint": plan.get("response_signature_fingerprint", ""),
        "retention_policy_label": plan.get("retention_policy_label", ""),
        "revocation_response_id": plan.get("revocation_response_id", ""),
        "revocation_source_type": plan.get("revocation_source_type", ""),
        "revocation_source_uri_hash": plan.get("revocation_source_uri_hash", ""),
        "source_metadata_hash": plan.get("source_metadata_hash", ""),
        "validation_policy_id": plan.get("validation_policy_id", ""),
    }


def _source_metadata_hash(preflight: dict[str, Any]) -> str:
    payload = {
        "checked_at_utc": preflight.get("checked_at_utc", ""),
        "expected_freshness_window_seconds": preflight.get("expected_freshness_window_seconds", ""),
        "preflight_id": preflight.get("preflight_id", ""),
        "revocation_source_type": preflight.get("revocation_source_type", ""),
        "revocation_source_uri_hash": preflight.get("revocation_source_uri_hash", ""),
        "validation_policy_id": preflight.get("validation_policy_id", ""),
    }
    return _sha256_hex(_canonical_json(payload).encode("utf-8"))


def _response_metadata_hash(response: dict[str, Any]) -> str:
    payload = {
        "checked_at_utc": response.get("checked_at_utc", ""),
        "preflight_id": response.get("preflight_id", ""),
        "response_next_update_utc": response.get("response_next_update_utc", ""),
        "response_nonce_hash": response.get("response_nonce_hash", ""),
        "response_signature_fingerprint": response.get("response_signature_fingerprint", ""),
        "response_status": response.get("response_status", ""),
        "response_this_update_utc": response.get("response_this_update_utc", ""),
        "revocation_response_id": response.get("revocation_response_id", ""),
        "revocation_source_uri_hash": response.get("revocation_source_uri_hash", ""),
        "validation_policy_id": response.get("validation_policy_id", ""),
    }
    return _sha256_hex(_canonical_json(payload).encode("utf-8"))


def _fresh_source_metadata(preflight: dict[str, Any], response: dict[str, Any], planned_at: str, max_age_seconds: int) -> bool:
    if max_age_seconds <= 0:
        return False
    planned = _parse_utc(planned_at)
    preflight_checked = _parse_utc(str(preflight.get("checked_at_utc", "")))
    response_next = _parse_utc(str(response.get("response_next_update_utc", "")))
    response_checked = _parse_utc(str(response.get("checked_at_utc", "")))
    if planned is None or preflight_checked is None or response_next is None or response_checked is None:
        return False
    if planned < preflight_checked or planned < response_checked:
        return False
    if planned > response_next:
        return False
    return (planned - preflight_checked).total_seconds() <= max_age_seconds


def _live_fetch_output_path(live_fetch_id: str) -> str:
    return f"revocation-live-fetch://local-only/sha256/{live_fetch_id}"


def _assert_live_fetch_safe(payload: Any) -> None:
    try:
        if _contains_raw_payload_marker(payload):
            raise RevocationLiveFetchError("REVOCATION_LIVE_FETCH_RAW_PAYLOAD_LEAKAGE")
        redacted = redacted_policy_payload(payload)
        assert_revocation_preflight_safe(redacted)
        assert_revocation_response_safe(redacted)
        if redacted != payload:
            raise RevocationLiveFetchError("REVOCATION_LIVE_FETCH_DIAGNOSTICS_UNSAFE")
    except Exception as exc:
        if isinstance(exc, RevocationLiveFetchError):
            raise
        raise RevocationLiveFetchError("REVOCATION_LIVE_FETCH_DIAGNOSTICS_UNSAFE") from exc


def _contains_raw_payload_marker(payload: Any) -> bool:
    text = _canonical_json(payload).lower()
    markers = (
        "raw_payload",
        "raw_governance_payload",
        "raw_ocsp",
        "raw_crl",
        "ocsp_bytes",
        "crl_bytes",
        "runtime_artifact",
        "live_fetch_response_body",
        "revocation_endpoint_url",
    )
    return any(marker in text for marker in markers)


def _load_json_object(path: Path | None, failure_code: str) -> dict[str, Any]:
    if path is None:
        raise RevocationLiveFetchError(failure_code)
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        raise RevocationLiveFetchError(failure_code) from exc
    if not isinstance(payload, dict):
        raise RevocationLiveFetchError(failure_code)
    return payload


def _timestamp_is_valid(value: str) -> bool:
    return _parse_utc(value) is not None


def _parse_utc(value: str) -> datetime | None:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if not value.endswith("Z") or parsed.tzinfo is None or parsed.utcoffset() != timezone.utc.utcoffset(parsed):
        return None
    return parsed


def _utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _canonical_json(payload: Any) -> str:
    try:
        return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    except (TypeError, ValueError) as exc:
        raise RevocationLiveFetchError("REVOCATION_LIVE_FETCH_SOURCE_MALFORMED") from exc


def _sha256_valid(value: str) -> bool:
    return len(value) == 64 and all(character in "0123456789abcdef" for character in value)


def _sha256_hex(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()
