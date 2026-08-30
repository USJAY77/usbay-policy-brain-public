from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from governance.policy_pack import assert_policy_diagnostics_safe, redacted_policy_payload
from governance.policy_parity import assert_parity_diagnostics_safe
from governance.policy_proof_bundle import (
    MODULE_VERSIONS as PROOF_MODULE_VERSIONS,
    PolicyProofBundleError,
    assert_proof_bundle_safe,
    verify_policy_proof_bundle,
)
from governance.policy_simulation import assert_simulation_diagnostics_safe

TIMESTAMP_ANCHOR_SCHEMA = "usbay.governance_proof_timestamp_anchor.v1"
TIMESTAMP_ANCHOR_ERROR_REGISTRY_PATH = Path("governance/proof_timestamp_anchor_errors.json")
TIMESTAMP_ANCHOR_ERROR_SCHEMA = "usbay.governance_proof_timestamp_anchor_error_registry.v1"
TIMESTAMP_ANCHOR_ERROR_CODES = (
    "TIMESTAMP_BUNDLE_HASH_MISSING",
    "TIMESTAMP_PAYLOAD_INVALID",
    "TIMESTAMP_CLOCK_INVALID",
    "TIMESTAMP_ANCHOR_UNVERIFIED",
    "TIMESTAMP_DIAGNOSTICS_UNSAFE",
)
MODULE_VERSIONS = {
    **PROOF_MODULE_VERSIONS,
    "proof_timestamp_anchor": TIMESTAMP_ANCHOR_SCHEMA,
}


class ProofTimestampAnchorError(RuntimeError):
    pass


@dataclass(frozen=True)
class ProofTimestampVerificationResult:
    valid: bool
    errors: tuple[str, ...]
    proof_bundle_hash: str
    timestamp: str
    anchor_hash: str
    validation_status: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "valid": self.valid,
            "errors": list(self.errors),
            "proof_bundle_hash": self.proof_bundle_hash,
            "timestamp": self.timestamp,
            "anchor_hash": self.anchor_hash,
            "validation_status": self.validation_status,
        }


def load_timestamp_anchor_error_registry(root: Path) -> dict[str, dict[str, str]]:
    path = root / TIMESTAMP_ANCHOR_ERROR_REGISTRY_PATH
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        raise ProofTimestampAnchorError("timestamp_anchor_error_registry_missing") from exc
    if not isinstance(payload, dict) or payload.get("schema") != TIMESTAMP_ANCHOR_ERROR_SCHEMA:
        raise ProofTimestampAnchorError("timestamp_anchor_error_registry_invalid")
    raw_errors = payload.get("errors")
    if not isinstance(raw_errors, list):
        raise ProofTimestampAnchorError("timestamp_anchor_error_registry_invalid")
    registry: dict[str, dict[str, str]] = {}
    for entry in raw_errors:
        if not isinstance(entry, dict) or not entry.get("code"):
            raise ProofTimestampAnchorError("timestamp_anchor_error_registry_invalid")
        registry[str(entry["code"])] = {
            "description": str(entry.get("description", "")),
            "fail_closed_reason": str(entry.get("fail_closed_reason", "")),
        }
    missing = sorted(set(TIMESTAMP_ANCHOR_ERROR_CODES) - set(registry))
    if missing:
        raise ProofTimestampAnchorError("timestamp_anchor_error_registry_incomplete:" + ",".join(missing))
    return registry


def anchor_proof_bundle(
    proof_bundle: dict[str, Any],
    *,
    timestamp: str | None = None,
) -> dict[str, Any]:
    verification = verify_policy_proof_bundle(proof_bundle)
    if not verification.valid:
        raise ProofTimestampAnchorError("TIMESTAMP_ANCHOR_UNVERIFIED")
    timestamp_value = timestamp or _utc_now()
    if not _timestamp_is_valid(timestamp_value):
        raise ProofTimestampAnchorError("TIMESTAMP_CLOCK_INVALID")
    payload = _timestamp_payload(
        proof_bundle_hash=verification.bundle_hash,
        timestamp=timestamp_value,
        validation_status="VERIFIED",
    )
    anchor = {
        "schema": TIMESTAMP_ANCHOR_SCHEMA,
        "proof_bundle_hash": verification.bundle_hash,
        "utc_timestamp": timestamp_value,
        "canonical_timestamp_payload": payload,
        "governance_module_versions": dict(MODULE_VERSIONS),
        "validation_status": "VERIFIED",
        "anchor_hash": _sha256_hex(_canonical_json(payload).encode("utf-8")),
    }
    _assert_anchor_safe(anchor)
    return anchor


def anchor_proof_bundle_file(proof_bundle_path: Path, output_path: Path, *, timestamp: str | None = None) -> dict[str, Any]:
    anchor = anchor_proof_bundle(_load_json_object(proof_bundle_path, "timestamp_proof_bundle_invalid"), timestamp=timestamp)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(_canonical_json(anchor) + "\n", encoding="utf-8")
    return anchor


def verify_proof_timestamp_anchor(
    anchor: dict[str, Any],
    *,
    proof_bundle: dict[str, Any] | None = None,
) -> ProofTimestampVerificationResult:
    errors: list[str] = []
    if not isinstance(anchor, dict) or anchor.get("schema") != TIMESTAMP_ANCHOR_SCHEMA:
        errors.append("TIMESTAMP_PAYLOAD_INVALID")
    proof_bundle_hash = str(anchor.get("proof_bundle_hash", "")) if isinstance(anchor, dict) else ""
    timestamp = str(anchor.get("utc_timestamp", "")) if isinstance(anchor, dict) else ""
    validation_status = str(anchor.get("validation_status", "")) if isinstance(anchor, dict) else ""
    payload = anchor.get("canonical_timestamp_payload") if isinstance(anchor, dict) else None
    anchor_hash = str(anchor.get("anchor_hash", "")) if isinstance(anchor, dict) else ""
    if not _is_sha256_hex(proof_bundle_hash):
        errors.append("TIMESTAMP_BUNDLE_HASH_MISSING")
    if not _timestamp_is_valid(timestamp):
        errors.append("TIMESTAMP_CLOCK_INVALID")
    expected_payload = _timestamp_payload(
        proof_bundle_hash=proof_bundle_hash,
        timestamp=timestamp,
        validation_status=validation_status,
    )
    if payload != expected_payload or not _is_sha256_hex(anchor_hash):
        errors.append("TIMESTAMP_PAYLOAD_INVALID")
    elif anchor_hash != _sha256_hex(_canonical_json(expected_payload).encode("utf-8")):
        errors.append("TIMESTAMP_ANCHOR_UNVERIFIED")
    if validation_status != "VERIFIED":
        errors.append("TIMESTAMP_ANCHOR_UNVERIFIED")
    if proof_bundle is not None:
        try:
            proof_verification = verify_policy_proof_bundle(proof_bundle)
        except PolicyProofBundleError:
            errors.append("TIMESTAMP_ANCHOR_UNVERIFIED")
        else:
            if not proof_verification.valid or proof_verification.bundle_hash != proof_bundle_hash:
                errors.append("TIMESTAMP_ANCHOR_UNVERIFIED")
    try:
        _assert_anchor_safe(anchor)
    except ProofTimestampAnchorError:
        errors.append("TIMESTAMP_DIAGNOSTICS_UNSAFE")
    return ProofTimestampVerificationResult(
        valid=not errors,
        errors=tuple(dict.fromkeys(errors)),
        proof_bundle_hash=proof_bundle_hash,
        timestamp=timestamp,
        anchor_hash=anchor_hash,
        validation_status=validation_status,
    )


def verify_proof_timestamp_anchor_file(
    anchor_path: Path,
    *,
    proof_bundle_path: Path | None = None,
) -> ProofTimestampVerificationResult:
    proof_bundle = _load_json_object(proof_bundle_path, "timestamp_proof_bundle_invalid") if proof_bundle_path else None
    return verify_proof_timestamp_anchor(
        _load_json_object(anchor_path, "timestamp_anchor_invalid"),
        proof_bundle=proof_bundle,
    )


def explain_timestamp_anchor(root: Path, code: str) -> dict[str, str]:
    registry = load_timestamp_anchor_error_registry(root)
    if code not in registry:
        raise ProofTimestampAnchorError("timestamp_anchor_error_unknown:" + code)
    return {"code": code, **registry[code]}


def timestamp_anchor_summary(anchor: dict[str, Any]) -> dict[str, Any]:
    verification = verify_proof_timestamp_anchor(anchor)
    return {
        "valid": verification.valid,
        "error_codes": list(verification.errors),
        "proof_bundle_hash": verification.proof_bundle_hash,
        "timestamp": verification.timestamp,
        "anchor_hash": verification.anchor_hash,
        "validation_status": verification.validation_status,
    }


def redacted_timestamp_anchor_payload(payload: Any) -> Any:
    return redacted_policy_payload(payload)


def assert_timestamp_anchor_safe(payload: Any) -> None:
    _assert_anchor_safe(payload)


def _timestamp_payload(*, proof_bundle_hash: str, timestamp: str, validation_status: str) -> dict[str, Any]:
    return {
        "governance_module_versions": dict(MODULE_VERSIONS),
        "proof_bundle_hash": proof_bundle_hash,
        "utc_timestamp": timestamp,
        "validation_status": validation_status,
    }


def _assert_anchor_safe(payload: Any) -> None:
    try:
        redacted = redacted_policy_payload(payload)
        assert_policy_diagnostics_safe(redacted)
        assert_simulation_diagnostics_safe(redacted)
        assert_parity_diagnostics_safe(redacted)
        assert_proof_bundle_safe(redacted)
        if redacted != payload:
            raise ProofTimestampAnchorError("TIMESTAMP_DIAGNOSTICS_UNSAFE")
    except Exception as exc:
        if isinstance(exc, ProofTimestampAnchorError):
            raise
        raise ProofTimestampAnchorError("TIMESTAMP_DIAGNOSTICS_UNSAFE") from exc


def _load_json_object(path: Path | None, failure_code: str) -> dict[str, Any]:
    if path is None:
        raise ProofTimestampAnchorError(failure_code)
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        raise ProofTimestampAnchorError(failure_code) from exc
    if not isinstance(payload, dict):
        raise ProofTimestampAnchorError(failure_code)
    return payload


def _canonical_json(payload: Any) -> str:
    try:
        return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    except (TypeError, ValueError) as exc:
        raise ProofTimestampAnchorError("TIMESTAMP_PAYLOAD_INVALID") from exc


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
