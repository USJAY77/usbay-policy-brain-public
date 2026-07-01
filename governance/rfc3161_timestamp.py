from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from governance.policy_pack import assert_policy_diagnostics_safe, redacted_policy_payload
from governance.policy_parity import assert_parity_diagnostics_safe
from governance.policy_proof_bundle import assert_proof_bundle_safe, verify_policy_proof_bundle
from governance.policy_simulation import assert_simulation_diagnostics_safe
from governance.proof_timestamp_anchor import (
    MODULE_VERSIONS as TIMESTAMP_MODULE_VERSIONS,
    assert_timestamp_anchor_safe,
    verify_proof_timestamp_anchor,
)
from scripts.verify_timestamp_chain import DEFAULT_SCHEMA, verify as verify_timestamp_chain

RFC3161_REQUEST_SCHEMA = "usbay.governance_rfc3161_timestamp_request_preflight.v1"
RFC3161_TIMESTAMP_AUTHORITY_SCHEMA = "usbay.governance.rfc3161_timestamp_authority.v1"
RFC3161_ERROR_REGISTRY_PATH = Path("governance/rfc3161_timestamp_errors.json")
RFC3161_ERROR_SCHEMA = "usbay.governance_rfc3161_timestamp_error_registry.v1"
RFC3161_TIMESTAMP_CHAIN_ENV = "USBAY_RFC3161_TIMESTAMP_CHAIN_PATH"
RFC3161_TIMESTAMP_SCHEMA_ENV = "USBAY_RFC3161_TIMESTAMP_SCHEMA_PATH"
CANONICAL_TIMESTAMP_AUTHORITY_MODULE = "governance.rfc3161_timestamp"
REASON_RFC3161_TIMESTAMP_CHAIN_INVALID = "RFC3161_TIMESTAMP_CHAIN_INVALID"
REASON_RFC3161_TIMESTAMP_AUTHORITY_DUPLICATE = "RFC3161_TIMESTAMP_AUTHORITY_DUPLICATE"
RFC3161_ERROR_CODES = (
    "RFC3161_BUNDLE_HASH_MISSING",
    "RFC3161_ANCHOR_HASH_MISSING",
    "RFC3161_REQUEST_INVALID",
    "RFC3161_NONCE_INVALID",
    "RFC3161_DIAGNOSTICS_UNSAFE",
    "RFC3161_TSA_RESPONSE_UNVERIFIED",
)
DEFAULT_POLICY_OID_PLACEHOLDER = "1.3.6.1.4.1.55555.1.3161.0"
MODULE_VERSIONS = {
    **TIMESTAMP_MODULE_VERSIONS,
    "rfc3161_timestamp_preflight": RFC3161_REQUEST_SCHEMA,
}


class RFC3161TimestampError(RuntimeError):
    pass


@dataclass(frozen=True)
class RFC3161RequestVerificationResult:
    valid: bool
    errors: tuple[str, ...]
    proof_bundle_hash: str
    timestamp_anchor_hash: str
    canonical_request_digest: str
    nonce: str
    requested_policy_oid: str
    tsa_response_status: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "valid": self.valid,
            "errors": list(self.errors),
            "proof_bundle_hash": self.proof_bundle_hash,
            "timestamp_anchor_hash": self.timestamp_anchor_hash,
            "canonical_request_digest": self.canonical_request_digest,
            "nonce": self.nonce,
            "requested_policy_oid": self.requested_policy_oid,
            "tsa_response_status": self.tsa_response_status,
        }


def load_rfc3161_error_registry(root: Path) -> dict[str, dict[str, str]]:
    path = root / RFC3161_ERROR_REGISTRY_PATH
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        raise RFC3161TimestampError("rfc3161_error_registry_missing") from exc
    if not isinstance(payload, dict) or payload.get("schema") != RFC3161_ERROR_SCHEMA:
        raise RFC3161TimestampError("rfc3161_error_registry_invalid")
    raw_errors = payload.get("errors")
    if not isinstance(raw_errors, list):
        raise RFC3161TimestampError("rfc3161_error_registry_invalid")
    registry: dict[str, dict[str, str]] = {}
    for entry in raw_errors:
        if not isinstance(entry, dict) or not entry.get("code"):
            raise RFC3161TimestampError("rfc3161_error_registry_invalid")
        registry[str(entry["code"])] = {
            "description": str(entry.get("description", "")),
            "fail_closed_reason": str(entry.get("fail_closed_reason", "")),
        }
    missing = sorted(set(RFC3161_ERROR_CODES) - set(registry))
    if missing:
        raise RFC3161TimestampError("rfc3161_error_registry_incomplete:" + ",".join(missing))
    return registry


def prepare_rfc3161_request_material(
    proof_bundle: dict[str, Any],
    timestamp_anchor: dict[str, Any],
    *,
    nonce: str | None = None,
    requested_policy_oid: str = DEFAULT_POLICY_OID_PLACEHOLDER,
) -> dict[str, Any]:
    proof_verification = verify_policy_proof_bundle(proof_bundle)
    if not proof_verification.valid:
        raise RFC3161TimestampError("RFC3161_BUNDLE_HASH_MISSING")
    anchor_verification = verify_proof_timestamp_anchor(timestamp_anchor, proof_bundle=proof_bundle)
    if not anchor_verification.valid:
        raise RFC3161TimestampError("RFC3161_ANCHOR_HASH_MISSING")
    nonce_value = nonce or _deterministic_nonce(
        proof_bundle_hash=proof_verification.bundle_hash,
        timestamp_anchor_hash=anchor_verification.anchor_hash,
        requested_policy_oid=requested_policy_oid,
    )
    if not _is_sha256_hex(nonce_value):
        raise RFC3161TimestampError("RFC3161_NONCE_INVALID")
    metadata = {
        "anchor_validation_status": anchor_verification.validation_status,
        "bundle_parity_verified": proof_verification.parity_verified,
        "simulation_decision": proof_verification.simulation_decision,
        "tsa_network_call": "NOT_REQUESTED",
    }
    payload = _canonical_request_payload(
        proof_bundle_hash=proof_verification.bundle_hash,
        timestamp_anchor_hash=anchor_verification.anchor_hash,
        nonce=nonce_value,
        requested_policy_oid=requested_policy_oid,
        redacted_metadata_summary=metadata,
    )
    request = {
        "schema": RFC3161_REQUEST_SCHEMA,
        "proof_bundle_hash": proof_verification.bundle_hash,
        "timestamp_anchor_hash": anchor_verification.anchor_hash,
        "canonical_request_digest": _sha256_hex(_canonical_json(payload).encode("utf-8")),
        "nonce": nonce_value,
        "requested_policy_oid": requested_policy_oid,
        "redacted_metadata_summary": redacted_policy_payload(metadata),
        "governance_module_versions": dict(MODULE_VERSIONS),
        "tsa_response_status": "NOT_REQUESTED",
    }
    _assert_rfc3161_safe(request)
    return request


def prepare_rfc3161_request_file(
    proof_bundle_path: Path,
    timestamp_anchor_path: Path,
    output_path: Path,
    *,
    nonce: str | None = None,
    requested_policy_oid: str = DEFAULT_POLICY_OID_PLACEHOLDER,
) -> dict[str, Any]:
    request = prepare_rfc3161_request_material(
        _load_json_object(proof_bundle_path, "rfc3161_proof_bundle_invalid"),
        _load_json_object(timestamp_anchor_path, "rfc3161_timestamp_anchor_invalid"),
        nonce=nonce,
        requested_policy_oid=requested_policy_oid,
    )
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(_canonical_json(request) + "\n", encoding="utf-8")
    return request


def verify_rfc3161_request_material(request: dict[str, Any]) -> RFC3161RequestVerificationResult:
    errors: list[str] = []
    if not isinstance(request, dict) or request.get("schema") != RFC3161_REQUEST_SCHEMA:
        errors.append("RFC3161_REQUEST_INVALID")
    proof_bundle_hash = str(request.get("proof_bundle_hash", "")) if isinstance(request, dict) else ""
    timestamp_anchor_hash = str(request.get("timestamp_anchor_hash", "")) if isinstance(request, dict) else ""
    digest = str(request.get("canonical_request_digest", "")) if isinstance(request, dict) else ""
    nonce = str(request.get("nonce", "")) if isinstance(request, dict) else ""
    requested_policy_oid = str(request.get("requested_policy_oid", "")) if isinstance(request, dict) else ""
    tsa_response_status = str(request.get("tsa_response_status", "")) if isinstance(request, dict) else ""
    metadata = request.get("redacted_metadata_summary") if isinstance(request, dict) else None
    if not _is_sha256_hex(proof_bundle_hash):
        errors.append("RFC3161_BUNDLE_HASH_MISSING")
    if not _is_sha256_hex(timestamp_anchor_hash):
        errors.append("RFC3161_ANCHOR_HASH_MISSING")
    if not _is_sha256_hex(nonce):
        errors.append("RFC3161_NONCE_INVALID")
    if not isinstance(metadata, dict) or not requested_policy_oid:
        errors.append("RFC3161_REQUEST_INVALID")
    if tsa_response_status != "NOT_REQUESTED":
        errors.append("RFC3161_TSA_RESPONSE_UNVERIFIED")
    if isinstance(metadata, dict):
        payload = _canonical_request_payload(
            proof_bundle_hash=proof_bundle_hash,
            timestamp_anchor_hash=timestamp_anchor_hash,
            nonce=nonce,
            requested_policy_oid=requested_policy_oid,
            redacted_metadata_summary=metadata,
        )
        if not _is_sha256_hex(digest) or digest != _sha256_hex(_canonical_json(payload).encode("utf-8")):
            errors.append("RFC3161_REQUEST_INVALID")
    try:
        _assert_rfc3161_safe(request)
    except RFC3161TimestampError:
        errors.append("RFC3161_DIAGNOSTICS_UNSAFE")
    return RFC3161RequestVerificationResult(
        valid=not errors,
        errors=tuple(dict.fromkeys(errors)),
        proof_bundle_hash=proof_bundle_hash,
        timestamp_anchor_hash=timestamp_anchor_hash,
        canonical_request_digest=digest,
        nonce=nonce,
        requested_policy_oid=requested_policy_oid,
        tsa_response_status=tsa_response_status,
    )


def verify_rfc3161_request_file(path: Path) -> RFC3161RequestVerificationResult:
    return verify_rfc3161_request_material(_load_json_object(path, "rfc3161_request_invalid"))


def timestamp_authority_map() -> dict[str, Any]:
    ownership = [
        {
            "module": "governance.rfc3161_timestamp",
            "role": "owner",
            "surface": "canonical RFC3161 request validation and timestamp authority readiness",
        },
        {
            "module": "governance.proof_timestamp_anchor",
            "role": "provider",
            "surface": "proof bundle timestamp anchor verification consumed by RFC3161 preflight",
        },
        {
            "module": "governance.timestamping",
            "role": "adapter",
            "surface": "generic timestamp verification result interface adapter",
        },
        {
            "module": "scripts.verify_timestamp_chain",
            "role": "adapter",
            "surface": "read-only timestamp chain verifier for readiness evidence",
        },
        {
            "module": "scripts.pb008_timestamp_verifier",
            "role": "deprecated_provider",
            "surface": "PB008 local receipt compatibility adapter; not runtime authority",
        },
    ]
    owners = [entry["module"] for entry in ownership if entry["role"] == "owner"]
    duplicates = owners[1:] if len(owners) > 1 else []
    return {
        "schema": RFC3161_TIMESTAMP_AUTHORITY_SCHEMA,
        "canonical_owner_module": CANONICAL_TIMESTAMP_AUTHORITY_MODULE,
        "ownership": ownership,
        "duplicate_ownership_paths": duplicates,
        "timestamp_authority_status": "VALID" if not duplicates else "BLOCKED",
        "reason_codes": [] if not duplicates else [REASON_RFC3161_TIMESTAMP_AUTHORITY_DUPLICATE],
        "read_only": True,
        "execution_enabled": False,
        "deployment_enabled": False,
        "runtime_modification_enabled": False,
        "connector_write_enabled": False,
    }


def timestamp_chain_readiness_report(
    *,
    chain_path: str | Path | None = None,
    schema_path: str | Path | None = None,
) -> dict[str, Any]:
    configured_chain = chain_path or os.getenv(RFC3161_TIMESTAMP_CHAIN_ENV, "")
    configured_schema = schema_path or os.getenv(RFC3161_TIMESTAMP_SCHEMA_ENV, "")
    authority = timestamp_authority_map()
    if authority["timestamp_authority_status"] != "VALID":
        return {
            **authority,
            "timestamp_chain_configured": bool(configured_chain),
            "timestamp_chain_status": "BLOCKED",
            "reason_codes": authority["reason_codes"],
        }
    if not configured_chain:
        return {
            **authority,
            "timestamp_chain_configured": False,
            "timestamp_chain_path": "",
            "timestamp_schema_path": "",
            "timestamp_chain_status": "VALID",
            "reason_codes": [],
        }
    schema = Path(configured_schema) if configured_schema else DEFAULT_SCHEMA
    chain = Path(configured_chain)
    errors = verify_timestamp_chain(schema, chain)
    return {
        **authority,
        "timestamp_chain_configured": True,
        "timestamp_chain_path": str(chain),
        "timestamp_schema_path": str(schema),
        "timestamp_chain_status": "VALID" if not errors else "BLOCKED",
        "timestamp_authority_status": "VALID" if not errors else "BLOCKED",
        "reason_codes": [] if not errors else [REASON_RFC3161_TIMESTAMP_CHAIN_INVALID, *errors],
        "fail_closed": bool(errors),
    }


def rfc3161_timestamp_audit_evidence(
    *,
    chain_path: str | Path | None = None,
    schema_path: str | Path | None = None,
) -> dict[str, Any]:
    readiness = timestamp_chain_readiness_report(chain_path=chain_path, schema_path=schema_path)
    return {
        "schema": "usbay.governance.rfc3161_timestamp_audit_evidence.v1",
        "canonical_authority": CANONICAL_TIMESTAMP_AUTHORITY_MODULE,
        "authority_map": timestamp_authority_map(),
        "readiness": readiness,
        "timestamp_authority_status": readiness["timestamp_authority_status"],
        "fail_closed": readiness["timestamp_authority_status"] != "VALID",
        "read_only": True,
        "execution_enabled": False,
        "deployment_enabled": False,
        "runtime_modification_enabled": False,
    }


def explain_rfc3161_preflight(root: Path, code: str) -> dict[str, str]:
    registry = load_rfc3161_error_registry(root)
    if code not in registry:
        raise RFC3161TimestampError("rfc3161_error_unknown:" + code)
    return {"code": code, **registry[code]}


def rfc3161_request_summary(request: dict[str, Any]) -> dict[str, Any]:
    verification = verify_rfc3161_request_material(request)
    return {
        "valid": verification.valid,
        "error_codes": list(verification.errors),
        "proof_bundle_hash": verification.proof_bundle_hash,
        "timestamp_anchor_hash": verification.timestamp_anchor_hash,
        "canonical_request_digest": verification.canonical_request_digest,
        "nonce": verification.nonce,
        "requested_policy_oid": verification.requested_policy_oid,
        "tsa_response_status": verification.tsa_response_status,
    }


def redacted_rfc3161_payload(payload: Any) -> Any:
    return redacted_policy_payload(payload)


def assert_rfc3161_safe(payload: Any) -> None:
    _assert_rfc3161_safe(payload)


def _canonical_request_payload(
    *,
    proof_bundle_hash: str,
    timestamp_anchor_hash: str,
    nonce: str,
    requested_policy_oid: str,
    redacted_metadata_summary: dict[str, Any],
) -> dict[str, Any]:
    return {
        "governance_module_versions": dict(MODULE_VERSIONS),
        "nonce": nonce,
        "proof_bundle_hash": proof_bundle_hash,
        "redacted_metadata_summary": redacted_metadata_summary,
        "requested_policy_oid": requested_policy_oid,
        "timestamp_anchor_hash": timestamp_anchor_hash,
    }


def _assert_rfc3161_safe(payload: Any) -> None:
    try:
        redacted = redacted_policy_payload(payload)
        assert_policy_diagnostics_safe(redacted)
        assert_simulation_diagnostics_safe(redacted)
        assert_parity_diagnostics_safe(redacted)
        assert_proof_bundle_safe(redacted)
        assert_timestamp_anchor_safe(redacted)
        if redacted != payload:
            raise RFC3161TimestampError("RFC3161_DIAGNOSTICS_UNSAFE")
    except Exception as exc:
        if isinstance(exc, RFC3161TimestampError):
            raise
        raise RFC3161TimestampError("RFC3161_DIAGNOSTICS_UNSAFE") from exc


def _deterministic_nonce(*, proof_bundle_hash: str, timestamp_anchor_hash: str, requested_policy_oid: str) -> str:
    return _sha256_hex(f"{proof_bundle_hash}:{timestamp_anchor_hash}:{requested_policy_oid}".encode("utf-8"))


def _load_json_object(path: Path, failure_code: str) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        raise RFC3161TimestampError(failure_code) from exc
    if not isinstance(payload, dict):
        raise RFC3161TimestampError(failure_code)
    return payload


def _canonical_json(payload: Any) -> str:
    try:
        return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    except (TypeError, ValueError) as exc:
        raise RFC3161TimestampError("RFC3161_REQUEST_INVALID") from exc


def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _is_sha256_hex(value: str) -> bool:
    return len(value) == 64 and all(character in "0123456789abcdef" for character in value)
