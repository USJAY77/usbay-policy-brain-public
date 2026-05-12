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
from governance.rfc3161_timestamp import assert_rfc3161_safe
from governance.signed_auditor_bundle import assert_signed_auditor_bundle_safe
from governance.signed_bundle_timestamp import (
    MODULE_VERSIONS as SIGNED_BUNDLE_TIMESTAMP_MODULE_VERSIONS,
    assert_signed_bundle_timestamp_safe,
    verify_signed_bundle_timestamp,
)
from governance.worm_evidence_manifest import assert_worm_safe

SIGNED_BUNDLE_LTV_SCHEMA = "usbay.governance_signed_bundle_ltv.v1"
SIGNED_BUNDLE_LTV_ERROR_REGISTRY_PATH = Path("governance/signed_bundle_ltv_errors.json")
SIGNED_BUNDLE_LTV_ERROR_SCHEMA = "usbay.governance_signed_bundle_ltv_error_registry.v1"
SIGNED_BUNDLE_LTV_ERROR_CODES = (
    "SIGNED_BUNDLE_LTV_TIMESTAMP_MISSING",
    "SIGNED_BUNDLE_LTV_CERT_CHAIN_MISSING",
    "SIGNED_BUNDLE_LTV_TRUST_ANCHOR_MISSING",
    "SIGNED_BUNDLE_LTV_REVOCATION_MISSING",
    "SIGNED_BUNDLE_LTV_HASH_MISMATCH",
    "SIGNED_BUNDLE_LTV_POLICY_INVALID",
    "SIGNED_BUNDLE_LTV_REPLAY_DETECTED",
    "SIGNED_BUNDLE_LTV_DIAGNOSTICS_UNSAFE",
)
ALLOWED_REVOCATION_EVIDENCE_TYPES = {"ocsp", "crl", "ocsp_crl", "offline_mock"}
MODULE_VERSIONS = {
    **SIGNED_BUNDLE_TIMESTAMP_MODULE_VERSIONS,
    "signed_bundle_ltv": SIGNED_BUNDLE_LTV_SCHEMA,
}


class SignedBundleLTVError(RuntimeError):
    pass


@dataclass(frozen=True)
class SignedBundleLTVVerificationResult:
    valid: bool
    errors: tuple[str, ...]
    ltv_evidence_id: str
    timestamp_attachment_id: str
    signed_bundle_id: str
    timestamp_token_hash: str
    trust_anchor_fingerprint: str
    retention_policy_label: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "valid": self.valid,
            "errors": list(self.errors),
            "ltv_evidence_id": self.ltv_evidence_id,
            "timestamp_attachment_id": self.timestamp_attachment_id,
            "signed_bundle_id": self.signed_bundle_id,
            "timestamp_token_hash": self.timestamp_token_hash,
            "trust_anchor_fingerprint": self.trust_anchor_fingerprint,
            "retention_policy_label": self.retention_policy_label,
        }


def load_signed_bundle_ltv_error_registry(root: Path) -> dict[str, dict[str, str]]:
    path = root / SIGNED_BUNDLE_LTV_ERROR_REGISTRY_PATH
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        raise SignedBundleLTVError("signed_bundle_ltv_error_registry_missing") from exc
    if not isinstance(payload, dict) or payload.get("schema") != SIGNED_BUNDLE_LTV_ERROR_SCHEMA:
        raise SignedBundleLTVError("signed_bundle_ltv_error_registry_invalid")
    raw_errors = payload.get("errors")
    if not isinstance(raw_errors, list):
        raise SignedBundleLTVError("signed_bundle_ltv_error_registry_invalid")
    registry: dict[str, dict[str, str]] = {}
    for entry in raw_errors:
        if not isinstance(entry, dict) or not entry.get("code"):
            raise SignedBundleLTVError("signed_bundle_ltv_error_registry_invalid")
        registry[str(entry["code"])] = {
            "description": str(entry.get("description", "")),
            "fail_closed_reason": str(entry.get("fail_closed_reason", "")),
        }
    missing = sorted(set(SIGNED_BUNDLE_LTV_ERROR_CODES) - set(registry))
    if missing:
        raise SignedBundleLTVError("signed_bundle_ltv_error_registry_incomplete:" + ",".join(missing))
    return registry


def create_signed_bundle_ltv_evidence(
    timestamp_attachment: dict[str, Any],
    *,
    tsa_certificate_fingerprint: str,
    tsa_certificate_chain_fingerprints: list[str],
    trust_anchor_fingerprint: str,
    revocation_evidence_type: str,
    revocation_evidence_hash: str,
    revocation_checked_at_utc: str | None = None,
    validation_policy_id: str,
) -> dict[str, Any]:
    timestamp_verification = verify_signed_bundle_timestamp(timestamp_attachment)
    if not timestamp_verification.valid:
        raise SignedBundleLTVError("SIGNED_BUNDLE_LTV_TIMESTAMP_MISSING")
    checked_at = revocation_checked_at_utc or _utc_now()
    if not _timestamp_is_valid(checked_at):
        raise SignedBundleLTVError("SIGNED_BUNDLE_LTV_REVOCATION_MISSING")
    if not _fingerprint_valid(tsa_certificate_fingerprint) or not _chain_valid(tsa_certificate_chain_fingerprints):
        raise SignedBundleLTVError("SIGNED_BUNDLE_LTV_CERT_CHAIN_MISSING")
    if not _fingerprint_valid(trust_anchor_fingerprint) or trust_anchor_fingerprint not in tsa_certificate_chain_fingerprints:
        raise SignedBundleLTVError("SIGNED_BUNDLE_LTV_TRUST_ANCHOR_MISSING")
    if revocation_evidence_type not in ALLOWED_REVOCATION_EVIDENCE_TYPES or not _fingerprint_valid(revocation_evidence_hash):
        raise SignedBundleLTVError("SIGNED_BUNDLE_LTV_REVOCATION_MISSING")
    if not _policy_valid(validation_policy_id):
        raise SignedBundleLTVError("SIGNED_BUNDLE_LTV_POLICY_INVALID")
    payload = {
        "governance_module_versions": dict(MODULE_VERSIONS),
        "retention_policy_label": timestamp_verification.retention_policy_label,
        "revocation_checked_at_utc": checked_at,
        "revocation_evidence_hash": revocation_evidence_hash,
        "revocation_evidence_type": revocation_evidence_type,
        "signed_bundle_id": timestamp_verification.signed_bundle_id,
        "timestamp_attachment_id": timestamp_verification.timestamp_attachment_id,
        "timestamp_token_hash": timestamp_verification.timestamp_token_hash,
        "trust_anchor_fingerprint": trust_anchor_fingerprint,
        "tsa_certificate_chain_fingerprints": list(tsa_certificate_chain_fingerprints),
        "tsa_certificate_fingerprint": tsa_certificate_fingerprint,
        "validation_policy_id": validation_policy_id,
    }
    evidence = {
        "schema": SIGNED_BUNDLE_LTV_SCHEMA,
        "ltv_evidence_id": _sha256_hex(_canonical_json(payload).encode("utf-8")),
        **payload,
    }
    _assert_ltv_safe(evidence)
    return evidence


def create_signed_bundle_ltv_evidence_file(
    timestamp_attachment_path: Path,
    output_path: Path,
    *,
    tsa_certificate_fingerprint: str,
    tsa_certificate_chain_fingerprints: list[str],
    trust_anchor_fingerprint: str,
    revocation_evidence_type: str,
    revocation_evidence_hash: str,
    revocation_checked_at_utc: str | None = None,
    validation_policy_id: str,
) -> dict[str, Any]:
    evidence = create_signed_bundle_ltv_evidence(
        _load_json_object(timestamp_attachment_path, "SIGNED_BUNDLE_LTV_TIMESTAMP_MISSING"),
        tsa_certificate_fingerprint=tsa_certificate_fingerprint,
        tsa_certificate_chain_fingerprints=tsa_certificate_chain_fingerprints,
        trust_anchor_fingerprint=trust_anchor_fingerprint,
        revocation_evidence_type=revocation_evidence_type,
        revocation_evidence_hash=revocation_evidence_hash,
        revocation_checked_at_utc=revocation_checked_at_utc,
        validation_policy_id=validation_policy_id,
    )
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(_canonical_json(evidence) + "\n", encoding="utf-8")
    return evidence


def verify_signed_bundle_ltv_evidence(
    evidence: dict[str, Any],
    *,
    timestamp_attachment: dict[str, Any] | None = None,
    existing_evidence: list[dict[str, Any]] | None = None,
) -> SignedBundleLTVVerificationResult:
    errors: list[str] = []
    if not isinstance(evidence, dict) or evidence.get("schema") != SIGNED_BUNDLE_LTV_SCHEMA:
        errors.append("SIGNED_BUNDLE_LTV_TIMESTAMP_MISSING")
    ltv_id = str(evidence.get("ltv_evidence_id", "")) if isinstance(evidence, dict) else ""
    timestamp_attachment_id = str(evidence.get("timestamp_attachment_id", "")) if isinstance(evidence, dict) else ""
    signed_bundle_id = str(evidence.get("signed_bundle_id", "")) if isinstance(evidence, dict) else ""
    timestamp_token_hash = str(evidence.get("timestamp_token_hash", "")) if isinstance(evidence, dict) else ""
    tsa_certificate_fingerprint = str(evidence.get("tsa_certificate_fingerprint", "")) if isinstance(evidence, dict) else ""
    chain = evidence.get("tsa_certificate_chain_fingerprints") if isinstance(evidence, dict) else None
    trust_anchor_fingerprint = str(evidence.get("trust_anchor_fingerprint", "")) if isinstance(evidence, dict) else ""
    revocation_type = str(evidence.get("revocation_evidence_type", "")) if isinstance(evidence, dict) else ""
    revocation_hash = str(evidence.get("revocation_evidence_hash", "")) if isinstance(evidence, dict) else ""
    checked_at = str(evidence.get("revocation_checked_at_utc", "")) if isinstance(evidence, dict) else ""
    validation_policy_id = str(evidence.get("validation_policy_id", "")) if isinstance(evidence, dict) else ""
    retention_policy_label = str(evidence.get("retention_policy_label", "")) if isinstance(evidence, dict) else ""
    if not _fingerprint_valid(timestamp_attachment_id) or not _fingerprint_valid(signed_bundle_id) or not _fingerprint_valid(timestamp_token_hash):
        errors.append("SIGNED_BUNDLE_LTV_TIMESTAMP_MISSING")
    if not _fingerprint_valid(tsa_certificate_fingerprint) or not _chain_valid(chain):
        errors.append("SIGNED_BUNDLE_LTV_CERT_CHAIN_MISSING")
        chain = []
    if not _fingerprint_valid(trust_anchor_fingerprint) or trust_anchor_fingerprint not in chain:
        errors.append("SIGNED_BUNDLE_LTV_TRUST_ANCHOR_MISSING")
    if revocation_type not in ALLOWED_REVOCATION_EVIDENCE_TYPES or not _fingerprint_valid(revocation_hash) or not _timestamp_is_valid(checked_at):
        errors.append("SIGNED_BUNDLE_LTV_REVOCATION_MISSING")
    if not _policy_valid(validation_policy_id):
        errors.append("SIGNED_BUNDLE_LTV_POLICY_INVALID")
    payload = _ltv_payload(evidence)
    if not _fingerprint_valid(ltv_id) or ltv_id != _sha256_hex(_canonical_json(payload).encode("utf-8")):
        errors.append("SIGNED_BUNDLE_LTV_HASH_MISMATCH")
    if timestamp_attachment is not None:
        timestamp_verification = verify_signed_bundle_timestamp(timestamp_attachment)
        if (
            not timestamp_verification.valid
            or timestamp_verification.timestamp_attachment_id != timestamp_attachment_id
            or timestamp_verification.signed_bundle_id != signed_bundle_id
            or timestamp_verification.timestamp_token_hash != timestamp_token_hash
            or timestamp_verification.retention_policy_label != retention_policy_label
        ):
            errors.append("SIGNED_BUNDLE_LTV_HASH_MISMATCH")
    for existing in existing_evidence or []:
        if isinstance(existing, dict) and existing.get("ltv_evidence_id") == ltv_id:
            errors.append("SIGNED_BUNDLE_LTV_REPLAY_DETECTED")
    try:
        _assert_ltv_safe(evidence)
    except SignedBundleLTVError:
        errors.append("SIGNED_BUNDLE_LTV_DIAGNOSTICS_UNSAFE")
    return SignedBundleLTVVerificationResult(
        valid=not errors,
        errors=tuple(dict.fromkeys(errors)),
        ltv_evidence_id=ltv_id,
        timestamp_attachment_id=timestamp_attachment_id,
        signed_bundle_id=signed_bundle_id,
        timestamp_token_hash=timestamp_token_hash,
        trust_anchor_fingerprint=trust_anchor_fingerprint,
        retention_policy_label=retention_policy_label,
    )


def verify_signed_bundle_ltv_evidence_file(
    evidence_path: Path,
    *,
    timestamp_attachment_path: Path | None = None,
    existing_evidence_paths: list[Path] | None = None,
) -> SignedBundleLTVVerificationResult:
    timestamp_attachment = _load_json_object(timestamp_attachment_path, "SIGNED_BUNDLE_LTV_TIMESTAMP_MISSING") if timestamp_attachment_path else None
    existing = [_load_json_object(path, "signed_bundle_ltv_existing_invalid") for path in existing_evidence_paths or []]
    return verify_signed_bundle_ltv_evidence(
        _load_json_object(evidence_path, "signed_bundle_ltv_invalid"),
        timestamp_attachment=timestamp_attachment,
        existing_evidence=existing,
    )


def explain_signed_bundle_ltv_failure(root: Path, code: str) -> dict[str, str]:
    registry = load_signed_bundle_ltv_error_registry(root)
    if code not in registry:
        raise SignedBundleLTVError("signed_bundle_ltv_error_unknown:" + code)
    return {"code": code, **registry[code]}


def signed_bundle_ltv_summary(evidence: dict[str, Any]) -> dict[str, Any]:
    return verify_signed_bundle_ltv_evidence(evidence).to_dict()


def redacted_signed_bundle_ltv_payload(payload: Any) -> Any:
    return redacted_policy_payload(payload)


def assert_signed_bundle_ltv_safe(payload: Any) -> None:
    _assert_ltv_safe(payload)


def _ltv_payload(evidence: dict[str, Any]) -> dict[str, Any]:
    return {
        "governance_module_versions": evidence.get("governance_module_versions", {}),
        "retention_policy_label": evidence.get("retention_policy_label", ""),
        "revocation_checked_at_utc": evidence.get("revocation_checked_at_utc", ""),
        "revocation_evidence_hash": evidence.get("revocation_evidence_hash", ""),
        "revocation_evidence_type": evidence.get("revocation_evidence_type", ""),
        "signed_bundle_id": evidence.get("signed_bundle_id", ""),
        "timestamp_attachment_id": evidence.get("timestamp_attachment_id", ""),
        "timestamp_token_hash": evidence.get("timestamp_token_hash", ""),
        "trust_anchor_fingerprint": evidence.get("trust_anchor_fingerprint", ""),
        "tsa_certificate_chain_fingerprints": evidence.get("tsa_certificate_chain_fingerprints", []),
        "tsa_certificate_fingerprint": evidence.get("tsa_certificate_fingerprint", ""),
        "validation_policy_id": evidence.get("validation_policy_id", ""),
    }


def _chain_valid(chain: Any) -> bool:
    return isinstance(chain, list) and bool(chain) and all(isinstance(item, str) and _fingerprint_valid(item) for item in chain) and len(set(chain)) == len(chain)


def _fingerprint_valid(value: str) -> bool:
    return len(value) == 64 and all(character in "0123456789abcdef" for character in value)


def _policy_valid(value: str) -> bool:
    return bool(value) and all(part.replace("-", "").replace("_", "").isalnum() for part in value.split(".")) and "." in value


def _assert_ltv_safe(payload: Any) -> None:
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
        assert_signed_bundle_timestamp_safe(redacted)
        if redacted != payload:
            raise SignedBundleLTVError("SIGNED_BUNDLE_LTV_DIAGNOSTICS_UNSAFE")
    except Exception as exc:
        if isinstance(exc, SignedBundleLTVError):
            raise
        raise SignedBundleLTVError("SIGNED_BUNDLE_LTV_DIAGNOSTICS_UNSAFE") from exc


def _load_json_object(path: Path | None, failure_code: str) -> dict[str, Any]:
    if path is None:
        raise SignedBundleLTVError(failure_code)
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        raise SignedBundleLTVError(failure_code) from exc
    if not isinstance(payload, dict):
        raise SignedBundleLTVError(failure_code)
    return payload


def _canonical_json(payload: Any) -> str:
    try:
        return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    except (TypeError, ValueError) as exc:
        raise SignedBundleLTVError("SIGNED_BUNDLE_LTV_HASH_MISMATCH") from exc


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
