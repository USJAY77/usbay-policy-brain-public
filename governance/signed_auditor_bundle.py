from __future__ import annotations

import base64
import hashlib
import json
import os
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from governance.auditor_verification_bundle import (
    MODULE_VERSIONS as AUDITOR_BUNDLE_MODULE_VERSIONS,
    assert_auditor_bundle_safe,
    verify_auditor_verification_bundle,
)
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
from governance.worm_evidence_manifest import assert_worm_safe

SIGNED_AUDITOR_BUNDLE_SCHEMA = "usbay.governance_signed_auditor_bundle.v1"
SIGNED_AUDITOR_BUNDLE_ERROR_REGISTRY_PATH = Path("governance/signed_auditor_bundle_errors.json")
SIGNED_AUDITOR_BUNDLE_ERROR_SCHEMA = "usbay.governance_signed_auditor_bundle_error_registry.v1"
SIGNED_AUDITOR_BUNDLE_ERROR_CODES = (
    "SIGNED_BUNDLE_MISSING",
    "SIGNED_BUNDLE_HASH_MISMATCH",
    "SIGNED_BUNDLE_SIGNATURE_INVALID",
    "SIGNED_BUNDLE_SIGNER_UNTRUSTED",
    "SIGNED_BUNDLE_REPLAY_DETECTED",
    "SIGNED_BUNDLE_SCOPE_INVALID",
    "SIGNED_BUNDLE_DIAGNOSTICS_UNSAFE",
)
SIGNATURE_ALGORITHM = "Ed25519"
SIGNATURE_PREFIX = "ed25519:"
PRIVATE_KEY_ENV = "USBAY_SIGNED_AUDITOR_BUNDLE_PRIVATE_KEY_PEM"
DEFAULT_TRUST_POLICY_PATH = Path("governance/ci_evidence_trust_policy.json")
MODULE_VERSIONS = {
    **AUDITOR_BUNDLE_MODULE_VERSIONS,
    "signed_auditor_bundle": SIGNED_AUDITOR_BUNDLE_SCHEMA,
}


class SignedAuditorBundleError(RuntimeError):
    pass


@dataclass(frozen=True)
class SignedAuditorBundleVerificationResult:
    valid: bool
    errors: tuple[str, ...]
    signed_bundle_id: str
    auditor_bundle_id: str
    auditor_bundle_hash: str
    signer_key_id: str
    retention_policy_label: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "valid": self.valid,
            "errors": list(self.errors),
            "signed_bundle_id": self.signed_bundle_id,
            "auditor_bundle_id": self.auditor_bundle_id,
            "auditor_bundle_hash": self.auditor_bundle_hash,
            "signer_key_id": self.signer_key_id,
            "retention_policy_label": self.retention_policy_label,
        }


def load_signed_auditor_bundle_error_registry(root: Path) -> dict[str, dict[str, str]]:
    path = root / SIGNED_AUDITOR_BUNDLE_ERROR_REGISTRY_PATH
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        raise SignedAuditorBundleError("signed_auditor_bundle_error_registry_missing") from exc
    if not isinstance(payload, dict) or payload.get("schema") != SIGNED_AUDITOR_BUNDLE_ERROR_SCHEMA:
        raise SignedAuditorBundleError("signed_auditor_bundle_error_registry_invalid")
    raw_errors = payload.get("errors")
    if not isinstance(raw_errors, list):
        raise SignedAuditorBundleError("signed_auditor_bundle_error_registry_invalid")
    registry: dict[str, dict[str, str]] = {}
    for entry in raw_errors:
        if not isinstance(entry, dict) or not entry.get("code"):
            raise SignedAuditorBundleError("signed_auditor_bundle_error_registry_invalid")
        registry[str(entry["code"])] = {
            "description": str(entry.get("description", "")),
            "fail_closed_reason": str(entry.get("fail_closed_reason", "")),
        }
    missing = sorted(set(SIGNED_AUDITOR_BUNDLE_ERROR_CODES) - set(registry))
    if missing:
        raise SignedAuditorBundleError("signed_auditor_bundle_error_registry_incomplete:" + ",".join(missing))
    return registry


def create_signed_auditor_bundle(
    auditor_bundle: dict[str, Any],
    *,
    private_key_pem: str,
    public_key_pem: str,
    signer_id: str,
    trust_policy: dict[str, Any],
    signed_at_utc: str | None = None,
) -> dict[str, Any]:
    bundle_verification = verify_auditor_verification_bundle(auditor_bundle)
    if not bundle_verification.valid:
        raise SignedAuditorBundleError("SIGNED_BUNDLE_MISSING")
    normalized_public_key = normalize_public_key_pem(public_key_pem)
    signer_key_id = signer_key_fingerprint(normalized_public_key)
    signed_at = signed_at_utc or _utc_now()
    if not _timestamp_is_valid(signed_at):
        raise SignedAuditorBundleError("SIGNED_BUNDLE_SCOPE_INVALID")
    if not _signer_trusted(trust_policy, signer_id=signer_id, signer_key_id=signer_key_id, public_key_pem=normalized_public_key, timestamp=signed_at):
        raise SignedAuditorBundleError("SIGNED_BUNDLE_SIGNER_UNTRUSTED")
    payload = {
        "auditor_bundle_hash": _sha256_hex(_canonical_json(auditor_bundle).encode("utf-8")),
        "auditor_bundle_id": bundle_verification.bundle_id,
        "governance_module_versions": dict(MODULE_VERSIONS),
        "retention_policy_label": bundle_verification.retention_policy_label,
        "signature_algorithm": SIGNATURE_ALGORITHM,
        "signed_at_utc": signed_at,
        "signer_id": signer_id,
        "signer_key_id": signer_key_id,
        "verification_scope": dict(sorted(auditor_bundle.get("verification_scope", {}).items())),
    }
    if not _scope_valid(payload["verification_scope"]):
        raise SignedAuditorBundleError("SIGNED_BUNDLE_SCOPE_INVALID")
    signed_bundle_id = _sha256_hex(_canonical_json(payload).encode("utf-8"))
    envelope = {
        "schema": SIGNED_AUDITOR_BUNDLE_SCHEMA,
        "signed_bundle_id": signed_bundle_id,
        **payload,
    }
    envelope["signature"] = SIGNATURE_PREFIX + _ed25519_sign(_canonical_json(_signature_payload(envelope)), private_key_pem)
    _assert_signed_bundle_safe(envelope)
    return envelope


def create_signed_auditor_bundle_file(
    auditor_bundle_path: Path,
    output_path: Path,
    *,
    private_key_pem: str,
    public_key_pem: str,
    signer_id: str,
    trust_policy: dict[str, Any],
    signed_at_utc: str | None = None,
) -> dict[str, Any]:
    envelope = create_signed_auditor_bundle(
        _load_json_object(auditor_bundle_path, "SIGNED_BUNDLE_MISSING"),
        private_key_pem=private_key_pem,
        public_key_pem=public_key_pem,
        signer_id=signer_id,
        trust_policy=trust_policy,
        signed_at_utc=signed_at_utc,
    )
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(_canonical_json(envelope) + "\n", encoding="utf-8")
    return envelope


def verify_signed_auditor_bundle(
    envelope: dict[str, Any],
    *,
    auditor_bundle: dict[str, Any] | None = None,
    trust_policy: dict[str, Any] | None = None,
    existing_envelopes: list[dict[str, Any]] | None = None,
) -> SignedAuditorBundleVerificationResult:
    errors: list[str] = []
    if not isinstance(envelope, dict) or envelope.get("schema") != SIGNED_AUDITOR_BUNDLE_SCHEMA:
        errors.append("SIGNED_BUNDLE_MISSING")
    signed_bundle_id = str(envelope.get("signed_bundle_id", "")) if isinstance(envelope, dict) else ""
    auditor_bundle_id = str(envelope.get("auditor_bundle_id", "")) if isinstance(envelope, dict) else ""
    auditor_bundle_hash = str(envelope.get("auditor_bundle_hash", "")) if isinstance(envelope, dict) else ""
    signer_id = str(envelope.get("signer_id", "")) if isinstance(envelope, dict) else ""
    signer_key_id = str(envelope.get("signer_key_id", "")) if isinstance(envelope, dict) else ""
    retention_policy_label = str(envelope.get("retention_policy_label", "")) if isinstance(envelope, dict) else ""
    signature = str(envelope.get("signature", "")) if isinstance(envelope, dict) else ""
    scope = envelope.get("verification_scope") if isinstance(envelope, dict) else None
    signed_at = str(envelope.get("signed_at_utc", "")) if isinstance(envelope, dict) else ""
    if not _is_sha256_hex(signed_bundle_id) or not _is_sha256_hex(auditor_bundle_id) or not _is_sha256_hex(auditor_bundle_hash):
        errors.append("SIGNED_BUNDLE_HASH_MISMATCH")
    if envelope.get("signature_algorithm") != SIGNATURE_ALGORITHM:
        errors.append("SIGNED_BUNDLE_SIGNATURE_INVALID")
    if not _scope_valid(scope) or not _timestamp_is_valid(signed_at) or not retention_policy_label:
        errors.append("SIGNED_BUNDLE_SCOPE_INVALID")
    payload = _envelope_payload(envelope)
    if not _is_sha256_hex(signed_bundle_id) or signed_bundle_id != _sha256_hex(_canonical_json(payload).encode("utf-8")):
        errors.append("SIGNED_BUNDLE_HASH_MISMATCH")
    if auditor_bundle is not None:
        bundle_verification = verify_auditor_verification_bundle(auditor_bundle)
        if (
            not bundle_verification.valid
            or bundle_verification.bundle_id != auditor_bundle_id
            or bundle_verification.retention_policy_label != retention_policy_label
            or _sha256_hex(_canonical_json(auditor_bundle).encode("utf-8")) != auditor_bundle_hash
        ):
            errors.append("SIGNED_BUNDLE_HASH_MISMATCH")
    trusted_public_key = _trusted_public_key(trust_policy or {}, signer_id=signer_id, signer_key_id=signer_key_id, timestamp=signed_at)
    if not trusted_public_key:
        errors.append("SIGNED_BUNDLE_SIGNER_UNTRUSTED")
    elif not _verify_signature(envelope, trusted_public_key):
        errors.append("SIGNED_BUNDLE_SIGNATURE_INVALID")
    for existing in existing_envelopes or []:
        if isinstance(existing, dict) and existing.get("signed_bundle_id") == signed_bundle_id:
            errors.append("SIGNED_BUNDLE_REPLAY_DETECTED")
    try:
        _assert_signed_bundle_safe(envelope)
    except SignedAuditorBundleError:
        errors.append("SIGNED_BUNDLE_DIAGNOSTICS_UNSAFE")
    return SignedAuditorBundleVerificationResult(
        valid=not errors,
        errors=tuple(dict.fromkeys(errors)),
        signed_bundle_id=signed_bundle_id,
        auditor_bundle_id=auditor_bundle_id,
        auditor_bundle_hash=auditor_bundle_hash,
        signer_key_id=signer_key_id,
        retention_policy_label=retention_policy_label,
    )


def verify_signed_auditor_bundle_file(
    envelope_path: Path,
    *,
    auditor_bundle_path: Path | None = None,
    trust_policy_path: Path | None = None,
    existing_envelope_paths: list[Path] | None = None,
) -> SignedAuditorBundleVerificationResult:
    trust_policy = load_trust_policy(trust_policy_path) if trust_policy_path else {}
    auditor_bundle = _load_json_object(auditor_bundle_path, "SIGNED_BUNDLE_MISSING") if auditor_bundle_path else None
    existing = [_load_json_object(path, "signed_bundle_existing_invalid") for path in existing_envelope_paths or []]
    return verify_signed_auditor_bundle(
        _load_json_object(envelope_path, "signed_bundle_invalid"),
        auditor_bundle=auditor_bundle,
        trust_policy=trust_policy,
        existing_envelopes=existing,
    )


def explain_signed_auditor_bundle_failure(root: Path, code: str) -> dict[str, str]:
    registry = load_signed_auditor_bundle_error_registry(root)
    if code not in registry:
        raise SignedAuditorBundleError("signed_auditor_bundle_error_unknown:" + code)
    return {"code": code, **registry[code]}


def signed_auditor_bundle_summary(envelope: dict[str, Any]) -> dict[str, Any]:
    verification = verify_signed_auditor_bundle(envelope)
    return verification.to_dict()


def load_trust_policy(path: Path) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        raise SignedAuditorBundleError("SIGNED_BUNDLE_SIGNER_UNTRUSTED") from exc
    if not isinstance(payload, dict):
        raise SignedAuditorBundleError("SIGNED_BUNDLE_SIGNER_UNTRUSTED")
    return payload


def public_key_from_private_key(private_key_pem: str) -> str:
    private_key = _load_private_key(private_key_pem)
    return private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("utf-8")


def normalize_public_key_pem(public_key_pem: str) -> str:
    if not isinstance(public_key_pem, str) or not public_key_pem.strip():
        raise SignedAuditorBundleError("SIGNED_BUNDLE_SIGNER_UNTRUSTED")
    normalized = public_key_pem.strip().replace("\\r\\n", "\n").replace("\\n", "\n").replace("\r\n", "\n").replace("\r", "\n")
    lines = [line.strip() for line in normalized.split("\n") if line.strip()]
    normalized = "\n".join(lines) + "\n"
    try:
        key = serialization.load_pem_public_key(normalized.encode("utf-8"))
    except Exception as exc:
        raise SignedAuditorBundleError("SIGNED_BUNDLE_SIGNER_UNTRUSTED") from exc
    if not isinstance(key, Ed25519PublicKey):
        raise SignedAuditorBundleError("SIGNED_BUNDLE_SIGNER_UNTRUSTED")
    return key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("utf-8")


def signer_key_fingerprint(public_key_pem: str) -> str:
    key = serialization.load_pem_public_key(normalize_public_key_pem(public_key_pem).encode("utf-8"))
    if not isinstance(key, Ed25519PublicKey):
        raise SignedAuditorBundleError("SIGNED_BUNDLE_SIGNER_UNTRUSTED")
    der = key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return hashlib.sha256(der).hexdigest()


def redacted_signed_auditor_bundle_payload(payload: Any) -> Any:
    return redacted_policy_payload(payload)


def assert_signed_auditor_bundle_safe(payload: Any) -> None:
    _assert_signed_bundle_safe(payload)


def _trusted_public_key(trust_policy: dict[str, Any], *, signer_id: str, signer_key_id: str, timestamp: str) -> str:
    if not isinstance(trust_policy, dict):
        return ""
    revoked = trust_policy.get("revoked_fingerprints", [])
    if isinstance(revoked, list) and signer_key_id in revoked:
        return ""
    for entry in trust_policy.get("allowed_signers", []):
        if not isinstance(entry, dict):
            continue
        if entry.get("signer_id") != signer_id or entry.get("public_key_fingerprint") != signer_key_id:
            continue
        public_key = str(entry.get("public_key_pem", ""))
        try:
            if signer_key_fingerprint(public_key) != signer_key_id:
                return ""
        except SignedAuditorBundleError:
            return ""
        if not _within_validity(timestamp, str(entry.get("valid_from", "")), str(entry.get("valid_until", ""))):
            return ""
        return normalize_public_key_pem(public_key)
    return ""


def _signer_trusted(trust_policy: dict[str, Any], *, signer_id: str, signer_key_id: str, public_key_pem: str, timestamp: str) -> bool:
    return _trusted_public_key(trust_policy, signer_id=signer_id, signer_key_id=signer_key_id, timestamp=timestamp) == normalize_public_key_pem(public_key_pem)


def _verify_signature(envelope: dict[str, Any], public_key_pem: str) -> bool:
    signature = str(envelope.get("signature", ""))
    if not signature.startswith(SIGNATURE_PREFIX):
        return False
    try:
        signature_bytes = base64.b64decode(signature[len(SIGNATURE_PREFIX) :], validate=True)
        public_key = serialization.load_pem_public_key(normalize_public_key_pem(public_key_pem).encode("utf-8"))
        if not isinstance(public_key, Ed25519PublicKey):
            return False
        public_key.verify(signature_bytes, _canonical_json(_signature_payload(envelope)).encode("utf-8"))
        return True
    except Exception:
        return False


def _ed25519_sign(payload: str, private_key_pem: str) -> str:
    private_key = _load_private_key(private_key_pem)
    return base64.b64encode(private_key.sign(payload.encode("utf-8"))).decode("ascii")


def _load_private_key(private_key_pem: str) -> Ed25519PrivateKey:
    try:
        key = serialization.load_pem_private_key(private_key_pem.encode("utf-8"), password=None)
    except Exception as exc:
        raise SignedAuditorBundleError("SIGNED_BUNDLE_SIGNATURE_INVALID") from exc
    if not isinstance(key, Ed25519PrivateKey):
        raise SignedAuditorBundleError("SIGNED_BUNDLE_SIGNATURE_INVALID")
    return key


def _signature_payload(envelope: dict[str, Any]) -> dict[str, Any]:
    payload = dict(envelope)
    payload.pop("signature", None)
    return payload


def _envelope_payload(envelope: dict[str, Any]) -> dict[str, Any]:
    return {
        "auditor_bundle_hash": envelope.get("auditor_bundle_hash", ""),
        "auditor_bundle_id": envelope.get("auditor_bundle_id", ""),
        "governance_module_versions": envelope.get("governance_module_versions", {}),
        "retention_policy_label": envelope.get("retention_policy_label", ""),
        "signature_algorithm": envelope.get("signature_algorithm", ""),
        "signed_at_utc": envelope.get("signed_at_utc", ""),
        "signer_id": envelope.get("signer_id", ""),
        "signer_key_id": envelope.get("signer_key_id", ""),
        "verification_scope": envelope.get("verification_scope", {}),
    }


def _scope_valid(scope: Any) -> bool:
    if not isinstance(scope, dict) or not scope:
        return False
    allowed = {"tenant_id", "environment", "purpose", "auditor_id"}
    if any(key not in allowed or not isinstance(value, str) or not value.strip() for key, value in scope.items()):
        return False
    return "purpose" in scope


def _within_validity(timestamp: str, valid_from: str, valid_until: str) -> bool:
    try:
        value = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
        start = datetime.fromisoformat(valid_from.replace("Z", "+00:00"))
        end = datetime.fromisoformat(valid_until.replace("Z", "+00:00"))
    except ValueError:
        return False
    return start <= value <= end


def _assert_signed_bundle_safe(payload: Any) -> None:
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
        if redacted != payload:
            raise SignedAuditorBundleError("SIGNED_BUNDLE_DIAGNOSTICS_UNSAFE")
    except Exception as exc:
        if isinstance(exc, SignedAuditorBundleError):
            raise
        raise SignedAuditorBundleError("SIGNED_BUNDLE_DIAGNOSTICS_UNSAFE") from exc


def _load_json_object(path: Path | None, failure_code: str) -> dict[str, Any]:
    if path is None:
        raise SignedAuditorBundleError(failure_code)
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        raise SignedAuditorBundleError(failure_code) from exc
    if not isinstance(payload, dict):
        raise SignedAuditorBundleError(failure_code)
    return payload


def _canonical_json(payload: Any) -> str:
    try:
        return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    except (TypeError, ValueError) as exc:
        raise SignedAuditorBundleError("SIGNED_BUNDLE_HASH_MISMATCH") from exc


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


def private_key_from_environment() -> str:
    value = os.getenv(PRIVATE_KEY_ENV, "")
    if not value:
        raise SignedAuditorBundleError("SIGNED_BUNDLE_SIGNATURE_INVALID")
    return value
