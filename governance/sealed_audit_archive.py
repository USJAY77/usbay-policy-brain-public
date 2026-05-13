from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from governance.evidence_chain import MODULE_VERSIONS as EVIDENCE_CHAIN_MODULE_VERSIONS
from governance.evidence_chain import assert_evidence_chain_safe, verify_evidence_chain
from governance.policy_pack import redacted_policy_payload
from governance.signed_bundle_ltv import assert_signed_bundle_ltv_safe, verify_signed_bundle_ltv_evidence
from governance.signed_bundle_revocation_preflight import assert_revocation_preflight_safe, verify_revocation_preflight
from governance.signed_bundle_revocation_response import (
    MODULE_VERSIONS as REVOCATION_RESPONSE_MODULE_VERSIONS,
    assert_revocation_response_safe,
    verify_revocation_response,
)
from governance.signed_bundle_timestamp import assert_signed_bundle_timestamp_safe, verify_signed_bundle_timestamp

SEALED_AUDIT_ARCHIVE_SCHEMA = "usbay.governance_sealed_audit_archive.v1"
SEALED_AUDIT_ARCHIVE_ERROR_REGISTRY_PATH = Path("governance/sealed_audit_archive_errors.json")
SEALED_AUDIT_ARCHIVE_ERROR_SCHEMA = "usbay.governance_sealed_audit_archive_error_registry.v1"
SEALED_AUDIT_ARCHIVE_ERROR_CODES = (
    "SEALED_ARCHIVE_MANIFEST_MISSING",
    "SEALED_ARCHIVE_ROOT_HASH_MISMATCH",
    "SEALED_ARCHIVE_SCOPE_INVALID",
    "SEALED_ARCHIVE_CHAIN_MISMATCH",
    "SEALED_ARCHIVE_REPLAY_DETECTED",
    "SEALED_ARCHIVE_POSITION_INVALID",
    "SEALED_ARCHIVE_ARTIFACT_MISSING",
    "SEALED_ARCHIVE_DIAGNOSTICS_UNSAFE",
)
ARCHIVE_ARTIFACT_ORDER = (
    "evidence_chain",
    "signed_bundle",
    "timestamp_attachment",
    "ltv_evidence",
    "revocation_preflight",
    "revocation_response",
)
MODULE_VERSIONS = {
    **EVIDENCE_CHAIN_MODULE_VERSIONS,
    **REVOCATION_RESPONSE_MODULE_VERSIONS,
    "sealed_audit_archive": SEALED_AUDIT_ARCHIVE_SCHEMA,
}


class SealedAuditArchiveError(RuntimeError):
    pass


@dataclass(frozen=True)
class SealedAuditArchiveVerificationResult:
    valid: bool
    errors: tuple[str, ...]
    archive_id: str
    archive_manifest_hash: str
    archive_root_hash: str
    evidence_chain_head_hash: str
    archive_scope: str
    archive_version: str
    retention_policy_label: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "valid": self.valid,
            "errors": list(self.errors),
            "archive_id": self.archive_id,
            "archive_manifest_hash": self.archive_manifest_hash,
            "archive_root_hash": self.archive_root_hash,
            "evidence_chain_head_hash": self.evidence_chain_head_hash,
            "archive_scope": self.archive_scope,
            "archive_version": self.archive_version,
            "retention_policy_label": self.retention_policy_label,
        }


def load_sealed_audit_archive_error_registry(root: Path) -> dict[str, dict[str, str]]:
    path = root / SEALED_AUDIT_ARCHIVE_ERROR_REGISTRY_PATH
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        raise SealedAuditArchiveError("sealed_audit_archive_error_registry_missing") from exc
    if not isinstance(payload, dict) or payload.get("schema") != SEALED_AUDIT_ARCHIVE_ERROR_SCHEMA:
        raise SealedAuditArchiveError("sealed_audit_archive_error_registry_invalid")
    raw_errors = payload.get("errors")
    if not isinstance(raw_errors, list):
        raise SealedAuditArchiveError("sealed_audit_archive_error_registry_invalid")
    registry: dict[str, dict[str, str]] = {}
    for entry in raw_errors:
        if not isinstance(entry, dict) or not entry.get("code"):
            raise SealedAuditArchiveError("sealed_audit_archive_error_registry_invalid")
        registry[str(entry["code"])] = {
            "description": str(entry.get("description", "")),
            "fail_closed_reason": str(entry.get("fail_closed_reason", "")),
        }
    missing = sorted(set(SEALED_AUDIT_ARCHIVE_ERROR_CODES) - set(registry))
    if missing:
        raise SealedAuditArchiveError("sealed_audit_archive_error_registry_incomplete:" + ",".join(missing))
    return registry


def create_sealed_audit_archive(
    *,
    evidence_chain: dict[str, Any],
    signed_bundle: dict[str, Any],
    timestamp_attachment: dict[str, Any],
    ltv_evidence: dict[str, Any],
    revocation_preflight: dict[str, Any],
    revocation_response: dict[str, Any],
    archive_created_at_utc: str | None = None,
    archive_scope: str,
    archive_version: str = "v1",
) -> dict[str, Any]:
    created_at = archive_created_at_utc or _utc_now()
    if not _timestamp_is_valid(created_at):
        raise SealedAuditArchiveError("SEALED_ARCHIVE_SCOPE_INVALID")
    if not _scope_valid(archive_scope) or not _scope_valid(archive_version):
        raise SealedAuditArchiveError("SEALED_ARCHIVE_SCOPE_INVALID")
    chain_verification = verify_evidence_chain(evidence_chain)
    if not chain_verification.valid:
        raise SealedAuditArchiveError("SEALED_ARCHIVE_CHAIN_MISMATCH")
    timestamp_verification = verify_signed_bundle_timestamp(timestamp_attachment, signed_bundle=signed_bundle)
    if not timestamp_verification.valid:
        raise SealedAuditArchiveError("SEALED_ARCHIVE_ARTIFACT_MISSING")
    ltv_verification = verify_signed_bundle_ltv_evidence(ltv_evidence, timestamp_attachment=timestamp_attachment)
    if not ltv_verification.valid:
        raise SealedAuditArchiveError("SEALED_ARCHIVE_ARTIFACT_MISSING")
    preflight_verification = verify_revocation_preflight(revocation_preflight, ltv_evidence=ltv_evidence)
    if not preflight_verification.valid:
        raise SealedAuditArchiveError("SEALED_ARCHIVE_ARTIFACT_MISSING")
    response_verification = verify_revocation_response(revocation_response, preflight=revocation_preflight, ltv_evidence=ltv_evidence)
    if not response_verification.valid:
        raise SealedAuditArchiveError("SEALED_ARCHIVE_ARTIFACT_MISSING")
    retention_policy_label = response_verification.retention_policy_label
    artifacts = {
        "evidence_chain": evidence_chain,
        "signed_bundle": signed_bundle,
        "timestamp_attachment": timestamp_attachment,
        "ltv_evidence": ltv_evidence,
        "revocation_preflight": revocation_preflight,
        "revocation_response": revocation_response,
    }
    manifest_entries = _manifest_entries(artifacts, archive_scope=archive_scope)
    archive_manifest_hash = _sha256_hex(_canonical_json(manifest_entries).encode("utf-8"))
    archive_root_hash = _archive_root_hash(manifest_entries)
    payload = {
        "archive_created_at_utc": created_at,
        "archive_manifest_hash": archive_manifest_hash,
        "archive_root_hash": archive_root_hash,
        "archive_scope": archive_scope,
        "archive_version": archive_version,
        "evidence_chain_head_hash": chain_verification.latest_chain_hash,
        "governance_module_versions": dict(MODULE_VERSIONS),
        "ltv_evidence_hash": _artifact_hash(ltv_evidence),
        "retention_policy_label": retention_policy_label,
        "revocation_preflight_hash": _artifact_hash(revocation_preflight),
        "revocation_response_hash": _artifact_hash(revocation_response),
        "signed_bundle_hash": _artifact_hash(signed_bundle),
        "timestamp_attachment_hash": _artifact_hash(timestamp_attachment),
    }
    archive = {
        "schema": SEALED_AUDIT_ARCHIVE_SCHEMA,
        "archive_id": _sha256_hex(_canonical_json(payload).encode("utf-8")),
        "archive_manifest": manifest_entries,
        **payload,
    }
    _assert_archive_safe(archive)
    return archive


def create_sealed_audit_archive_file(
    output_path: Path,
    *,
    evidence_chain_path: Path,
    signed_bundle_path: Path,
    timestamp_attachment_path: Path,
    ltv_evidence_path: Path,
    revocation_preflight_path: Path,
    revocation_response_path: Path,
    archive_created_at_utc: str | None = None,
    archive_scope: str,
    archive_version: str = "v1",
) -> dict[str, Any]:
    archive = create_sealed_audit_archive(
        evidence_chain=_load_json_object(evidence_chain_path, "SEALED_ARCHIVE_ARTIFACT_MISSING"),
        signed_bundle=_load_json_object(signed_bundle_path, "SEALED_ARCHIVE_ARTIFACT_MISSING"),
        timestamp_attachment=_load_json_object(timestamp_attachment_path, "SEALED_ARCHIVE_ARTIFACT_MISSING"),
        ltv_evidence=_load_json_object(ltv_evidence_path, "SEALED_ARCHIVE_ARTIFACT_MISSING"),
        revocation_preflight=_load_json_object(revocation_preflight_path, "SEALED_ARCHIVE_ARTIFACT_MISSING"),
        revocation_response=_load_json_object(revocation_response_path, "SEALED_ARCHIVE_ARTIFACT_MISSING"),
        archive_created_at_utc=archive_created_at_utc,
        archive_scope=archive_scope,
        archive_version=archive_version,
    )
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(_canonical_json(archive) + "\n", encoding="utf-8")
    return archive


def verify_sealed_audit_archive(
    archive: dict[str, Any],
    *,
    evidence_chain: dict[str, Any] | None = None,
    signed_bundle: dict[str, Any] | None = None,
    timestamp_attachment: dict[str, Any] | None = None,
    ltv_evidence: dict[str, Any] | None = None,
    revocation_preflight: dict[str, Any] | None = None,
    revocation_response: dict[str, Any] | None = None,
    expected_archive_scope: str | None = None,
    existing_archives: list[dict[str, Any]] | None = None,
) -> SealedAuditArchiveVerificationResult:
    errors: list[str] = []
    if not isinstance(archive, dict) or archive.get("schema") != SEALED_AUDIT_ARCHIVE_SCHEMA:
        errors.append("SEALED_ARCHIVE_MANIFEST_MISSING")
    archive_id = str(archive.get("archive_id", "")) if isinstance(archive, dict) else ""
    manifest_hash = str(archive.get("archive_manifest_hash", "")) if isinstance(archive, dict) else ""
    root_hash = str(archive.get("archive_root_hash", "")) if isinstance(archive, dict) else ""
    chain_head = str(archive.get("evidence_chain_head_hash", "")) if isinstance(archive, dict) else ""
    archive_scope = str(archive.get("archive_scope", "")) if isinstance(archive, dict) else ""
    archive_version = str(archive.get("archive_version", "")) if isinstance(archive, dict) else ""
    retention_policy_label = str(archive.get("retention_policy_label", "")) if isinstance(archive, dict) else ""
    entries = archive.get("archive_manifest") if isinstance(archive, dict) else None
    if not isinstance(entries, list) or len(entries) != len(ARCHIVE_ARTIFACT_ORDER):
        errors.append("SEALED_ARCHIVE_MANIFEST_MISSING")
        entries = []
    if not _scope_valid(archive_scope) or not _scope_valid(archive_version) or (expected_archive_scope is not None and archive_scope != expected_archive_scope):
        errors.append("SEALED_ARCHIVE_SCOPE_INVALID")
    if manifest_hash != _sha256_hex(_canonical_json(entries).encode("utf-8")):
        errors.append("SEALED_ARCHIVE_MANIFEST_MISSING")
    if root_hash != _archive_root_hash(entries):
        errors.append("SEALED_ARCHIVE_ROOT_HASH_MISMATCH")
    if not _positions_valid(entries, archive_scope=archive_scope):
        errors.append("SEALED_ARCHIVE_POSITION_INVALID")
    if not _entry_order_valid(entries):
        errors.append("SEALED_ARCHIVE_POSITION_INVALID")
    payload = _archive_payload(archive)
    if not _is_sha256_hex(archive_id) or archive_id != _sha256_hex(_canonical_json(payload).encode("utf-8")):
        errors.append("SEALED_ARCHIVE_ROOT_HASH_MISMATCH")
    supplied = {
        "evidence_chain": evidence_chain,
        "signed_bundle": signed_bundle,
        "timestamp_attachment": timestamp_attachment,
        "ltv_evidence": ltv_evidence,
        "revocation_preflight": revocation_preflight,
        "revocation_response": revocation_response,
    }
    if any(value is not None for value in supplied.values()):
        if any(value is None for value in supplied.values()):
            errors.append("SEALED_ARCHIVE_ARTIFACT_MISSING")
        else:
            expected_entries = _manifest_entries(supplied, archive_scope=archive_scope)  # type: ignore[arg-type]
            if entries != expected_entries:
                errors.append("SEALED_ARCHIVE_ARTIFACT_MISSING")
            expected_hash_fields = _expected_hash_fields(supplied)  # type: ignore[arg-type]
            for field, expected_value in expected_hash_fields.items():
                if archive.get(field) != expected_value:
                    errors.append("SEALED_ARCHIVE_ARTIFACT_MISSING")
            chain_verification = verify_evidence_chain(evidence_chain or {})
            if not chain_verification.valid or chain_verification.latest_chain_hash != chain_head:
                errors.append("SEALED_ARCHIVE_CHAIN_MISMATCH")
            if not verify_signed_bundle_timestamp(timestamp_attachment or {}, signed_bundle=signed_bundle).valid:
                errors.append("SEALED_ARCHIVE_ARTIFACT_MISSING")
            if not verify_signed_bundle_ltv_evidence(ltv_evidence or {}, timestamp_attachment=timestamp_attachment).valid:
                errors.append("SEALED_ARCHIVE_ARTIFACT_MISSING")
            if not verify_revocation_preflight(revocation_preflight or {}, ltv_evidence=ltv_evidence).valid:
                errors.append("SEALED_ARCHIVE_ARTIFACT_MISSING")
            response_verification = verify_revocation_response(revocation_response or {}, preflight=revocation_preflight, ltv_evidence=ltv_evidence)
            if not response_verification.valid or response_verification.retention_policy_label != retention_policy_label:
                errors.append("SEALED_ARCHIVE_ARTIFACT_MISSING")
    for existing in existing_archives or []:
        if isinstance(existing, dict) and existing.get("archive_id") == archive_id:
            errors.append("SEALED_ARCHIVE_REPLAY_DETECTED")
    try:
        _assert_archive_safe(archive)
    except SealedAuditArchiveError:
        errors.append("SEALED_ARCHIVE_DIAGNOSTICS_UNSAFE")
    return SealedAuditArchiveVerificationResult(
        valid=not errors,
        errors=tuple(dict.fromkeys(errors)),
        archive_id=archive_id,
        archive_manifest_hash=manifest_hash,
        archive_root_hash=root_hash,
        evidence_chain_head_hash=chain_head,
        archive_scope=archive_scope,
        archive_version=archive_version,
        retention_policy_label=retention_policy_label,
    )


def verify_sealed_audit_archive_file(
    archive_path: Path,
    *,
    evidence_chain_path: Path | None = None,
    signed_bundle_path: Path | None = None,
    timestamp_attachment_path: Path | None = None,
    ltv_evidence_path: Path | None = None,
    revocation_preflight_path: Path | None = None,
    revocation_response_path: Path | None = None,
    expected_archive_scope: str | None = None,
    existing_archive_paths: list[Path] | None = None,
) -> SealedAuditArchiveVerificationResult:
    existing = [_load_json_object(path, "sealed_audit_archive_existing_invalid") for path in existing_archive_paths or []]
    return verify_sealed_audit_archive(
        _load_json_object(archive_path, "sealed_audit_archive_invalid"),
        evidence_chain=_load_json_object(evidence_chain_path, "SEALED_ARCHIVE_ARTIFACT_MISSING") if evidence_chain_path else None,
        signed_bundle=_load_json_object(signed_bundle_path, "SEALED_ARCHIVE_ARTIFACT_MISSING") if signed_bundle_path else None,
        timestamp_attachment=_load_json_object(timestamp_attachment_path, "SEALED_ARCHIVE_ARTIFACT_MISSING") if timestamp_attachment_path else None,
        ltv_evidence=_load_json_object(ltv_evidence_path, "SEALED_ARCHIVE_ARTIFACT_MISSING") if ltv_evidence_path else None,
        revocation_preflight=_load_json_object(revocation_preflight_path, "SEALED_ARCHIVE_ARTIFACT_MISSING") if revocation_preflight_path else None,
        revocation_response=_load_json_object(revocation_response_path, "SEALED_ARCHIVE_ARTIFACT_MISSING") if revocation_response_path else None,
        expected_archive_scope=expected_archive_scope,
        existing_archives=existing,
    )


def explain_sealed_audit_archive_failure(root: Path, code: str) -> dict[str, str]:
    registry = load_sealed_audit_archive_error_registry(root)
    if code not in registry:
        raise SealedAuditArchiveError("sealed_audit_archive_error_unknown:" + code)
    return {"code": code, **registry[code]}


def sealed_audit_archive_summary(archive: dict[str, Any]) -> dict[str, Any]:
    return verify_sealed_audit_archive(archive).to_dict()


def redacted_sealed_audit_archive_payload(payload: Any) -> Any:
    return redacted_policy_payload(payload)


def assert_sealed_audit_archive_safe(payload: Any) -> None:
    _assert_archive_safe(payload)


def _manifest_entries(artifacts: dict[str, dict[str, Any]], *, archive_scope: str) -> list[dict[str, Any]]:
    entries: list[dict[str, Any]] = []
    previous_binding = "0" * 64
    for position, artifact_type in enumerate(ARCHIVE_ARTIFACT_ORDER):
        artifact_hash = _artifact_hash(artifacts[artifact_type])
        binding_payload = {
            "append_only_position": position,
            "artifact_type": artifact_type,
            "file_canonical_hash": artifact_hash,
            "previous_replay_binding_hash": previous_binding,
            "verification_scope": archive_scope,
        }
        replay_binding_hash = _sha256_hex(_canonical_json(binding_payload).encode("utf-8"))
        entry_payload = {
            "append_only_position": position,
            "artifact_type": artifact_type,
            "file_canonical_hash": artifact_hash,
            "replay_binding_hash": replay_binding_hash,
            "verification_scope": archive_scope,
        }
        entry = {
            **entry_payload,
            "manifest_entry_hash": _sha256_hex(_canonical_json(entry_payload).encode("utf-8")),
        }
        entries.append(entry)
        previous_binding = replay_binding_hash
    return entries


def _positions_valid(entries: list[Any], *, archive_scope: str) -> bool:
    seen_hashes: set[str] = set()
    previous_binding = "0" * 64
    for position, entry in enumerate(entries):
        if not isinstance(entry, dict) or entry.get("append_only_position") != position:
            return False
        if entry.get("verification_scope") != archive_scope:
            return False
        if entry.get("artifact_type") not in ARCHIVE_ARTIFACT_ORDER:
            return False
        artifact_hash = str(entry.get("file_canonical_hash", ""))
        if not _is_sha256_hex(artifact_hash) or artifact_hash in seen_hashes:
            return False
        seen_hashes.add(artifact_hash)
        binding_payload = {
            "append_only_position": position,
            "artifact_type": entry.get("artifact_type", ""),
            "file_canonical_hash": artifact_hash,
            "previous_replay_binding_hash": previous_binding,
            "verification_scope": archive_scope,
        }
        replay_binding_hash = _sha256_hex(_canonical_json(binding_payload).encode("utf-8"))
        entry_payload = {
            "append_only_position": position,
            "artifact_type": entry.get("artifact_type", ""),
            "file_canonical_hash": artifact_hash,
            "replay_binding_hash": replay_binding_hash,
            "verification_scope": archive_scope,
        }
        if entry.get("replay_binding_hash") != replay_binding_hash:
            return False
        if entry.get("manifest_entry_hash") != _sha256_hex(_canonical_json(entry_payload).encode("utf-8")):
            return False
        previous_binding = replay_binding_hash
    return True


def _entry_order_valid(entries: list[Any]) -> bool:
    return [entry.get("artifact_type") for entry in entries if isinstance(entry, dict)] == list(ARCHIVE_ARTIFACT_ORDER)


def _archive_root_hash(entries: list[Any]) -> str:
    return _sha256_hex(_canonical_json([entry.get("manifest_entry_hash", "") for entry in entries if isinstance(entry, dict)]).encode("utf-8"))


def _archive_payload(archive: dict[str, Any]) -> dict[str, Any]:
    return {
        "archive_created_at_utc": archive.get("archive_created_at_utc", ""),
        "archive_manifest_hash": archive.get("archive_manifest_hash", ""),
        "archive_root_hash": archive.get("archive_root_hash", ""),
        "archive_scope": archive.get("archive_scope", ""),
        "archive_version": archive.get("archive_version", ""),
        "evidence_chain_head_hash": archive.get("evidence_chain_head_hash", ""),
        "governance_module_versions": archive.get("governance_module_versions", {}),
        "ltv_evidence_hash": archive.get("ltv_evidence_hash", ""),
        "retention_policy_label": archive.get("retention_policy_label", ""),
        "revocation_preflight_hash": archive.get("revocation_preflight_hash", ""),
        "revocation_response_hash": archive.get("revocation_response_hash", ""),
        "signed_bundle_hash": archive.get("signed_bundle_hash", ""),
        "timestamp_attachment_hash": archive.get("timestamp_attachment_hash", ""),
    }


def _expected_hash_fields(artifacts: dict[str, dict[str, Any]]) -> dict[str, str]:
    return {
        "ltv_evidence_hash": _artifact_hash(artifacts["ltv_evidence"]),
        "revocation_preflight_hash": _artifact_hash(artifacts["revocation_preflight"]),
        "revocation_response_hash": _artifact_hash(artifacts["revocation_response"]),
        "signed_bundle_hash": _artifact_hash(artifacts["signed_bundle"]),
        "timestamp_attachment_hash": _artifact_hash(artifacts["timestamp_attachment"]),
    }


def _artifact_hash(artifact: dict[str, Any]) -> str:
    return _sha256_hex(_canonical_json(artifact).encode("utf-8"))


def _scope_valid(value: str) -> bool:
    return bool(value) and all(part.replace("-", "").replace("_", "").isalnum() for part in value.split(".")) and len(value) <= 128


def _assert_archive_safe(payload: Any) -> None:
    try:
        redacted = redacted_policy_payload(payload)
        assert_evidence_chain_safe(redacted)
        assert_signed_bundle_timestamp_safe(redacted)
        assert_signed_bundle_ltv_safe(redacted)
        assert_revocation_preflight_safe(redacted)
        assert_revocation_response_safe(redacted)
        if redacted != payload:
            raise SealedAuditArchiveError("SEALED_ARCHIVE_DIAGNOSTICS_UNSAFE")
    except Exception as exc:
        if isinstance(exc, SealedAuditArchiveError):
            raise
        raise SealedAuditArchiveError("SEALED_ARCHIVE_DIAGNOSTICS_UNSAFE") from exc


def _load_json_object(path: Path | None, failure_code: str) -> dict[str, Any]:
    if path is None:
        raise SealedAuditArchiveError(failure_code)
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        raise SealedAuditArchiveError(failure_code) from exc
    if not isinstance(payload, dict):
        raise SealedAuditArchiveError(failure_code)
    return payload


def _canonical_json(payload: Any) -> str:
    try:
        return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    except (TypeError, ValueError) as exc:
        raise SealedAuditArchiveError("SEALED_ARCHIVE_ROOT_HASH_MISMATCH") from exc


def _utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _timestamp_is_valid(value: str) -> bool:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return False
    return value.endswith("Z") and parsed.tzinfo is not None and parsed.utcoffset() == timezone.utc.utcoffset(parsed)


def _is_sha256_hex(value: str) -> bool:
    return len(value) == 64 and all(character in "0123456789abcdef" for character in value)


def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()
