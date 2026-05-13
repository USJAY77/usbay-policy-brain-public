from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from governance.evidence_record_chain import assert_evidence_record_safe, verify_evidence_record
from governance.policy_pack import redacted_policy_payload
from governance.sealed_audit_archive import assert_sealed_audit_archive_safe, verify_sealed_audit_archive
from governance.tsa_live_verification import (
    MODULE_VERSIONS as TSA_LIVE_MODULE_VERSIONS,
    assert_tsa_live_verification_safe,
    verify_tsa_live_verification_plan,
)
from governance.worm_immutable_storage import assert_worm_immutable_storage_safe, verify_worm_immutable_storage_plan

REGULATOR_EXPORT_PROFILE_SCHEMA = "usbay.governance_regulator_export_profile.v1"
REGULATOR_EXPORT_PROFILE_ERROR_REGISTRY_PATH = Path("governance/regulator_export_profile_errors.json")
REGULATOR_EXPORT_PROFILE_ERROR_SCHEMA = "usbay.governance_regulator_export_profile_error_registry.v1"
REGULATOR_EXPORT_PROFILE_ERROR_CODES = (
    "REGULATOR_EXPORT_EVIDENCE_CHAIN_MISSING",
    "REGULATOR_EXPORT_SEALED_ARCHIVE_MISSING",
    "REGULATOR_EXPORT_WORM_MANIFEST_MISSING",
    "REGULATOR_EXPORT_TSA_METADATA_MISSING",
    "REGULATOR_EXPORT_POLICY_DECISION_MISSING",
    "REGULATOR_EXPORT_OUTPUT_PATH_MUTABLE",
    "REGULATOR_EXPORT_DUPLICATE_EVIDENCE_REFERENCE",
    "REGULATOR_EXPORT_ENTRY_ORDER_INVALID",
    "REGULATOR_EXPORT_RAW_PAYLOAD_LEAKAGE",
    "REGULATOR_EXPORT_DIAGNOSTICS_UNSAFE",
)
EXPORT_PROFILE_TYPES = (
    "EU_AI_ACT_AUDIT",
    "GDPR_ART32_SECURITY",
    "DORA_OPERATIONAL_RESILIENCE",
    "INTERNAL_GOVERNANCE_REVIEW",
)
REGULATOR_EXPORT_MODE = "LOCAL_ONLY"
REGULATOR_EXPORT_ENTRY_ORDER = (
    "sealed_audit_archive",
    "evidence_record_chain",
    "worm_immutable_storage",
    "tsa_live_verification",
    "policy_decision_metadata",
)
MODULE_VERSIONS = {
    **TSA_LIVE_MODULE_VERSIONS,
    "regulator_export_profile": REGULATOR_EXPORT_PROFILE_SCHEMA,
}


class RegulatorExportProfileError(RuntimeError):
    pass


@dataclass(frozen=True)
class RegulatorExportProfileVerificationResult:
    valid: bool
    errors: tuple[str, ...]
    regulator_export_profile_id: str
    export_profile_type: str
    export_profile_hash: str
    export_output_path: str
    sealed_archive_id: str
    evidence_record_id: str
    worm_storage_plan_id: str
    tsa_live_verification_id: str
    policy_decision_metadata_hash: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "valid": self.valid,
            "errors": list(self.errors),
            "regulator_export_profile_id": self.regulator_export_profile_id,
            "export_profile_type": self.export_profile_type,
            "export_profile_hash": self.export_profile_hash,
            "export_output_path": self.export_output_path,
            "sealed_archive_id": self.sealed_archive_id,
            "evidence_record_id": self.evidence_record_id,
            "worm_storage_plan_id": self.worm_storage_plan_id,
            "tsa_live_verification_id": self.tsa_live_verification_id,
            "policy_decision_metadata_hash": self.policy_decision_metadata_hash,
        }


def load_regulator_export_profile_error_registry(root: Path) -> dict[str, dict[str, str]]:
    path = root / REGULATOR_EXPORT_PROFILE_ERROR_REGISTRY_PATH
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        raise RegulatorExportProfileError("regulator_export_profile_error_registry_missing") from exc
    if not isinstance(payload, dict) or payload.get("schema") != REGULATOR_EXPORT_PROFILE_ERROR_SCHEMA:
        raise RegulatorExportProfileError("regulator_export_profile_error_registry_invalid")
    raw_errors = payload.get("errors")
    if not isinstance(raw_errors, list):
        raise RegulatorExportProfileError("regulator_export_profile_error_registry_invalid")
    registry: dict[str, dict[str, str]] = {}
    for entry in raw_errors:
        if not isinstance(entry, dict) or not entry.get("code"):
            raise RegulatorExportProfileError("regulator_export_profile_error_registry_invalid")
        registry[str(entry["code"])] = {
            "description": str(entry.get("description", "")),
            "fail_closed_reason": str(entry.get("fail_closed_reason", "")),
        }
    missing = sorted(set(REGULATOR_EXPORT_PROFILE_ERROR_CODES) - set(registry))
    if missing:
        raise RegulatorExportProfileError("regulator_export_profile_error_registry_incomplete:" + ",".join(missing))
    return registry


def prepare_regulator_export_profile(
    *,
    sealed_archive: dict[str, Any],
    evidence_record_chain: dict[str, Any],
    worm_immutable_storage: dict[str, Any],
    tsa_live_verification: dict[str, Any],
    policy_decision_metadata: dict[str, Any],
    export_profile_type: str,
    created_at_utc: str | None = None,
) -> dict[str, Any]:
    archive_verification = verify_sealed_audit_archive(sealed_archive)
    if not archive_verification.valid:
        raise RegulatorExportProfileError("REGULATOR_EXPORT_SEALED_ARCHIVE_MISSING")
    record_verification = verify_evidence_record(evidence_record_chain, sealed_archive=sealed_archive)
    if not record_verification.valid:
        raise RegulatorExportProfileError("REGULATOR_EXPORT_EVIDENCE_CHAIN_MISSING")
    worm_verification = verify_worm_immutable_storage_plan(
        worm_immutable_storage,
        sealed_archive=sealed_archive,
        evidence_record_chain=evidence_record_chain,
    )
    if not worm_verification.valid:
        raise RegulatorExportProfileError("REGULATOR_EXPORT_WORM_MANIFEST_MISSING")
    tsa_verification = verify_tsa_live_verification_plan(tsa_live_verification)
    if not tsa_verification.valid:
        raise RegulatorExportProfileError("REGULATOR_EXPORT_TSA_METADATA_MISSING")
    if not _profile_type_valid(export_profile_type):
        raise RegulatorExportProfileError("REGULATOR_EXPORT_POLICY_DECISION_MISSING")
    if not _policy_metadata_valid(policy_decision_metadata):
        raise RegulatorExportProfileError("REGULATOR_EXPORT_POLICY_DECISION_MISSING")
    created_at = created_at_utc or _utc_now()
    if not _timestamp_is_valid(created_at):
        raise RegulatorExportProfileError("REGULATOR_EXPORT_POLICY_DECISION_MISSING")
    policy_hash = _hash_object(policy_decision_metadata)
    entries = _profile_entries(
        sealed_archive=sealed_archive,
        evidence_record_chain=evidence_record_chain,
        worm_immutable_storage=worm_immutable_storage,
        tsa_live_verification=tsa_live_verification,
        policy_decision_metadata=policy_decision_metadata,
        export_profile_type=export_profile_type,
    )
    profile_hash = _profile_hash(entries)
    payload = {
        "archive_root_hash": archive_verification.archive_root_hash,
        "created_at_utc": created_at,
        "evidence_record_id": record_verification.evidence_record_id,
        "export_mode": REGULATOR_EXPORT_MODE,
        "export_profile_hash": profile_hash,
        "export_profile_type": export_profile_type,
        "governance_module_versions": dict(MODULE_VERSIONS),
        "policy_decision_metadata_hash": policy_hash,
        "retention_policy_label": archive_verification.retention_policy_label,
        "sealed_archive_id": archive_verification.archive_id,
        "tsa_live_verification_id": tsa_verification.tsa_live_verification_id,
        "worm_storage_plan_id": worm_verification.worm_storage_plan_id,
    }
    profile_id = _sha256_hex(_canonical_json(payload).encode("utf-8"))
    profile = {
        "schema": REGULATOR_EXPORT_PROFILE_SCHEMA,
        "regulator_export_profile_id": profile_id,
        "evidence_references": entries,
        "export_output_path": _export_output_path(export_profile_type=export_profile_type, profile_id=profile_id),
        **payload,
    }
    _assert_regulator_export_profile_safe(profile)
    return profile


def prepare_regulator_export_profile_file(
    *,
    sealed_archive_path: Path,
    evidence_record_path: Path,
    worm_immutable_storage_path: Path,
    tsa_live_verification_path: Path,
    policy_decision_metadata_path: Path,
    output_path: Path,
    export_profile_type: str,
    created_at_utc: str | None = None,
) -> dict[str, Any]:
    profile = prepare_regulator_export_profile(
        sealed_archive=_load_json_object(sealed_archive_path, "REGULATOR_EXPORT_SEALED_ARCHIVE_MISSING"),
        evidence_record_chain=_load_json_object(evidence_record_path, "REGULATOR_EXPORT_EVIDENCE_CHAIN_MISSING"),
        worm_immutable_storage=_load_json_object(worm_immutable_storage_path, "REGULATOR_EXPORT_WORM_MANIFEST_MISSING"),
        tsa_live_verification=_load_json_object(tsa_live_verification_path, "REGULATOR_EXPORT_TSA_METADATA_MISSING"),
        policy_decision_metadata=_load_json_object(policy_decision_metadata_path, "REGULATOR_EXPORT_POLICY_DECISION_MISSING"),
        export_profile_type=export_profile_type,
        created_at_utc=created_at_utc,
    )
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(_canonical_json(profile) + "\n", encoding="utf-8")
    return profile


def verify_regulator_export_profile(
    profile: dict[str, Any],
    *,
    sealed_archive: dict[str, Any] | None = None,
    evidence_record_chain: dict[str, Any] | None = None,
    worm_immutable_storage: dict[str, Any] | None = None,
    tsa_live_verification: dict[str, Any] | None = None,
    policy_decision_metadata: dict[str, Any] | None = None,
) -> RegulatorExportProfileVerificationResult:
    errors: list[str] = []
    if not isinstance(profile, dict) or profile.get("schema") != REGULATOR_EXPORT_PROFILE_SCHEMA:
        errors.append("REGULATOR_EXPORT_SEALED_ARCHIVE_MISSING")
    profile_id = str(profile.get("regulator_export_profile_id", "")) if isinstance(profile, dict) else ""
    profile_type = str(profile.get("export_profile_type", "")) if isinstance(profile, dict) else ""
    profile_hash = str(profile.get("export_profile_hash", "")) if isinstance(profile, dict) else ""
    output_path = str(profile.get("export_output_path", "")) if isinstance(profile, dict) else ""
    sealed_archive_id = str(profile.get("sealed_archive_id", "")) if isinstance(profile, dict) else ""
    evidence_record_id = str(profile.get("evidence_record_id", "")) if isinstance(profile, dict) else ""
    worm_plan_id = str(profile.get("worm_storage_plan_id", "")) if isinstance(profile, dict) else ""
    tsa_id = str(profile.get("tsa_live_verification_id", "")) if isinstance(profile, dict) else ""
    policy_hash = str(profile.get("policy_decision_metadata_hash", "")) if isinstance(profile, dict) else ""
    entries = profile.get("evidence_references") if isinstance(profile, dict) else None
    if not _profile_type_valid(profile_type):
        errors.append("REGULATOR_EXPORT_POLICY_DECISION_MISSING")
    if not _is_sha256_hex(sealed_archive_id):
        errors.append("REGULATOR_EXPORT_SEALED_ARCHIVE_MISSING")
    if not _is_sha256_hex(evidence_record_id):
        errors.append("REGULATOR_EXPORT_EVIDENCE_CHAIN_MISSING")
    if not _is_sha256_hex(worm_plan_id):
        errors.append("REGULATOR_EXPORT_WORM_MANIFEST_MISSING")
    if not _is_sha256_hex(tsa_id):
        errors.append("REGULATOR_EXPORT_TSA_METADATA_MISSING")
    if not _is_sha256_hex(policy_hash):
        errors.append("REGULATOR_EXPORT_POLICY_DECISION_MISSING")
    if not isinstance(entries, list) or len(entries) != len(REGULATOR_EXPORT_ENTRY_ORDER):
        errors.append("REGULATOR_EXPORT_EVIDENCE_CHAIN_MISSING")
        entries = []
    if not _entry_order_valid(entries):
        errors.append("REGULATOR_EXPORT_ENTRY_ORDER_INVALID")
    if not _entries_valid(entries, export_profile_type=profile_type):
        errors.append("REGULATOR_EXPORT_DUPLICATE_EVIDENCE_REFERENCE")
    if profile_hash != _profile_hash(entries):
        errors.append("REGULATOR_EXPORT_EVIDENCE_CHAIN_MISSING")
    if output_path != _export_output_path(export_profile_type=profile_type, profile_id=profile_id):
        errors.append("REGULATOR_EXPORT_OUTPUT_PATH_MUTABLE")
    if not _timestamp_is_valid(str(profile.get("created_at_utc", ""))):
        errors.append("REGULATOR_EXPORT_POLICY_DECISION_MISSING")
    payload = _profile_payload(profile)
    if not _is_sha256_hex(profile_id) or profile_id != _sha256_hex(_canonical_json(payload).encode("utf-8")):
        errors.append("REGULATOR_EXPORT_EVIDENCE_CHAIN_MISSING")
    if sealed_archive is not None:
        archive_result = verify_sealed_audit_archive(sealed_archive)
        if not archive_result.valid or archive_result.archive_id != sealed_archive_id or archive_result.archive_root_hash != profile.get("archive_root_hash"):
            errors.append("REGULATOR_EXPORT_SEALED_ARCHIVE_MISSING")
    if evidence_record_chain is not None:
        record_result = verify_evidence_record(evidence_record_chain, sealed_archive=sealed_archive)
        if not record_result.valid or record_result.evidence_record_id != evidence_record_id or record_result.sealed_archive_id != sealed_archive_id:
            errors.append("REGULATOR_EXPORT_EVIDENCE_CHAIN_MISSING")
    if worm_immutable_storage is not None:
        worm_result = verify_worm_immutable_storage_plan(worm_immutable_storage, sealed_archive=sealed_archive, evidence_record_chain=evidence_record_chain)
        if not worm_result.valid or worm_result.worm_storage_plan_id != worm_plan_id:
            errors.append("REGULATOR_EXPORT_WORM_MANIFEST_MISSING")
    if tsa_live_verification is not None:
        tsa_result = verify_tsa_live_verification_plan(tsa_live_verification)
        if not tsa_result.valid or tsa_result.tsa_live_verification_id != tsa_id:
            errors.append("REGULATOR_EXPORT_TSA_METADATA_MISSING")
    if policy_decision_metadata is not None:
        if not _policy_metadata_valid(policy_decision_metadata) or _hash_object(policy_decision_metadata) != policy_hash:
            errors.append("REGULATOR_EXPORT_POLICY_DECISION_MISSING")
    try:
        _assert_regulator_export_profile_safe(profile)
    except RegulatorExportProfileError as exc:
        if str(exc) == "REGULATOR_EXPORT_RAW_PAYLOAD_LEAKAGE":
            errors.append("REGULATOR_EXPORT_RAW_PAYLOAD_LEAKAGE")
        else:
            errors.append("REGULATOR_EXPORT_DIAGNOSTICS_UNSAFE")
    return RegulatorExportProfileVerificationResult(
        valid=not errors,
        errors=tuple(dict.fromkeys(errors)),
        regulator_export_profile_id=profile_id,
        export_profile_type=profile_type,
        export_profile_hash=profile_hash,
        export_output_path=output_path,
        sealed_archive_id=sealed_archive_id,
        evidence_record_id=evidence_record_id,
        worm_storage_plan_id=worm_plan_id,
        tsa_live_verification_id=tsa_id,
        policy_decision_metadata_hash=policy_hash,
    )


def verify_regulator_export_profile_file(
    regulator_export_profile_path: Path,
    *,
    sealed_archive_path: Path | None = None,
    evidence_record_path: Path | None = None,
    worm_immutable_storage_path: Path | None = None,
    tsa_live_verification_path: Path | None = None,
    policy_decision_metadata_path: Path | None = None,
) -> RegulatorExportProfileVerificationResult:
    return verify_regulator_export_profile(
        _load_json_object(regulator_export_profile_path, "regulator_export_profile_invalid"),
        sealed_archive=_load_json_object(sealed_archive_path, "REGULATOR_EXPORT_SEALED_ARCHIVE_MISSING") if sealed_archive_path else None,
        evidence_record_chain=_load_json_object(evidence_record_path, "REGULATOR_EXPORT_EVIDENCE_CHAIN_MISSING") if evidence_record_path else None,
        worm_immutable_storage=_load_json_object(worm_immutable_storage_path, "REGULATOR_EXPORT_WORM_MANIFEST_MISSING") if worm_immutable_storage_path else None,
        tsa_live_verification=_load_json_object(tsa_live_verification_path, "REGULATOR_EXPORT_TSA_METADATA_MISSING") if tsa_live_verification_path else None,
        policy_decision_metadata=_load_json_object(policy_decision_metadata_path, "REGULATOR_EXPORT_POLICY_DECISION_MISSING") if policy_decision_metadata_path else None,
    )


def explain_regulator_export_profile_failure(root: Path, code: str) -> dict[str, str]:
    registry = load_regulator_export_profile_error_registry(root)
    if code not in registry:
        raise RegulatorExportProfileError("regulator_export_profile_error_unknown:" + code)
    return {"code": code, **registry[code]}


def regulator_export_profile_summary(profile: dict[str, Any]) -> dict[str, Any]:
    return verify_regulator_export_profile(profile).to_dict()


def redacted_regulator_export_profile_payload(payload: Any) -> Any:
    return redacted_policy_payload(payload)


def assert_regulator_export_profile_safe(payload: Any) -> None:
    _assert_regulator_export_profile_safe(payload)


def _profile_entries(
    *,
    sealed_archive: dict[str, Any],
    evidence_record_chain: dict[str, Any],
    worm_immutable_storage: dict[str, Any],
    tsa_live_verification: dict[str, Any],
    policy_decision_metadata: dict[str, Any],
    export_profile_type: str,
) -> list[dict[str, Any]]:
    artifacts = {
        "sealed_audit_archive": sealed_archive,
        "evidence_record_chain": evidence_record_chain,
        "worm_immutable_storage": worm_immutable_storage,
        "tsa_live_verification": tsa_live_verification,
        "policy_decision_metadata": policy_decision_metadata,
    }
    entries: list[dict[str, Any]] = []
    previous_binding = "0" * 64
    for position, evidence_type in enumerate(REGULATOR_EXPORT_ENTRY_ORDER):
        evidence_hash = _hash_object(artifacts[evidence_type])
        binding_payload = {
            "append_only_position": position,
            "evidence_hash": evidence_hash,
            "evidence_type": evidence_type,
            "export_profile_type": export_profile_type,
            "previous_replay_binding_hash": previous_binding,
        }
        replay_binding_hash = _sha256_hex(_canonical_json(binding_payload).encode("utf-8"))
        entry_payload = {
            "append_only_position": position,
            "evidence_hash": evidence_hash,
            "evidence_type": evidence_type,
            "export_profile_type": export_profile_type,
            "replay_binding_hash": replay_binding_hash,
        }
        entries.append({**entry_payload, "evidence_reference_hash": _sha256_hex(_canonical_json(entry_payload).encode("utf-8"))})
        previous_binding = replay_binding_hash
    return entries


def _entries_valid(entries: list[Any], *, export_profile_type: str) -> bool:
    seen_hashes: set[str] = set()
    previous_binding = "0" * 64
    for position, entry in enumerate(entries):
        if not isinstance(entry, dict) or entry.get("append_only_position") != position:
            return False
        evidence_type = str(entry.get("evidence_type", ""))
        evidence_hash = str(entry.get("evidence_hash", ""))
        if evidence_type not in REGULATOR_EXPORT_ENTRY_ORDER or not _is_sha256_hex(evidence_hash) or evidence_hash in seen_hashes:
            return False
        binding_payload = {
            "append_only_position": position,
            "evidence_hash": evidence_hash,
            "evidence_type": evidence_type,
            "export_profile_type": export_profile_type,
            "previous_replay_binding_hash": previous_binding,
        }
        replay_binding_hash = _sha256_hex(_canonical_json(binding_payload).encode("utf-8"))
        entry_payload = {
            "append_only_position": position,
            "evidence_hash": evidence_hash,
            "evidence_type": evidence_type,
            "export_profile_type": export_profile_type,
            "replay_binding_hash": replay_binding_hash,
        }
        if entry.get("export_profile_type") != export_profile_type or entry.get("replay_binding_hash") != replay_binding_hash:
            return False
        if entry.get("evidence_reference_hash") != _sha256_hex(_canonical_json(entry_payload).encode("utf-8")):
            return False
        seen_hashes.add(evidence_hash)
        previous_binding = replay_binding_hash
    return True


def _entry_order_valid(entries: list[Any]) -> bool:
    return [entry.get("evidence_type") for entry in entries if isinstance(entry, dict)] == list(REGULATOR_EXPORT_ENTRY_ORDER)


def _policy_metadata_valid(metadata: dict[str, Any]) -> bool:
    if not isinstance(metadata, dict):
        return False
    allowed = {"policy_decision_id", "policy_decision", "policy_hash", "decision_timestamp_utc", "actor_hash", "policy_version_hash"}
    if any(key not in allowed for key in metadata):
        return False
    decision = str(metadata.get("policy_decision", ""))
    return (
        _is_sha256_hex(str(metadata.get("policy_decision_id", "")))
        and decision in {"ALLOW", "DENY", "REQUIRE_HUMAN_REVIEW", "FAIL_CLOSED"}
        and _is_sha256_hex(str(metadata.get("policy_hash", "")))
        and _timestamp_is_valid(str(metadata.get("decision_timestamp_utc", "")))
        and _is_sha256_hex(str(metadata.get("actor_hash", "")))
        and _is_sha256_hex(str(metadata.get("policy_version_hash", "")))
    )


def _profile_payload(profile: dict[str, Any]) -> dict[str, Any]:
    return {
        "archive_root_hash": profile.get("archive_root_hash", ""),
        "created_at_utc": profile.get("created_at_utc", ""),
        "evidence_record_id": profile.get("evidence_record_id", ""),
        "export_mode": profile.get("export_mode", ""),
        "export_profile_hash": profile.get("export_profile_hash", ""),
        "export_profile_type": profile.get("export_profile_type", ""),
        "governance_module_versions": profile.get("governance_module_versions", {}),
        "policy_decision_metadata_hash": profile.get("policy_decision_metadata_hash", ""),
        "retention_policy_label": profile.get("retention_policy_label", ""),
        "sealed_archive_id": profile.get("sealed_archive_id", ""),
        "tsa_live_verification_id": profile.get("tsa_live_verification_id", ""),
        "worm_storage_plan_id": profile.get("worm_storage_plan_id", ""),
    }


def _profile_hash(entries: list[Any]) -> str:
    return _sha256_hex(_canonical_json([entry.get("evidence_reference_hash", "") for entry in entries if isinstance(entry, dict)]).encode("utf-8"))


def _export_output_path(*, export_profile_type: str, profile_id: str) -> str:
    return f"regulator-export://local-only/sha256/{export_profile_type}/{profile_id}"


def _profile_type_valid(value: str) -> bool:
    return value in EXPORT_PROFILE_TYPES


def _assert_regulator_export_profile_safe(payload: Any) -> None:
    try:
        if _contains_raw_payload_marker(payload):
            raise RegulatorExportProfileError("REGULATOR_EXPORT_RAW_PAYLOAD_LEAKAGE")
        redacted = redacted_policy_payload(payload)
        assert_sealed_audit_archive_safe(redacted)
        assert_evidence_record_safe(redacted)
        assert_worm_immutable_storage_safe(redacted)
        assert_tsa_live_verification_safe(redacted)
        if redacted != payload:
            raise RegulatorExportProfileError("REGULATOR_EXPORT_DIAGNOSTICS_UNSAFE")
    except Exception as exc:
        if isinstance(exc, RegulatorExportProfileError):
            raise
        raise RegulatorExportProfileError("REGULATOR_EXPORT_DIAGNOSTICS_UNSAFE") from exc


def _contains_raw_payload_marker(payload: Any) -> bool:
    text = _canonical_json(payload).lower()
    markers = ("raw_payload", "raw_governance_payload", "raw_ocsp", "raw_crl", "ocsp_bytes", "crl_bytes", "runtime_artifact")
    return any(marker in text for marker in markers)


def _load_json_object(path: Path | None, failure_code: str) -> dict[str, Any]:
    if path is None:
        raise RegulatorExportProfileError(failure_code)
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        raise RegulatorExportProfileError(failure_code) from exc
    if not isinstance(payload, dict):
        raise RegulatorExportProfileError(failure_code)
    return payload


def _hash_object(payload: Any) -> str:
    return _sha256_hex(_canonical_json(payload).encode("utf-8"))


def _canonical_json(payload: Any) -> str:
    try:
        return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    except (TypeError, ValueError) as exc:
        raise RegulatorExportProfileError("REGULATOR_EXPORT_EVIDENCE_CHAIN_MISSING") from exc


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
