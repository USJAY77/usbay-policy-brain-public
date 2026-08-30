from __future__ import annotations

import json
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
POLICY_PATH = ROOT / "governance" / "media_audit_export_policy.json"
MANIFEST_PATH = ROOT / "artifacts" / "media-audit-export-manifest.json"
PLACEHOLDER_SIGNATURE = "MEDIA_AUDIT_EXPORT_SIGNATURE_PLACEHOLDER_NON_PRODUCTION"
REFERENCE_FIELDS = (
    "provenance_reference",
    "approval_chain_reference",
    "timestamp_reference",
    "distribution_reference",
    "revocation_reference",
)
SENSITIVE_MARKERS = (
    "BEGIN " + "PRIVATE KEY",
    "api" + "_key",
    "access" + "_token",
    "oauth" + "_token",
    "client" + "_secret",
    "credentials",
    "legal_contract",
    "personal_data",
    "raw_audio",
    "raw_video",
    "raw_voice",
    "raw_image",
    "script:",
    "lyrics:",
    "voice_sample",
    "copyrighted_content",
)


def load_media_audit_export_policy(path: Path = POLICY_PATH) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def load_media_audit_export_manifest(path: Path = MANIFEST_PATH) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def valid_audit_export_manifest() -> dict[str, Any]:
    return load_media_audit_export_manifest()


def verify_media_audit_export_manifest(
    manifest: dict[str, Any] | None,
    *,
    policy: dict[str, Any] | None = None,
) -> dict[str, Any]:
    resolved_policy = policy or load_media_audit_export_policy()
    if resolved_policy.get("non_production_scaffolding") is not True:
        return _fail_closed("MEDIA_AUDIT_EXPORT_POLICY_SCOPE_UNCLEAR")
    if resolved_policy.get("regulator_export_allowed") is not True:
        return _fail_closed("MEDIA_AUDIT_EXPORT_POLICY_DISABLED")
    if manifest is None:
        return _fail_closed("MEDIA_AUDIT_EXPORT_MANIFEST_MISSING")
    if not isinstance(manifest, dict):
        return _fail_closed("MEDIA_AUDIT_EXPORT_MANIFEST_MALFORMED")
    if manifest.get("non_production_demo") is not True:
        return _fail_closed("MEDIA_AUDIT_EXPORT_SCOPE_UNCLEAR")

    if resolved_policy.get("export_scope_required") is True and not manifest.get("export_scope"):
        return _fail_closed("MEDIA_AUDIT_EXPORT_SCOPE_MISSING")
    if manifest.get("export_scope") not in resolved_policy["export_scopes"]:
        return _fail_closed("MEDIA_AUDIT_EXPORT_SCOPE_UNAPPROVED")

    missing = [field for field in REFERENCE_FIELDS if not manifest.get(field)]
    if missing:
        return _fail_closed("MEDIA_AUDIT_EXPORT_LINEAGE_MISSING", missing_fields=missing)

    fail_closed_flags = manifest.get("fail_closed_flags")
    if not isinstance(fail_closed_flags, dict):
        return _fail_closed("MEDIA_AUDIT_EXPORT_FAIL_CLOSED_FLAGS_MISSING")
    for flag in (
        "fail_closed_on_missing_audit_lineage",
        "fail_closed_on_unsigned_export_manifest",
        "fail_closed_on_sensitive_payload_detection",
        "fail_closed_on_missing_export_scope",
    ):
        if fail_closed_flags.get(flag) is not True:
            return _fail_closed("MEDIA_AUDIT_EXPORT_FAIL_CLOSED_FLAG_DISABLED", flag=flag)

    if manifest.get("signature_placeholder") != PLACEHOLDER_SIGNATURE:
        return _fail_closed("MEDIA_AUDIT_EXPORT_MANIFEST_UNSIGNED")
    if _contains_sensitive_payload(manifest):
        return _fail_closed("MEDIA_AUDIT_EXPORT_SENSITIVE_PAYLOAD_DETECTED")

    return {
        "decision": "PASS",
        "export_contains_references_only": True,
        "export_scope": manifest["export_scope"],
        "fail_closed": False,
        "media_asset_id": manifest["media_asset_id"],
        "non_production_scaffolding": True,
        "production_export_signature": False,
        "reason": "MEDIA_AUDIT_EXPORT_MANIFEST_VALID",
    }


def _contains_sensitive_payload(value: Any) -> bool:
    if isinstance(value, dict):
        return any(_contains_sensitive_payload(item) for item in value.values())
    if isinstance(value, list):
        return any(_contains_sensitive_payload(item) for item in value)
    if not isinstance(value, str):
        return False
    lowered = value.lower()
    return any(marker.lower() in lowered for marker in SENSITIVE_MARKERS)


def _fail_closed(reason: str, **details: Any) -> dict[str, Any]:
    evidence: dict[str, Any] = {
        "decision": "FAIL_CLOSED",
        "fail_closed": True,
        "reason": reason,
        "silent_pass": False,
    }
    evidence.update(details)
    return evidence
