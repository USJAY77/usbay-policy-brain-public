from __future__ import annotations

from typing import Any

from governance.execution_contracts import sha256_json
from governance.release_gate_contracts import parse_timestamp


RELEASE_MANIFEST_SCHEMA = "usbay.release.manifest.v1"
REQUIRED_MANIFEST_FIELDS = (
    "manifest_id",
    "release_id",
    "policy_version",
    "policy_hash",
    "evidence_hash",
    "audit_registry_hash",
    "test_summary_hash",
    "rollback_plan_hash",
    "target_environment",
    "created_at",
    "created_by",
    "lineage_hash",
)
SENSITIVE_MARKERS = ("secret", "token", "credential", "screenshot", "private", "password", "api_key", "cookie", "authorization")


def contains_sensitive_marker(value: Any) -> bool:
    text = str(value).lower()
    if isinstance(value, dict):
        text = " ".join(str(item).lower() for pair in value.items() for item in pair)
    elif isinstance(value, list):
        text = " ".join(str(item).lower() for item in value)
    return any(marker in text for marker in SENSITIVE_MARKERS)


def build_release_manifest(**fields: Any) -> dict[str, Any]:
    manifest = {"schema": RELEASE_MANIFEST_SCHEMA}
    for field in REQUIRED_MANIFEST_FIELDS:
        manifest[field] = str(fields.get(field, ""))
    manifest["status"] = str(fields.get("status", "BLOCKED"))
    manifest["reason_codes"] = sorted(str(code) for code in fields.get("reason_codes", []) if code)
    manifest["manifest_hash"] = sha256_json(manifest | {"manifest_hash": ""})
    return manifest


def validate_release_manifest(manifest: dict[str, Any] | None) -> tuple[str, tuple[str, ...]]:
    if not isinstance(manifest, dict):
        return "BLOCKED", ("RELEASE_MANIFEST_MALFORMED",)
    reasons: list[str] = []
    if manifest.get("schema") != RELEASE_MANIFEST_SCHEMA:
        reasons.append("RELEASE_MANIFEST_SCHEMA_INVALID")
    for field in REQUIRED_MANIFEST_FIELDS:
        if manifest.get(field) in ("", None):
            reasons.append(f"RELEASE_MANIFEST_{field.upper()}_MISSING")
    if parse_timestamp(manifest.get("created_at")) is None:
        reasons.append("RELEASE_MANIFEST_CREATED_AT_INVALID")
    if contains_sensitive_marker(manifest):
        reasons.append("RELEASE_MANIFEST_SENSITIVE_PAYLOAD_BLOCKED")
    expected_hash = sha256_json(manifest | {"manifest_hash": ""})
    if manifest.get("manifest_hash") and manifest.get("manifest_hash") != expected_hash:
        reasons.append("RELEASE_MANIFEST_HASH_MISMATCH")
    return ("BLOCKED" if reasons else "READY"), tuple(sorted(set(reasons)))
