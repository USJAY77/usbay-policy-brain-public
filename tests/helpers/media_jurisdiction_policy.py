from __future__ import annotations

import json
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
POLICY_PATH = ROOT / "governance" / "media_jurisdiction_policy.json"
MANIFEST_PATH = ROOT / "artifacts" / "media-jurisdiction-export-manifest.json"
REFERENCE_FIELDS = (
    "provenance_reference",
    "approval_reference",
    "rights_reference",
    "distribution_reference",
    "revocation_reference",
)


def load_media_jurisdiction_policy(path: Path = POLICY_PATH) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def load_media_jurisdiction_export_manifest(path: Path = MANIFEST_PATH) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def valid_jurisdiction_evidence(
    media_asset_id: str,
    *,
    jurisdiction: str = "eu_ai_act",
    platform: str = "spotify",
) -> dict[str, Any]:
    return {
        "audit_export_jurisdiction_scope_bound": True,
        "cross_jurisdiction_conflict": False,
        "distribution_region_locked": False,
        "jurisdiction_scope": jurisdiction,
        "linked_emergency_freeze": False,
        "media_asset_id": media_asset_id,
        "platform": platform,
        "platform_restricted": False,
        "regional_consent_active": True,
        "regional_rights_active": True,
        "regional_rights_expires_at": "2027-05-26T00:00:00Z",
        "revocation_state": "DISTRIBUTION_AUTHORIZED",
    }


def verify_media_jurisdiction(
    evidence: dict[str, Any] | None,
    *,
    media_asset_id: str,
    platform: str,
    export_required: bool = False,
    policy: dict[str, Any] | None = None,
) -> dict[str, Any]:
    resolved_policy = policy or load_media_jurisdiction_policy()
    if resolved_policy.get("non_production_scaffolding") is not True:
        return _fail_closed("MEDIA_JURISDICTION_POLICY_SCOPE_UNCLEAR")
    if evidence is None:
        return _fail_closed("MEDIA_JURISDICTION_SCOPE_MISSING")
    if not isinstance(evidence, dict):
        return _fail_closed("MEDIA_JURISDICTION_EVIDENCE_MALFORMED")
    if evidence.get("media_asset_id") != media_asset_id:
        return _fail_closed("MEDIA_JURISDICTION_MEDIA_ASSET_SCOPE_MISMATCH")

    jurisdiction = evidence.get("jurisdiction_scope")
    if resolved_policy.get("jurisdiction_scope_required") is True and not jurisdiction:
        return _fail_closed("MEDIA_JURISDICTION_SCOPE_MISSING")
    if jurisdiction not in resolved_policy["placeholder_jurisdictions"]:
        return _fail_closed("MEDIA_JURISDICTION_UNKNOWN")
    if evidence.get("cross_jurisdiction_conflict") is True:
        return _fail_closed("MEDIA_CROSS_JURISDICTION_CONFLICT")
    if evidence.get("regional_rights_active") is not True:
        return _fail_closed("MEDIA_REGIONAL_RIGHTS_REVOKED")
    if evidence.get("regional_rights_expires_at") <= "2026-05-26T00:00:00Z":
        return _fail_closed("MEDIA_REGIONAL_RIGHTS_EXPIRED")
    if evidence.get("regional_consent_active") is not True:
        return _fail_closed("MEDIA_REGIONAL_CONSENT_MISSING")
    if evidence.get("distribution_region_locked") is True:
        return _fail_closed("MEDIA_REGION_LOCKED_DISTRIBUTION")
    if evidence.get("platform") != platform or evidence.get("platform_restricted") is True:
        return _fail_closed("MEDIA_RESTRICTED_PLATFORM_DISTRIBUTION")
    if evidence.get("linked_emergency_freeze") is True or evidence.get("revocation_state") == "EMERGENCY_FROZEN":
        return _fail_closed("MEDIA_JURISDICTION_EMERGENCY_FREEZE_PROPAGATED")
    if export_required and evidence.get("audit_export_jurisdiction_scope_bound") is not True:
        return _fail_closed("MEDIA_AUDIT_EXPORT_JURISDICTION_SCOPE_MISSING")

    return {
        "decision": "PASS",
        "fail_closed": False,
        "jurisdiction_scope": jurisdiction,
        "media_asset_id": media_asset_id,
        "non_production_scaffolding": True,
        "reason": "MEDIA_JURISDICTION_GOVERNANCE_VALID",
    }


def verify_jurisdiction_export_manifest(
    manifest: dict[str, Any] | None,
    *,
    policy: dict[str, Any] | None = None,
) -> dict[str, Any]:
    resolved_policy = policy or load_media_jurisdiction_policy()
    if manifest is None:
        return _fail_closed("MEDIA_JURISDICTION_EXPORT_MANIFEST_MISSING")
    if not isinstance(manifest, dict):
        return _fail_closed("MEDIA_JURISDICTION_EXPORT_MANIFEST_MALFORMED")
    if manifest.get("non_production_demo") is not True:
        return _fail_closed("MEDIA_JURISDICTION_EXPORT_SCOPE_UNCLEAR")
    if resolved_policy.get("audit_export_requires_jurisdiction_scope") is True and not manifest.get("jurisdiction_scope"):
        return _fail_closed("MEDIA_AUDIT_EXPORT_JURISDICTION_SCOPE_MISSING")
    if manifest.get("jurisdiction_scope") not in resolved_policy["placeholder_jurisdictions"]:
        return _fail_closed("MEDIA_JURISDICTION_UNKNOWN")
    missing = [field for field in REFERENCE_FIELDS if not manifest.get(field)]
    if missing:
        return _fail_closed("MEDIA_JURISDICTION_EXPORT_LINEAGE_MISSING", missing_fields=missing)
    flags = manifest.get("fail_closed_flags")
    if not isinstance(flags, dict) or any(value is not True for value in flags.values()):
        return _fail_closed("MEDIA_JURISDICTION_EXPORT_FAIL_CLOSED_FLAGS_MISSING")
    return {
        "decision": "PASS",
        "export_contains_references_only": True,
        "fail_closed": False,
        "jurisdiction_scope": manifest["jurisdiction_scope"],
        "reason": "MEDIA_JURISDICTION_EXPORT_MANIFEST_VALID",
    }


def _fail_closed(reason: str, **details: Any) -> dict[str, Any]:
    evidence: dict[str, Any] = {
        "decision": "FAIL_CLOSED",
        "fail_closed": True,
        "reason": reason,
        "silent_pass": False,
    }
    evidence.update(details)
    return evidence
