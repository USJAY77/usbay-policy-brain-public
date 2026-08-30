from __future__ import annotations

import json
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
POLICY_PATH = ROOT / "governance" / "media_model_drift_policy.json"
MANIFEST_PATH = ROOT / "artifacts" / "media-drift-governance-manifest.json"
EXPECTED_MODEL_IDENTIFIER = "AI_MEDIA_MODEL_PLACEHOLDER_NON_PRODUCTION"
EXPECTED_MODEL_VERSION = "media-demo-model-v1"
REFERENCE_FIELDS = (
    "provenance_reference",
    "approval_reference",
    "jurisdiction_reference",
    "revocation_reference",
    "export_schema_reference",
)
DRIFT_REASON_BY_STATE = {
    "MODEL_VERSION_DRIFT": "MEDIA_MODEL_VERSION_DRIFT",
    "POLICY_LINEAGE_BROKEN": "MEDIA_POLICY_LINEAGE_BROKEN",
    "PROVENANCE_CHAIN_GAP": "MEDIA_PROVENANCE_CHAIN_GAP",
    "APPROVAL_REGRESSION": "MEDIA_APPROVAL_CHAIN_REGRESSION",
    "JURISDICTION_POLICY_CONFLICT": "MEDIA_JURISDICTION_POLICY_DRIFT",
    "EXPORT_SCHEMA_DRIFT": "MEDIA_EXPORT_SCHEMA_DRIFT",
    "DISTRIBUTION_SCOPE_DRIFT": "MEDIA_DISTRIBUTION_SCOPE_REGRESSION",
    "REVOCATION_OVERRIDE_LOST": "MEDIA_REVOCATION_OVERRIDE_LOST",
}


def load_media_model_drift_policy(path: Path = POLICY_PATH) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def load_media_drift_manifest(path: Path = MANIFEST_PATH) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def valid_drift_evidence(media_asset_id: str) -> dict[str, Any]:
    manifest = load_media_drift_manifest()
    manifest["media_asset_id"] = media_asset_id
    return {
        "approval_chain_regression": False,
        "distribution_scope_regression": False,
        "drift_findings": [],
        "export_schema_drift": False,
        "jurisdiction_policy_drift": False,
        "media_asset_id": media_asset_id,
        "model_identifier": manifest["model_identifier"],
        "model_version": manifest["model_version"],
        "policy_lineage_valid": True,
        "provenance_continuity": True,
        "revocation_override_present": True,
        "timestamp_chain_continuity": True,
    }


def verify_media_model_drift(
    evidence: dict[str, Any] | None,
    *,
    media_asset_id: str,
    policy: dict[str, Any] | None = None,
) -> dict[str, Any]:
    resolved_policy = policy or load_media_model_drift_policy()
    if resolved_policy.get("non_production_scaffolding") is not True:
        return _fail_closed("MEDIA_MODEL_DRIFT_POLICY_SCOPE_UNCLEAR")
    if resolved_policy.get("drift_review_required") is not True:
        return _fail_closed("MEDIA_MODEL_DRIFT_REVIEW_DISABLED")
    if evidence is None:
        return _fail_closed("MEDIA_MODEL_DRIFT_EVIDENCE_MISSING")
    if not isinstance(evidence, dict):
        return _fail_closed("MEDIA_MODEL_DRIFT_EVIDENCE_MALFORMED")
    if evidence.get("media_asset_id") != media_asset_id:
        return _fail_closed("MEDIA_MODEL_DRIFT_MEDIA_ASSET_SCOPE_MISMATCH")
    if evidence.get("model_identifier") != EXPECTED_MODEL_IDENTIFIER:
        return _fail_closed("MEDIA_MODEL_IDENTITY_MISMATCH")
    if evidence.get("model_version") != EXPECTED_MODEL_VERSION:
        return _fail_closed("MEDIA_MODEL_VERSION_DRIFT")
    if evidence.get("provenance_continuity") is not True:
        return _fail_closed("MEDIA_PROVENANCE_CHAIN_GAP")
    if evidence.get("policy_lineage_valid") is not True:
        return _fail_closed("MEDIA_POLICY_LINEAGE_BROKEN")
    if evidence.get("timestamp_chain_continuity") is not True:
        return _fail_closed("MEDIA_TIMESTAMP_CHAIN_GAP")
    if evidence.get("jurisdiction_policy_drift") is True:
        return _fail_closed("MEDIA_JURISDICTION_POLICY_DRIFT")
    if evidence.get("approval_chain_regression") is True:
        return _fail_closed("MEDIA_APPROVAL_CHAIN_REGRESSION")
    if evidence.get("export_schema_drift") is True:
        return _fail_closed("MEDIA_EXPORT_SCHEMA_DRIFT")
    if evidence.get("distribution_scope_regression") is True:
        return _fail_closed("MEDIA_DISTRIBUTION_SCOPE_REGRESSION")
    if evidence.get("revocation_override_present") is not True:
        return _fail_closed("MEDIA_REVOCATION_OVERRIDE_LOST")
    for finding in evidence.get("drift_findings", []):
        if finding in DRIFT_REASON_BY_STATE:
            return _fail_closed(DRIFT_REASON_BY_STATE[finding])

    return {
        "decision": "PASS",
        "drift_review_required": True,
        "fail_closed": False,
        "media_asset_id": media_asset_id,
        "non_production_scaffolding": True,
        "reason": "MEDIA_MODEL_DRIFT_GOVERNANCE_VALID",
    }


def verify_media_drift_manifest(
    manifest: dict[str, Any] | None,
    *,
    policy: dict[str, Any] | None = None,
) -> dict[str, Any]:
    resolved_policy = policy or load_media_model_drift_policy()
    if manifest is None:
        return _fail_closed("MEDIA_DRIFT_MANIFEST_MISSING")
    if not isinstance(manifest, dict):
        return _fail_closed("MEDIA_DRIFT_MANIFEST_MALFORMED")
    if manifest.get("non_production_demo") is not True:
        return _fail_closed("MEDIA_DRIFT_MANIFEST_SCOPE_UNCLEAR")
    if manifest.get("model_identifier") != EXPECTED_MODEL_IDENTIFIER:
        return _fail_closed("MEDIA_MODEL_IDENTITY_MISMATCH")
    if manifest.get("model_version") != EXPECTED_MODEL_VERSION:
        return _fail_closed("MEDIA_MODEL_VERSION_DRIFT")
    missing = [field for field in REFERENCE_FIELDS if not manifest.get(field)]
    if missing:
        return _fail_closed("MEDIA_DRIFT_MANIFEST_LINEAGE_MISSING", missing_fields=missing)
    flags = manifest.get("fail_closed_flags")
    if not isinstance(flags, dict) or any(value is not True for value in flags.values()):
        return _fail_closed("MEDIA_DRIFT_MANIFEST_FAIL_CLOSED_FLAGS_MISSING")
    for finding in manifest.get("drift_findings", []):
        if finding in resolved_policy["drift_states"]:
            return _fail_closed(DRIFT_REASON_BY_STATE[finding])
    return {
        "decision": "PASS",
        "drift_findings": [],
        "fail_closed": False,
        "media_asset_id": manifest["media_asset_id"],
        "reason": "MEDIA_DRIFT_MANIFEST_VALID",
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
