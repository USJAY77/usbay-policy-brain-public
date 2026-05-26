from __future__ import annotations

import json
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
POLICY_PATH = ROOT / "governance" / "media_dashboard_export_policy.json"
MANIFEST_PATH = ROOT / "artifacts" / "media-dashboard-export-manifest.json"


def load_media_dashboard_export_policy(path: Path = POLICY_PATH) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def load_media_dashboard_export_manifest(path: Path = MANIFEST_PATH) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def valid_dashboard_export_manifest() -> dict[str, Any]:
    return load_media_dashboard_export_manifest()


def verify_media_dashboard_export(
    manifest: dict[str, Any] | None,
    *,
    policy: dict[str, Any] | None = None,
) -> dict[str, Any]:
    resolved_policy = policy or load_media_dashboard_export_policy()
    if resolved_policy.get("non_production_scaffolding") is not True:
        return _fail_closed("MEDIA_DASHBOARD_EXPORT_POLICY_SCOPE_UNCLEAR")
    if manifest is None:
        return _fail_closed("MEDIA_DASHBOARD_EXPORT_MANIFEST_MISSING")
    if not isinstance(manifest, dict):
        return _fail_closed("MEDIA_DASHBOARD_EXPORT_MANIFEST_MALFORMED")
    if manifest.get("non_production_demo") is not True or manifest.get("reference_only") is not True:
        return _fail_closed("MEDIA_DASHBOARD_EXPORT_SCOPE_UNCLEAR")
    for field, reason in (
        ("lifecycle_graph_reference", "MEDIA_DASHBOARD_LIFECYCLE_GRAPH_REFERENCE_MISSING"),
        ("audit_export_reference", "MEDIA_DASHBOARD_AUDIT_EXPORT_REFERENCE_MISSING"),
        ("regulator_export_reference", "MEDIA_DASHBOARD_REGULATOR_EXPORT_REFERENCE_MISSING"),
        ("escalation_dashboard_reference", "MEDIA_DASHBOARD_ESCALATION_REFERENCE_MISSING"),
    ):
        if not manifest.get(field):
            return _fail_closed(reason)
    if not manifest.get("export_scope"):
        return _fail_closed("MEDIA_DASHBOARD_EXPORT_UNSCOPED")
    if manifest.get("export_contains_sensitive_payload") is True:
        return _fail_closed("MEDIA_DASHBOARD_EXPORT_SENSITIVE_PAYLOAD")
    if not manifest.get("export_purpose"):
        return _fail_closed("MEDIA_DASHBOARD_EXPORT_PURPOSE_MISSING")

    return {
        "dashboard_export_reference_only": True,
        "decision": "PASS",
        "fail_closed": False,
        "non_production_scaffolding": True,
        "reason": "MEDIA_DASHBOARD_EXPORT_VALID",
    }


def _fail_closed(reason: str) -> dict[str, Any]:
    return {"decision": "FAIL_CLOSED", "fail_closed": True, "reason": reason, "silent_pass": False}
