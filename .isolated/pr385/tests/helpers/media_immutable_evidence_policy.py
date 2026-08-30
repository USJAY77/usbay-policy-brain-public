from __future__ import annotations

import json
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
POLICY_PATH = ROOT / "governance" / "media_immutable_evidence_policy.json"
MANIFEST_PATH = ROOT / "artifacts" / "media-immutable-evidence-manifest.json"


def load_media_immutable_evidence_policy(path: Path = POLICY_PATH) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def load_media_immutable_evidence_manifest(path: Path = MANIFEST_PATH) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def valid_immutable_evidence_manifest() -> dict[str, Any]:
    return load_media_immutable_evidence_manifest()


def verify_media_immutable_evidence(
    manifest: dict[str, Any] | None,
    *,
    policy: dict[str, Any] | None = None,
) -> dict[str, Any]:
    resolved_policy = policy or load_media_immutable_evidence_policy()
    if resolved_policy.get("non_production_scaffolding") is not True:
        return _fail_closed("MEDIA_IMMUTABLE_EVIDENCE_POLICY_SCOPE_UNCLEAR")
    if resolved_policy.get("immutable_evidence_required") is not True:
        return _fail_closed("MEDIA_IMMUTABLE_EVIDENCE_POLICY_DISABLED")
    if manifest is None:
        return _fail_closed("MEDIA_IMMUTABLE_EVIDENCE_MISSING")
    if not isinstance(manifest, dict):
        return _fail_closed("MEDIA_IMMUTABLE_EVIDENCE_MALFORMED")
    if manifest.get("non_production_demo") is not True or manifest.get("reference_only") is not True:
        return _fail_closed("MEDIA_IMMUTABLE_EVIDENCE_SCOPE_UNCLEAR")
    if not manifest.get("signature_reference"):
        return _fail_closed("MEDIA_EVIDENCE_BUNDLE_UNSIGNED")
    if not manifest.get("chain_hash_reference"):
        return _fail_closed("MEDIA_EVIDENCE_CHAIN_HASH_MISSING")
    if manifest.get("mutable_storage_marker") is True:
        return _fail_closed("MEDIA_EVIDENCE_MUTABLE_STORAGE_MARKER")
    if not manifest.get("timestamp_reference"):
        return _fail_closed("MEDIA_EVIDENCE_TIMESTAMP_REFERENCE_MISSING")
    if manifest.get("lineage_gap_detected") is True:
        return _fail_closed("MEDIA_EVIDENCE_LINEAGE_GAP")
    if manifest.get("replay_anchor_present") is not True or not manifest.get("evidence_anchor_reference"):
        return _fail_closed("MEDIA_REPLAY_WITHOUT_EVIDENCE_ANCHOR")

    return {
        "decision": "PASS",
        "fail_closed": False,
        "immutable_evidence_reference_only": True,
        "non_production_scaffolding": True,
        "reason": "MEDIA_IMMUTABLE_EVIDENCE_VALID",
    }


def _fail_closed(reason: str) -> dict[str, Any]:
    return {"decision": "FAIL_CLOSED", "fail_closed": True, "reason": reason, "silent_pass": False}
