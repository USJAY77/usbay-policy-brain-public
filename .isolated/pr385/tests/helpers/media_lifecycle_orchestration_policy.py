from __future__ import annotations

import json
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
POLICY_PATH = ROOT / "governance" / "media_lifecycle_orchestration_policy.json"
MANIFEST_PATH = ROOT / "artifacts" / "media-lifecycle-orchestration-manifest.json"


def load_media_lifecycle_orchestration_policy(path: Path = POLICY_PATH) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def load_media_lifecycle_orchestration_manifest(path: Path = MANIFEST_PATH) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def valid_lifecycle_orchestration_manifest() -> dict[str, Any]:
    return load_media_lifecycle_orchestration_manifest()


def verify_media_lifecycle_orchestration(
    manifest: dict[str, Any] | None,
    *,
    policy: dict[str, Any] | None = None,
) -> dict[str, Any]:
    resolved_policy = policy or load_media_lifecycle_orchestration_policy()
    if resolved_policy.get("non_production_scaffolding") is not True:
        return _fail_closed("MEDIA_ORCHESTRATION_POLICY_SCOPE_UNCLEAR")
    if manifest is None:
        return _fail_closed("MEDIA_ORCHESTRATION_MANIFEST_MISSING")
    if not isinstance(manifest, dict):
        return _fail_closed("MEDIA_ORCHESTRATION_MANIFEST_MALFORMED")
    if manifest.get("non_production_demo") is not True or manifest.get("reference_only") is not True:
        return _fail_closed("MEDIA_ORCHESTRATION_SCOPE_UNCLEAR")

    expected_stages = resolved_policy["declarative_lifecycle_stages"]
    executed_stages = manifest.get("executed_stages")
    if not isinstance(executed_stages, list):
        return _fail_closed("MEDIA_ORCHESTRATION_STAGE_LIST_MISSING")
    if any(stage not in expected_stages for stage in executed_stages):
        return _fail_closed("MEDIA_ORCHESTRATION_UNKNOWN_STAGE")
    if executed_stages != expected_stages or manifest.get("stage_order_valid") is not True:
        return _fail_closed("MEDIA_ORCHESTRATION_STAGE_ORDER_VIOLATION")
    if manifest.get("required_gates_present") is not True:
        return _fail_closed("MEDIA_ORCHESTRATION_REQUIRED_GATE_MISSING")
    if manifest.get("attempted_runtime_override") is True:
        return _fail_closed("MEDIA_ORCHESTRATION_RUNTIME_OVERRIDE_ATTEMPT")

    allowlist = [tuple(item) for item in resolved_policy["state_transition_allowlist"]]
    transitions = list(zip(executed_stages, executed_stages[1:]))
    if transitions != allowlist:
        return _fail_closed("MEDIA_ORCHESTRATION_STAGE_ORDER_VIOLATION")

    return {
        "decision": "PASS",
        "fail_closed": False,
        "non_production_scaffolding": True,
        "orchestration_reference_only": True,
        "reason": "MEDIA_LIFECYCLE_ORCHESTRATION_VALID",
    }


def _fail_closed(reason: str) -> dict[str, Any]:
    return {"decision": "FAIL_CLOSED", "fail_closed": True, "reason": reason, "silent_pass": False}
