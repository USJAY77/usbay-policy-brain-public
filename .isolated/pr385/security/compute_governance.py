from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any


DEFAULT_COMPUTE_POLICY_PATH = Path("governance/compute_policy.json")
DEFAULT_POLICY_AUTHORITY_PATH = Path("governance/policy_authority.json")
RISK_ORDER = {
    "low": 0,
    "medium": 1,
    "high": 2,
    "critical": 3,
}


class ComputeGovernanceError(RuntimeError):
    pass


def canonical_policy_json(policy: dict[str, Any]) -> str:
    return json.dumps(policy, sort_keys=True, separators=(",", ":"))


def compute_policy_hash(policy: dict[str, Any]) -> str:
    return hashlib.sha256(canonical_policy_json(policy).encode("utf-8")).hexdigest()


def _normalize_compute_policy(policy: dict[str, Any]) -> dict[str, Any]:
    if "allowed" in policy or "restricted" in policy:
        allowed = [str(item).lower() for item in policy.get("allowed", [])]
        restricted = [str(item).lower() for item in policy.get("restricted", [])]
        return {
            "allowed": allowed,
            "restricted": restricted,
            "known_compute": sorted(set(allowed + restricted)),
            "default": str(policy.get("default", "")).lower(),
            "sensitive_data_allowed_on": [
                str(item).lower() for item in policy.get("sensitive_data_allowed_on", [])
            ],
            "human_review_required_for": [
                str(item).lower() for item in policy.get("human_review_required_for", [])
            ],
            "cloud_compute_allowed": bool(policy.get("cloud_compute_allowed", False)),
        }
    allowed = [str(item).lower() for item in policy.get("allowed_compute", [])]
    restricted = [str(item).lower() for item in policy.get("restricted_compute", [])]
    return {
        "allowed": allowed,
        "restricted": restricted,
        "known_compute": sorted(set(allowed + restricted)),
        "default": str(policy.get("default_compute", "")).lower(),
        "sensitive_data_allowed_on": [
            str(item).lower() for item in policy.get("sensitive_data_allowed_on", [])
        ],
        "human_review_required_for": [
            str(item).lower() for item in policy.get("human_review_required_for", [])
        ],
        "cloud_compute_allowed": bool(policy.get("cloud_allowed", policy.get("cloud_compute_allowed", False))),
    }


def _validate_normalized_policy(policy: dict[str, Any]) -> dict[str, Any]:
    if not policy["allowed"] or not all(isinstance(item, str) and item for item in policy["allowed"]):
        raise ComputeGovernanceError("compute_policy_invalid")
    if not all(isinstance(item, str) and item for item in policy["known_compute"]):
        raise ComputeGovernanceError("compute_policy_invalid")
    if not policy["default"] or policy["default"] not in policy["known_compute"]:
        raise ComputeGovernanceError("compute_policy_invalid")
    if not all(isinstance(item, str) and item for item in policy["sensitive_data_allowed_on"]):
        raise ComputeGovernanceError("compute_policy_invalid")
    if not all(isinstance(item, str) and item for item in policy["human_review_required_for"]):
        raise ComputeGovernanceError("compute_policy_invalid")
    return policy


def load_compute_policy(
    path: Path | None = None,
    authority_path: Path | None = None,
) -> dict[str, Any]:
    authority = authority_path or DEFAULT_POLICY_AUTHORITY_PATH
    if authority.exists() and path is None:
        try:
            authority_data = json.loads(authority.read_text(encoding="utf-8"))
            compute_policy = authority_data.get("compute_policy")
        except Exception as exc:
            raise ComputeGovernanceError("compute_policy_unavailable") from exc
        if not isinstance(compute_policy, dict):
            raise ComputeGovernanceError("compute_policy_invalid")
        return _validate_normalized_policy(_normalize_compute_policy(compute_policy))

    policy_path = path or DEFAULT_COMPUTE_POLICY_PATH
    try:
        policy = json.loads(policy_path.read_text(encoding="utf-8"))
    except Exception as exc:
        raise ComputeGovernanceError("compute_policy_unavailable") from exc
    if not isinstance(policy, dict):
        raise ComputeGovernanceError("compute_policy_invalid")
    return _validate_normalized_policy(_normalize_compute_policy(policy))


def compute_policy_state(path: Path | None = None) -> dict[str, Any]:
    try:
        policy = load_compute_policy(path)
    except ComputeGovernanceError as exc:
        return {"state": "invalid", "reason": str(exc), "compute_policy_hash": None}
    return {
        "state": "valid",
        "reason": "ok",
        "compute_policy_hash": compute_policy_hash(policy),
        "default_compute": policy["default"],
    }


def _is_sensitive(payload: dict[str, Any]) -> bool:
    sensitivity = str(payload.get("data_sensitivity", "")).lower()
    if sensitivity in {"sensitive", "restricted", "confidential", "high"}:
        return True
    return payload.get("sensitive_data") is True


def _is_cloud_compute(payload: dict[str, Any], compute_target: str) -> bool:
    location = str(payload.get("execution_location", "")).lower()
    if payload.get("cloud_compute") is True:
        return True
    return compute_target.startswith("cloud_") or location == "cloud"


def _risk_exceeds_without_review(policy: dict[str, Any], risk_level: str) -> bool:
    risk = RISK_ORDER.get(risk_level)
    maximum = RISK_ORDER.get(str(policy.get("max_risk_without_review", "")).lower())
    if risk is None or maximum is None:
        return True
    return risk > maximum


def validate_compute_request(payload: dict[str, Any], policy_path: Path | None = None) -> tuple[str, str, dict[str, Any]]:
    try:
        policy = load_compute_policy(policy_path)
    except ComputeGovernanceError as exc:
        return "DENY", str(exc), {"compute_policy_hash": None}
    if not isinstance(payload, dict):
        return "DENY", "compute_target_missing", {"compute_policy_hash": compute_policy_hash(policy)}

    compute_target = payload.get("compute_target")
    evidence = {
        "compute_target": compute_target,
        "compute_policy_hash": compute_policy_hash(policy),
        "compute_risk_level": str(payload.get("compute_risk_level", payload.get("risk_level", "unknown"))).lower(),
        "human_review": payload.get("human_review") is True,
        "data_sensitivity": str(payload.get("data_sensitivity", "")).lower(),
        "execution_location": str(payload.get("execution_location", "")).lower(),
    }
    if not isinstance(compute_target, str) or not compute_target:
        return "DENY", "compute_target_missing", evidence
    if evidence["data_sensitivity"] not in {"low", "medium", "high"}:
        return "DENY", "sensitive_data_compute_denied", evidence
    if evidence["execution_location"] not in {"local", "edge", "cloud"}:
        return "DENY", "compute_target_not_allowed", evidence
    compute_target = compute_target.lower()
    evidence["compute_target"] = compute_target
    if compute_target not in policy["known_compute"]:
        return "DENY", "compute_target_not_allowed", evidence
    if compute_target not in policy["allowed"] and payload.get("human_review") is not True:
        return "DENY", "human_review_required", evidence

    cloud_compute = _is_cloud_compute(payload, compute_target)
    if cloud_compute and policy.get("cloud_compute_allowed") is not True:
        return "DENY", "compute_target_not_allowed", evidence

    sensitive = _is_sensitive(payload)
    if sensitive and (cloud_compute or compute_target not in policy["sensitive_data_allowed_on"]):
        return "DENY", "sensitive_data_compute_denied", evidence

    review_targets = {str(item).lower() for item in policy["human_review_required_for"]}
    requires_review = compute_target in review_targets or cloud_compute
    if requires_review and payload.get("human_review") is not True:
        return "DENY", "human_review_required", evidence

    return "ALLOW", "compute_governance_valid", evidence
