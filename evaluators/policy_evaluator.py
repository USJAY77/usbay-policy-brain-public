from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any


EVALUATOR_VERSION = "pb207-policy-evaluator-contract-v1"
DEFAULT_POLICY_REGISTRY_PATH = Path("governance/policy_registry.json")
VALID_DECISIONS = {"PASS", "FAIL"}


class PolicyEvaluationError(RuntimeError):
    pass


def canonical_json(data: Any) -> str:
    return json.dumps(data, sort_keys=True, separators=(",", ":"))


def sha256_json(data: Any) -> str:
    return hashlib.sha256(canonical_json(data).encode("utf-8")).hexdigest()


def load_policy_registry(path: str | Path = DEFAULT_POLICY_REGISTRY_PATH) -> dict[str, Any]:
    registry_path = Path(path)
    if not registry_path.exists():
        raise PolicyEvaluationError("MISSING_POLICY")
    try:
        registry = json.loads(registry_path.read_text(encoding="utf-8"))
    except Exception as exc:
        raise PolicyEvaluationError("MALFORMED_POLICY_REGISTRY") from exc
    if not isinstance(registry, dict):
        raise PolicyEvaluationError("MALFORMED_POLICY_REGISTRY")
    return registry


def active_policy_hash(registry: dict[str, Any]) -> str:
    contract_hash = registry.get("policy_hash")
    if isinstance(contract_hash, str) and len(contract_hash) == 64:
        return contract_hash
    # Backward-compatible hash for the existing signed registry shape.
    return sha256_json(registry)


def policy_is_active(registry: dict[str, Any]) -> bool:
    if "active" in registry:
        return registry.get("active") is True
    return True


def validate_pr_request(payload: dict[str, Any]) -> list[str]:
    gaps: list[str] = []
    if not isinstance(payload, dict):
        return ["MALFORMED_REQUEST"]
    if not isinstance(payload.get("repository"), str) or not payload.get("repository"):
        gaps.append("MISSING_REPOSITORY")
    if not isinstance(payload.get("pull_request"), dict):
        gaps.append("MISSING_PULL_REQUEST")
    if not isinstance(payload.get("diff"), dict):
        gaps.append("MALFORMED_DIFF")
    else:
        changed_files = payload["diff"].get("changed_files")
        if not isinstance(changed_files, list) or not all(isinstance(item, str) for item in changed_files):
            gaps.append("MALFORMED_DIFF")
    requested_hash = payload.get("policy_hash")
    if requested_hash is not None and not isinstance(requested_hash, str):
        gaps.append("UNKNOWN_POLICY_HASH")
    return gaps


def evaluate_pr(
    payload: dict[str, Any],
    *,
    policy_registry_path: str | Path = DEFAULT_POLICY_REGISTRY_PATH,
) -> dict[str, Any]:
    try:
        registry = load_policy_registry(policy_registry_path)
        registry_hash = active_policy_hash(registry)
        gaps = validate_pr_request(payload)
        if not policy_is_active(registry):
            gaps.append("POLICY_INACTIVE")
        requested_hash = payload.get("policy_hash") if isinstance(payload, dict) else None
        if requested_hash and requested_hash != registry_hash:
            gaps.append("UNKNOWN_POLICY_HASH")
        decision = "PASS" if not gaps else "FAIL"
        return {
            "decision": decision,
            "gaps": sorted(set(gaps)),
            "policy_hash": registry_hash,
            "evaluator_version": EVALUATOR_VERSION,
        }
    except PolicyEvaluationError as exc:
        return {
            "decision": "FAIL",
            "gaps": [str(exc)],
            "policy_hash": None,
            "evaluator_version": EVALUATOR_VERSION,
        }
    except Exception:
        return {
            "decision": "FAIL",
            "gaps": ["EVALUATOR_ERROR"],
            "policy_hash": None,
            "evaluator_version": EVALUATOR_VERSION,
        }
