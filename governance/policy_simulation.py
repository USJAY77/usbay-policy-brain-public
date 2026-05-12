from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from governance.policy_pack import (
    PolicyPackValidationError,
    assert_policy_diagnostics_safe,
    load_policy_pack,
    redacted_policy_payload,
    validate_policy_pack,
)

SIMULATION_ERROR_REGISTRY_PATH = Path("governance/policy_simulation_errors.json")
SIMULATION_ERROR_SCHEMA = "usbay.governance_policy_simulation_error_registry.v1"
SIMULATION_ERROR_CODES = (
    "SIM_POLICY_PACK_INVALID",
    "SIM_SCOPE_MISMATCH",
    "SIM_CONFLICTING_DECISION",
    "SIM_HUMAN_APPROVAL_REQUIRED",
    "SIM_FAIL_CLOSED_DEFAULT",
)
DECISION_ALLOW = "ALLOW"
DECISION_DENY = "DENY"
DECISION_REQUIRE_HUMAN_REVIEW = "REQUIRE_HUMAN_REVIEW"
DECISION_FAIL_CLOSED = "FAIL_CLOSED"


class PolicySimulationError(RuntimeError):
    pass


@dataclass(frozen=True)
class PolicySimulationResult:
    decision: str
    errors: tuple[str, ...]
    matched_policy_ids: tuple[str, ...]
    tenant_id: str
    environment: str
    risk_level: str
    human_approval_required: bool

    def to_dict(self) -> dict[str, Any]:
        return {
            "decision": self.decision,
            "errors": list(self.errors),
            "matched_policy_ids": list(self.matched_policy_ids),
            "tenant_id": self.tenant_id,
            "environment": self.environment,
            "risk_level": self.risk_level,
            "human_approval_required": self.human_approval_required,
        }


def load_simulation_error_registry(root: Path) -> dict[str, dict[str, str]]:
    path = root / SIMULATION_ERROR_REGISTRY_PATH
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        raise PolicySimulationError("simulation_error_registry_missing") from exc
    if not isinstance(payload, dict) or payload.get("schema") != SIMULATION_ERROR_SCHEMA:
        raise PolicySimulationError("simulation_error_registry_invalid")
    raw_errors = payload.get("errors")
    if not isinstance(raw_errors, list):
        raise PolicySimulationError("simulation_error_registry_invalid")
    registry: dict[str, dict[str, str]] = {}
    for entry in raw_errors:
        if not isinstance(entry, dict) or not entry.get("code"):
            raise PolicySimulationError("simulation_error_registry_invalid")
        registry[str(entry["code"])] = {
            "description": str(entry.get("description", "")),
            "fail_closed_reason": str(entry.get("fail_closed_reason", "")),
        }
    missing = sorted(set(SIMULATION_ERROR_CODES) - set(registry))
    if missing:
        raise PolicySimulationError("simulation_error_registry_incomplete:" + ",".join(missing))
    return registry


def simulate_policy_decision(
    policy_pack: dict[str, Any],
    request_context: dict[str, Any],
    *,
    tenant_id: str,
    environment: str,
    risk_level: str,
    required_human_approval: bool = False,
) -> PolicySimulationResult:
    validation = validate_policy_pack(policy_pack)
    if not validation.valid:
        return PolicySimulationResult(
            decision=DECISION_FAIL_CLOSED,
            errors=("SIM_POLICY_PACK_INVALID",),
            matched_policy_ids=(),
            tenant_id=tenant_id,
            environment=environment,
            risk_level=risk_level,
            human_approval_required=True,
        )
    if not _scope_allows(policy_pack.get("scope"), tenant_id, environment):
        return PolicySimulationResult(
            decision=DECISION_FAIL_CLOSED,
            errors=("SIM_SCOPE_MISMATCH",),
            matched_policy_ids=(),
            tenant_id=tenant_id,
            environment=environment,
            risk_level=risk_level,
            human_approval_required=True,
        )
    allow_matches: list[str] = []
    deny_matches: list[str] = []
    human_review_matches: list[str] = []
    for policy in policy_pack.get("policies", []):
        if not isinstance(policy, dict) or not _scope_allows(policy.get("scope"), tenant_id, environment):
            continue
        policy_id = str(policy.get("policy_id", ""))
        if _rules_match(policy.get("allow_rules"), request_context):
            allow_matches.append(policy_id)
            if _requires_human_review(policy, risk_level, required_human_approval):
                human_review_matches.append(policy_id)
        if _rules_match(policy.get("deny_rules"), request_context):
            deny_matches.append(policy_id)
    if allow_matches and deny_matches:
        return PolicySimulationResult(
            decision=DECISION_FAIL_CLOSED,
            errors=("SIM_CONFLICTING_DECISION",),
            matched_policy_ids=tuple(sorted(set(allow_matches + deny_matches))),
            tenant_id=tenant_id,
            environment=environment,
            risk_level=risk_level,
            human_approval_required=True,
        )
    if deny_matches:
        return PolicySimulationResult(
            decision=DECISION_DENY,
            errors=(),
            matched_policy_ids=tuple(sorted(set(deny_matches))),
            tenant_id=tenant_id,
            environment=environment,
            risk_level=risk_level,
            human_approval_required=False,
        )
    if human_review_matches:
        return PolicySimulationResult(
            decision=DECISION_REQUIRE_HUMAN_REVIEW,
            errors=("SIM_HUMAN_APPROVAL_REQUIRED",),
            matched_policy_ids=tuple(sorted(set(human_review_matches))),
            tenant_id=tenant_id,
            environment=environment,
            risk_level=risk_level,
            human_approval_required=True,
        )
    if allow_matches:
        return PolicySimulationResult(
            decision=DECISION_ALLOW,
            errors=(),
            matched_policy_ids=tuple(sorted(set(allow_matches))),
            tenant_id=tenant_id,
            environment=environment,
            risk_level=risk_level,
            human_approval_required=False,
        )
    return PolicySimulationResult(
        decision=DECISION_FAIL_CLOSED,
        errors=("SIM_FAIL_CLOSED_DEFAULT",),
        matched_policy_ids=(),
        tenant_id=tenant_id,
        environment=environment,
        risk_level=risk_level,
        human_approval_required=True,
    )


def simulate_policy_file(
    policy_pack_path: Path,
    request_context_path: Path,
    *,
    tenant_id: str,
    environment: str,
    risk_level: str,
    required_human_approval: bool = False,
) -> PolicySimulationResult:
    return simulate_policy_decision(
        load_policy_pack(policy_pack_path),
        _load_request_context(request_context_path),
        tenant_id=tenant_id,
        environment=environment,
        risk_level=risk_level,
        required_human_approval=required_human_approval,
    )


def explain_policy_decision(root: Path, code: str) -> dict[str, str]:
    registry = load_simulation_error_registry(root)
    if code not in registry:
        raise PolicySimulationError("simulation_error_unknown:" + code)
    return {"code": code, **registry[code]}


def simulation_summary(result: PolicySimulationResult) -> dict[str, Any]:
    return {
        "decision": result.decision,
        "error_codes": list(result.errors),
        "matched_policy_count": len(result.matched_policy_ids),
        "tenant_id": result.tenant_id,
        "environment": result.environment,
        "risk_level": result.risk_level,
        "human_approval_required": result.human_approval_required,
    }


def redacted_simulation_payload(payload: Any) -> Any:
    return redacted_policy_payload(payload)


def assert_simulation_diagnostics_safe(payload: Any) -> None:
    assert_policy_diagnostics_safe(payload)


def _load_request_context(path: Path) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        raise PolicySimulationError("simulation_request_context_invalid") from exc
    if not isinstance(payload, dict):
        raise PolicySimulationError("simulation_request_context_invalid")
    return payload


def _scope_allows(scope: Any, tenant_id: str, environment: str) -> bool:
    if not isinstance(scope, dict):
        return False
    tenant_ids = scope.get("tenant_ids")
    environments = scope.get("environments")
    return isinstance(tenant_ids, list) and tenant_id in tenant_ids and isinstance(environments, list) and environment in environments


def _requires_human_review(policy: dict[str, Any], risk_level: str, required_human_approval: bool) -> bool:
    risk = str(risk_level or policy.get("risk_level", "")).lower()
    return required_human_approval or risk in {"high", "critical"} or policy.get("requires_human_approval") is True


def _rules_match(rules: Any, request_context: dict[str, Any]) -> bool:
    if not isinstance(rules, list):
        return False
    for rule in rules:
        if not isinstance(rule, dict):
            continue
        if _rule_matches(rule, request_context):
            return True
    return False


def _rule_matches(rule: dict[str, Any], request_context: dict[str, Any]) -> bool:
    action = str(rule.get("action", ""))
    resource = str(rule.get("resource", "*") or "*")
    condition = str(rule.get("condition", "*") or "*")
    if action and action != str(request_context.get("action", "")):
        return False
    if resource != "*" and resource != str(request_context.get("resource", "")):
        return False
    if condition != "*" and condition != str(request_context.get("condition", "")):
        return False
    return True
