from __future__ import annotations


REQUIRED_COMPONENTS = [
    "runtime_controller",
    "execution_boundary",
    "decision_engine",
    "risk_classifier",
    "policy_enforcement",
    "approval_workflow",
    "execution_contract",
    "audit_binding",
    "provider_abstraction",
    "runtime_safety",
    "rollback",
]


def build_integration_matrix(component_status: dict[str, bool]) -> dict:
    missing = [component for component in REQUIRED_COMPONENTS if not component_status.get(component)]
    return {
        "required_components": REQUIRED_COMPONENTS,
        "missing_components": missing,
        "readiness": "READY" if not missing else "BLOCKED",
    }

