from __future__ import annotations

from typing import Any


OPERATOR_APPROVAL_VIEW_MODEL_VERSION = "pb218-operator-approval-view-model-v1"


def build_operator_approval_view_model(
    *,
    action_id: str,
    actor: str,
    target: str,
    risk_level: str,
    policy_hash: str,
    approval_status: str = "BLOCKED",
) -> dict[str, Any]:
    status = approval_status if approval_status in {"BLOCKED", "REQUIRED", "APPROVED", "DENIED", "EXPIRED"} else "BLOCKED"
    return {
        "view_model_version": OPERATOR_APPROVAL_VIEW_MODEL_VERSION,
        "local_only": True,
        "executes_approval": False,
        "action_id": action_id,
        "actor": actor,
        "target": target,
        "risk_level": risk_level,
        "policy_hash": policy_hash,
        "approval_status": status,
        "allowed_controls": ["display_evidence", "record_manual_review_intent"],
        "disabled_controls": ["execute_approval", "activate_connector", "deploy"],
    }
