from __future__ import annotations

from pathlib import Path

from approval.operator_approval_view_model import build_operator_approval_view_model


RUNBOOK = Path("governance/evidence/pb216_220/operator_approval_runbook.md")


def test_operator_approval_runbook_exists_and_requires_manual_high_risk_review() -> None:
    text = RUNBOOK.read_text(encoding="utf-8")
    assert "High-risk automation" in text
    assert "No real approval execution" in text
    assert "FAIL_CLOSED" in text
    assert "Do not store secrets" in text


def test_operator_approval_view_model_is_local_only_and_non_executing() -> None:
    model = build_operator_approval_view_model(
        action_id="approval-test",
        actor="operator",
        target="GitHub",
        risk_level="HIGH",
        policy_hash="d" * 64,
    )
    assert model["local_only"] is True
    assert model["executes_approval"] is False
    assert "execute_approval" in model["disabled_controls"]
    assert model["approval_status"] == "BLOCKED"
