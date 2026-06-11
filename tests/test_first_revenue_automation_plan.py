from __future__ import annotations

from pathlib import Path


PLAN = Path("governance/evidence/pb221_225/first_revenue_automation_plan.md")


def test_first_revenue_plan_exists_and_selects_governed_github_codex_workflow() -> None:
    text = PLAN.read_text(encoding="utf-8")
    assert "governed GitHub/Codex workflow" in text
    assert "Pricing model" in text
    assert "Buyer" in text
    assert "Risks" in text
    assert "Controls" in text
    assert "Evidence" in text
    assert "Rollout plan" in text


def test_first_revenue_plan_prohibits_sales_automation_activation() -> None:
    text = PLAN.read_text(encoding="utf-8")
    assert "No sales automation activation" in text
    assert "No connector activation" in text
    assert "BLOCKED" in text
