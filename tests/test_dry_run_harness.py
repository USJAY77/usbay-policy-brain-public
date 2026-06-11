from __future__ import annotations

from pathlib import Path

from automation.dry_run_harness import FLOW, simulate_dry_run_flow


def test_dry_run_harness_simulates_required_flow_and_writes_audit(tmp_path: Path) -> None:
    audit_path = tmp_path / "dry_run_audit.json"
    result = simulate_dry_run_flow(actor="automation-readiness", policy_hash="f" * 64, audit_path=audit_path)
    assert result["decision"] == "VERIFIED"
    assert [step["system"] for step in result["steps"]] == list(FLOW)
    assert all(step["mode"] == "DRY_RUN" for step in result["steps"])
    assert all(step["live_action_performed"] is False for step in result["steps"])
    assert all(step["external_call_performed"] is False for step in result["steps"])
    assert result["production_automation_activated"] is False
    assert result["audit"]["audit_hash"]
    assert audit_path.exists()


def test_dry_run_harness_does_not_store_raw_payloads_or_secrets(tmp_path: Path) -> None:
    audit_path = tmp_path / "dry_run_audit.json"
    simulate_dry_run_flow(actor="automation-readiness", policy_hash="f" * 64, audit_path=audit_path)
    audit_text = audit_path.read_text(encoding="utf-8").lower()
    assert "secret" not in audit_text
    assert "raw_payload" not in audit_text
    assert "token" not in audit_text
