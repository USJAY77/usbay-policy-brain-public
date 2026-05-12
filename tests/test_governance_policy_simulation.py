from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

from governance.policy_pack import POLICY_PACK_SCHEMA
from governance.policy_simulation import (
    DECISION_ALLOW,
    DECISION_DENY,
    DECISION_FAIL_CLOSED,
    DECISION_REQUIRE_HUMAN_REVIEW,
    SIMULATION_ERROR_CODES,
    explain_policy_decision,
    load_simulation_error_registry,
    simulate_policy_decision,
)


ROOT = Path(__file__).resolve().parents[1]


def _policy_pack() -> dict:
    return {
        "schema": POLICY_PACK_SCHEMA,
        "fail_closed": True,
        "valid_from": "2026-01-01T00:00:00Z",
        "valid_until": "2027-01-01T00:00:00Z",
        "scope": {"tenant_ids": ["t1"], "environments": ["test"]},
        "policies": [
            {
                "policy_id": "policy.allow.read",
                "risk_level": "low",
                "requires_human_approval": False,
                "fail_closed": True,
                "valid_from": "2026-01-01T00:00:00Z",
                "valid_until": "2027-01-01T00:00:00Z",
                "scope": {"tenant_ids": ["t1"], "environments": ["test"]},
                "allow_rules": [{"action": "read", "resource": "ledger"}],
                "deny_rules": [],
            },
            {
                "policy_id": "policy.deny.delete",
                "risk_level": "low",
                "requires_human_approval": False,
                "fail_closed": True,
                "valid_from": "2026-01-01T00:00:00Z",
                "valid_until": "2027-01-01T00:00:00Z",
                "scope": {"tenant_ids": ["t1"], "environments": ["test"]},
                "allow_rules": [],
                "deny_rules": [{"action": "delete", "resource": "ledger"}],
            },
        ],
    }


def test_allow_preview() -> None:
    result = simulate_policy_decision(
        _policy_pack(),
        {"action": "read", "resource": "ledger"},
        tenant_id="t1",
        environment="test",
        risk_level="low",
    )

    assert result.decision == DECISION_ALLOW
    assert result.errors == ()
    assert result.matched_policy_ids == ("policy.allow.read",)


def test_deny_preview() -> None:
    result = simulate_policy_decision(
        _policy_pack(),
        {"action": "delete", "resource": "ledger"},
        tenant_id="t1",
        environment="test",
        risk_level="low",
    )

    assert result.decision == DECISION_DENY
    assert result.errors == ()
    assert result.matched_policy_ids == ("policy.deny.delete",)


def test_human_review_preview() -> None:
    pack = _policy_pack()
    pack["policies"][0]["requires_human_approval"] = True

    result = simulate_policy_decision(
        pack,
        {"action": "read", "resource": "ledger"},
        tenant_id="t1",
        environment="test",
        risk_level="high",
    )

    assert result.decision == DECISION_REQUIRE_HUMAN_REVIEW
    assert result.errors == ("SIM_HUMAN_APPROVAL_REQUIRED",)


def test_conflicting_rule_fails_closed() -> None:
    pack = _policy_pack()
    pack["policies"][0]["deny_rules"] = [{"action": "read", "resource": "ledger"}]

    result = simulate_policy_decision(
        pack,
        {"action": "read", "resource": "ledger"},
        tenant_id="t1",
        environment="test",
        risk_level="low",
    )

    assert result.decision == DECISION_FAIL_CLOSED
    assert result.errors == ("SIM_POLICY_PACK_INVALID",)


def test_invalid_policy_pack_fails_closed() -> None:
    pack = _policy_pack()
    pack["fail_closed"] = False

    result = simulate_policy_decision(
        pack,
        {"action": "read", "resource": "ledger"},
        tenant_id="t1",
        environment="test",
        risk_level="low",
    )

    assert result.decision == DECISION_FAIL_CLOSED
    assert result.errors == ("SIM_POLICY_PACK_INVALID",)


def test_tenant_environment_scope_mismatch_fails_closed() -> None:
    result = simulate_policy_decision(
        _policy_pack(),
        {"action": "read", "resource": "ledger"},
        tenant_id="t2",
        environment="production",
        risk_level="low",
    )

    assert result.decision == DECISION_FAIL_CLOSED
    assert result.errors == ("SIM_SCOPE_MISMATCH",)


def test_simulation_error_registry_complete() -> None:
    registry = load_simulation_error_registry(ROOT)

    assert set(SIMULATION_ERROR_CODES).issubset(registry)
    assert explain_policy_decision(ROOT, "SIM_FAIL_CLOSED_DEFAULT")["fail_closed_reason"]


def test_simulation_cli_redacts_request_context(tmp_path: Path) -> None:
    pack_path = tmp_path / "pack.json"
    request_path = tmp_path / "request.json"
    pack_path.write_text(json.dumps(_policy_pack(), sort_keys=True), encoding="utf-8")
    request_path.write_text(json.dumps({"action": "read", "resource": "ledger", "approval_contents": "do-not-print"}), encoding="utf-8")

    completed = subprocess.run(
        [
            sys.executable,
            "scripts/governance_diagnostics.py",
            "simulate-policy",
            "--policy-pack",
            str(pack_path),
            "--request-context",
            str(request_path),
            "--tenant-id",
            "t1",
            "--environment",
            "test",
        ],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
    )

    assert completed.returncode == 0
    assert "ALLOW" in completed.stdout
    assert "do-not-print" not in completed.stdout
    assert "approval_contents" not in completed.stdout


def test_show_simulation_summary_cli(tmp_path: Path) -> None:
    pack_path = tmp_path / "pack.json"
    request_path = tmp_path / "request.json"
    pack_path.write_text(json.dumps(_policy_pack(), sort_keys=True), encoding="utf-8")
    request_path.write_text(json.dumps({"action": "delete", "resource": "ledger"}), encoding="utf-8")

    completed = subprocess.run(
        [
            sys.executable,
            "scripts/governance_diagnostics.py",
            "show-simulation-summary",
            "--policy-pack",
            str(pack_path),
            "--request-context",
            str(request_path),
            "--tenant-id",
            "t1",
            "--environment",
            "test",
        ],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
    )

    assert completed.returncode == 0
    assert '"decision":"DENY"' in completed.stdout
