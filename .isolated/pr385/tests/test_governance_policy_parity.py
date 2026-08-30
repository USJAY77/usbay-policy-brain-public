from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

from governance.policy_pack import POLICY_PACK_SCHEMA
from governance.policy_parity import (
    PARITY_ERROR_CODES,
    build_runtime_decision_record,
    explain_parity_failure,
    load_parity_error_registry,
    request_context_hash,
    verify_policy_parity,
)
from governance.policy_simulation import (
    DECISION_ALLOW,
    DECISION_DENY,
    DECISION_FAIL_CLOSED,
    DECISION_REQUIRE_HUMAN_REVIEW,
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


def _runtime_record(decision: str, request_context: dict, *, pack: dict | None = None, required_human_approval: bool = False) -> dict:
    return build_runtime_decision_record(
        decision=decision,
        policy_pack=pack or _policy_pack(),
        request_context=request_context,
        tenant_id="t1",
        environment="test",
        risk_level="high" if required_human_approval else "low",
        required_human_approval=required_human_approval,
    )


def test_allow_runtime_parity() -> None:
    pack = _policy_pack()
    request = {"action": "read", "resource": "ledger"}
    result = verify_policy_parity(
        pack,
        request,
        _runtime_record(DECISION_ALLOW, request, pack=pack),
        tenant_id="t1",
        environment="test",
        risk_level="low",
    )

    assert result.valid is True
    assert result.errors == ()
    assert result.simulated_decision == DECISION_ALLOW
    assert result.runtime_decision == DECISION_ALLOW


def test_deny_runtime_parity() -> None:
    pack = _policy_pack()
    request = {"action": "delete", "resource": "ledger"}
    result = verify_policy_parity(
        pack,
        request,
        _runtime_record(DECISION_DENY, request, pack=pack),
        tenant_id="t1",
        environment="test",
        risk_level="low",
    )

    assert result.valid is True
    assert result.simulated_decision == DECISION_DENY
    assert result.runtime_decision == DECISION_DENY


def test_human_review_runtime_parity() -> None:
    pack = _policy_pack()
    pack["policies"][0]["requires_human_approval"] = True
    request = {"action": "read", "resource": "ledger"}
    result = verify_policy_parity(
        pack,
        request,
        _runtime_record(DECISION_REQUIRE_HUMAN_REVIEW, request, pack=pack, required_human_approval=True),
        tenant_id="t1",
        environment="test",
        risk_level="high",
        required_human_approval=True,
    )

    assert result.valid is True
    assert result.simulated_decision == DECISION_REQUIRE_HUMAN_REVIEW
    assert result.human_approval_required is True


def test_fail_closed_runtime_parity() -> None:
    pack = _policy_pack()
    request = {"action": "write", "resource": "ledger"}
    result = verify_policy_parity(
        pack,
        request,
        _runtime_record(DECISION_FAIL_CLOSED, request, pack=pack),
        tenant_id="t1",
        environment="test",
        risk_level="low",
    )

    assert result.valid is True
    assert result.simulated_decision == DECISION_FAIL_CLOSED
    assert result.runtime_decision == DECISION_FAIL_CLOSED


def test_policy_hash_mismatch_fails_closed() -> None:
    pack = _policy_pack()
    request = {"action": "read", "resource": "ledger"}
    runtime_record = _runtime_record(DECISION_ALLOW, request, pack=pack)
    runtime_record["policy_hash"] = "f" * 64

    result = verify_policy_parity(
        pack,
        request,
        runtime_record,
        tenant_id="t1",
        environment="test",
        risk_level="low",
    )

    assert result.valid is False
    assert "PARITY_POLICY_HASH_MISMATCH" in result.errors


def test_context_drift_rejected() -> None:
    pack = _policy_pack()
    request = {"action": "read", "resource": "ledger"}
    runtime_record = _runtime_record(DECISION_ALLOW, request, pack=pack)
    runtime_record["context_hash"] = request_context_hash(
        {"action": "delete", "resource": "ledger"},
        tenant_id="t1",
        environment="test",
        risk_level="low",
    )

    result = verify_policy_parity(
        pack,
        request,
        runtime_record,
        tenant_id="t1",
        environment="test",
        risk_level="low",
    )

    assert result.valid is False
    assert "PARITY_CONTEXT_DRIFT" in result.errors


def test_fail_closed_required_when_runtime_allows_unmatched_request() -> None:
    pack = _policy_pack()
    request = {"action": "write", "resource": "ledger"}
    result = verify_policy_parity(
        pack,
        request,
        _runtime_record(DECISION_ALLOW, request, pack=pack),
        tenant_id="t1",
        environment="test",
        risk_level="low",
    )

    assert result.valid is False
    assert "PARITY_FAIL_CLOSED_REQUIRED" in result.errors
    assert "PARITY_DECISION_MISMATCH" in result.errors


def test_scope_mismatch_rejected() -> None:
    pack = _policy_pack()
    request = {"action": "read", "resource": "ledger"}
    runtime_record = _runtime_record(DECISION_ALLOW, request, pack=pack)
    runtime_record["tenant_id"] = "t2"

    result = verify_policy_parity(
        pack,
        request,
        runtime_record,
        tenant_id="t1",
        environment="test",
        risk_level="low",
    )

    assert result.valid is False
    assert "PARITY_SCOPE_MISMATCH" in result.errors


def test_parity_error_registry_complete() -> None:
    registry = load_parity_error_registry(ROOT)

    assert set(PARITY_ERROR_CODES).issubset(registry)
    assert explain_parity_failure(ROOT, "PARITY_DECISION_MISMATCH")["fail_closed_reason"]


def test_policy_parity_cli_redacts_request_context(tmp_path: Path) -> None:
    pack = _policy_pack()
    request = {"action": "read", "resource": "ledger", "approval_contents": "do-not-print"}
    runtime_record = _runtime_record(DECISION_ALLOW, request, pack=pack)
    pack_path = tmp_path / "pack.json"
    request_path = tmp_path / "request.json"
    runtime_path = tmp_path / "runtime.json"
    pack_path.write_text(json.dumps(pack, sort_keys=True), encoding="utf-8")
    request_path.write_text(json.dumps(request, sort_keys=True), encoding="utf-8")
    runtime_path.write_text(json.dumps(runtime_record, sort_keys=True), encoding="utf-8")

    completed = subprocess.run(
        [
            sys.executable,
            "scripts/governance_diagnostics.py",
            "verify-policy-parity",
            "--policy-pack",
            str(pack_path),
            "--request-context",
            str(request_path),
            "--runtime-decision",
            str(runtime_path),
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
    assert '"valid":true' in completed.stdout
    assert "do-not-print" not in completed.stdout
    assert "approval_contents" not in completed.stdout


def test_show_parity_summary_cli_fails_closed_on_mismatch(tmp_path: Path) -> None:
    pack = _policy_pack()
    request = {"action": "read", "resource": "ledger"}
    runtime_record = _runtime_record(DECISION_DENY, request, pack=pack)
    pack_path = tmp_path / "pack.json"
    request_path = tmp_path / "request.json"
    runtime_path = tmp_path / "runtime.json"
    pack_path.write_text(json.dumps(pack, sort_keys=True), encoding="utf-8")
    request_path.write_text(json.dumps(request, sort_keys=True), encoding="utf-8")
    runtime_path.write_text(json.dumps(runtime_record, sort_keys=True), encoding="utf-8")

    completed = subprocess.run(
        [
            sys.executable,
            "scripts/governance_diagnostics.py",
            "show-parity-summary",
            "--policy-pack",
            str(pack_path),
            "--request-context",
            str(request_path),
            "--runtime-decision",
            str(runtime_path),
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

    assert completed.returncode == 1
    assert "PARITY_DECISION_MISMATCH" in completed.stdout
