from __future__ import annotations

import json
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

from governance.policy_pack import (
    POLICY_ERROR_CODES,
    POLICY_PACK_SCHEMA,
    explain_policy_error,
    load_policy_error_registry,
    policy_pack_summary,
    validate_policy_pack,
)


ROOT = Path(__file__).resolve().parents[1]
NOW = datetime(2026, 5, 12, tzinfo=timezone.utc)


def _policy_pack() -> dict:
    return {
        "schema": POLICY_PACK_SCHEMA,
        "fail_closed": True,
        "valid_from": "2026-01-01T00:00:00Z",
        "valid_until": "2027-01-01T00:00:00Z",
        "scope": {"tenant_ids": ["t1"], "environments": ["test"]},
        "policies": [
            {
                "policy_id": "policy.read.t1",
                "risk_level": "low",
                "requires_human_approval": False,
                "fail_closed": True,
                "valid_from": "2026-01-01T00:00:00Z",
                "valid_until": "2027-01-01T00:00:00Z",
                "scope": {"tenant_ids": ["t1"], "environments": ["test"]},
                "allow_rules": [{"action": "read", "resource": "ledger"}],
                "deny_rules": [{"action": "delete", "resource": "ledger"}],
            }
        ],
    }


def _codes(result) -> set[str]:
    return {error.code for error in result.errors}


def test_valid_policy_pack_passes() -> None:
    result = validate_policy_pack(_policy_pack(), now=NOW)

    assert result.valid is True
    assert result.errors == ()
    assert policy_pack_summary(result)["policy_count"] == 1


def test_duplicate_policy_ids_fail_closed() -> None:
    pack = _policy_pack()
    pack["policies"].append(dict(pack["policies"][0]))

    result = validate_policy_pack(pack, now=NOW)

    assert result.valid is False
    assert "POLICY_DUPLICATE_ID" in _codes(result)


def test_conflicting_allow_deny_rules_fail_closed() -> None:
    pack = _policy_pack()
    pack["policies"][0]["deny_rules"] = [{"action": "read", "resource": "ledger"}]

    result = validate_policy_pack(pack, now=NOW)

    assert result.valid is False
    assert "POLICY_CONFLICTING_RULES" in _codes(result)


def test_expired_policy_rejected() -> None:
    pack = _policy_pack()
    pack["policies"][0]["valid_until"] = "2026-01-02T00:00:00Z"

    result = validate_policy_pack(pack, now=NOW)

    assert result.valid is False
    assert "POLICY_EXPIRED" in _codes(result)


def test_missing_fail_closed_default_rejected() -> None:
    pack = _policy_pack()
    pack["fail_closed"] = False
    pack["policies"][0].pop("fail_closed")

    result = validate_policy_pack(pack, now=NOW)

    assert result.valid is False
    assert "POLICY_FAIL_CLOSED_MISSING" in _codes(result)


def test_missing_human_approval_on_high_risk_policy_rejected() -> None:
    pack = _policy_pack()
    pack["policies"][0]["risk_level"] = "critical"
    pack["policies"][0]["requires_human_approval"] = False

    result = validate_policy_pack(pack, now=NOW)

    assert result.valid is False
    assert "POLICY_MISSING_HUMAN_APPROVAL" in _codes(result)


def test_invalid_tenant_or_environment_scope_rejected() -> None:
    pack = _policy_pack()
    pack["policies"][0]["scope"] = {"tenant_ids": ["foreign"], "environments": ["prodish"]}

    result = validate_policy_pack(pack, now=NOW)

    assert result.valid is False
    assert "POLICY_SCOPE_INVALID" in _codes(result)


def test_policy_error_registry_is_complete() -> None:
    registry = load_policy_error_registry(ROOT)

    assert set(POLICY_ERROR_CODES).issubset(registry)
    assert explain_policy_error(ROOT, "POLICY_SCHEMA_INVALID")["fail_closed_reason"]


def test_policy_diagnostics_are_redacted_and_fail_closed(tmp_path: Path) -> None:
    pack = _policy_pack()
    pack["policies"][0]["policy_id"] = "policy.raw_secret"
    pack["policies"][0]["valid_until"] = "2026-01-02T00:00:00Z"
    path = tmp_path / "policy_pack.json"
    path.write_text(json.dumps(pack, sort_keys=True), encoding="utf-8")

    completed = subprocess.run(
        [
            sys.executable,
            "scripts/governance_diagnostics.py",
            "validate-policy-pack",
            "--policy-pack",
            str(path),
        ],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
    )

    assert completed.returncode == 1
    output = completed.stdout + completed.stderr
    assert "POLICY_EXPIRED" in output
    assert "raw_secret" not in output
    assert "[REDACTED]" in output


def test_show_policy_summary_command(tmp_path: Path) -> None:
    path = tmp_path / "policy_pack.json"
    path.write_text(json.dumps(_policy_pack(), sort_keys=True), encoding="utf-8")

    completed = subprocess.run(
        [
            sys.executable,
            "scripts/governance_diagnostics.py",
            "show-policy-summary",
            "--policy-pack",
            str(path),
        ],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
    )

    assert completed.returncode == 0
    assert '"policy_count":1' in completed.stdout
