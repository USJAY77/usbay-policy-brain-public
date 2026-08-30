from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

from governance.incidents import (
    REQUIRED_INCIDENT_CODES,
    GovernanceIncidentError,
    assert_audit_safe_payload,
    fail_closed_reason,
    incident_code_for_failure,
    incident_summary,
    load_incident_runbooks,
    recommended_operator_action,
    recovery_checklist,
    validate_recovery_path,
    validate_runbook_coverage,
)


ROOT = Path(__file__).resolve().parents[1]


def test_each_required_incident_code_has_runbook() -> None:
    runbooks = load_incident_runbooks(ROOT)

    assert set(REQUIRED_INCIDENT_CODES).issubset(runbooks)
    for code in REQUIRED_INCIDENT_CODES:
        runbook = runbooks[code]
        assert runbook.fail_closed_reason
        assert runbook.recommended_operator_action
        assert runbook.recovery_checklist
        assert runbook.human_approval_required is True


@pytest.mark.parametrize(
    ("failure", "expected_code"),
    [
        ("trust_policy_fingerprint_mismatch:0", "GOV_SIGNER_DRIFT"),
        ("GOVERNANCE_DEPENDENCY_GRAPH_DRIFT", "GOV_DEPENDENCY_DRIFT"),
        ("release_integrity_signature_invalid", "GOV_RELEASE_MISMATCH"),
        ("release_integrity_rollback_target_invalid", "GOV_ROLLBACK_INVALID"),
        ("release_integrity_trust_policy_mismatch", "GOV_TRUST_POLICY_MISMATCH"),
        ("GOVERNANCE_TELEMETRY_UNSAFE", "GOV_TELEMETRY_UNSAFE"),
    ],
)
def test_incident_code_mapping(failure: str, expected_code: str) -> None:
    runbooks = load_incident_runbooks(ROOT)

    assert incident_code_for_failure(failure, runbooks) == expected_code


def test_runbook_views_are_audit_safe() -> None:
    payloads = [
        incident_summary(ROOT, ["release_integrity_trust_policy_mismatch"]),
        recommended_operator_action(ROOT, "GOV_TRUST_POLICY_MISMATCH"),
        fail_closed_reason(ROOT, "GOV_TRUST_POLICY_MISMATCH"),
        recovery_checklist(ROOT, "GOV_TRUST_POLICY_MISMATCH"),
    ]

    for payload in payloads:
        assert_audit_safe_payload(payload)
        encoded = json.dumps(payload, sort_keys=True)
        assert "PRIVATE KEY" not in encoded
        assert "raw_secret" not in encoded


def test_invalid_recovery_path_requires_human_approval() -> None:
    with pytest.raises(GovernanceIncidentError) as exc:
        validate_recovery_path(ROOT, "GOV_ROLLBACK_INVALID", human_approval_confirmed=False)

    assert str(exc.value) == "incident_recovery_human_approval_required"


def test_approved_recovery_path_is_explicit() -> None:
    result = validate_recovery_path(ROOT, "GOV_ROLLBACK_INVALID", human_approval_confirmed=True)

    assert result == {"code": "GOV_ROLLBACK_INVALID", "recovery_path_valid": True}


def test_runbook_coverage_rejects_unknown_fail_closed_condition() -> None:
    with pytest.raises(GovernanceIncidentError) as exc:
        validate_runbook_coverage(ROOT, ["unmapped_fail_closed_condition"])

    assert "incident_runbook_missing:unmapped_fail_closed_condition" in str(exc.value)


def test_diagnostics_redacts_secret_like_failure_output() -> None:
    private_key_marker = "BEGIN " + "PRIVATE KEY"
    completed = subprocess.run(
        [
            sys.executable,
            "scripts/governance_diagnostics.py",
            "incident-summary",
            "--failure",
            "GOVERNANCE_TELEMETRY_UNSAFE:" + private_key_marker,
        ],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
    )

    assert completed.returncode == 0
    output = completed.stdout + completed.stderr
    assert private_key_marker not in output
    assert "[REDACTED]" in output
    assert "GOV_TELEMETRY_UNSAFE" in output


def test_diagnostics_recovery_command_rejects_unapproved_path() -> None:
    completed = subprocess.run(
        [
            sys.executable,
            "scripts/governance_diagnostics.py",
            "validate-recovery",
            "--incident-code",
            "GOV_ROLLBACK_INVALID",
        ],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
    )

    assert completed.returncode == 1
    assert "incident_recovery_human_approval_required" in completed.stdout
