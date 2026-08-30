from __future__ import annotations

import pytest

from governance.policy_registry_contracts import build_policy_audit_record, build_policy_record, validate_policy_record


pytestmark = pytest.mark.governance


def policy(**overrides):
    payload = {
        "policy_id": "policy-1",
        "policy_name": "Runtime Governance",
        "policy_version": "v1",
        "status": "DRAFT",
        "created_at": "2026-06-18T08:00:00Z",
        "audit_hash": "a" * 64,
        "lineage_hash": "l" * 64,
    }
    payload.update(overrides)
    return build_policy_record(**payload)


def test_valid_registration_contract():
    validation = validate_policy_record(policy())

    assert validation.valid is True
    assert validation.status == "VERIFIED"


@pytest.mark.parametrize("field", ["policy_hash", "audit_hash", "lineage_hash"])
def test_missing_hash_audit_or_lineage_blocks(field):
    record = policy()
    record[field] = ""

    validation = validate_policy_record(record)

    assert validation.valid is False


def test_invalid_status_blocks():
    validation = validate_policy_record(policy(status="AUTO_APPROVED"))

    assert validation.status == "BLOCKED"
    assert "POLICY_STATUS_UNKNOWN:AUTO_APPROVED" in validation.reason_codes


def test_hash_mismatch_reports_tamper():
    record = policy()
    record["policy_name"] = "Changed"

    validation = validate_policy_record(record)

    assert validation.status == "TAMPER_DETECTED"
    assert "POLICY_HASH_MISMATCH" in validation.reason_codes


def test_policy_audit_record_disables_auto_lifecycle():
    audit = build_policy_audit_record(policy=policy(), action="register", reason_codes=[])

    assert audit["audit_hash"]
    assert audit["auto_approved"] is False
    assert audit["auto_promoted"] is False
    assert audit["auto_activated"] is False
    assert audit["auto_retired"] is False
