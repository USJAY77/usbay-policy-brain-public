from __future__ import annotations

import pytest

from governance.customer_workspace_contracts import (
    FAIL_CLOSED_REASON_CODES,
    build_customer_workspace,
    validate_customer_workspace,
)


pytestmark = pytest.mark.governance


def workspace(**overrides):
    payload = {
        "workspace_id": "ws-1",
        "workspace_name": "Customer One",
        "tenant_id": "tenant-1",
        "workspace_state": "ACTIVE",
        "policy_hash": "p" * 64,
        "audit_hash": "a" * 64,
        "evidence_hash": "e" * 64,
        "lineage_hash": "l" * 64,
        "human_approval": True,
        "created_at": "2026-06-18T00:00:00Z",
        "reason_codes": [],
        "fail_closed": False,
    }
    payload.update(overrides)
    return build_customer_workspace(**payload)


def test_valid_customer_workspace_contract():
    result = validate_customer_workspace(workspace())

    assert result.valid is True
    assert result.status == "ACTIVE"


def test_missing_tenant_blocks():
    result = validate_customer_workspace(workspace(tenant_id=""))

    assert result.status == "BLOCKED"
    assert "MISSING_TENANT" in result.reason_codes


def test_missing_policy_audit_evidence_block():
    result = validate_customer_workspace(workspace(policy_hash="", audit_hash="", evidence_hash=""))

    assert "MISSING_POLICY" in result.reason_codes
    assert "MISSING_AUDIT" in result.reason_codes
    assert "MISSING_EVIDENCE" in result.reason_codes


def test_workspace_without_human_approval_blocks():
    result = validate_customer_workspace(workspace(human_approval=False))

    assert "NO_HUMAN_APPROVAL" in result.reason_codes


def test_unknown_workspace_state_blocks():
    result = validate_customer_workspace(workspace(workspace_state="UNKNOWN"))

    assert "WORKSPACE_STATE_UNKNOWN:UNKNOWN" in result.reason_codes


def test_fail_closed_reason_code_registry_contains_required_codes():
    assert "UNKNOWN_WORKSPACE" in FAIL_CLOSED_REASON_CODES
    assert "CONNECTOR_WRITE_FORBIDDEN" in FAIL_CLOSED_REASON_CODES
