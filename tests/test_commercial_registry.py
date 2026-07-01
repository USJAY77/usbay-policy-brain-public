from __future__ import annotations

import pytest

from governance.commercial_contracts import COMMERCIAL_GOVERNANCE_POLICY_VERSION, build_commercial_record, compute_commercial_governance_hash
from governance.commercial_registry import CommercialRegistry, empty_commercial_dashboard_state


pytestmark = pytest.mark.governance


def commercial_record(**overrides):
    payload = build_commercial_record(
        commercial_id="commercial-1",
        tenant_id="tenant-1",
        workspace_id="workspace-1",
        registered_commercial_record=True,
        customer_commercial_record=True,
        contract_record=True,
        subscription_record=True,
        billing_record=True,
        invoice_record=True,
        pricing_record=True,
        renewal_record=True,
        human_approval=True,
        policy_binding=True,
        audit_hash="a" * 64,
        evidence_hash="e" * 64,
        lineage_hash="l" * 64,
        customer_commercial_status="AUTHORIZED",
        contract_status="AUTHORIZED",
        subscription_status="AUTHORIZED",
        billing_status="AUTHORIZED",
        invoice_status="AUTHORIZED",
        pricing_status="AUTHORIZED",
        renewal_status="AUTHORIZED",
        policy_version=COMMERCIAL_GOVERNANCE_POLICY_VERSION,
    )
    payload.update(overrides)
    if "commercial_governance_hash" not in overrides:
        payload["commercial_governance_hash"] = compute_commercial_governance_hash(payload)
    return payload


def test_commercial_registry_lists_records_read_only():
    registry = CommercialRegistry([commercial_record()])

    assert registry.get_commercial_record("commercial-1")["billing_status"] == "AUTHORIZED"
    assert registry.list_commercial_records()[0]["commercial_id"] == "commercial-1"
    assert registry.summary()["commercial_registry_status"] == "VALID"
    assert registry.summary()["payment_processing_enabled"] is False
    assert registry.summary()["email_sending_enabled"] is False


def test_empty_commercial_registry_blocks_unknown_record():
    summary = CommercialRegistry().summary()

    assert summary["commercial_registry_status"] == "BLOCKED"
    assert summary["commercial_reason_codes"] == ["UNKNOWN_COMMERCIAL_RECORD"]


def test_empty_commercial_dashboard_state_blocks_execution():
    state = empty_commercial_dashboard_state()

    assert state["commercial_status"] == "BLOCKED"
    assert state["customer_commercial_status"] == "BLOCKED"
    assert state["contract_status"] == "BLOCKED"
    assert state["subscription_status"] == "BLOCKED"
    assert state["billing_status"] == "BLOCKED"
    assert state["invoice_status"] == "BLOCKED"
    assert state["pricing_status"] == "BLOCKED"
    assert state["renewal_status"] == "BLOCKED"
    assert state["commercial_reason_codes"] == ["UNKNOWN_COMMERCIAL_RECORD"]
    assert state["billing_execution_enabled"] is False
    assert state["payment_processing_enabled"] is False
    assert state["invoice_sending_enabled"] is False
    assert state["contract_signing_enabled"] is False
    assert state["customer_activation_enabled"] is False
    assert state["subscription_activation_enabled"] is False
    assert state["renewal_execution_enabled"] is False
    assert state["pricing_modification_enabled"] is False
    assert state["connector_write_enabled"] is False
    assert state["email_sending_enabled"] is False
    assert state["deployment_enabled"] is False
    assert state["auto_remediation"] is False
    assert state["auto_approval"] is False
