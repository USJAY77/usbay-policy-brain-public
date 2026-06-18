from __future__ import annotations

import pytest

from governance.connector_capabilities import evaluate_connector_capabilities
from governance.connector_contracts import CONNECTOR_GOVERNANCE_POLICY_VERSION, build_connector_governance_record, compute_connector_governance_hash


pytestmark = pytest.mark.governance


def record(**overrides):
    payload = build_connector_governance_record(
        connector_id="github-connector-1",
        connector_type="GITHUB",
        tenant_id="tenant-1",
        workspace_id="workspace-1",
        capability="READ_ONLY",
        permission="READ",
        registered_connector=True,
        human_approval=True,
        policy_binding=True,
        audit_hash="a" * 64,
        evidence_hash="e" * 64,
        lineage_hash="l" * 64,
        policy_version=CONNECTOR_GOVERNANCE_POLICY_VERSION,
    )
    payload.update(overrides)
    if "connector_governance_hash" not in overrides:
        payload["connector_governance_hash"] = compute_connector_governance_hash(payload)
    return payload


def test_valid_connector_capability_is_read_only():
    result = evaluate_connector_capabilities(record())

    assert result["connector_capability_status"] == "VALID"
    assert result["connector_execution_enabled"] is False
    assert result["connector_write_enabled"] is False


def test_unknown_connector_capability_blocks():
    result = evaluate_connector_capabilities(record(capability="WRITE"))

    assert result["connector_capability_status"] == "BLOCKED"
    assert result["reason_codes"] == ["UNKNOWN_CAPABILITY"]


def test_connector_execution_capability_blocks():
    result = evaluate_connector_capabilities(record(connector_execution=True))

    assert result["connector_capability_status"] == "BLOCKED"
    assert "CONNECTOR_EXECUTION_FORBIDDEN" in result["reason_codes"]
