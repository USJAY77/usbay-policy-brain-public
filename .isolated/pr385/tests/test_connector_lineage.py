from __future__ import annotations

import pytest

from governance.connector_contracts import CONNECTOR_GOVERNANCE_POLICY_VERSION, build_connector_governance_record, compute_connector_governance_hash
from governance.connector_lineage import evaluate_connector_lineage


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


def test_valid_connector_lineage_passes():
    result = evaluate_connector_lineage(record())

    assert result["connector_lineage_status"] == "VALID"
    assert result["reason_codes"] == []


def test_missing_connector_lineage_blocks():
    result = evaluate_connector_lineage(record(lineage_hash=""))

    assert result["connector_lineage_status"] == "BLOCKED"
    assert result["reason_codes"] == ["MISSING_LINEAGE"]


def test_governance_bypass_blocks_lineage():
    result = evaluate_connector_lineage(record(governance_bypass=True))

    assert result["connector_lineage_status"] == "BLOCKED"
    assert "CONNECTOR_GOVERNANCE_BYPASS" in result["reason_codes"]
