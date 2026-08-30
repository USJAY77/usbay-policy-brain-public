from __future__ import annotations

import pytest

from governance.connector_contracts import CONNECTOR_GOVERNANCE_POLICY_VERSION, build_connector_governance_record, compute_connector_governance_hash
from governance.external_api_governance import evaluate_external_api_governance


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


def test_governed_external_api_has_no_invocation():
    result = evaluate_external_api_governance(record())

    assert result["external_api_status"] == "VALID"
    assert result["api_invocation_enabled"] is False
    assert result["network_access_enabled"] is False


def test_ungoverned_external_api_blocks():
    result = evaluate_external_api_governance(record(external_api_governed=False))

    assert result["external_api_status"] == "BLOCKED"
    assert result["reason_codes"] == ["EXTERNAL_API_NOT_GOVERNED"]


def test_api_invocation_blocks():
    result = evaluate_external_api_governance(record(api_invocation=True))

    assert result["external_api_status"] == "BLOCKED"
    assert result["reason_codes"] == ["EXTERNAL_API_NOT_GOVERNED"]
