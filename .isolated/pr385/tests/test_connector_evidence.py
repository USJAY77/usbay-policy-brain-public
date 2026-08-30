from __future__ import annotations

import pytest

from governance.connector_contracts import CONNECTOR_GOVERNANCE_POLICY_VERSION, build_connector_governance_record, compute_connector_governance_hash
from governance.connector_evidence import evaluate_connector_evidence


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


def test_valid_connector_evidence_passes():
    result = evaluate_connector_evidence(record())

    assert result["connector_evidence_status"] == "VALID"
    assert result["reason_codes"] == []


def test_missing_connector_audit_blocks():
    result = evaluate_connector_evidence(record(audit_hash=""))

    assert result["connector_evidence_status"] == "BLOCKED"
    assert result["reason_codes"] == ["MISSING_AUDIT_LINKAGE"]


def test_missing_connector_evidence_blocks():
    result = evaluate_connector_evidence(record(evidence_hash=""))

    assert result["connector_evidence_status"] == "BLOCKED"
    assert result["reason_codes"] == ["MISSING_EVIDENCE_LINKAGE"]
