from __future__ import annotations

import pytest

from governance.connector_contracts import CONNECTOR_GOVERNANCE_POLICY_VERSION, build_connector_governance_record, compute_connector_governance_hash
from governance.connector_permissions import evaluate_connector_permissions


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


def test_valid_connector_permission_is_read_only():
    result = evaluate_connector_permissions(record())

    assert result["connector_permission_status"] == "VALID"
    assert result["email_send_enabled"] is False
    assert result["calendar_write_enabled"] is False
    assert result["repository_write_enabled"] is False
    assert result["file_write_enabled"] is False


def test_unknown_connector_permission_blocks():
    result = evaluate_connector_permissions(record(permission="WRITE"))

    assert result["connector_permission_status"] == "BLOCKED"
    assert result["reason_codes"] == ["UNKNOWN_PERMISSION"]


def test_email_and_repository_write_permissions_block():
    result = evaluate_connector_permissions(record(email_send=True, repository_write=True))

    assert result["connector_permission_status"] == "BLOCKED"
    assert "EMAIL_SEND_FORBIDDEN" in result["reason_codes"]
    assert "REPOSITORY_WRITE_FORBIDDEN" in result["reason_codes"]
