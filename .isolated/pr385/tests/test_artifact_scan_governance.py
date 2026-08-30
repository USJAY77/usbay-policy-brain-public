from __future__ import annotations

import pytest

from governance.artifact_scan_governance import evaluate_artifact_scan_governance


pytestmark = pytest.mark.governance


def test_artifact_scan_governance_valid_for_owner():
    result = evaluate_artifact_scan_governance(
        {"artifact_scanned": True, "scan_record": True, "tenant_id": "tenant-1", "workspace_id": "ws-1"},
        requesting_tenant_id="tenant-1",
        requesting_workspace_id="ws-1",
    )

    assert result["artifact_scan_status"] == "VALID"
    assert result["file_deletion_enabled"] is False


def test_artifact_scan_governance_blocks_unscanned_missing_record_and_cross_tenant():
    result = evaluate_artifact_scan_governance(
        {"artifact_scanned": False, "scan_record": False, "tenant_id": "tenant-1", "workspace_id": "ws-1"},
        requesting_tenant_id="tenant-2",
        requesting_workspace_id="ws-2",
    )

    assert "ARTIFACT_NOT_SCANNED" in result["reason_codes"]
    assert "MISSING_SCAN_RECORD" in result["reason_codes"]
    assert "CROSS_TENANT_ARTIFACT" in result["reason_codes"]
