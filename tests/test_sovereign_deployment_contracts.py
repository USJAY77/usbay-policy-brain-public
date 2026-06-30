from __future__ import annotations

import pytest

from governance.sovereign_deployment_contracts import build_sovereign_deployment_record, validate_sovereign_deployment


pytestmark = pytest.mark.governance


def deployment(**overrides):
    payload = {
        "deployment_id": "dep-1",
        "tenant_id": "tenant-1",
        "environment_id": "env-1",
        "cluster_id": "cluster-1",
        "node_id": "node-1",
        "deployment_type": "SOVEREIGN_CLOUD",
        "sovereignty_level": "REGIONAL",
        "policy_hash": "p" * 64,
        "audit_hash": "a" * 64,
        "evidence_hash": "e" * 64,
        "lineage_hash": "l" * 64,
        "deployment_status": "READY",
        "reason_codes": [],
        "created_at": "2026-06-18T00:00:00Z",
        "fail_closed": False,
    }
    payload.update(overrides)
    return build_sovereign_deployment_record(**payload)


def test_valid_deployment_contract():
    result = validate_sovereign_deployment(deployment())

    assert result.valid is True
    assert result.status == "READY"


def test_unknown_deployment_type_blocks():
    result = validate_sovereign_deployment(deployment(deployment_type="PUBLIC_CLOUD"))

    assert result.status == "BLOCKED"
    assert "SOVEREIGN_DEPLOYMENT_TYPE_UNKNOWN:PUBLIC_CLOUD" in result.reason_codes


def test_missing_audit_blocks():
    result = validate_sovereign_deployment(deployment(audit_hash=""))

    assert "SOVEREIGN_AUDIT_HASH_MISSING" in result.reason_codes


def test_missing_lineage_blocks():
    result = validate_sovereign_deployment(deployment(lineage_hash=""))

    assert "SOVEREIGN_LINEAGE_HASH_MISSING" in result.reason_codes


def test_sensitive_marker_blocks():
    record = deployment()
    record["note"] = "raw_payload forbidden"

    result = validate_sovereign_deployment(record)

    assert "SOVEREIGN_SENSITIVE_PAYLOAD_BLOCKED" in result.reason_codes
