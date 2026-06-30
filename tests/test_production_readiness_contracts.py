from __future__ import annotations

import pytest

from governance.production_readiness_contracts import (
    PRODUCTION_READINESS_POLICY_VERSION,
    build_production_readiness_record,
    validate_production_readiness,
)


pytestmark = pytest.mark.governance


def valid_record(**overrides):
    payload = {
        "readiness_id": "ready-1",
        "environment_id": "prod-us-1",
        "tenant_id": "tenant-1",
        "policy_hash": "p" * 64,
        "audit_hash": "a" * 64,
        "evidence_hash": "e" * 64,
        "lineage_hash": "l" * 64,
        "backup_status": "READY",
        "recovery_status": "READY",
        "runbook_status": "READY",
        "release_status": "READY",
        "readiness_status": "READY",
        "created_at": "2026-06-18T00:00:00Z",
        "policy_version": PRODUCTION_READINESS_POLICY_VERSION,
        "reason_codes": [],
        "fail_closed": False,
    }
    payload.update(overrides)
    return build_production_readiness_record(**payload)


def test_valid_readiness_contract():
    result = validate_production_readiness(valid_record())

    assert result.valid is True
    assert result.status == "READY"


def test_invalid_snapshot_blocks():
    result = validate_production_readiness(None)

    assert result.status == "BLOCKED"
    assert "PRODUCTION_READINESS_MALFORMED" in result.reason_codes


def test_missing_audit_blocks():
    record = valid_record(audit_hash="")

    result = validate_production_readiness(record)

    assert result.status == "BLOCKED"
    assert "PRODUCTION_AUDIT_HASH_MISSING" in result.reason_codes


def test_missing_lineage_blocks():
    record = valid_record(lineage_hash="")

    result = validate_production_readiness(record)

    assert result.status == "BLOCKED"
    assert "PRODUCTION_LINEAGE_HASH_MISSING" in result.reason_codes


def test_unknown_status_blocks():
    record = valid_record(backup_status="UNKNOWN")

    result = validate_production_readiness(record)

    assert result.status == "BLOCKED"
    assert "PRODUCTION_BACKUP_STATUS_UNKNOWN:UNKNOWN" in result.reason_codes


def test_sensitive_marker_blocks():
    record = valid_record()
    record["note"] = "contains secret"

    result = validate_production_readiness(record)

    assert result.status == "BLOCKED"
    assert "PRODUCTION_SENSITIVE_PAYLOAD_BLOCKED" in result.reason_codes
