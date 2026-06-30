from __future__ import annotations

from datetime import datetime, timezone

import pytest

from governance.backup_validation import validate_backup_readiness


pytestmark = pytest.mark.governance


NOW = datetime(2026, 6, 18, tzinfo=timezone.utc)


def backup(**overrides):
    payload = {
        "backup_exists": True,
        "backup_integrity": "VERIFIED",
        "backup_timestamp": "2026-06-18T00:00:00Z",
        "backup_scope": "production",
        "backup_lineage": "lineage-1",
        "audit_hash": "a" * 64,
    }
    payload.update(overrides)
    return payload


def test_valid_backup_readiness():
    result = validate_backup_readiness(backup(), now=NOW)

    assert result["backup_validation_status"] == "READY"
    assert result["fail_closed"] is False


def test_missing_backup_blocks():
    result = validate_backup_readiness(backup(backup_exists=False), now=NOW)

    assert result["backup_validation_status"] == "BLOCKED"
    assert "BACKUP_MISSING" in result["reason_codes"]


def test_missing_audit_blocks():
    result = validate_backup_readiness(backup(audit_hash=""), now=NOW)

    assert "BACKUP_AUDIT_MISSING" in result["reason_codes"]


def test_missing_lineage_blocks():
    result = validate_backup_readiness(backup(backup_lineage="", lineage_hash=""), now=NOW)

    assert "BACKUP_LINEAGE_MISSING" in result["reason_codes"]


def test_expired_backup_blocks():
    result = validate_backup_readiness(backup(backup_timestamp="2026-06-16T00:00:00Z"), now=NOW)

    assert "BACKUP_EXPIRED" in result["reason_codes"]
