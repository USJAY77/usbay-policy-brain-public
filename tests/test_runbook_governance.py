from __future__ import annotations

from datetime import datetime, timezone

import pytest

from governance.runbook_governance import validate_runbook_governance


pytestmark = pytest.mark.governance


NOW = datetime(2026, 6, 18, tzinfo=timezone.utc)


def runbook(**overrides):
    payload = {
        "runbook_exists": True,
        "runbook_owner": "ops-owner",
        "runbook_version": "2026.06",
        "runbook_review": "APPROVED",
        "review_timestamp": "2026-06-18T00:00:00Z",
        "audit_hash": "a" * 64,
        "lineage_hash": "l" * 64,
    }
    payload.update(overrides)
    return payload


def test_valid_runbook_governance():
    result = validate_runbook_governance(runbook(), now=NOW)

    assert result["runbook_status"] == "READY"
    assert result["deploy_enabled"] is False


def test_missing_runbook_blocks():
    result = validate_runbook_governance(runbook(runbook_exists=False), now=NOW)

    assert "RUNBOOK_MISSING" in result["reason_codes"]


def test_unknown_owner_blocks():
    result = validate_runbook_governance(runbook(runbook_owner=""), now=NOW)

    assert "RUNBOOK_OWNER_MISSING" in result["reason_codes"]


def test_missing_version_blocks():
    result = validate_runbook_governance(runbook(runbook_version=""), now=NOW)

    assert "RUNBOOK_VERSION_MISSING" in result["reason_codes"]


def test_expired_review_blocks():
    result = validate_runbook_governance(runbook(review_timestamp="2026-04-01T00:00:00Z"), now=NOW)

    assert "RUNBOOK_REVIEW_EXPIRED" in result["reason_codes"]
