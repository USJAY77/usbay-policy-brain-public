from __future__ import annotations

import pytest

from governance.observation_contracts import (
    OBSERVATION_EVENT_SCHEMA,
    OBSERVATION_HEALTH_SCHEMA,
    OBSERVATION_POLICY_VERSION,
    OBSERVATION_SNAPSHOT_SCHEMA,
    build_observation_audit_record,
    validate_event,
    validate_health,
    validate_snapshot,
)


pytestmark = pytest.mark.governance


def snapshot(**overrides):
    payload = {
        "schema": OBSERVATION_SNAPSHOT_SCHEMA,
        "snapshot_id": "snapshot-1",
        "event_id": "event-1",
        "component": "Gateway",
        "status": "HEALTHY",
        "timestamp": "2026-06-17T08:00:00Z",
        "policy_version": OBSERVATION_POLICY_VERSION,
        "audit_hash": "a" * 64,
        "lineage_hash": "l" * 64,
        "fail_closed": False,
        "reason_codes": [],
    }
    payload.update(overrides)
    return payload


def test_valid_snapshot_health_and_event():
    assert validate_snapshot(snapshot()).valid is True
    assert validate_health(snapshot(schema=OBSERVATION_HEALTH_SCHEMA)).valid is True
    assert validate_event(snapshot(schema=OBSERVATION_EVENT_SCHEMA, event_type="observation")).valid is True


def test_invalid_snapshot_blocks():
    validation = validate_snapshot(snapshot(schema="wrong"))

    assert validation.valid is False
    assert "OBSERVATION_SCHEMA_INVALID" in validation.reason_codes


@pytest.mark.parametrize("field", ["audit_hash", "lineage_hash", "timestamp"])
def test_missing_trust_or_timestamp_blocks(field):
    validation = validate_snapshot(snapshot(**{field: ""}))

    assert validation.valid is False


def test_unknown_status_blocks():
    validation = validate_snapshot(snapshot(status="MAYBE"))

    assert validation.valid is False
    assert "OBSERVATION_STATUS_UNKNOWN:MAYBE" in validation.reason_codes


def test_unknown_event_type_blocks():
    validation = validate_event(snapshot(schema=OBSERVATION_EVENT_SCHEMA, event_type="auto repair"))

    assert validation.valid is False
    assert "OBSERVATION_EVENT_TYPE_UNKNOWN:auto repair" in validation.reason_codes


def test_audit_record_is_read_only_and_fail_closed():
    audit = build_observation_audit_record(payload=snapshot(), decision="OBSERVED", reason_codes=[])

    assert audit["audit_hash"]
    assert audit["execution_enabled"] is False
    assert audit["deployment_enabled"] is False
    assert audit["auto_remediation_enabled"] is False
    assert audit["fail_closed"] is True
