from __future__ import annotations

import pytest

from governance.event_timeline import build_event_timeline, timeline_latest_event
from governance.observation_contracts import OBSERVATION_EVENT_SCHEMA, OBSERVATION_POLICY_VERSION


pytestmark = pytest.mark.governance


def event(event_type, timestamp, **overrides):
    payload = {
        "schema": OBSERVATION_EVENT_SCHEMA,
        "snapshot_id": f"{event_type}-snapshot",
        "event_id": f"{event_type}-event",
        "component": "Gateway",
        "status": "HEALTHY",
        "timestamp": timestamp,
        "policy_version": OBSERVATION_POLICY_VERSION,
        "audit_hash": "a" * 64,
        "lineage_hash": "l" * 64,
        "fail_closed": False,
        "reason_codes": [],
        "event_type": event_type,
    }
    payload.update(overrides)
    return payload


def test_timeline_orders_events_chronologically_without_inference():
    timeline = build_event_timeline(
        [
            event("decision", "2026-06-17T08:06:00Z"),
            event("observation", "2026-06-17T08:00:00Z"),
            event("connector read", "2026-06-17T08:05:00Z"),
        ]
    )

    assert timeline["timeline_status"] == "HEALTHY"
    assert [item["event_type"] for item in timeline["events"]] == ["observation", "connector read", "decision"]
    assert timeline["inferred_events"] is False
    assert timeline_latest_event(timeline)["event_type"] == "decision"


def test_missing_timestamp_blocks_timeline():
    timeline = build_event_timeline([event("observation", "")])

    assert timeline["timeline_status"] == "BLOCKED"
    assert timeline["fail_closed"] is True
    assert any("TIMESTAMP" in code for code in timeline["reason_codes"])


def test_unknown_event_type_blocks_timeline():
    timeline = build_event_timeline([event("auto fixed", "2026-06-17T08:00:00Z")])

    assert timeline["timeline_status"] == "BLOCKED"
    assert any("EVENT_TYPE_UNKNOWN" in code for code in timeline["reason_codes"])


def test_malformed_events_block_timeline():
    timeline = build_event_timeline(None)

    assert timeline["timeline_status"] == "BLOCKED"
    assert timeline["events"] == []
