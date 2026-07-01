from __future__ import annotations

from typing import Any

from governance.observation_contracts import (
    OBSERVATION_TIMELINE_SCHEMA,
    parse_timestamp,
    validate_event,
    validate_timeline,
)


ORDERED_EVENT_TYPES = (
    "observation",
    "proposal",
    "request",
    "approval",
    "review",
    "decision",
    "work item",
    "connector read",
    "evidence verification",
)


def build_event_timeline(events: list[dict[str, Any]] | None) -> dict[str, Any]:
    if not isinstance(events, list):
        return {
            "schema": OBSERVATION_TIMELINE_SCHEMA,
            "timeline_status": "BLOCKED",
            "events": [],
            "event_count": 0,
            "reason_codes": ["OBSERVATION_TIMELINE_EVENTS_MALFORMED"],
            "fail_closed": True,
            "inferred_events": False,
        }
    reasons: list[str] = []
    accepted_events: list[dict[str, Any]] = []
    for index, event in enumerate(events):
        validation = validate_event(event)
        if not validation.valid:
            reasons.extend(f"EVENT_{index}_{code}" for code in validation.reason_codes)
        if isinstance(event, dict) and parse_timestamp(event.get("timestamp")) is not None:
            accepted_events.append(dict(event))
    accepted_events.sort(key=lambda event: parse_timestamp(event.get("timestamp")))
    timeline = {
        "schema": OBSERVATION_TIMELINE_SCHEMA,
        "timeline_status": "BLOCKED" if reasons else "HEALTHY",
        "events": accepted_events,
        "event_count": len(accepted_events),
        "reason_codes": sorted(set(reasons)),
        "fail_closed": bool(reasons),
        "inferred_events": False,
        "event_type_order": list(ORDERED_EVENT_TYPES),
    }
    validation = validate_timeline(timeline)
    if not validation.valid:
        timeline["timeline_status"] = "BLOCKED"
        timeline["fail_closed"] = True
        timeline["reason_codes"] = sorted(set(timeline["reason_codes"] + list(validation.reason_codes)))
    return timeline


def timeline_latest_event(timeline: dict[str, Any] | None) -> dict[str, Any]:
    if not isinstance(timeline, dict):
        return {}
    events = timeline.get("events", [])
    if not isinstance(events, list) or not events:
        return {}
    latest = events[-1]
    return latest if isinstance(latest, dict) else {}
