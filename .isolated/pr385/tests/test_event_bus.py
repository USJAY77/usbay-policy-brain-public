import json
import re
from dataclasses import FrozenInstanceError
from pathlib import Path

import pytest

from governance.runtime.event_bus import (
    EVENT_BLOCKED,
    EVENT_READY,
    EXECUTION_REQUESTED,
    GOVERNED_EVENT_ROUTES,
    MISSING_EVENT_FIELD,
    RAW_PAYLOAD_FORBIDDEN,
    UNKNOWN_EVENT_ROUTE,
    GovernanceEvent,
    append_governance_event,
)


EVIDENCE = Path(__file__).resolve().parents[1] / "governance" / "evidence" / "event_bus.json"
HASH_RE = re.compile(r"^sha256:[0-9a-f]{64}$")


def _event(**overrides):
    payload = {
        "policy_hash": "sha256:policy",
        "tenant_hash": "sha256:tenant",
        "evidence_hash": "sha256:evidence",
        "correlation_id": "correlation-1",
        "timestamp": "2026-07-09T00:00:00Z",
        "actor": "codex",
        "route": "audit",
        "decision_id": "decision-1",
    }
    payload.update(overrides)
    return GovernanceEvent(**payload)


def test_event_append_is_ready_and_append_only():
    result = append_governance_event((), _event())

    assert result.event_state == EVENT_READY
    assert result.event_count == 1
    assert result.events == (_event(),)
    assert result.execution_allowed is False


def test_missing_event_field_blocks_without_append():
    result = append_governance_event((_event(decision_id="prior"),), _event(policy_hash=""))

    assert result.event_state == EVENT_BLOCKED
    assert result.event_count == 1
    assert MISSING_EVENT_FIELD in result.denial_reasons


def test_missing_or_empty_route_blocks_without_append():
    missing = append_governance_event((_event(decision_id="prior"),), _event(route=""))

    assert missing.event_state == EVENT_BLOCKED
    assert missing.event_count == 1
    assert MISSING_EVENT_FIELD in missing.denial_reasons
    assert UNKNOWN_EVENT_ROUTE in missing.denial_reasons


def test_unknown_route_blocks_without_exception():
    first = append_governance_event((), _event(route="unknown_route"))
    second = append_governance_event((), _event(route="unknown_route"))

    assert first.event_state == EVENT_BLOCKED
    assert first.event_count == 0
    assert UNKNOWN_EVENT_ROUTE in first.denial_reasons
    assert first.as_dict() == second.as_dict()


def test_execution_like_routes_block_fail_closed():
    blocked_routes = (
        "socket_publish",
        "provider_execute",
        "network_send",
        "subprocess_start",
        "broker_publish",
        "background_job",
        "production_activate",
        "runtime-design",
    )

    for route in blocked_routes:
        result = append_governance_event((), _event(route=route))
        assert result.event_state == EVENT_BLOCKED
        assert result.events == ()
        assert UNKNOWN_EVENT_ROUTE in result.denial_reasons
        assert result.execution_allowed is False
        assert result.provider_execution is False
        assert result.production_activation is False


def test_route_allow_list_is_exact():
    near_matches = (
        " runtime-design",
        "Runtime-design",
        "Runtime-Design",
        "runtime",
        "runtime-design ",
        "runtime-design/",
        "runtime-design/v1",
        "runtime_design",
    )

    for route in near_matches:
        result = append_governance_event((), _event(route=route))
        assert result.event_state == EVENT_BLOCKED
        assert UNKNOWN_EVENT_ROUTE in result.denial_reasons


def test_known_metadata_only_routes_can_append_with_valid_metadata():
    for route in GOVERNED_EVENT_ROUTES:
        result = append_governance_event((), _event(route=route))
        assert result.event_state == EVENT_READY
        assert result.event_count == 1
        assert result.execution_allowed is False
        assert result.provider_execution is False
        assert result.production_activation is False


def test_raw_payload_and_execution_request_block():
    result = append_governance_event((), _event(metadata={"secret": "do-not-log"}, requested_execution=True))

    assert result.event_state == EVENT_BLOCKED
    assert RAW_PAYLOAD_FORBIDDEN in result.denial_reasons
    assert EXECUTION_REQUESTED in result.denial_reasons


def test_event_is_immutable():
    event = _event()

    with pytest.raises(FrozenInstanceError):
        event.actor = "replit"


def test_event_output_is_deterministic_and_redacted():
    first = append_governance_event((), _event())
    second = append_governance_event((), _event())
    rendered = json.dumps(first.as_dict(), sort_keys=True)

    assert first.as_dict() == second.as_dict()
    assert "correlation-1" not in rendered
    assert "codex" not in rendered


def test_event_bus_evidence_is_hash_only():
    evidence = json.loads(EVIDENCE.read_text(encoding="utf-8"))
    rendered = json.dumps(evidence, sort_keys=True)

    assert HASH_RE.match(evidence["tenant_hash"])
    assert HASH_RE.match(evidence["policy_hash"])
    assert HASH_RE.match(evidence["evidence_hash"])
    assert HASH_RE.match(evidence["event_bus_hash"])
    assert evidence["append_only"] is True
    assert evidence["network"] is False
    assert evidence["message_broker"] is False
    assert evidence["execution_allowed"] is False
    assert evidence["hash_only"] is True
    assert evidence["redacted"] is True
    assert evidence["provider_execution"] is False
    assert evidence["production_activation"] is False
    assert HASH_RE.match(evidence["route_registry_hash"])
    for forbidden in ("credential", "provider_data", "raw_payload", "secret", "sensitive", "token"):
        assert forbidden not in rendered
