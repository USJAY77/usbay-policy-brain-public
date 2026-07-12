import json
from pathlib import Path

from governance.runtime.runtime_coordinator import (
    BLOCKED,
    COORDINATOR_BLOCKED,
    COORDINATOR_READY,
    EVENT_ROUTES,
    EXECUTION_REQUESTED,
    INVALID_STATE,
    MISSING_DECISION_METADATA,
    MISSING_EVIDENCE,
    MISSING_GOVERNANCE_METADATA,
    PROVIDER_EXECUTION_REQUESTED,
    PRODUCTION_ACTIVATION_REQUESTED,
    RAW_PAYLOAD_FORBIDDEN,
    READY,
    ROUTE_FAIL_CLOSED,
    RUNTIME_UNAVAILABLE,
    UNKNOWN_ACTOR,
    UNKNOWN_EVENT_ROUTE,
    UNKNOWN_RUNTIME,
    RuntimeComponentReference,
    RuntimeCoordinatorRequest,
    coordinate_runtime,
)


HASH = "sha256:" + "a" * 64
OTHER_HASH = "sha256:" + "b" * 64


def _component(name, state=READY, evidence_hash=HASH, available=True):
    return RuntimeComponentReference(
        name=name,
        state=state,
        evidence_hash=evidence_hash,
        available=available,
    )


def _request(**overrides):
    request = {
        "runtime_id": "runtime-local-1",
        "actor": "codex",
        "tenant_id": "tenant-a",
        "policy_hash": HASH,
        "orchestration_hash": OTHER_HASH,
        "evidence_hash": HASH,
        "health_hash": OTHER_HASH,
        "decision_metadata_hash": HASH,
        "timestamp": "2026-07-09T00:00:00Z",
        "coordinator_state": COORDINATOR_READY,
        "scheduler_state": READY,
        "event_route": "audit",
        "agent_runtime": _component("agent_runtime"),
        "scheduler": _component("scheduler"),
        "event_bus": _component("event_bus"),
        "runtime_health": _component("runtime_health"),
        "tmux": _component("tmux"),
        "gateway": _component("gateway"),
        "audit": _component("audit"),
    }
    request.update(overrides)
    return RuntimeCoordinatorRequest(**request)


def test_runtime_coordinator_ready_metadata_only():
    decision = coordinate_runtime(_request())
    payload = decision.as_dict()

    assert decision.coordinator_state == COORDINATOR_READY
    assert decision.actor_hash.startswith("sha256:")
    assert decision.scheduler_contract_state == READY
    assert decision.event_route == "audit"
    assert decision.execution_allowed is False
    assert decision.provider_execution is False
    assert decision.production_activation is False
    assert decision.hash_only is True
    assert decision.redacted is True
    assert decision.blocking_reasons == ()
    assert payload["execution_allowed"] is False
    assert payload["provider_execution"] is False
    assert payload["production_activation"] is False


def test_missing_tenant_blocks():
    decision = coordinate_runtime(_request(tenant_id=""))

    assert decision.coordinator_state == COORDINATOR_BLOCKED
    assert MISSING_GOVERNANCE_METADATA in decision.blocking_reasons


def test_missing_policy_hash_blocks():
    decision = coordinate_runtime(_request(policy_hash=""))

    assert decision.coordinator_state == COORDINATOR_BLOCKED
    assert MISSING_GOVERNANCE_METADATA in decision.blocking_reasons


def test_missing_evidence_hash_blocks():
    decision = coordinate_runtime(_request(evidence_hash=""))

    assert decision.coordinator_state == COORDINATOR_BLOCKED
    assert MISSING_GOVERNANCE_METADATA in decision.blocking_reasons


def test_missing_orchestration_hash_blocks():
    decision = coordinate_runtime(_request(orchestration_hash=""))

    assert decision.coordinator_state == COORDINATOR_BLOCKED
    assert MISSING_GOVERNANCE_METADATA in decision.blocking_reasons


def test_missing_health_hash_blocks():
    decision = coordinate_runtime(_request(health_hash=""))

    assert decision.coordinator_state == COORDINATOR_BLOCKED
    assert MISSING_GOVERNANCE_METADATA in decision.blocking_reasons


def test_missing_timestamp_blocks():
    decision = coordinate_runtime(_request(timestamp=""))

    assert decision.coordinator_state == COORDINATOR_BLOCKED
    assert MISSING_GOVERNANCE_METADATA in decision.blocking_reasons


def test_missing_decision_metadata_blocks():
    decision = coordinate_runtime(_request(decision_metadata_hash=""))

    assert decision.coordinator_state == COORDINATOR_BLOCKED
    assert MISSING_DECISION_METADATA in decision.blocking_reasons


def test_unknown_actor_blocks():
    decision = coordinate_runtime(_request(actor="unknown_agent"))

    assert decision.coordinator_state == COORDINATOR_BLOCKED
    assert UNKNOWN_ACTOR in decision.blocking_reasons


def test_unknown_coordinator_state_blocks():
    decision = coordinate_runtime(_request(coordinator_state="LIVE_READY"))

    assert decision.coordinator_state == COORDINATOR_BLOCKED
    assert INVALID_STATE in decision.blocking_reasons


def test_scheduler_contract_rejects_invalid_state():
    decision = coordinate_runtime(_request(scheduler_state="RUNNING"))

    assert decision.coordinator_state == COORDINATOR_BLOCKED
    assert decision.scheduler_contract_state == BLOCKED
    assert INVALID_STATE in decision.blocking_reasons


def test_event_route_contract_rejects_unknown_route():
    decision = coordinate_runtime(_request(event_route="socket_publish"))

    assert decision.coordinator_state == COORDINATOR_BLOCKED
    assert decision.event_route == ROUTE_FAIL_CLOSED
    assert UNKNOWN_EVENT_ROUTE in decision.blocking_reasons


def test_unknown_component_blocks():
    decision = coordinate_runtime(_request(audit=_component("unknown_component")))
    repeated = coordinate_runtime(_request(audit=_component("unknown_component")))

    assert decision.coordinator_state == COORDINATOR_BLOCKED
    assert UNKNOWN_RUNTIME in decision.blocking_reasons
    assert "unknown_component" in decision.component_hashes
    assert decision.component_hashes["unknown_component"].startswith("sha256:")
    assert decision.health_aggregation_hash == repeated.health_aggregation_hash
    assert decision.execution_allowed is False
    assert decision.provider_execution is False
    assert decision.production_activation is False


def test_invalid_event_bus_state_blocks():
    decision = coordinate_runtime(_request(event_bus=_component("event_bus", state="BROKER_ONLINE")))

    assert decision.coordinator_state == COORDINATOR_BLOCKED
    assert INVALID_STATE in decision.blocking_reasons
    assert decision.execution_allowed is False


def test_missing_component_evidence_blocks():
    decision = coordinate_runtime(_request(tmux=_component("tmux", evidence_hash="")))

    assert decision.coordinator_state == COORDINATOR_BLOCKED
    assert MISSING_EVIDENCE in decision.blocking_reasons


def test_unavailable_runtime_component_blocks():
    decision = coordinate_runtime(_request(gateway=_component("gateway", available=False)))

    assert decision.coordinator_state == COORDINATOR_BLOCKED
    assert RUNTIME_UNAVAILABLE in decision.blocking_reasons


def test_blocked_runtime_component_blocks():
    decision = coordinate_runtime(_request(audit=_component("audit", state=BLOCKED)))

    assert decision.coordinator_state == COORDINATOR_BLOCKED
    assert RUNTIME_UNAVAILABLE in decision.blocking_reasons


def test_blocked_event_bus_component_blocks_coordinator():
    decision = coordinate_runtime(_request(event_bus=_component("event_bus", state=BLOCKED)))

    assert decision.coordinator_state == COORDINATOR_BLOCKED
    assert RUNTIME_UNAVAILABLE in decision.blocking_reasons
    assert decision.execution_allowed is False
    assert decision.provider_execution is False
    assert decision.production_activation is False


def test_invalid_component_health_state_blocks():
    decision = coordinate_runtime(_request(runtime_health=_component("runtime_health", state="GREEN")))

    assert decision.coordinator_state == COORDINATOR_BLOCKED
    assert INVALID_STATE in decision.blocking_reasons
    assert decision.execution_allowed is False


def test_execution_request_blocks():
    decision = coordinate_runtime(_request(requested_execution=True))

    assert decision.coordinator_state == COORDINATOR_BLOCKED
    assert EXECUTION_REQUESTED in decision.blocking_reasons


def test_provider_execution_request_blocks():
    decision = coordinate_runtime(_request(provider_execution_requested=True))

    assert decision.coordinator_state == COORDINATOR_BLOCKED
    assert PROVIDER_EXECUTION_REQUESTED in decision.blocking_reasons


def test_production_activation_request_blocks():
    decision = coordinate_runtime(_request(production_activation_requested=True))

    assert decision.coordinator_state == COORDINATOR_BLOCKED
    assert PRODUCTION_ACTIVATION_REQUESTED in decision.blocking_reasons


def test_raw_payload_metadata_blocks():
    decision = coordinate_runtime(_request(metadata={"raw_payload": "forbidden"}))

    assert decision.coordinator_state == COORDINATOR_BLOCKED
    assert RAW_PAYLOAD_FORBIDDEN in decision.blocking_reasons


def test_prompt_and_provider_metadata_blocks():
    decision = coordinate_runtime(_request(metadata={"prompt": "forbidden", "provider_data": "forbidden"}))

    assert decision.coordinator_state == COORDINATOR_BLOCKED
    assert RAW_PAYLOAD_FORBIDDEN in decision.blocking_reasons


def test_all_event_routes_are_accepted():
    for route in EVENT_ROUTES:
        decision = coordinate_runtime(_request(event_route=route))
        assert UNKNOWN_EVENT_ROUTE not in decision.blocking_reasons


def test_runtime_decision_hash_is_deterministic():
    first = coordinate_runtime(_request())
    second = coordinate_runtime(_request())

    assert first.decision_hash == second.decision_hash
    assert first.runtime_evidence_hash == second.runtime_evidence_hash
    assert first.health_aggregation_hash == second.health_aggregation_hash


def test_runtime_coordinator_evidence_is_hash_only_and_redacted():
    evidence = json.loads(Path("governance/evidence/runtime_coordinator.json").read_text())
    rendered = json.dumps(evidence, sort_keys=True)

    assert evidence["hash_only"] is True
    assert evidence["redacted"] is True
    assert evidence["execution_allowed"] is False
    assert evidence["provider_execution"] is False
    assert evidence["production_activation"] is False
    assert evidence["human_approval_fabricated"] is False
    assert evidence["live_runtime_ready"] is False
    for key in ("runtime_id", "policy_hash", "orchestration_hash", "health_hash", "decision_hash"):
        assert evidence[key].startswith("sha256:")
        assert len(evidence[key]) == 71
    for forbidden in ("credential", "provider_data", "prompt", "raw_payload", "secret", "sensitive_value"):
        assert forbidden not in rendered
