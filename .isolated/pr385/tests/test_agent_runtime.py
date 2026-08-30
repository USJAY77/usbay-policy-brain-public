import json
import re
from pathlib import Path

from governance.runtime.agent_runtime import (
    BLOCKED,
    EXECUTION_REQUESTED,
    INVALID_STATE,
    MISSING_GOVERNANCE_METADATA,
    RAW_PAYLOAD_FORBIDDEN,
    READY,
    RUNTIME_BLOCKED,
    RUNTIME_READY,
    UNKNOWN_ACTION,
    UNKNOWN_ACTOR,
    UNKNOWN_CAPABILITY,
    AgentRuntimeRequest,
    coordinate_agent_runtime,
)


EVIDENCE = Path(__file__).resolve().parents[1] / "governance" / "evidence" / "agent_runtime.json"
HASH_RE = re.compile(r"^sha256:[0-9a-f]{64}$")


def _request(**overrides):
    payload = {
        "actor": "codex",
        "capability": "design",
        "action": "coordinate",
        "state": READY,
        "tenant_id": "tenant-runtime",
        "policy_hash": "sha256:policy",
        "evidence_hash": "sha256:evidence",
        "correlation_id": "correlation-1",
    }
    payload.update(overrides)
    return AgentRuntimeRequest(**payload)


def test_agent_runtime_ready_metadata_only():
    result = coordinate_agent_runtime(_request())

    assert result.readiness_state == RUNTIME_READY
    assert result.runtime_state == READY
    assert result.runtime_id.startswith("sha256:")
    assert result.execution_allowed is False
    assert result.hash_only is True
    assert result.redacted is True


def test_unknown_actor_capability_action_block():
    result = coordinate_agent_runtime(_request(actor="bot", capability="deploy", action="push"))

    assert result.readiness_state == RUNTIME_BLOCKED
    assert result.runtime_state == BLOCKED
    assert UNKNOWN_ACTOR in result.denial_reasons
    assert UNKNOWN_CAPABILITY in result.denial_reasons
    assert UNKNOWN_ACTION in result.denial_reasons


def test_missing_governance_metadata_blocks():
    result = coordinate_agent_runtime(_request(tenant_id="", policy_hash="", evidence_hash="", correlation_id=""))

    assert result.readiness_state == RUNTIME_BLOCKED
    assert MISSING_GOVERNANCE_METADATA in result.denial_reasons


def test_invalid_state_blocks():
    result = coordinate_agent_runtime(_request(state="EXECUTING"))

    assert result.runtime_state == BLOCKED
    assert INVALID_STATE in result.denial_reasons


def test_execution_request_and_raw_payload_block():
    result = coordinate_agent_runtime(_request(requested_execution=True, metadata={"raw_payload": "do-not-log"}))

    assert result.runtime_state == BLOCKED
    assert EXECUTION_REQUESTED in result.denial_reasons
    assert RAW_PAYLOAD_FORBIDDEN in result.denial_reasons


def test_agent_runtime_is_deterministic_and_redacted():
    first = coordinate_agent_runtime(_request())
    second = coordinate_agent_runtime(_request())
    rendered = json.dumps(first.as_dict(), sort_keys=True)

    assert first.as_dict() == second.as_dict()
    assert "tenant-runtime" not in rendered
    assert "correlation-1" not in rendered


def test_agent_runtime_evidence_is_hash_only():
    evidence = json.loads(EVIDENCE.read_text(encoding="utf-8"))

    assert HASH_RE.match(evidence["tenant_hash"])
    assert HASH_RE.match(evidence["policy_hash"])
    assert HASH_RE.match(evidence["evidence_hash"])
    assert HASH_RE.match(evidence["runtime_hash"])
    assert evidence["execution_allowed"] is False
    assert evidence["hash_only"] is True
    assert evidence["redacted"] is True
    assert evidence["provider_execution"] is False
    assert evidence["production_activation"] is False
