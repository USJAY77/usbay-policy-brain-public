import json
import re
from pathlib import Path

from governance.runtime.runtime_health import (
    AGENT_RUNTIME_NOT_READY,
    AUDIT_NOT_READY,
    BLOCKED,
    DEGRADED,
    EVENT_BUS_NOT_READY,
    HEALTHY,
    MISSING_GOVERNANCE_METADATA,
    POLICY_UNAVAILABLE,
    SCHEDULER_NOT_READY,
    TMUX_UNKNOWN,
    UNKNOWN,
    RuntimeHealthRequest,
    evaluate_runtime_health,
)


EVIDENCE = Path(__file__).resolve().parents[1] / "governance" / "evidence" / "runtime_health.json"
HASH_RE = re.compile(r"^sha256:[0-9a-f]{64}$")


def _request(**overrides):
    payload = {
        "tenant_id": "tenant-runtime",
        "policy_hash": "sha256:policy",
        "evidence_hash": "sha256:evidence",
        "policy_available": True,
        "audit_ready": True,
        "tmux_available": True,
        "scheduler_ready": True,
        "event_bus_ready": True,
        "agent_runtime_ready": True,
    }
    payload.update(overrides)
    return RuntimeHealthRequest(**payload)


def test_runtime_health_healthy_from_metadata():
    result = evaluate_runtime_health(_request())

    assert result.health_state == HEALTHY
    assert result.health_hash.startswith("sha256:")
    assert result.execution_allowed is False
    assert result.hash_only is True
    assert result.redacted is True


def test_missing_metadata_policy_or_audit_blocks():
    result = evaluate_runtime_health(_request(tenant_id="", policy_hash="", evidence_hash="", policy_available=False, audit_ready=False))

    assert result.health_state == BLOCKED
    assert MISSING_GOVERNANCE_METADATA in result.denial_reasons
    assert POLICY_UNAVAILABLE in result.denial_reasons
    assert AUDIT_NOT_READY in result.denial_reasons


def test_unknown_tmux_metadata_returns_unknown():
    result = evaluate_runtime_health(_request(tmux_available=None))

    assert result.health_state == UNKNOWN
    assert TMUX_UNKNOWN in result.denial_reasons


def test_component_not_ready_degrades():
    result = evaluate_runtime_health(_request(scheduler_ready=False, event_bus_ready=False, agent_runtime_ready=False))

    assert result.health_state == DEGRADED
    assert SCHEDULER_NOT_READY in result.denial_reasons
    assert EVENT_BUS_NOT_READY in result.denial_reasons
    assert AGENT_RUNTIME_NOT_READY in result.denial_reasons


def test_runtime_health_is_deterministic_and_redacted():
    first = evaluate_runtime_health(_request())
    second = evaluate_runtime_health(_request())
    rendered = json.dumps(first.as_dict(), sort_keys=True)

    assert first.as_dict() == second.as_dict()
    assert "tenant-runtime" not in rendered


def test_runtime_health_evidence_is_hash_only():
    evidence = json.loads(EVIDENCE.read_text(encoding="utf-8"))

    assert HASH_RE.match(evidence["tenant_hash"])
    assert HASH_RE.match(evidence["policy_hash"])
    assert HASH_RE.match(evidence["evidence_hash"])
    assert HASH_RE.match(evidence["health_hash"])
    assert evidence["daemon"] is False
    assert evidence["polling_loop"] is False
    assert evidence["execution_allowed"] is False
    assert evidence["hash_only"] is True
    assert evidence["redacted"] is True
