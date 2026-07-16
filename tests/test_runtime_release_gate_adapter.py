import hashlib
import json
import re
from pathlib import Path

from governance.runtime import runtime_release_gate_adapter as adapter
from governance.runtime.runtime_release_gate_adapter import (
    COMPONENT_ORDER,
    DUPLICATE_METADATA,
    EVIDENCE_MISMATCH,
    EXECUTION_FLAG_ENABLED,
    INVALID_CHRONOLOGY,
    INVALID_HASH,
    MISSING_APPROVAL,
    MISSING_EVIDENCE,
    NON_HASH_ONLY_EVIDENCE,
    POLICY_MISMATCH,
    PRODUCTION_ACTIVATION_ENABLED,
    PROVIDER_EXECUTION_ENABLED,
    RELEASE_BLOCKED,
    RELEASE_READY_METADATA,
    REPLAY_MISMATCH,
    SENSITIVE_DATA_PRESENT,
    TENANT_MISMATCH,
    UNKNOWN_COMPONENT,
    UNKNOWN_METADATA,
    UNKNOWN_STAGE,
    UNREDACTED_EVIDENCE,
    UNSUPPORTED_SCHEMA,
    UNSUPPORTED_VERSION,
    RuntimeReleaseGateRequest,
    evaluate_runtime_release_gate,
)


EVIDENCE = Path(__file__).resolve().parents[1] / "governance" / "evidence" / "runtime_release_gate_adapter.json"
SOURCE = Path(adapter.__file__)
HASH_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
TIMESTAMPS = {
    "agent_runtime": "2026-07-15T09:00:00Z",
    "runtime_coordinator": "2026-07-15T09:01:00Z",
    "event_bus": "2026-07-15T09:02:00Z",
    "runtime_health": "2026-07-15T09:03:00Z",
    "execution_scheduler": "2026-07-15T09:04:00Z",
    "runtime_evidence_aggregator": "2026-07-15T09:05:00Z",
    "runtime_policy_binding": "2026-07-15T09:06:00Z",
    "runtime_approval_gate": "2026-07-15T09:07:00Z",
    "runtime_replay_verifier": "2026-07-15T09:08:00Z",
}


def _hash(label):
    return "sha256:" + hashlib.sha256(label.encode("utf-8")).hexdigest()


def _components(**overrides):
    references = []
    for component in COMPONENT_ORDER:
        evidence_hash = _hash(f"evidence:{component}")
        if component == "runtime_evidence_aggregator":
            evidence_hash = _hash("aggregate-evidence")
        if component == "runtime_approval_gate":
            evidence_hash = _hash("approval")
        if component == "runtime_replay_verifier":
            evidence_hash = _hash("replay")
        payload = {
            "component": component,
            "policy_hash": _hash("policy"),
            "tenant_hash": _hash("tenant"),
            "evidence_hash": evidence_hash,
            "decision_hash": _hash(f"decision:{component}"),
            "timestamp": TIMESTAMPS[component],
            "schema_version": "phase-b.runtime-release-gate-adapter.v1",
            "output_version": "phase-b.release-readiness.v1",
            "hash_algorithm": "sha256",
            "hash_only": True,
            "redacted": True,
            "execution_allowed": False,
            "provider_execution": False,
            "production_activation": False,
        }
        payload.update(overrides.get(component, {}))
        references.append(payload)
    return references


def _request(component_references=None, **overrides):
    payload = {
        "release_id": "release-runtime-001",
        "policy_hash": _hash("policy"),
        "tenant_hash": _hash("tenant"),
        "evidence_hash": _hash("aggregate-evidence"),
        "approval_hash": _hash("approval"),
        "replay_hash": _hash("replay"),
        "release_stage": "PR_REVIEW",
        "schema_version": "phase-b.runtime-release-gate-adapter.v1",
        "output_version": "phase-b.release-readiness.v1",
        "hash_algorithm": "sha256",
        "component_references": component_references if component_references is not None else _components(),
        "execution_allowed": False,
        "provider_execution": False,
        "production_activation": False,
        "hash_only": True,
        "redacted": True,
    }
    payload.update(overrides)
    return RuntimeReleaseGateRequest(**payload)


def test_valid_release_gate_metadata_is_deterministic():
    first = evaluate_runtime_release_gate(_request())
    second = evaluate_runtime_release_gate(_request())

    assert first.readiness_state == RELEASE_READY_METADATA
    assert first.denial_code is None
    assert first.as_dict() == second.as_dict()
    assert HASH_RE.match(first.release_readiness_hash)
    assert first.execution_allowed is False
    assert first.provider_execution is False
    assert first.production_activation is False


def test_missing_required_evidence_blocks():
    result = evaluate_runtime_release_gate(_request(component_references=_components()[:-1]))

    assert result.readiness_state == RELEASE_BLOCKED
    assert MISSING_EVIDENCE in result.denial_reasons


def test_missing_approval_blocks():
    result = evaluate_runtime_release_gate(_request(approval_hash=""))

    assert result.readiness_state == RELEASE_BLOCKED
    assert MISSING_APPROVAL in result.denial_reasons


def test_replay_policy_tenant_and_evidence_mismatch_block():
    replay = evaluate_runtime_release_gate(_request(replay_hash=_hash("other-replay")))
    policy = evaluate_runtime_release_gate(_request(component_references=_components(agent_runtime={"policy_hash": _hash("other-policy")})))
    tenant = evaluate_runtime_release_gate(_request(component_references=_components(agent_runtime={"tenant_hash": _hash("other-tenant")})))
    evidence = evaluate_runtime_release_gate(_request(evidence_hash=_hash("other-evidence")))

    assert REPLAY_MISMATCH in replay.denial_reasons
    assert POLICY_MISMATCH in policy.denial_reasons
    assert TENANT_MISMATCH in tenant.denial_reasons
    assert EVIDENCE_MISMATCH in evidence.denial_reasons


def test_malformed_duplicate_unknown_metadata_block():
    malformed = evaluate_runtime_release_gate({"release_id": object()})
    duplicate_components = _components() + [_components()[0]]
    duplicate = evaluate_runtime_release_gate(_request(component_references=duplicate_components))
    unknown = evaluate_runtime_release_gate(_request(component_references=_components(agent_runtime={"component": "gateway"})))
    unknown_meta = evaluate_runtime_release_gate({**_request().as_dict(), "unexpected": "x"})

    assert adapter.MALFORMED_METADATA in malformed.denial_reasons
    assert DUPLICATE_METADATA in duplicate.denial_reasons
    assert UNKNOWN_COMPONENT in unknown.denial_reasons
    assert UNKNOWN_METADATA in unknown_meta.denial_reasons


def test_invalid_chronology_blocks():
    result = evaluate_runtime_release_gate(_request(component_references=_components(runtime_health={"timestamp": "2026-07-15T08:00:00Z"})))

    assert INVALID_CHRONOLOGY in result.denial_reasons


def test_unsupported_schema_version_and_stage_block():
    schema = evaluate_runtime_release_gate(_request(schema_version="phase-b.unknown"))
    version = evaluate_runtime_release_gate(_request(output_version="phase-b.unknown"))
    stage = evaluate_runtime_release_gate(_request(release_stage="PRODUCTION"))

    assert UNSUPPORTED_SCHEMA in schema.denial_reasons
    assert UNSUPPORTED_VERSION in version.denial_reasons
    assert UNKNOWN_STAGE in stage.denial_reasons


def test_invalid_hash_blocks():
    result = evaluate_runtime_release_gate(_request(policy_hash="sha256:not-valid"))

    assert INVALID_HASH in result.denial_reasons


def test_non_hash_only_unredacted_and_execution_flags_block():
    non_hash = evaluate_runtime_release_gate(_request(hash_only=False))
    unredacted = evaluate_runtime_release_gate(_request(redacted=False))
    execution = evaluate_runtime_release_gate(_request(execution_allowed=True))
    provider = evaluate_runtime_release_gate(_request(provider_execution=True))
    production = evaluate_runtime_release_gate(_request(production_activation=True))

    assert NON_HASH_ONLY_EVIDENCE in non_hash.denial_reasons
    assert UNREDACTED_EVIDENCE in unredacted.denial_reasons
    assert EXECUTION_FLAG_ENABLED in execution.denial_reasons
    assert PROVIDER_EXECUTION_ENABLED in provider.denial_reasons
    assert PRODUCTION_ACTIVATION_ENABLED in production.denial_reasons


def test_sensitive_data_blocks():
    components = _components()
    components[0]["token"] = "forbidden"

    result = evaluate_runtime_release_gate(_request(component_references=components))

    assert SENSITIVE_DATA_PRESENT in result.denial_reasons


def test_no_execution_capable_imports():
    source = SOURCE.read_text(encoding="utf-8")

    for forbidden in (
        "import asyncio",
        "import os",
        "import socket",
        "import subprocess",
        "import threading",
        "requests",
        "urllib",
        "redis",
        "kafka",
        "tmux",
        "eval(",
        "exec(",
    ):
        assert forbidden not in source


def test_evidence_fixture_is_hash_only_redacted_and_safe():
    evidence = json.loads(EVIDENCE.read_text(encoding="utf-8"))
    rendered = json.dumps(evidence, sort_keys=True)

    assert tuple(evidence["component_allow_list"]) == COMPONENT_ORDER
    assert evidence["hash_only"] is True
    assert evidence["redacted"] is True
    assert evidence["execution_allowed"] is False
    assert evidence["provider_execution"] is False
    assert evidence["production_activation"] is False
    assert HASH_RE.match(evidence["sample_release_readiness_hash"])
    assert set(adapter.DENIAL_CODES).issubset(set(evidence["denial_codes"]))
    for forbidden in ("credential_value", "secret_value", "token_value", "customer_email", "provider_value"):
        assert forbidden not in rendered
