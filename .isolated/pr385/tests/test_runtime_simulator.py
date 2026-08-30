import hashlib
import json
import re
from pathlib import Path

from governance.runtime import runtime_simulator as simulator
from governance.runtime.runtime_simulator import (
    APPROVAL_MISSING,
    CROSS_TENANT_METADATA,
    EXECUTION_FLAG_ENABLED,
    INVALID_SCHEMA,
    MALFORMED_METADATA,
    MISSING_METADATA,
    MISSING_PREDECESSOR_HASH,
    NON_HASH_ONLY_EVIDENCE,
    POLICY_MISMATCH,
    PRODUCTION_ACTIVATION_ENABLED,
    PROVIDER_EXECUTION_ENABLED,
    SENSITIVE_DATA_PRESENT,
    SIM_BLOCKED,
    SIM_FAILED_CLOSED,
    SIM_READY,
    SIM_REVIEW_REQUIRED,
    UNKNOWN_COMPONENT,
    UNKNOWN_METADATA,
    UNREDACTED_EVIDENCE,
    UNSUPPORTED_HASH_ALGORITHM,
    UNSUPPORTED_VERSION,
    RuntimeSimulatorRequest,
    simulate_runtime,
)


EVIDENCE = Path(__file__).resolve().parents[1] / "governance" / "evidence" / "runtime_simulator.json"
SOURCE = Path(simulator.__file__)
HASH_RE = re.compile(r"^sha256:[0-9a-f]{64}$")


def _hash(label):
    return "sha256:" + hashlib.sha256(label.encode("utf-8")).hexdigest()


def _release_metadata(**overrides):
    payload = {
        "component": "runtime_release_gate_adapter",
        "release_readiness_hash": _hash("release-readiness"),
        "policy_hash": _hash("policy"),
        "tenant_hash": _hash("tenant"),
        "evidence_hash": _hash("evidence"),
        "approval_hash": _hash("approval"),
        "replay_hash": _hash("replay"),
        "readiness_state": "RELEASE_READY_METADATA",
        "schema_version": "phase-b.runtime-release-gate-adapter.v1",
        "output_version": "phase-b.release-readiness.v1",
        "hash_algorithm": "sha256",
        "hash_only": True,
        "redacted": True,
        "execution_allowed": False,
        "provider_execution": False,
        "production_activation": False,
    }
    payload.update(overrides)
    return payload


def _request(release_metadata=None, **overrides):
    payload = {
        "simulation_id": "sim-runtime-001",
        "policy_hash": _hash("policy"),
        "tenant_hash": _hash("tenant"),
        "evidence_hash": _hash("evidence"),
        "release_readiness_hash": _hash("release-readiness"),
        "approval_hash": _hash("approval"),
        "simulation_mode": "LOCAL_METADATA_ONLY",
        "schema_version": "phase-c.runtime-simulator.v1",
        "simulator_version": "phase-c.runtime-simulator-output.v1",
        "hash_algorithm": "sha256",
        "release_metadata": release_metadata if release_metadata is not None else _release_metadata(),
        "execution_allowed": False,
        "provider_execution": False,
        "production_activation": False,
        "hash_only": True,
        "redacted": True,
    }
    payload.update(overrides)
    return RuntimeSimulatorRequest(**payload)


def test_valid_release_metadata_returns_deterministic_sim_ready():
    first = simulate_runtime(_request())
    second = simulate_runtime(_request())

    assert first.simulation_state == SIM_READY
    assert first.denial_code is None
    assert first.as_dict() == second.as_dict()
    assert HASH_RE.match(first.simulation_hash)
    assert first.execution_allowed is False
    assert first.provider_execution is False
    assert first.production_activation is False
    assert first.hash_only is True
    assert first.redacted is True


def test_missing_metadata_blocks():
    payload = _request().as_dict()
    payload.pop("release_metadata")

    result = simulate_runtime(payload)

    assert result.simulation_state == SIM_BLOCKED
    assert MISSING_METADATA in result.denial_reasons


def test_invalid_schema_blocks():
    result = simulate_runtime(_request(schema_version="phase-c.unknown"))

    assert result.simulation_state == SIM_BLOCKED
    assert INVALID_SCHEMA in result.denial_reasons


def test_missing_predecessor_hash_blocks():
    result = simulate_runtime(_request(release_readiness_hash=""))

    assert result.simulation_state == SIM_BLOCKED
    assert MISSING_PREDECESSOR_HASH in result.denial_reasons


def test_unknown_component_blocks():
    result = simulate_runtime(_request(release_metadata=_release_metadata(component="runtime_gateway")))

    assert result.simulation_state == SIM_BLOCKED
    assert UNKNOWN_COMPONENT in result.denial_reasons


def test_unsupported_version_blocks():
    request_version = simulate_runtime(_request(simulator_version="phase-c.unknown"))
    release_version = simulate_runtime(_request(release_metadata=_release_metadata(output_version="phase-b.unknown")))

    assert request_version.simulation_state == SIM_BLOCKED
    assert release_version.simulation_state == SIM_BLOCKED
    assert UNSUPPORTED_VERSION in request_version.denial_reasons
    assert UNSUPPORTED_VERSION in release_version.denial_reasons


def test_cross_tenant_metadata_blocks():
    result = simulate_runtime(_request(release_metadata=_release_metadata(tenant_hash=_hash("other-tenant"))))

    assert result.simulation_state == SIM_BLOCKED
    assert CROSS_TENANT_METADATA in result.denial_reasons


def test_policy_mismatch_blocks():
    result = simulate_runtime(_request(release_metadata=_release_metadata(policy_hash=_hash("other-policy"))))

    assert result.simulation_state == SIM_BLOCKED
    assert POLICY_MISMATCH in result.denial_reasons


def test_approval_missing_routes_to_review_required():
    release = _release_metadata(approval_hash="")

    result = simulate_runtime(_request(release_metadata=release, approval_hash=""))

    assert result.simulation_state == SIM_REVIEW_REQUIRED
    assert result.denial_code == APPROVAL_MISSING
    assert result.execution_allowed is False
    assert result.provider_execution is False
    assert result.production_activation is False


def test_malformed_payload_fails_closed():
    result = simulate_runtime(object())

    assert result.simulation_state == SIM_FAILED_CLOSED
    assert MALFORMED_METADATA in result.denial_reasons


def test_unknown_metadata_blocks():
    payload = _request().as_dict()
    payload["unexpected"] = "value"

    result = simulate_runtime(payload)

    assert result.simulation_state == SIM_BLOCKED
    assert UNKNOWN_METADATA in result.denial_reasons


def test_execution_flags_block():
    execution = simulate_runtime(_request(execution_allowed=True))
    provider = simulate_runtime(_request(provider_execution=True))
    production = simulate_runtime(_request(production_activation=True))

    assert EXECUTION_FLAG_ENABLED in execution.denial_reasons
    assert PROVIDER_EXECUTION_ENABLED in provider.denial_reasons
    assert PRODUCTION_ACTIVATION_ENABLED in production.denial_reasons
    assert execution.execution_allowed is False
    assert provider.provider_execution is False
    assert production.production_activation is False


def test_hash_only_and_redaction_required():
    non_hash = simulate_runtime(_request(hash_only=False))
    unredacted = simulate_runtime(_request(redacted=False))

    assert NON_HASH_ONLY_EVIDENCE in non_hash.denial_reasons
    assert UNREDACTED_EVIDENCE in unredacted.denial_reasons


def test_sensitive_data_fails_closed():
    release = _release_metadata(token="forbidden")

    result = simulate_runtime(_request(release_metadata=release))

    assert result.simulation_state == SIM_FAILED_CLOSED
    assert SENSITIVE_DATA_PRESENT in result.denial_reasons


def test_unsupported_hash_algorithm_blocks():
    result = simulate_runtime(_request(hash_algorithm="sha512"))

    assert result.simulation_state == SIM_BLOCKED
    assert UNSUPPORTED_HASH_ALGORITHM in result.denial_reasons


def test_evidence_fixture_is_hash_only_redacted_and_execution_disabled():
    evidence = json.loads(EVIDENCE.read_text(encoding="utf-8"))

    assert evidence["component"] == "runtime_simulator"
    assert evidence["hash_only"] is True
    assert evidence["redacted"] is True
    assert evidence["execution_allowed"] is False
    assert evidence["provider_execution"] is False
    assert evidence["production_activation"] is False
    assert HASH_RE.match(evidence["sample_simulation_hash"])
    assert "raw_payload" not in json.dumps(evidence).lower()


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
        "Popen(",
        "Thread(",
        "create_task(",
        "exec(",
        "eval(",
    ):
        assert forbidden not in source
