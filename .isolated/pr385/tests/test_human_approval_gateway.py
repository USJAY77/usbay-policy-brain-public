import hashlib
import json
import re
from pathlib import Path

from governance.runtime import human_approval_gateway as gateway
from governance.runtime.human_approval_gateway import (
    APPROVAL_BLOCKED,
    APPROVAL_EXPIRED,
    APPROVAL_EXPIRED_REASON,
    APPROVAL_FAILED_CLOSED,
    APPROVAL_NOT_GRANTED,
    APPROVAL_REQUIRED,
    APPROVAL_TIMESTAMP_IN_FUTURE,
    APPROVAL_VALID,
    DEPLOYMENT_EXECUTION_ENABLED,
    DUPLICATE_APPROVAL_REFERENCE,
    EVIDENCE_MISMATCH,
    EXECUTION_FLAG_ENABLED,
    INVALID_HASH,
    MALFORMED_METADATA,
    MISSING_APPROVAL_HASH,
    MISSING_APPROVAL_REFERENCE,
    MISSING_SIMULATOR_HASH,
    NETWORK_ACCESS_ENABLED,
    POLICY_MISMATCH,
    POLICY_MUTATION_ENABLED,
    PRODUCTION_ACTIVATION_ENABLED,
    PROVIDER_EXECUTION_ENABLED,
    RAW_APPROVAL_CONTENT,
    REPLAYED_APPROVAL_REFERENCE,
    RUNTIME_EXECUTION_ENABLED,
    SIMULATOR_HASH_MISMATCH,
    TENANT_MISMATCH,
    UNKNOWN_COMPONENT,
    UNKNOWN_METADATA,
    UNREDACTED_EVIDENCE,
    UNSUPPORTED_HASH_ALGORITHM,
    UNSUPPORTED_SCHEMA,
    UNSUPPORTED_VERSION,
    WRONG_APPROVAL_SCOPE,
    WRONG_APPROVER_ROLE,
    HumanApprovalGatewayRequest,
    validate_human_approval,
)


EVIDENCE = Path(__file__).resolve().parents[1] / "governance" / "evidence" / "human_approval_gateway.json"
SOURCE = Path(gateway.__file__)
HASH_RE = re.compile(r"^sha256:[0-9a-f]{64}$")


def _hash(label):
    return "sha256:" + hashlib.sha256(label.encode("utf-8")).hexdigest()


def _simulator_metadata(**overrides):
    payload = {
        "component": "runtime_simulator",
        "schema_version": "phase-c.runtime-simulator.v1",
        "output_version": "phase-c.runtime-simulator-output.v1",
        "simulation_hash": _hash("simulator-decision"),
        "simulation_state": "SIM_READY",
        "policy_hash": _hash("policy"),
        "tenant_hash": _hash("tenant"),
        "evidence_hash": _hash("evidence"),
        "hash_algorithm": "sha256",
        "hash_only": True,
        "redacted": True,
        "execution_allowed": False,
        "provider_execution": False,
        "production_activation": False,
    }
    payload.update(overrides)
    return payload


def _approval_metadata(**overrides):
    payload = {
        "component": "human_approval_reference",
        "schema_version": "phase-c.human-approval-reference.v1",
        "output_version": "phase-c.human-approval-reference-output.v1",
        "approval_reference": "approval-ref-runtime-001",
        "approval_hash": _hash("approval"),
        "approval_status": "APPROVED",
        "approver_role_hash": _hash("approver-role"),
        "scope_hash": _hash("approval-scope"),
        "tenant_hash": _hash("tenant"),
        "policy_hash": _hash("policy"),
        "evidence_hash": _hash("evidence"),
        "simulator_decision_hash": _hash("simulator-decision"),
        "issued_at": "2026-07-18T09:55:00Z",
        "expires_at": "2026-07-18T10:30:00Z",
        "hash_algorithm": "sha256",
    }
    payload.update(overrides)
    return payload


def _request(approval_metadata=None, simulator_metadata=None, **overrides):
    payload = {
        "gateway_id": "approval-gateway-runtime-001",
        "policy_hash": _hash("policy"),
        "tenant_hash": _hash("tenant"),
        "evidence_hash": _hash("evidence"),
        "simulator_decision_hash": _hash("simulator-decision"),
        "approval_reference": "approval-ref-runtime-001",
        "approval_hash": _hash("approval"),
        "approver_role_hash": _hash("approver-role"),
        "scope_hash": _hash("approval-scope"),
        "as_of": "2026-07-18T10:00:00Z",
        "schema_version": "phase-c.human-approval-gateway.v1",
        "output_version": "phase-c.human-approval-gateway-output.v1",
        "hash_algorithm": "sha256",
        "simulator_metadata": simulator_metadata if simulator_metadata is not None else _simulator_metadata(),
        "approval_metadata": approval_metadata if approval_metadata is not None else _approval_metadata(),
        "prior_approval_hashes": (),
        "execution_allowed": False,
        "provider_execution": False,
        "production_activation": False,
        "runtime_execution": False,
        "deployment_execution": False,
        "policy_mutation": False,
        "network_access": False,
        "hash_only": True,
        "redacted": True,
    }
    payload.update(overrides)
    return HumanApprovalGatewayRequest(**payload)


def test_valid_external_approval_metadata_is_deterministic_and_non_executing():
    first = validate_human_approval(_request())
    second = validate_human_approval(_request())

    assert first.approval_state == APPROVAL_VALID
    assert first.denial_code is None
    assert first.as_dict() == second.as_dict()
    assert HASH_RE.match(first.approval_gateway_hash)
    assert first.execution_allowed is False
    assert first.provider_execution is False
    assert first.production_activation is False
    assert first.runtime_execution is False
    assert first.deployment_execution is False
    assert first.policy_mutation is False
    assert first.network_access is False


def test_missing_approval_reference_requires_approval():
    result = validate_human_approval(_request(approval_reference=""))

    assert result.approval_state == APPROVAL_REQUIRED
    assert MISSING_APPROVAL_REFERENCE in result.denial_reasons


def test_missing_approval_hash_requires_approval():
    approval = _approval_metadata(approval_hash="")
    result = validate_human_approval(_request(approval_metadata=approval, approval_hash=""))

    assert result.approval_state == APPROVAL_REQUIRED
    assert MISSING_APPROVAL_HASH in result.denial_reasons


def test_ungranted_approval_requires_approval():
    result = validate_human_approval(_request(approval_metadata=_approval_metadata(approval_status="PENDING")))

    assert result.approval_state == APPROVAL_REQUIRED
    assert APPROVAL_NOT_GRANTED in result.denial_reasons


def test_expired_approval_returns_expired_state():
    approval = _approval_metadata(expires_at="2026-07-18T09:59:59Z")

    result = validate_human_approval(_request(approval_metadata=approval))

    assert result.approval_state == APPROVAL_EXPIRED
    assert APPROVAL_EXPIRED_REASON in result.denial_reasons


def test_future_approval_timestamp_blocks_outside_tolerance():
    approval = _approval_metadata(issued_at="2026-07-18T10:10:01Z")

    result = validate_human_approval(_request(approval_metadata=approval))

    assert result.approval_state == APPROVAL_BLOCKED
    assert APPROVAL_TIMESTAMP_IN_FUTURE in result.denial_reasons


def test_wrong_role_and_scope_block():
    role = validate_human_approval(_request(approval_metadata=_approval_metadata(approver_role_hash=_hash("wrong-role"))))
    scope = validate_human_approval(_request(approval_metadata=_approval_metadata(scope_hash=_hash("wrong-scope"))))

    assert role.approval_state == APPROVAL_BLOCKED
    assert scope.approval_state == APPROVAL_BLOCKED
    assert WRONG_APPROVER_ROLE in role.denial_reasons
    assert WRONG_APPROVAL_SCOPE in scope.denial_reasons


def test_tenant_policy_and_evidence_mismatch_block():
    tenant = validate_human_approval(_request(approval_metadata=_approval_metadata(tenant_hash=_hash("other-tenant"))))
    policy = validate_human_approval(_request(approval_metadata=_approval_metadata(policy_hash=_hash("other-policy"))))
    evidence = validate_human_approval(_request(approval_metadata=_approval_metadata(evidence_hash=_hash("other-evidence"))))

    assert TENANT_MISMATCH in tenant.denial_reasons
    assert POLICY_MISMATCH in policy.denial_reasons
    assert EVIDENCE_MISMATCH in evidence.denial_reasons
    assert tenant.approval_state == APPROVAL_BLOCKED


def test_simulator_hash_mismatch_blocks():
    approval = _approval_metadata(simulator_decision_hash=_hash("different-simulator"))

    result = validate_human_approval(_request(approval_metadata=approval))

    assert result.approval_state == APPROVAL_BLOCKED
    assert SIMULATOR_HASH_MISMATCH in result.denial_reasons


def test_duplicate_or_replayed_approval_blocks():
    result = validate_human_approval(_request(prior_approval_hashes=(_hash("approval"),)))

    assert result.approval_state == APPROVAL_BLOCKED
    assert DUPLICATE_APPROVAL_REFERENCE in result.denial_reasons
    assert REPLAYED_APPROVAL_REFERENCE in result.denial_reasons


def test_malformed_payload_fails_closed():
    result = validate_human_approval(object())

    assert result.approval_state == APPROVAL_FAILED_CLOSED
    assert MALFORMED_METADATA in result.denial_reasons


def test_raw_approval_content_fails_closed():
    approval = _approval_metadata(comment="looks fine")

    result = validate_human_approval(_request(approval_metadata=approval))

    assert result.approval_state == APPROVAL_FAILED_CLOSED
    assert RAW_APPROVAL_CONTENT in result.denial_reasons


def test_unknown_metadata_blocks():
    payload = _request().as_dict()
    payload["unexpected"] = "value"

    result = validate_human_approval(payload)

    assert result.approval_state == APPROVAL_BLOCKED
    assert UNKNOWN_METADATA in result.denial_reasons


def test_unknown_component_blocks():
    approval = _approval_metadata(component="runtime_auto_approval")

    result = validate_human_approval(_request(approval_metadata=approval))

    assert result.approval_state == APPROVAL_BLOCKED
    assert UNKNOWN_COMPONENT in result.denial_reasons


def test_unsupported_schema_version_and_hash_algorithm_block():
    schema = validate_human_approval(_request(schema_version="phase-c.gateway.v2"))
    version = validate_human_approval(_request(output_version="phase-c.output.v2"))
    algorithm = validate_human_approval(_request(hash_algorithm="sha512"))

    assert UNSUPPORTED_SCHEMA in schema.denial_reasons
    assert UNSUPPORTED_VERSION in version.denial_reasons
    assert UNSUPPORTED_HASH_ALGORITHM in algorithm.denial_reasons
    assert schema.approval_state == APPROVAL_BLOCKED


def test_malformed_hashes_block():
    result = validate_human_approval(_request(policy_hash="not-a-hash"))

    assert result.approval_state == APPROVAL_BLOCKED
    assert INVALID_HASH in result.denial_reasons


def test_missing_or_invalid_simulator_metadata_blocks():
    missing = validate_human_approval(_request(simulator_metadata={}))
    missing_hash = validate_human_approval(_request(simulator_metadata=_simulator_metadata(simulation_hash="")))
    mismatch = validate_human_approval(_request(simulator_metadata=_simulator_metadata(simulation_hash=_hash("other-sim"))))

    assert missing.approval_state == APPROVAL_BLOCKED
    assert missing_hash.approval_state == APPROVAL_BLOCKED
    assert mismatch.approval_state == APPROVAL_BLOCKED
    assert MISSING_SIMULATOR_HASH in missing_hash.denial_reasons
    assert SIMULATOR_HASH_MISMATCH in mismatch.denial_reasons


def test_execution_flags_always_block_and_output_false():
    cases = (
        ({"execution_allowed": True}, EXECUTION_FLAG_ENABLED),
        ({"provider_execution": True}, PROVIDER_EXECUTION_ENABLED),
        ({"production_activation": True}, PRODUCTION_ACTIVATION_ENABLED),
        ({"runtime_execution": True}, RUNTIME_EXECUTION_ENABLED),
        ({"deployment_execution": True}, DEPLOYMENT_EXECUTION_ENABLED),
        ({"policy_mutation": True}, POLICY_MUTATION_ENABLED),
        ({"network_access": True}, NETWORK_ACCESS_ENABLED),
    )
    for override, reason in cases:
        result = validate_human_approval(_request(**override))
        assert result.approval_state == APPROVAL_BLOCKED
        assert reason in result.denial_reasons
        assert result.execution_allowed is False
        assert result.provider_execution is False
        assert result.production_activation is False
        assert result.runtime_execution is False
        assert result.deployment_execution is False
        assert result.policy_mutation is False
        assert result.network_access is False


def test_unredacted_simulator_metadata_blocks():
    result = validate_human_approval(_request(simulator_metadata=_simulator_metadata(redacted=False)))

    assert result.approval_state == APPROVAL_BLOCKED
    assert UNREDACTED_EVIDENCE in result.denial_reasons


def test_evidence_fixture_is_hash_only_redacted_and_non_executing():
    evidence = json.loads(EVIDENCE.read_text(encoding="utf-8"))

    assert evidence["component"] == "human_approval_gateway"
    assert evidence["hash_only"] is True
    assert evidence["redacted"] is True
    for flag in (
        "execution_allowed",
        "provider_execution",
        "production_activation",
        "runtime_execution",
        "deployment_execution",
        "policy_mutation",
        "network_access",
    ):
        assert evidence[flag] is False
    assert HASH_RE.match(evidence["sample_approval_gateway_hash"])
    assert "raw_payload" not in json.dumps(evidence).lower()
    assert "email" not in json.dumps(evidence).lower()


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
