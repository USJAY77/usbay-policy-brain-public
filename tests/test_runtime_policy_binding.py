import hashlib
import json
import re
from pathlib import Path

from governance.runtime import runtime_policy_binding as binding
from governance.runtime.runtime_policy_binding import (
    COMPONENT_ORDER,
    DECISION_CONTINUITY_MISMATCH,
    DUPLICATE_EVIDENCE,
    EVIDENCE_HASH_MISMATCH,
    EXECUTION_FLAG_ENABLED,
    GENESIS_DECISION_HASH,
    INVALID_HASH,
    MISSING_DEPENDENCY,
    MISSING_HASH,
    NON_HASH_ONLY_EVIDENCE,
    POLICY_BLOCKED,
    POLICY_BOUND,
    POLICY_HASH_MISMATCH,
    PRODUCTION_ACTIVATION_ENABLED,
    PROVIDER_EXECUTION_ENABLED,
    RAW_PAYLOAD_PRESENT,
    RUNTIME_VERSION_MISMATCH,
    SENSITIVE_DATA_PRESENT,
    TENANT_HASH_MISMATCH,
    UNKNOWN_COMPONENT,
    UNKNOWN_SCHEMA,
    UNREDACTED_EVIDENCE,
    RuntimePolicyBindingRequest,
    RuntimePolicyEvidenceReference,
    bind_runtime_policy,
)


EVIDENCE = Path(__file__).resolve().parents[1] / "governance" / "evidence" / "runtime_policy_binding.json"
SOURCE = Path(binding.__file__)
HASH_RE = re.compile(r"^sha256:[0-9a-f]{64}$")


def _hash(label):
    return "sha256:" + hashlib.sha256(label.encode("utf-8")).hexdigest()


def _references(**overrides):
    references = []
    previous = GENESIS_DECISION_HASH
    for component in COMPONENT_ORDER:
        decision_hash = _hash(f"decision:{component}")
        payload = {
            "component": component,
            "evidence_hash": _hash(f"evidence:{component}"),
            "policy_hash": _hash("policy"),
            "tenant_hash": _hash("tenant"),
            "decision_hash": decision_hash,
            "previous_decision_hash": previous,
            "schema_version": "phase-b.runtime-policy-binding.v1",
            "runtime_version": "phase-b.runtime.v1",
            "hash_algorithm": "sha256",
            "hash_only": True,
            "redacted": True,
            "execution_allowed": False,
            "provider_execution": False,
            "production_activation": False,
        }
        payload.update(overrides.get(component, {}))
        references.append(RuntimePolicyEvidenceReference(**payload))
        previous = decision_hash
    return references


def _dict_references(**overrides):
    return [reference.as_dict() for reference in _references(**overrides)]


def _request(references=None, **overrides):
    payload = {
        "policy_hash": _hash("policy"),
        "tenant_hash": _hash("tenant"),
        "evidence_hash": _hash("evidence:runtime_evidence_aggregator"),
        "runtime_version": "phase-b.runtime.v1",
        "references": references if references is not None else _references(),
    }
    payload.update(overrides)
    return RuntimePolicyBindingRequest(**payload)


def test_valid_policy_binding_is_deterministic_metadata_only():
    first = bind_runtime_policy(_request())
    second = bind_runtime_policy(_request())

    assert first.status == POLICY_BOUND
    assert first.denial_code is None
    assert first.as_dict() == second.as_dict()
    assert HASH_RE.match(first.binding_hash)
    assert HASH_RE.match(first.decision_chain_hash)
    assert first.component_order == COMPONENT_ORDER
    assert first.hash_only is True
    assert first.redacted is True
    assert first.execution_allowed is False
    assert first.provider_execution is False
    assert first.production_activation is False


def test_input_order_does_not_change_binding_hash():
    forward = bind_runtime_policy(_request(references=_dict_references()))
    reverse = bind_runtime_policy(_request(references=tuple(reversed(_dict_references()))))

    assert forward.as_dict() == reverse.as_dict()


def test_missing_dependency_blocks():
    result = bind_runtime_policy(_request(references=_references()[:-1]))

    assert result.status == POLICY_BLOCKED
    assert MISSING_DEPENDENCY in result.denial_reasons


def test_unknown_component_blocks():
    refs = _dict_references()
    refs[0]["component"] = "gateway"

    result = bind_runtime_policy(_request(references=refs))

    assert result.status == POLICY_BLOCKED
    assert UNKNOWN_COMPONENT in result.denial_reasons


def test_duplicate_evidence_blocks():
    refs = _dict_references()
    refs.append(dict(refs[0]))

    result = bind_runtime_policy(_request(references=refs))

    assert result.status == POLICY_BLOCKED
    assert DUPLICATE_EVIDENCE in result.denial_reasons


def test_missing_hash_blocks():
    result = bind_runtime_policy(_request(policy_hash=""))

    assert result.status == POLICY_BLOCKED
    assert MISSING_HASH in result.denial_reasons


def test_invalid_hash_blocks():
    result = bind_runtime_policy(_request(references=_dict_references(agent_runtime={"evidence_hash": "sha256:not-valid"})))

    assert result.status == POLICY_BLOCKED
    assert INVALID_HASH in result.denial_reasons


def test_policy_hash_mismatch_blocks():
    result = bind_runtime_policy(_request(references=_dict_references(agent_runtime={"policy_hash": _hash("other-policy")})))

    assert result.status == POLICY_BLOCKED
    assert POLICY_HASH_MISMATCH in result.denial_reasons


def test_tenant_hash_mismatch_blocks():
    result = bind_runtime_policy(_request(references=_dict_references(agent_runtime={"tenant_hash": _hash("other-tenant")})))

    assert result.status == POLICY_BLOCKED
    assert TENANT_HASH_MISMATCH in result.denial_reasons


def test_evidence_hash_mismatch_blocks():
    result = bind_runtime_policy(_request(evidence_hash=_hash("different-aggregator-evidence")))

    assert result.status == POLICY_BLOCKED
    assert EVIDENCE_HASH_MISMATCH in result.denial_reasons


def test_decision_hash_continuity_mismatch_blocks():
    result = bind_runtime_policy(_request(references=_dict_references(runtime_coordinator={"previous_decision_hash": _hash("wrong-previous")})))

    assert result.status == POLICY_BLOCKED
    assert DECISION_CONTINUITY_MISMATCH in result.denial_reasons


def test_unknown_schema_blocks():
    result = bind_runtime_policy(_request(references=_dict_references(agent_runtime={"schema_version": "phase-b.unknown"})))

    assert result.status == POLICY_BLOCKED
    assert UNKNOWN_SCHEMA in result.denial_reasons


def test_runtime_version_mismatch_blocks():
    result = bind_runtime_policy(_request(references=_dict_references(agent_runtime={"runtime_version": "phase-b.runtime.v0"})))

    assert result.status == POLICY_BLOCKED
    assert RUNTIME_VERSION_MISMATCH in result.denial_reasons


def test_non_hash_only_and_unredacted_evidence_blocks():
    result = bind_runtime_policy(_request(references=_dict_references(agent_runtime={"hash_only": False, "redacted": False})))

    assert result.status == POLICY_BLOCKED
    assert NON_HASH_ONLY_EVIDENCE in result.denial_reasons
    assert UNREDACTED_EVIDENCE in result.denial_reasons


def test_execution_like_flags_block_and_remain_false():
    result = bind_runtime_policy(_request(references=_dict_references(
        agent_runtime={
            "execution_allowed": True,
            "provider_execution": True,
            "production_activation": True,
        },
    )))

    assert result.status == POLICY_BLOCKED
    assert EXECUTION_FLAG_ENABLED in result.denial_reasons
    assert PROVIDER_EXECUTION_ENABLED in result.denial_reasons
    assert PRODUCTION_ACTIVATION_ENABLED in result.denial_reasons
    assert result.execution_allowed is False
    assert result.provider_execution is False
    assert result.production_activation is False


def test_raw_payload_and_sensitive_fields_block():
    refs = _dict_references()
    refs[0]["raw_payload"] = {"value": "forbidden"}
    refs[1]["token"] = "forbidden"

    result = bind_runtime_policy(_request(references=refs))

    assert result.status == POLICY_BLOCKED
    assert RAW_PAYLOAD_PRESENT in result.denial_reasons
    assert SENSITIVE_DATA_PRESENT in result.denial_reasons


def test_near_match_component_names_block():
    for component in ("Agent_Runtime", "agent_runtime ", "xagent_runtime", "agent_runtime_v2"):
        refs = _dict_references()
        refs[0]["component"] = component
        result = bind_runtime_policy(_request(references=refs))
        assert result.status == POLICY_BLOCKED
        assert UNKNOWN_COMPONENT in result.denial_reasons


def test_no_execution_capable_imports_or_calls():
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


def test_output_is_redacted_hash_only():
    result = bind_runtime_policy(_request())
    rendered = json.dumps(result.as_dict(), sort_keys=True)

    for raw_value in ("tenant-runtime", "policy-body", "decision:agent_runtime", "evidence:agent_runtime"):
        assert raw_value not in rendered
    assert all(HASH_RE.match(value) for value in result.component_evidence_hashes.values())


def test_evidence_fixture_is_hash_only_and_redacted():
    evidence = json.loads(EVIDENCE.read_text(encoding="utf-8"))
    rendered = json.dumps(evidence, sort_keys=True)

    assert tuple(evidence["component_allow_list"]) == COMPONENT_ORDER
    assert evidence["hash_only"] is True
    assert evidence["redacted"] is True
    assert evidence["execution_allowed"] is False
    assert evidence["provider_execution"] is False
    assert evidence["production_activation"] is False
    assert HASH_RE.match(evidence["sample_binding_hash"])
    assert set(binding.DENIAL_CODES).issubset(set(evidence["denial_codes"]))
    for forbidden in ("credential_value", "provider_value", "secret_value", "token_value", "customer_email"):
        assert forbidden not in rendered
