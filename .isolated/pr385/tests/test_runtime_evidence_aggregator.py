import json
import re
from pathlib import Path

from governance.runtime import runtime_evidence_aggregator as aggregator
from governance.runtime.runtime_evidence_aggregator import (
    AGGREGATION_FAILED_CLOSED,
    COMPONENT_ORDER,
    DUPLICATE_COMPONENT,
    EVIDENCE_AGGREGATED,
    EVIDENCE_BLOCKED,
    EXECUTION_FLAG_ENABLED,
    INVALID_FIELD_TYPE,
    INVALID_HASH,
    NON_HASH_ONLY_EVIDENCE,
    POLICY_HASH_MISMATCH,
    PRODUCTION_ACTIVATION_ENABLED,
    PROVIDER_EXECUTION_ENABLED,
    RAW_PAYLOAD_PRESENT,
    RUNTIME_METADATA_MISMATCH,
    SENSITIVE_DATA_PRESENT,
    TENANT_HASH_MISMATCH,
    TIMESTAMP_INVALID,
    TIMESTAMP_ORDER_INVALID,
    UNKNOWN_COMPONENT,
    UNREDACTED_EVIDENCE,
    UNSUPPORTED_EVIDENCE_VERSION,
    UNSUPPORTED_HASH_ALGORITHM,
    UNSUPPORTED_SCHEMA_VERSION,
    MISSING_COMPONENT_EVIDENCE,
    MISSING_REQUIRED_FIELD,
    RuntimeEvidenceReference,
    aggregate_runtime_evidence,
)


EVIDENCE = Path(__file__).resolve().parents[1] / "governance" / "evidence" / "runtime_evidence_aggregator.json"
SOURCE = Path(aggregator.__file__)
HASH_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
TIMESTAMPS = {
    "agent_runtime": "2026-07-13T10:00:00Z",
    "runtime_coordinator": "2026-07-13T10:01:00Z",
    "event_bus": "2026-07-13T10:02:00Z",
    "runtime_health": "2026-07-13T10:03:00Z",
    "execution_scheduler": "2026-07-13T10:04:00Z",
}


def _hash(label):
    import hashlib

    return "sha256:" + hashlib.sha256(label.encode("utf-8")).hexdigest()


def _references(**overrides):
    references = []
    for component in COMPONENT_ORDER:
        payload = {
            "component": component,
            "evidence_hash": _hash(f"evidence:{component}"),
            "policy_hash": _hash("policy"),
            "tenant_hash": _hash("tenant"),
            "decision_hash": _hash(f"decision:{component}"),
            "timestamp": TIMESTAMPS[component],
            "schema_version": "phase-b.runtime-evidence-aggregator.v1",
            "evidence_version": "phase-b.runtime-evidence.v1",
            "hash_algorithm": "sha256",
            "redacted": True,
            "hash_only": True,
            "execution_allowed": False,
            "provider_execution": False,
            "production_activation": False,
        }
        payload.update(overrides.get(component, {}))
        references.append(RuntimeEvidenceReference(**payload))
    return references


def _dict_references(**overrides):
    return [reference.as_dict() for reference in _references(**overrides)]


def test_valid_aggregation_of_all_five_required_components():
    result = aggregate_runtime_evidence(_references())

    assert result.status == EVIDENCE_AGGREGATED
    assert result.denial_code is None
    assert result.component_order == COMPONENT_ORDER
    assert result.component_count == 5
    assert HASH_RE.match(result.aggregate_decision_hash)
    assert HASH_RE.match(result.aggregate_evidence_hash)
    assert result.hash_only is True
    assert result.redacted is True
    assert result.execution_allowed is False
    assert result.provider_execution is False
    assert result.production_activation is False


def test_identical_input_produces_identical_hashes():
    first = aggregate_runtime_evidence(_references())
    second = aggregate_runtime_evidence(_references())

    assert first.as_dict() == second.as_dict()


def test_input_dictionary_order_does_not_change_result():
    forward = aggregate_runtime_evidence(_dict_references())
    reverse = aggregate_runtime_evidence(tuple(reversed(_dict_references())))

    assert forward.as_dict() == reverse.as_dict()


def test_missing_component_denial():
    result = aggregate_runtime_evidence(_references()[:-1])

    assert result.status == EVIDENCE_BLOCKED
    assert MISSING_COMPONENT_EVIDENCE in result.denial_reasons


def test_unknown_component_denial():
    refs = _dict_references()
    refs[0]["component"] = "gateway"

    result = aggregate_runtime_evidence(refs)

    assert result.status == EVIDENCE_BLOCKED
    assert UNKNOWN_COMPONENT in result.denial_reasons


def test_duplicate_component_denial():
    refs = _dict_references()
    refs.append(dict(refs[0]))

    result = aggregate_runtime_evidence(refs)

    assert result.status == EVIDENCE_BLOCKED
    assert DUPLICATE_COMPONENT in result.denial_reasons


def test_missing_required_field_denial():
    refs = _dict_references()
    refs[0].pop("policy_hash")

    result = aggregate_runtime_evidence(refs)

    assert result.status == EVIDENCE_BLOCKED
    assert MISSING_REQUIRED_FIELD in result.denial_reasons


def test_invalid_field_type_denial():
    result = aggregate_runtime_evidence(_dict_references(agent_runtime={"redacted": "true"}))

    assert result.status == EVIDENCE_BLOCKED
    assert INVALID_FIELD_TYPE in result.denial_reasons


def test_malformed_hash_denial():
    result = aggregate_runtime_evidence(_dict_references(agent_runtime={"evidence_hash": "sha256:not-valid"}))

    assert result.status == EVIDENCE_BLOCKED
    assert INVALID_HASH in result.denial_reasons


def test_unsupported_hash_algorithm_denial():
    result = aggregate_runtime_evidence(_dict_references(agent_runtime={"hash_algorithm": "sha512"}))

    assert result.status == EVIDENCE_BLOCKED
    assert UNSUPPORTED_HASH_ALGORITHM in result.denial_reasons


def test_unsupported_schema_version_denial():
    result = aggregate_runtime_evidence(_dict_references(agent_runtime={"schema_version": "v0"}))

    assert result.status == EVIDENCE_BLOCKED
    assert UNSUPPORTED_SCHEMA_VERSION in result.denial_reasons


def test_unsupported_evidence_version_denial():
    result = aggregate_runtime_evidence(_dict_references(agent_runtime={"evidence_version": "v0"}))

    assert result.status == EVIDENCE_BLOCKED
    assert UNSUPPORTED_EVIDENCE_VERSION in result.denial_reasons


def test_policy_hash_mismatch_denial():
    result = aggregate_runtime_evidence(_dict_references(agent_runtime={"policy_hash": _hash("other-policy")}))

    assert result.status == EVIDENCE_BLOCKED
    assert POLICY_HASH_MISMATCH in result.denial_reasons
    assert RUNTIME_METADATA_MISMATCH in result.denial_reasons


def test_tenant_hash_mismatch_denial():
    result = aggregate_runtime_evidence(_dict_references(agent_runtime={"tenant_hash": _hash("other-tenant")}))

    assert result.status == EVIDENCE_BLOCKED
    assert TENANT_HASH_MISMATCH in result.denial_reasons
    assert RUNTIME_METADATA_MISMATCH in result.denial_reasons


def test_invalid_timestamp_denial():
    result = aggregate_runtime_evidence(_dict_references(agent_runtime={"timestamp": "13-07-2026"}))

    assert result.status == EVIDENCE_BLOCKED
    assert TIMESTAMP_INVALID in result.denial_reasons


def test_timestamp_chronology_violation_denial():
    result = aggregate_runtime_evidence(_dict_references(agent_runtime={"timestamp": "2026-07-13T10:09:00Z"}))

    assert result.status == EVIDENCE_BLOCKED
    assert TIMESTAMP_ORDER_INVALID in result.denial_reasons


def test_non_hash_only_evidence_denial():
    result = aggregate_runtime_evidence(_dict_references(agent_runtime={"hash_only": False}))

    assert result.status == EVIDENCE_BLOCKED
    assert NON_HASH_ONLY_EVIDENCE in result.denial_reasons


def test_unredacted_evidence_denial():
    result = aggregate_runtime_evidence(_dict_references(agent_runtime={"redacted": False}))

    assert result.status == EVIDENCE_BLOCKED
    assert UNREDACTED_EVIDENCE in result.denial_reasons


def test_execution_allowed_true_denial():
    result = aggregate_runtime_evidence(_dict_references(agent_runtime={"execution_allowed": True}))

    assert result.status == EVIDENCE_BLOCKED
    assert EXECUTION_FLAG_ENABLED in result.denial_reasons
    assert result.execution_allowed is False


def test_provider_execution_true_denial():
    result = aggregate_runtime_evidence(_dict_references(agent_runtime={"provider_execution": True}))

    assert result.status == EVIDENCE_BLOCKED
    assert PROVIDER_EXECUTION_ENABLED in result.denial_reasons
    assert result.provider_execution is False


def test_production_activation_true_denial():
    result = aggregate_runtime_evidence(_dict_references(agent_runtime={"production_activation": True}))

    assert result.status == EVIDENCE_BLOCKED
    assert PRODUCTION_ACTIVATION_ENABLED in result.denial_reasons
    assert result.production_activation is False


def test_raw_payload_denial():
    refs = _dict_references()
    refs[0]["raw_payload"] = {"value": "forbidden"}

    result = aggregate_runtime_evidence(refs)

    assert result.status == EVIDENCE_BLOCKED
    assert RAW_PAYLOAD_PRESENT in result.denial_reasons


def test_credential_or_sensitive_data_field_denial():
    refs = _dict_references()
    refs[0]["token"] = "forbidden"

    result = aggregate_runtime_evidence(refs)

    assert result.status == EVIDENCE_BLOCKED
    assert SENSITIVE_DATA_PRESENT in result.denial_reasons


def test_no_execution_capable_imports_or_behavior():
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


def test_aggregate_output_remains_metadata_only():
    result = aggregate_runtime_evidence(_references())
    rendered = json.dumps(result.as_dict(), sort_keys=True)

    for raw_value in ("tenant-runtime", "policy-body", "decision:agent_runtime", "evidence:agent_runtime"):
        assert raw_value not in rendered
    for value in result.component_evidence_hashes.values():
        assert HASH_RE.match(value)


def test_every_denial_produces_fixed_denial_code():
    result = aggregate_runtime_evidence(())

    assert result.status == EVIDENCE_BLOCKED
    assert result.denial_code in aggregator.DENIAL_CODES
    assert result.denial_code != AGGREGATION_FAILED_CLOSED


def test_no_failed_case_returns_evidence_aggregated():
    failures = [
        aggregate_runtime_evidence(()),
        aggregate_runtime_evidence(_dict_references(agent_runtime={"hash_only": False})),
        aggregate_runtime_evidence(_dict_references(agent_runtime={"execution_allowed": True})),
    ]

    assert all(result.status != EVIDENCE_AGGREGATED for result in failures)


def test_component_allow_list_is_exact_against_near_matches():
    variants = (
        "Agent_Runtime",
        "agent_runtime ",
        " agent_runtime",
        "agent_runtime_v2",
        "xagent_runtime",
        "agent",
        "agent-runtime",
        "agent_runtime\u200b",
    )

    for variant in variants:
        refs = _dict_references()
        refs[0]["component"] = variant
        result = aggregate_runtime_evidence(refs)
        assert result.status == EVIDENCE_BLOCKED
        assert UNKNOWN_COMPONENT in result.denial_reasons


def test_evidence_fixture_is_hash_only_and_redacted():
    evidence = json.loads(EVIDENCE.read_text(encoding="utf-8"))
    rendered = json.dumps(evidence, sort_keys=True)

    assert tuple(evidence["component_allow_list"]) == COMPONENT_ORDER
    assert evidence["hash_algorithm"] == "sha256"
    assert evidence["hash_only"] is True
    assert evidence["redacted"] is True
    assert evidence["execution_allowed"] is False
    assert evidence["provider_execution"] is False
    assert evidence["production_activation"] is False
    assert HASH_RE.match(evidence["sample_aggregate_evidence_hash"])
    assert set(aggregator.DENIAL_CODES).issubset(set(evidence["denial_codes"]))
    for forbidden in ("credential_value", "provider_value", "secret_value", "token_value", "customer_email"):
        assert forbidden not in rendered
