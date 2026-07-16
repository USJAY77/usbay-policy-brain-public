import hashlib
import json
import re
from pathlib import Path

from governance.runtime import runtime_replay_verifier as verifier
from governance.runtime.runtime_replay_verifier import (
    APPROVAL_MISMATCH,
    CHAIN_BROKEN,
    CHRONOLOGY_INVALID,
    COMPONENT_ORDER,
    DUPLICATE_EVIDENCE,
    DUPLICATE_REPLAY_ID,
    EVIDENCE_MISMATCH,
    EVIDENCE_VERSION_UNSUPPORTED,
    EXECUTION_FLAG_ENABLED,
    HASH_ALGORITHM_UNSUPPORTED,
    INVALID_HASH,
    NON_HASH_ONLY_EVIDENCE,
    NON_REDACTED_EVIDENCE,
    OMITTED_EVIDENCE,
    POLICY_MISMATCH,
    PRODUCTION_ACTIVATION_ENABLED,
    PROVIDER_EXECUTION_ENABLED,
    RAW_OR_SENSITIVE_DATA_PRESENT,
    REORDERED_EVIDENCE,
    REPLAY_DUPLICATE,
    REPLAY_HASH_MISMATCH,
    REPLAY_ID_REUSE_MISMATCH,
    REPLAY_MALFORMED,
    REPLAY_TENANT_MISMATCH,
    REPLAY_UNKNOWN_INPUT,
    REPLAY_VERIFIED,
    SCHEMA_VERSION_UNSUPPORTED,
    STALE_APPROVAL,
    TENANT_MISMATCH,
    TIMESTAMP_INVALID,
    UNKNOWN_METADATA,
    UNKNOWN_OUTCOME,
    RuntimeReplayRequest,
    reconstruct_replay_hash,
    verify_runtime_replay,
)


EVIDENCE = Path(__file__).resolve().parents[1] / "governance" / "evidence" / "runtime_replay_verifier.json"
SOURCE = Path(verifier.__file__)
HASH_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
TIMESTAMPS = {
    "agent_runtime": "2026-07-15T08:00:00Z",
    "runtime_coordinator": "2026-07-15T08:01:00Z",
    "event_bus": "2026-07-15T08:02:00Z",
    "runtime_health": "2026-07-15T08:03:00Z",
    "execution_scheduler": "2026-07-15T08:04:00Z",
    "runtime_evidence_aggregator": "2026-07-15T08:05:00Z",
    "runtime_policy_binding": "2026-07-15T08:06:00Z",
    "runtime_approval_gate": "2026-07-15T08:09:00Z",
}


def _hash(label):
    return "sha256:" + hashlib.sha256(label.encode("utf-8")).hexdigest()


def _components(**overrides):
    previous = _hash("previous-root")
    references = []
    for component in COMPONENT_ORDER:
        decision_hash = _hash(f"decision:{component}")
        payload = {
            "component": component,
            "policy_hash": _hash("policy"),
            "tenant_hash": _hash("tenant"),
            "evidence_hash": _hash("evidence") if component == "runtime_evidence_aggregator" else _hash(f"evidence:{component}"),
            "approval_hash": _hash("approval"),
            "decision_hash": decision_hash,
            "previous_decision_hash": previous,
            "schema_version": "phase-b.runtime-replay-verifier.v1",
            "evidence_version": "phase-b.runtime-replay.v1",
            "hash_algorithm": "sha256",
            "timestamp": TIMESTAMPS[component],
            "redacted": True,
            "hash_only": True,
            "execution_allowed": False,
            "provider_execution": False,
            "production_activation": False,
        }
        payload.update(overrides.get(component, {}))
        references.append(payload)
        previous = decision_hash
    return references


def _request_payload(**overrides):
    components = overrides.pop("component_references", _components())
    previous_decision_hash = _hash("previous-root")
    expected_outcome = overrides.get("expected_outcome", REPLAY_VERIFIED)
    decision_hash = verifier._canonical_hash({
        "policy_hash": overrides.get("policy_hash", _hash("policy")),
        "tenant_hash": overrides.get("tenant_hash", _hash("tenant")),
        "evidence_hash": overrides.get("evidence_hash", _hash("evidence")),
        "approval_hash": overrides.get("approval_hash", _hash("approval")),
        "previous_decision_hash": previous_decision_hash,
        "component_decisions": tuple(item["decision_hash"] for item in components),
        "expected_outcome": expected_outcome,
    })
    components = [dict(item) for item in components]
    payload = {
        "replay_id": "replay-runtime-001",
        "original_decision_id": "decision-original-001",
        "actor": "codex",
        "action": "runtime_replay_verify",
        "policy_hash": _hash("policy"),
        "tenant_hash": _hash("tenant"),
        "evidence_hash": _hash("evidence"),
        "approval_hash": _hash("approval"),
        "decision_hash": decision_hash,
        "previous_decision_hash": previous_decision_hash,
        "timestamp": "2026-07-15T08:10:00Z",
        "original_timestamp": "2026-07-15T08:00:00Z",
        "schema_version": "phase-b.runtime-replay-verifier.v1",
        "evidence_version": "phase-b.runtime-replay.v1",
        "hash_algorithm": "sha256",
        "expected_outcome": expected_outcome,
        "execution_allowed": False,
        "provider_execution": False,
        "production_activation": False,
        "redacted": True,
        "hash_only": True,
        "component_references": components,
        "recorded_replay_hash": _hash("placeholder"),
    }
    payload.update(overrides)
    payload["recorded_replay_hash"] = reconstruct_replay_hash(payload, {item["component"]: item for item in components})
    return payload


def _request(**overrides):
    return RuntimeReplayRequest(**_request_payload(**overrides))


def test_valid_deterministic_replay():
    result = verify_runtime_replay(_request())

    assert result.status == REPLAY_VERIFIED
    assert result.denial_code is None
    assert HASH_RE.match(result.replay_hash)
    assert result.execution_allowed is False
    assert result.provider_execution is False
    assert result.production_activation is False
    assert result.redacted is True
    assert result.hash_only is True


def test_same_input_produces_same_replay_result():
    first = verify_runtime_replay(_request())
    second = verify_runtime_replay(_request())

    assert first.as_dict() == second.as_dict()


def test_valid_denial_replay():
    payload = _request_payload(expected_outcome=verifier.REPLAY_DENIED)
    result = verify_runtime_replay(payload)

    assert result.status == verifier.REPLAY_DENIED
    assert result.denial_reasons == ()


def test_unknown_field_fails_closed():
    payload = _request_payload()
    payload["unknown"] = "x"

    result = verify_runtime_replay(payload)

    assert UNKNOWN_METADATA in result.denial_reasons


def test_missing_field_fails_closed():
    payload = _request_payload()
    payload.pop("policy_hash")

    result = verify_runtime_replay(payload)

    assert verifier.MISSING_METADATA in result.denial_reasons


def test_malformed_field_fails_closed():
    payload = _request_payload(actor=object())

    result = verify_runtime_replay(payload)

    assert REPLAY_MALFORMED in result.denial_reasons


def test_duplicate_replay_id_fails_closed():
    payload = _request_payload()

    result = verify_runtime_replay(payload, prior_replays=(payload,))

    assert DUPLICATE_REPLAY_ID in result.denial_reasons


def test_replay_id_reuse_with_altered_metadata_fails_closed():
    payload = _request_payload()
    prior = dict(payload)
    prior["actor"] = "other"

    result = verify_runtime_replay(payload, prior_replays=(prior,))

    assert REPLAY_ID_REUSE_MISMATCH in result.denial_reasons


def test_invalid_and_uppercase_hash_fail_closed():
    bad = verify_runtime_replay(_request_payload(policy_hash="sha256:not-valid"))
    upper = verify_runtime_replay(_request_payload(policy_hash=_hash("policy").upper()))

    assert INVALID_HASH in bad.denial_reasons
    assert INVALID_HASH in upper.denial_reasons


def test_policy_tenant_evidence_approval_mismatches_fail_closed():
    policy = verify_runtime_replay(_request_payload(component_references=_components(agent_runtime={"policy_hash": _hash("other-policy")})))
    tenant = verify_runtime_replay(_request_payload(component_references=_components(agent_runtime={"tenant_hash": _hash("other-tenant")})))
    evidence = verify_runtime_replay(_request_payload(evidence_hash=_hash("other-evidence")))
    approval = verify_runtime_replay(_request_payload(component_references=_components(agent_runtime={"approval_hash": _hash("other-approval")})))

    assert POLICY_MISMATCH in policy.denial_reasons
    assert TENANT_MISMATCH in tenant.denial_reasons
    assert EVIDENCE_MISMATCH in evidence.denial_reasons
    assert APPROVAL_MISMATCH in approval.denial_reasons


def test_decision_and_previous_chain_mismatch_fail_closed():
    decision = verify_runtime_replay(_request_payload(decision_hash=_hash("wrong-decision")))
    chain = verify_runtime_replay(_request_payload(component_references=_components(runtime_coordinator={"previous_decision_hash": _hash("wrong-previous")})))

    assert verifier.DECISION_MISMATCH in decision.denial_reasons
    assert CHAIN_BROKEN in chain.denial_reasons


def test_reordered_missing_and_duplicate_evidence_fail_closed():
    reordered_components = tuple(reversed(_components()))
    missing_components = _components()[:-1]
    duplicate_components = _components() + [_components()[0]]

    reordered = verify_runtime_replay(_request_payload(component_references=reordered_components))
    missing = verify_runtime_replay(_request_payload(component_references=missing_components))
    duplicate = verify_runtime_replay(_request_payload(component_references=duplicate_components))

    assert REORDERED_EVIDENCE in reordered.denial_reasons
    assert OMITTED_EVIDENCE in missing.denial_reasons
    assert DUPLICATE_EVIDENCE in duplicate.denial_reasons


def test_cross_tenant_and_cross_policy_fail_closed():
    cross_tenant = verify_runtime_replay(_request_payload(component_references=_components(runtime_health={"tenant_hash": _hash("tenant-b")})))
    cross_policy = verify_runtime_replay(_request_payload(component_references=_components(runtime_health={"policy_hash": _hash("policy-b")})))

    assert TENANT_MISMATCH in cross_tenant.denial_reasons
    assert POLICY_MISMATCH in cross_policy.denial_reasons


def test_stale_approval_fails_closed():
    result = verify_runtime_replay(_request_payload(component_references=_components(runtime_approval_gate={"timestamp": "2026-07-15T07:59:30Z"})))

    assert STALE_APPROVAL in result.denial_reasons


def test_invalid_timestamp_and_chronology_fail_closed():
    invalid = verify_runtime_replay(_request_payload(timestamp="2026-07-15 08:10:00"))
    chronology = verify_runtime_replay(_request_payload(timestamp="2026-07-15T07:59:00Z"))

    assert TIMESTAMP_INVALID in invalid.denial_reasons
    assert CHRONOLOGY_INVALID in chronology.denial_reasons


def test_unsupported_schema_evidence_version_and_algorithm_fail_closed():
    schema = verify_runtime_replay(_request_payload(schema_version="phase-b.unknown"))
    evidence = verify_runtime_replay(_request_payload(evidence_version="phase-b.unknown"))
    algorithm = verify_runtime_replay(_request_payload(hash_algorithm="sha512"))

    assert SCHEMA_VERSION_UNSUPPORTED in schema.denial_reasons
    assert EVIDENCE_VERSION_UNSUPPORTED in evidence.denial_reasons
    assert HASH_ALGORITHM_UNSUPPORTED in algorithm.denial_reasons


def test_non_redacted_and_non_hash_only_evidence_fail_closed():
    redacted = verify_runtime_replay(_request_payload(redacted=False))
    hash_only = verify_runtime_replay(_request_payload(hash_only=False))

    assert NON_REDACTED_EVIDENCE in redacted.denial_reasons
    assert NON_HASH_ONLY_EVIDENCE in hash_only.denial_reasons


def test_execution_like_flags_fail_closed():
    execution = verify_runtime_replay(_request_payload(execution_allowed=True))
    provider = verify_runtime_replay(_request_payload(provider_execution=True))
    production = verify_runtime_replay(_request_payload(production_activation=True))

    assert verifier.EXECUTION_FLAG_ENABLED in execution.denial_reasons
    assert verifier.PROVIDER_EXECUTION_ENABLED in provider.denial_reasons
    assert verifier.PRODUCTION_ACTIVATION_ENABLED in production.denial_reasons
    assert execution.execution_allowed is False
    assert provider.provider_execution is False
    assert production.production_activation is False


def test_unknown_and_near_match_outcome_fail_closed():
    unknown = verify_runtime_replay(_request_payload(expected_outcome="REPLAY_ALLOW"))
    near = verify_runtime_replay(_request_payload(expected_outcome="replay_verified"))

    assert UNKNOWN_OUTCOME in unknown.denial_reasons
    assert UNKNOWN_OUTCOME in near.denial_reasons


def test_hash_mismatch_detects_tampering():
    payload = _request_payload()
    payload["recorded_replay_hash"] = _hash("tampered")

    result = verify_runtime_replay(payload)

    assert REPLAY_HASH_MISMATCH in result.denial_reasons


def test_sensitive_data_fails_closed():
    payload = _request_payload()
    payload["component_references"][0]["raw_payload"] = "forbidden"

    result = verify_runtime_replay(payload)

    assert RAW_OR_SENSITIVE_DATA_PRESENT in result.denial_reasons


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


def test_evidence_contains_no_secrets_or_sensitive_data():
    evidence = json.loads(EVIDENCE.read_text(encoding="utf-8"))
    rendered = json.dumps(evidence, sort_keys=True)

    assert evidence["hash_only"] is True
    assert evidence["redacted"] is True
    assert evidence["execution_allowed"] is False
    assert evidence["provider_execution"] is False
    assert evidence["production_activation"] is False
    assert HASH_RE.match(evidence["sample_replay_hash"])
    assert set(verifier.DENIAL_CODES).issubset(set(evidence["denial_codes"]))
    for forbidden in ("credential_value", "provider_value", "secret_value", "token_value", "customer_email", "approval_text"):
        assert forbidden not in rendered
