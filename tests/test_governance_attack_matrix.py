"""§7 — security attack test matrix (fail-closed before any side effect).

Consolidates the attack cases from the governance hardening batch spec that
are not already covered by the dedicated suites:
- test_authority_registry.py (actor/approval attacks)
- test_subprocess_isolation.py (secret inheritance, timeout, runaway child)
- test_media_execution_governance.py (contract/authorization validation)

Cases here: forged approval id, approval/contract mismatch, missing policy
decision, malformed provider result, provider-result substitution, replayed
result via single-use execution, evidence tampering detection, and
authorization bypass attempts against the governed entry point.
"""

from __future__ import annotations

import hashlib
import json

import pytest

from audit.ledger import verify_chain
from governance.authority_registry import MediaAuthorityRegistry
from governance.media_execution import (
    MediaExecutionConsumptionStore,
    build_media_authorization,
    build_media_execution_contract,
    validate_media_execution,
)
from governance.media_provider_adapter import (
    StubMediaProviderAdapter,
    execute_media_contract,
)


def _hash(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


PROMPT_HASH = _hash("attack matrix prompt")


def _contract(**overrides):
    base = dict(
        execution_id="exec-am-0001",
        actor_id="human-actor-1",
        tenant_reference="tenant-alpha",
        provider="higgsfield",
        action="video.generate",
        model_identifier="model-x",
        prompt_hash=PROMPT_HASH,
        input_asset_hashes=(),
        requested_duration_seconds=8,
        output_type="video",
        max_outputs=1,
        budget_ceiling=5.0,
        timeout_seconds=60,
        authorization_id="authz-am-0001",
        policy_decision_id="policy-am-0001",
        evidence_id="evidence-am-0001",
    )
    base.update(overrides)
    return build_media_execution_contract(**base)


def _authorization(**overrides):
    base = dict(
        authorization_id="authz-am-0001",
        provider="higgsfield",
        action="video.generate",
        model_identifier="model-x",
        prompt_hash=PROMPT_HASH,
        max_outputs=1,
        max_duration_seconds=10,
        budget_ceiling=5.0,
        policy_decision_id="policy-am-0001",
        publication_authorized=False,
    )
    base.update(overrides)
    return build_media_authorization(**base)


@pytest.fixture()
def registry(tmp_path):
    reg = MediaAuthorityRegistry(tmp_path / "authority.db")
    reg.register_actor("human-actor-1")
    reg.register_approval(authorization=_authorization(), actor_id="human-actor-1")
    return reg


@pytest.fixture()
def store(tmp_path):
    return MediaExecutionConsumptionStore(tmp_path / "consumption.db")


@pytest.fixture()
def evidence_log(tmp_path):
    return tmp_path / "evidence.jsonl"


def _execute(contract, authorization, adapter, registry, store, evidence_log):
    return execute_media_contract(
        contract, authorization, adapter,
        consumption_store=store, authority_registry=registry,
        evidence_log=evidence_log,
    )


# forged approval id: contract/authorization present an id never granted
def test_forged_approval_id_denies(registry, store, evidence_log):
    adapter = StubMediaProviderAdapter()
    result = _execute(
        _contract(authorization_id="authz-FORGED"),
        _authorization(authorization_id="authz-FORGED"),
        adapter, registry, store, evidence_log,
    )
    assert result["decision"] == "BLOCK"
    assert result["reason_code"] == "APPROVAL_UNKNOWN"
    assert adapter.call_count == 0


# approval/contract mismatch (approval granted for a different contract scope)
def test_approval_for_other_contract_scope_denies(registry, store, evidence_log):
    adapter = StubMediaProviderAdapter()
    other_hash = _hash("different governed request")
    result = _execute(
        _contract(prompt_hash=other_hash),
        _authorization(prompt_hash=other_hash),
        adapter, registry, store, evidence_log,
    )
    assert result["decision"] == "BLOCK"
    assert result["reason_code"] == "APPROVAL_BINDING_MISMATCH"
    assert adapter.call_count == 0


# missing policy decision reference
def test_missing_policy_decision_denies():
    from governance.media_execution import MediaGovernanceError

    with pytest.raises(MediaGovernanceError):
        _contract(policy_decision_id="")


def test_policy_decision_mismatch_denies(store):
    decision = validate_media_execution(
        _contract(policy_decision_id="policy-OTHER"),
        _authorization(),
        consumption_store=store,
    )
    assert decision["decision"] == "BLOCK"
    assert decision["reason_code"] == "POLICY_DECISION_MISMATCH"


# malformed provider result: missing/invalid output hash never becomes evidence
def test_missing_output_hash_rejected(registry, store, evidence_log):
    class NoHashStub(StubMediaProviderAdapter):
        def execute(self, contract):
            result = super().execute(contract)
            del result["output_asset_hash"]
            return result

    result = _execute(
        _contract(), _authorization(), NoHashStub(), registry, store, evidence_log
    )
    assert result["decision"] == "BLOCK"
    assert result["reason_code"] == "PROVIDER_RESULT_MALFORMED"
    assert not evidence_log.exists()


def test_invalid_output_hash_rejected(registry, store, evidence_log):
    class BadHashStub(StubMediaProviderAdapter):
        def execute(self, contract):
            result = super().execute(contract)
            result["output_asset_hash"] = "not-a-sha256"
            return result

    result = _execute(
        _contract(), _authorization(), BadHashStub(), registry, store, evidence_log
    )
    assert result["decision"] == "BLOCK"
    assert result["reason_code"] == "PROVIDER_RESULT_MALFORMED"
    assert not evidence_log.exists()


# provider-result substitution (result for another execution)
def test_provider_result_substitution_denies(registry, store, evidence_log):
    class SubstitutingStub(StubMediaProviderAdapter):
        def execute(self, contract):
            result = super().execute(contract)
            result["execution_id"] = "exec-SOMEONE-ELSE"
            return result

    result = _execute(
        _contract(), _authorization(), SubstitutingStub(), registry, store, evidence_log
    )
    assert result["decision"] == "BLOCK"
    assert result["reason_code"] == "PROVIDER_RESULT_MISMATCH"
    assert not evidence_log.exists()


# replayed external result: single-use execution prevents re-acceptance
def test_replayed_execution_result_denies(registry, store, evidence_log):
    adapter = StubMediaProviderAdapter()
    first = _execute(_contract(), _authorization(), adapter, registry, store, evidence_log)
    assert first["decision"] == "ALLOW"
    replay = _execute(_contract(), _authorization(), adapter, registry, store, evidence_log)
    assert replay["decision"] == "BLOCK"
    assert replay["reason_code"] == "EXECUTION_ALREADY_CONSUMED"
    assert adapter.call_count == 1


# evidence tampering is detected by chain verification
def test_evidence_tampering_detected(registry, store, evidence_log):
    adapter = StubMediaProviderAdapter()
    result = _execute(_contract(), _authorization(), adapter, registry, store, evidence_log)
    assert result["decision"] == "ALLOW"
    verify_chain(evidence_log)  # intact chain verifies
    lines = evidence_log.read_text().splitlines()
    entry = json.loads(lines[0])
    entry["output_asset_hash"] = "0" * 64  # tamper
    evidence_log.write_text(json.dumps(entry) + "\n")
    with pytest.raises(Exception):
        verify_chain(evidence_log)


# authorization bypass attempt: calling adapter directly is not the governed
# path; the governed entry point refuses when governance objects are absent.
def test_bypass_without_authorization_denies(registry, store, evidence_log):
    adapter = StubMediaProviderAdapter()
    result = _execute(_contract(), None, adapter, registry, store, evidence_log)
    assert result["decision"] == "BLOCK"
    assert result["reason_code"] == "AUTHORIZATION_MISSING"
    assert adapter.call_count == 0


def test_bypass_without_contract_denies(registry, store, evidence_log):
    adapter = StubMediaProviderAdapter()
    result = _execute(None, _authorization(), adapter, registry, store, evidence_log)
    assert result["decision"] == "BLOCK"
    assert result["reason_code"] == "CONTRACT_MISSING"
    assert adapter.call_count == 0
