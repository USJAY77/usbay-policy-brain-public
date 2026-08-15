"""Governed media execution foundation tests (Higgsfield boundary).

Test-first suite: proves unsafe behavior is BLOCKED before/after implementation.
No real provider calls are made anywhere in this suite.
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path

import pytest

from governance.media_execution import (
    MediaGovernanceError,
    build_media_authorization,
    build_media_execution_contract,
    validate_media_execution,
    MediaExecutionConsumptionStore,
    record_media_execution_evidence,
    enforce_publication_gate,
    build_publication_authorization,
)
from governance.media_provider_adapter import (
    HiggsfieldAdapter,
    StubMediaProviderAdapter,
    execute_media_contract,
    higgsfield_status,
)
from audit.ledger import verify_chain


def _hash(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


PROMPT = "governed test prompt: calm ocean at dawn"
PROMPT_HASH = _hash(PROMPT)


def _contract(**overrides):
    base = dict(
        execution_id="exec-0001",
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
        authorization_id="authz-0001",
        policy_decision_id="policy-0001",
        evidence_id="evidence-0001",
    )
    base.update(overrides)
    return build_media_execution_contract(**base)


def _authorization(**overrides):
    base = dict(
        authorization_id="authz-0001",
        provider="higgsfield",
        action="video.generate",
        model_identifier="model-x",
        prompt_hash=PROMPT_HASH,
        max_outputs=1,
        max_duration_seconds=10,
        budget_ceiling=5.0,
        policy_decision_id="policy-0001",
        publication_authorized=False,
    )
    base.update(overrides)
    return build_media_authorization(**base)


@pytest.fixture()
def store(tmp_path):
    return MediaExecutionConsumptionStore(tmp_path / "media_consumption.db")


@pytest.fixture()
def evidence_log(tmp_path):
    return tmp_path / "media_execution_evidence.jsonl"


# A. missing execution contract -> BLOCK
def test_missing_contract_blocks(store):
    decision = validate_media_execution(None, _authorization(), consumption_store=store)
    assert decision["decision"] == "BLOCK"
    assert decision["reason_code"] == "CONTRACT_MISSING"


# B. missing authorization -> BLOCK
def test_missing_authorization_blocks(store):
    decision = validate_media_execution(_contract(), None, consumption_store=store)
    assert decision["decision"] == "BLOCK"
    assert decision["reason_code"] == "AUTHORIZATION_MISSING"


# authorization id mismatch -> BLOCK
def test_authorization_id_mismatch_blocks(store):
    decision = validate_media_execution(
        _contract(authorization_id="authz-OTHER"), _authorization(), consumption_store=store
    )
    assert decision["decision"] == "BLOCK"
    assert decision["reason_code"] == "AUTHORIZATION_MISMATCH"


# C. provider mismatch -> BLOCK
def test_provider_mismatch_blocks(store):
    decision = validate_media_execution(
        _contract(), _authorization(provider="otherprovider"), consumption_store=store
    )
    assert decision["decision"] == "BLOCK"
    assert decision["reason_code"] == "PROVIDER_MISMATCH"


def test_disallowed_provider_contract_blocks():
    with pytest.raises(MediaGovernanceError):
        _contract(provider="unlisted-provider")


# D. prompt/input hash mismatch -> BLOCK
def test_prompt_hash_mismatch_blocks(store):
    decision = validate_media_execution(
        _contract(prompt_hash=_hash("tampered prompt")), _authorization(), consumption_store=store
    )
    assert decision["decision"] == "BLOCK"
    assert decision["reason_code"] == "PROMPT_HASH_MISMATCH"


# E. model mismatch where constrained -> BLOCK
def test_model_mismatch_blocks(store):
    decision = validate_media_execution(
        _contract(model_identifier="model-EVIL"), _authorization(), consumption_store=store
    )
    assert decision["decision"] == "BLOCK"
    assert decision["reason_code"] == "MODEL_MISMATCH"


# F. output count exceeds authorization -> BLOCK
def test_output_count_exceeds_blocks(store):
    decision = validate_media_execution(
        _contract(max_outputs=3), _authorization(max_outputs=1), consumption_store=store
    )
    assert decision["decision"] == "BLOCK"
    assert decision["reason_code"] == "OUTPUT_LIMIT_EXCEEDED"


# G. duration exceeds authorization -> BLOCK
def test_duration_exceeds_blocks(store):
    decision = validate_media_execution(
        _contract(requested_duration_seconds=20), _authorization(), consumption_store=store
    )
    assert decision["decision"] == "BLOCK"
    assert decision["reason_code"] == "DURATION_LIMIT_EXCEEDED"


# budget exceeds -> BLOCK
def test_budget_exceeds_blocks(store):
    decision = validate_media_execution(
        _contract(budget_ceiling=100.0), _authorization(budget_ceiling=5.0), consumption_store=store
    )
    assert decision["decision"] == "BLOCK"
    assert decision["reason_code"] == "BUDGET_LIMIT_EXCEEDED"


# H/I. Higgsfield credentials/interface not proven -> BLOCK, no network
def test_higgsfield_adapter_fails_closed(store, evidence_log):
    adapter = HiggsfieldAdapter()
    assert adapter.status() in {"NOT_CONFIGURED", "INTERFACE_UNKNOWN"}
    result = execute_media_contract(
        _contract(),
        _authorization(),
        adapter,
        consumption_store=store,
        evidence_log=evidence_log,
    )
    assert result["decision"] == "BLOCK"
    assert result["reason_code"] in {
        "HIGGSFIELD_INTERFACE_NOT_PROVEN",
        "PROVIDER_NOT_CONFIGURED",
    }
    assert result.get("provider_execution") == "PROVIDER_EXECUTION_BLOCKED"
    assert not evidence_log.exists() or "ALLOW" not in evidence_log.read_text()


def test_higgsfield_status_is_truthful():
    assert higgsfield_status() in {"NOT_CONFIGURED", "INTERFACE_UNKNOWN"}


# J. publication requested without human approval -> BLOCK
def test_publication_without_human_approval_blocks():
    contract = _contract()
    assert contract.publication_allowed is False
    decision = enforce_publication_gate(contract, publication_authorization=None)
    assert decision["decision"] == "BLOCK"
    assert decision["reason_code"] == "PUBLICATION_NOT_AUTHORIZED"


def test_publication_with_human_approval_allows():
    contract = _contract()
    approval = build_publication_authorization(
        execution_id=contract.execution_id,
        approver_id="human-approver-1",
        evidence_reference="evidence-0001",
    )
    decision = enforce_publication_gate(contract, publication_authorization=approval)
    assert decision["decision"] == "ALLOW"


def test_publication_approval_for_other_execution_blocks():
    contract = _contract()
    approval = build_publication_authorization(
        execution_id="exec-OTHER",
        approver_id="human-approver-1",
        evidence_reference="evidence-0001",
    )
    decision = enforce_publication_gate(contract, publication_authorization=approval)
    assert decision["decision"] == "BLOCK"


# K. secret values never in contract/evidence
def test_no_secret_or_prompt_in_evidence(store, evidence_log):
    adapter = StubMediaProviderAdapter()
    contract = _contract()
    result = execute_media_contract(
        contract, _authorization(), adapter, consumption_store=store, evidence_log=evidence_log
    )
    assert result["decision"] == "ALLOW"
    raw = evidence_log.read_text()
    assert PROMPT not in raw  # raw prompt never copied into evidence
    for name in ("SESSION_SECRET", "GITHUB_TOKEN", "CLOUDFLARE_API_TOKEN", "CLOUDFLARE_ACCOUNT_ID"):
        value = os.environ.get(name)
        if value:
            assert value not in raw
    serialized_result = json.dumps(result, default=str)
    for name in ("SESSION_SECRET", "GITHUB_TOKEN", "CLOUDFLARE_API_TOKEN"):
        value = os.environ.get(name)
        if value:
            assert value not in serialized_result


# L. valid bounded contract reaches provider adapter (stub)
def test_valid_contract_reaches_stub_adapter(store, evidence_log):
    adapter = StubMediaProviderAdapter()
    result = execute_media_contract(
        _contract(), _authorization(), adapter, consumption_store=store, evidence_log=evidence_log
    )
    assert result["decision"] == "ALLOW"
    assert adapter.call_count == 1
    assert result["publication_authorized"] is False


# M/N. successful result creates provenance evidence, chained + linked to asset hash
def test_provenance_evidence_written_and_chained(store, evidence_log):
    adapter = StubMediaProviderAdapter()
    contract = _contract()
    result = execute_media_contract(
        contract, _authorization(), adapter, consumption_store=store, evidence_log=evidence_log
    )
    assert result["decision"] == "ALLOW"
    last_hash, count, last_entry = verify_chain(evidence_log)
    assert count == 1
    assert last_entry["entry_type"] == "MEDIA_EXECUTION_EVIDENCE"
    assert last_entry["execution_id"] == contract.execution_id
    assert last_entry["authorization_id"] == contract.authorization_id
    assert last_entry["policy_decision_id"] == contract.policy_decision_id
    assert last_entry["provider"] == "higgsfield"
    assert last_entry["prompt_hash"] == contract.prompt_hash
    assert last_entry["output_asset_hash"] == result["output_asset_hash"]
    assert last_entry["publication_status"] == "NOT_AUTHORIZED"
    assert result["evidence_entry_hash"] == last_hash


# adapter failure -> BLOCK, no evidence claiming success
def test_adapter_failure_blocks(store, evidence_log):
    adapter = StubMediaProviderAdapter(fail=True)
    result = execute_media_contract(
        _contract(), _authorization(), adapter, consumption_store=store, evidence_log=evidence_log
    )
    assert result["decision"] == "BLOCK"
    assert result["reason_code"] == "PROVIDER_EXECUTION_FAILED"


# evidence write failure -> BLOCK (audit-before-success semantics)
def test_evidence_write_failure_blocks(store, tmp_path):
    adapter = StubMediaProviderAdapter()
    bad_log = tmp_path / "as_dir"
    bad_log.mkdir()  # path is a directory: append must fail
    result = execute_media_contract(
        _contract(), _authorization(), adapter, consumption_store=store, evidence_log=bad_log
    )
    assert result["decision"] == "BLOCK"
    assert result["reason_code"] == "EVIDENCE_WRITE_FAILED"


# O. duplicate/single-use execution blocked, persists across store instances
def test_single_use_execution_blocks_duplicates(store, evidence_log, tmp_path):
    adapter = StubMediaProviderAdapter()
    first = execute_media_contract(
        _contract(), _authorization(), adapter, consumption_store=store, evidence_log=evidence_log
    )
    assert first["decision"] == "ALLOW"
    second = execute_media_contract(
        _contract(), _authorization(), adapter, consumption_store=store, evidence_log=evidence_log
    )
    assert second["decision"] == "BLOCK"
    assert second["reason_code"] == "EXECUTION_ALREADY_CONSUMED"
    assert adapter.call_count == 1
    # persistence across process/store re-instantiation
    reopened = MediaExecutionConsumptionStore(store.path)
    third = execute_media_contract(
        _contract(), _authorization(), adapter, consumption_store=reopened, evidence_log=evidence_log
    )
    assert third["decision"] == "BLOCK"
    assert adapter.call_count == 1


# consumption store failure -> BLOCK
def test_consumption_store_failure_blocks(evidence_log, tmp_path):
    class BrokenStore:
        path = tmp_path / "x.db"

        def reserve(self, execution_id):
            raise RuntimeError("store down")

    adapter = StubMediaProviderAdapter()
    result = execute_media_contract(
        _contract(), _authorization(), adapter, consumption_store=BrokenStore(), evidence_log=evidence_log
    )
    assert result["decision"] == "BLOCK"
    assert result["reason_code"] == "CONSUMPTION_STORE_FAILURE"
    assert adapter.call_count == 0


# malformed contract inputs fail closed at construction
@pytest.mark.parametrize(
    "overrides",
    [
        {"prompt_hash": "not-a-hash"},
        {"max_outputs": 0},
        {"requested_duration_seconds": 0},
        {"timeout_seconds": 0},
        {"provider": ""},
        {"action": ""},
        {"execution_id": ""},
        {"authorization_id": ""},
        {"policy_decision_id": ""},
    ],
)
def test_malformed_contract_blocks(overrides):
    with pytest.raises(MediaGovernanceError):
        _contract(**overrides)


# contract cannot be created with publication pre-enabled
def test_contract_publication_defaults_false():
    contract = _contract()
    assert contract.publication_allowed is False


# adversarial: unapproved/substituted adapter -> BLOCK, no external execution
def test_unapproved_adapter_blocks(store, evidence_log):
    class RogueAdapter:
        provider_name = "higgsfield"

        def execute(self, contract):  # pragma: no cover - must never run
            raise AssertionError("rogue adapter must never execute")

    result = execute_media_contract(
        _contract(), _authorization(), RogueAdapter(), consumption_store=store, evidence_log=evidence_log
    )
    assert result["decision"] == "BLOCK"
    assert result["reason_code"] == "ADAPTER_NOT_APPROVED"


def test_adapter_provider_name_mismatch_blocks(store, evidence_log):
    adapter = StubMediaProviderAdapter()
    adapter.provider_name = "otherprovider"
    result = execute_media_contract(
        _contract(), _authorization(), adapter, consumption_store=store, evidence_log=evidence_log
    )
    assert result["decision"] == "BLOCK"
    assert result["reason_code"] == "ADAPTER_NOT_APPROVED"
    assert adapter.call_count == 0


# adversarial: provider result not bound to contract -> BLOCK
def test_provider_result_execution_id_mismatch_blocks(store, evidence_log):
    class SubstitutingStub(StubMediaProviderAdapter):
        def execute(self, contract):
            result = super().execute(contract)
            result["execution_id"] = "exec-SUBSTITUTED"
            return result

    result = execute_media_contract(
        _contract(), _authorization(), SubstitutingStub(), consumption_store=store, evidence_log=evidence_log
    )
    assert result["decision"] == "BLOCK"
    assert result["reason_code"] == "PROVIDER_RESULT_MISMATCH"
    assert not evidence_log.exists()


# adversarial: provider-controlled metadata cannot smuggle prompts/secrets into evidence
def test_provider_metadata_is_allowlisted(store, evidence_log):
    class LeakyStub(StubMediaProviderAdapter):
        def execute(self, contract):
            result = super().execute(contract)
            result["output_metadata"] = {
                "output_type": "video",
                "prompt": PROMPT,
                "api_key": "sk-fake-not-a-real-secret",
            }
            return result

    result = execute_media_contract(
        _contract(), _authorization(), LeakyStub(), consumption_store=store, evidence_log=evidence_log
    )
    assert result["decision"] == "ALLOW"
    raw = evidence_log.read_text()
    assert PROMPT not in raw
    assert "sk-fake-not-a-real-secret" not in raw
    assert "api_key" not in raw


def test_oversized_provider_reference_blocks(store, evidence_log):
    class OversizeStub(StubMediaProviderAdapter):
        def execute(self, contract):
            result = super().execute(contract)
            result["provider_request_reference"] = "x" * 4096
            return result

    result = execute_media_contract(
        _contract(), _authorization(), OversizeStub(), consumption_store=store, evidence_log=evidence_log
    )
    assert result["decision"] == "BLOCK"
    assert result["reason_code"] == "PROVIDER_RESULT_MALFORMED"
