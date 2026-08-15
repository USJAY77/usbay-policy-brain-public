"""GAP 1 — durable approval/identity registry tests (fail-closed).

Proves every unknown/missing/expired/substituted/replayed authority state
DENIES, and that approvals only exist through explicit registration.
No provider calls occur anywhere in this suite.
"""

from __future__ import annotations

import hashlib
import sqlite3

import pytest

from governance.authority_registry import (
    MediaAuthorityRegistry,
    verify_media_authority,
)
from governance.media_execution import (
    MediaExecutionConsumptionStore,
    build_media_authorization,
    build_media_execution_contract,
)
from governance.media_provider_adapter import (
    StubMediaProviderAdapter,
    execute_media_contract,
)


def _hash(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


PROMPT_HASH = _hash("governed test prompt: calm ocean at dawn")


def _contract(**overrides):
    base = dict(
        execution_id="exec-ar-0001",
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
        authorization_id="authz-ar-0001",
        policy_decision_id="policy-0001",
        evidence_id="evidence-0001",
    )
    base.update(overrides)
    return build_media_execution_contract(**base)


def _authorization(**overrides):
    base = dict(
        authorization_id="authz-ar-0001",
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
def registry(tmp_path):
    return MediaAuthorityRegistry(tmp_path / "authority.db")


@pytest.fixture()
def store(tmp_path):
    return MediaExecutionConsumptionStore(tmp_path / "consumption.db")


@pytest.fixture()
def evidence_log(tmp_path):
    return tmp_path / "evidence.jsonl"


def _grant(registry, authorization=None, actor_id="human-actor-1", **kw):
    registry.register_actor(actor_id)
    registry.register_approval(
        authorization=authorization or _authorization(), actor_id=actor_id, **kw
    )


# ---- registry decision surface ------------------------------------------


def test_missing_registry_denies():
    decision = verify_media_authority(None, _contract(), _authorization())
    assert decision["decision"] == "BLOCK"
    assert decision["reason_code"] == "AUTHORITY_REGISTRY_MISSING"


def test_wrong_registry_type_denies():
    class FakeRegistry:
        def verify_authority(self, *a, **kw):  # pragma: no cover - must not run
            return {"decision": "ALLOW_AUTHORITY"}

    decision = verify_media_authority(FakeRegistry(), _contract(), _authorization())
    assert decision["decision"] == "BLOCK"
    assert decision["reason_code"] == "AUTHORITY_REGISTRY_MISSING"


def test_unknown_actor_denies(registry):
    # approval exists but the actor was never registered under this id
    registry.register_actor("someone-else")
    registry.register_approval(
        authorization=_authorization(), actor_id="someone-else"
    )
    decision = registry.verify_authority(_contract(), _authorization())
    assert decision["decision"] == "BLOCK"
    assert decision["reason_code"] == "ACTOR_UNKNOWN"


def test_revoked_actor_denies(registry):
    _grant(registry)
    registry.revoke_actor("human-actor-1")
    decision = registry.verify_authority(_contract(), _authorization())
    assert decision["decision"] == "BLOCK"
    assert decision["reason_code"] == "ACTOR_REVOKED"


def test_unregistered_approval_denies(registry):
    registry.register_actor("human-actor-1")  # actor known, approval never granted
    decision = registry.verify_authority(_contract(), _authorization())
    assert decision["decision"] == "BLOCK"
    assert decision["reason_code"] == "APPROVAL_UNKNOWN"


def test_expired_approval_denies(registry):
    _grant(registry)
    with sqlite3.connect(registry.path) as conn:  # force expiry into the past
        conn.execute(
            "UPDATE media_approval SET expires_at = '2000-01-01T00:00:00Z'"
        )
    decision = registry.verify_authority(_contract(), _authorization())
    assert decision["decision"] == "BLOCK"
    assert decision["reason_code"] == "APPROVAL_EXPIRED"


def test_approval_bound_to_other_actor_denies(registry):
    registry.register_actor("human-actor-1")
    registry.register_actor("other-actor")
    registry.register_approval(authorization=_authorization(), actor_id="other-actor")
    decision = registry.verify_authority(_contract(), _authorization())
    assert decision["decision"] == "BLOCK"
    assert decision["reason_code"] == "APPROVAL_ACTOR_MISMATCH"


def test_substituted_authorization_terms_deny(registry):
    # Approval granted for max_duration 10s; presenter escalates to 300s.
    _grant(registry, authorization=_authorization(max_duration_seconds=10))
    escalated = _authorization(max_duration_seconds=300)
    decision = registry.verify_authority(
        _contract(requested_duration_seconds=300), escalated
    )
    assert decision["decision"] == "BLOCK"
    assert decision["reason_code"] == "APPROVAL_BINDING_MISMATCH"


def test_substituted_prompt_hash_denies(registry):
    _grant(registry)
    other_hash = _hash("a completely different prompt")
    decision = registry.verify_authority(
        _contract(prompt_hash=other_hash), _authorization(prompt_hash=other_hash)
    )
    assert decision["decision"] == "BLOCK"
    assert decision["reason_code"] == "APPROVAL_BINDING_MISMATCH"


def test_replayed_approval_denies(registry):
    _grant(registry)
    first = registry.verify_authority(_contract(), _authorization())
    assert first["decision"] == "ALLOW_AUTHORITY"
    replay = registry.verify_authority(
        _contract(execution_id="exec-ar-0002"), _authorization()
    )
    assert replay["decision"] == "BLOCK"
    assert replay["reason_code"] == "APPROVAL_REPLAYED"


def test_consume_false_does_not_burn_approval(registry):
    _grant(registry)
    peek = registry.verify_authority(_contract(), _authorization(), consume=False)
    assert peek["decision"] == "ALLOW_AUTHORITY"
    real = registry.verify_authority(_contract(), _authorization())
    assert real["decision"] == "ALLOW_AUTHORITY"


def test_registry_failure_denies(registry, monkeypatch):
    _grant(registry)

    def broken_conn():
        raise RuntimeError("registry down")

    monkeypatch.setattr(registry, "_conn", broken_conn)
    decision = registry.verify_authority(_contract(), _authorization())
    assert decision["decision"] == "BLOCK"
    assert decision["reason_code"] == "AUTHORITY_REGISTRY_FAILURE"


def test_registry_is_durable_across_instances(tmp_path):
    path = tmp_path / "authority.db"
    first = MediaAuthorityRegistry(path)
    _grant(first)
    reopened = MediaAuthorityRegistry(path)
    decision = reopened.verify_authority(_contract(), _authorization())
    assert decision["decision"] == "ALLOW_AUTHORITY"
    replay = MediaAuthorityRegistry(path).verify_authority(
        _contract(execution_id="exec-ar-0002"), _authorization()
    )
    assert replay["reason_code"] == "APPROVAL_REPLAYED"


def test_duplicate_approval_registration_rejected(registry):
    _grant(registry)
    with pytest.raises(sqlite3.IntegrityError):
        registry.register_approval(
            authorization=_authorization(), actor_id="human-actor-1"
        )


# ---- wiring into the governed execution pipeline -------------------------


def test_execute_without_registry_blocks(store, evidence_log):
    adapter = StubMediaProviderAdapter()
    result = execute_media_contract(
        _contract(), _authorization(), adapter,
        consumption_store=store, evidence_log=evidence_log,
    )
    assert result["decision"] == "BLOCK"
    assert result["reason_code"] == "AUTHORITY_REGISTRY_MISSING"
    assert adapter.call_count == 0
    assert not evidence_log.exists()


def test_execute_with_registered_authority_allows(registry, store, evidence_log):
    _grant(registry)
    adapter = StubMediaProviderAdapter()
    result = execute_media_contract(
        _contract(), _authorization(), adapter,
        consumption_store=store, authority_registry=registry,
        evidence_log=evidence_log,
    )
    assert result["decision"] == "ALLOW"
    assert adapter.call_count == 1


def test_execute_with_unknown_approval_blocks_before_adapter(registry, store, evidence_log):
    registry.register_actor("human-actor-1")
    adapter = StubMediaProviderAdapter()
    result = execute_media_contract(
        _contract(), _authorization(), adapter,
        consumption_store=store, authority_registry=registry,
        evidence_log=evidence_log,
    )
    assert result["decision"] == "BLOCK"
    assert result["reason_code"] == "APPROVAL_UNKNOWN"
    assert adapter.call_count == 0
    assert not evidence_log.exists()


def test_execute_replayed_approval_new_execution_blocks(registry, store, evidence_log):
    _grant(registry)
    adapter = StubMediaProviderAdapter()
    first = execute_media_contract(
        _contract(), _authorization(), adapter,
        consumption_store=store, authority_registry=registry,
        evidence_log=evidence_log,
    )
    assert first["decision"] == "ALLOW"
    second = execute_media_contract(
        _contract(execution_id="exec-ar-0002"), _authorization(), adapter,
        consumption_store=store, authority_registry=registry,
        evidence_log=evidence_log,
    )
    assert second["decision"] == "BLOCK"
    assert second["reason_code"] == "APPROVAL_REPLAYED"
    assert adapter.call_count == 1


# contract-scoped approvals: approval pinned to one execution contract
def test_contract_scoped_approval_rejects_other_contract(registry):
    registry.register_actor("human-actor-1")
    registry.register_approval(
        authorization=_authorization(),
        actor_id="human-actor-1",
        execution_id="exec-ar-0001",
    )
    other = registry.verify_authority(
        _contract(execution_id="exec-ar-9999"), _authorization(), consume=False
    )
    assert other["decision"] == "BLOCK"
    assert other["reason_code"] == "APPROVAL_CONTRACT_MISMATCH"
    pinned = registry.verify_authority(_contract(), _authorization())
    assert pinned["decision"] == "ALLOW_AUTHORITY"
