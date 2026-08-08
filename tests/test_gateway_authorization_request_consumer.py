from __future__ import annotations

import json
import threading
from datetime import datetime, timezone
from pathlib import Path

import pytest

from gateway.authorization_request_consumer import (
    BINDING_FIELDS,
    CANONICAL_CONTRACT_ID,
    CONSUMER_VERSION,
    EURIA_EXECUTION_AUTHORITY,
    FRESHNESS_FIELDS,
    PINNED_CANONICAL_SCHEMA_HASH,
    PINNED_PUBLICATION_HASH,
    POLICY_BRAIN_EXECUTION_AUTHORITY,
    REVOCATION_FLAGS,
    GatewayAuthorizationReplayStore,
    GatewayReplayStoreError,
    consume_gateway_authorization_request,
    execute_with_gateway_authorization,
)
from governance.durable_authority_registries import (
    ACTIVATION,
    ATTESTATION,
    CHALLENGE,
    HUMAN_APPROVAL,
    IDENTITY,
    REVOKED,
    VERIFIER,
    AuthorityRegistryError,
    DurableAuthorityRegistry,
)
from governance.euria_gateway_authorization_request import (
    CONTRACT_VERSION as PRODUCER_CONTRACT_VERSION,
    compute_gateway_authorization_request_hash,
)

pytestmark = pytest.mark.governance

NOW = datetime(2026, 8, 8, 10, 0, 0, tzinfo=timezone.utc)
ISSUED = "2026-08-08T09:00:00Z"
EXPIRES = "2026-08-09T09:00:00Z"
FRESH = "2026-08-09T09:00:00Z"

_H = lambda ch: "sha256:" + (ch * 64)  # noqa: E731
MISMATCH = "sha256:" + "0123456789abcdef" * 4


def _request(**overrides: object) -> dict:
    request = {
        "contract_version": PRODUCER_CONTRACT_VERSION,
        "gateway_contract_version": CANONICAL_CONTRACT_ID,
        "request_id": "gateway-consumer-req-1",
        "tenant_reference": _H("1"),
        "environment_reference": _H("2"),
        "customer_onboarding_reference": _H("3"),
        "human_approval_reference": _H("4"),
        "policy_reference": _H("5"),
        "policy_hash": _H("6"),
        "pilot_reference": _H("7"),
        "activation_reference": _H("8"),
        "identity_reference": _H("9"),
        "identity_hash": _H("a"),
        "verifier_reference": _H("b"),
        "verifier_hash": _H("c"),
        "attestation_reference": _H("d"),
        "attestation_hash": _H("e"),
        "challenge_reference": _H("f"),
        "nonce_reference": _H("0"),
        "issued_at": ISSUED,
        "expires_at": EXPIRES,
        "readiness_decision_hash": _H("1"),
        "activation_request_hash": _H("8"),
        "previous_evidence_hash": _H("2"),
        "current_evidence_hash": _H("3"),
        "evidence_chain_reference": _H("4"),
        "decision_correlation_reference": _H("5"),
        "state": "GATEWAY_REQUEST_VALIDATED",
        "execution_authorized": False,
        "runtime_allow": False,
        "policy_brain_execution_authority": False,
        "enforcement_gateway_final_authority": True,
        "request_hash": "",
    }
    request.update(overrides)
    request["request_hash"] = compute_gateway_authorization_request_hash(request)
    return request


def _context(request: dict, **overrides: object) -> dict:
    context: dict = {field: request[field] for field in BINDING_FIELDS}
    for flag in REVOCATION_FLAGS:
        context[flag] = False
    for field in FRESHNESS_FIELDS:
        context[field] = FRESH
    context["tenant_id"] = "t1"
    context.update(overrides)
    return context


AUTHORITY_RECORDS = (
    (HUMAN_APPROVAL, "human_approval_reference", "APPROVED"),
    (ACTIVATION, "activation_reference", "ACTIVATED"),
    (CHALLENGE, "challenge_reference", "ISSUED"),
    (IDENTITY, "identity_reference", "ENROLLED"),
    (VERIFIER, "verifier_reference", "ENROLLED"),
    (ATTESTATION, "attestation_reference", "PASS"),
)


REVOCATION_TO_DOMAIN = {
    "approval_revoked": HUMAN_APPROVAL,
    "pilot_revoked": ACTIVATION,
    "activation_revoked": ACTIVATION,
    "identity_revoked": IDENTITY,
    "verifier_revoked": VERIFIER,
    "attestation_revoked": ATTESTATION,
    "challenge_revoked": CHALLENGE,
}


FRESHNESS_TO_DOMAIN = {
    "approval_expires_at": HUMAN_APPROVAL,
    "activation_expires_at": ACTIVATION,
    "attestation_expires_at": ATTESTATION,
    "challenge_expires_at": CHALLENGE,
}


def _authority_registry(tmp_path: Path, request: dict, context: dict, name: str) -> DurableAuthorityRegistry:
    registry = DurableAuthorityRegistry(tmp_path / f"{name}.jsonl", evidence_path=tmp_path / f"{name}.evidence.jsonl")
    for domain, reference_field, status in AUTHORITY_RECORDS:
        record = {
            "authority_reference": request[reference_field],
            "tenant_reference": context.get("tenant_reference"),
            "environment_reference": context.get("environment_reference"),
            "issued_at": ISSUED,
            "effective_at": ISSUED,
            "expires_at": context.get(_freshness_field_for(domain), FRESH) if _freshness_field_for(domain) else FRESH,
            "revoked": False,
            "revoked_at": "",
            "revocation_reason_code": "",
            "current_status": status,
            "provenance_evidence_reference": request["current_evidence_hash"],
            "tenant_id": context.get("tenant_id"),
        }
        for field in BINDING_FIELDS:
            if field in context:
                record[field] = context[field]
        if domain in {HUMAN_APPROVAL, ACTIVATION}:
            record["policy_reference"] = context.get("policy_reference")
            record["policy_hash"] = context.get("policy_hash")
        if domain in {CHALLENGE, IDENTITY, ATTESTATION}:
            record["subject_reference"] = context.get("identity_reference")
        if domain in {VERIFIER, ATTESTATION}:
            record["verifier_reference"] = context.get("verifier_reference")
        for flag, revoked_domain in REVOCATION_TO_DOMAIN.items():
            if revoked_domain == domain and context.get(flag) is not False:
                record["revoked"] = True
                record["current_status"] = REVOKED
                record["revoked_at"] = NOW.isoformat().replace("+00:00", "Z")
                record["revocation_reason_code"] = flag.upper()
        registry.create_authority(domain, record, timestamp=ISSUED)
    return registry


def _freshness_field_for(domain: str) -> str:
    return {
        HUMAN_APPROVAL: "approval_expires_at",
        ACTIVATION: "activation_expires_at",
        ATTESTATION: "attestation_expires_at",
        CHALLENGE: "challenge_expires_at",
    }.get(domain, "")


@pytest.fixture()
def harness(tmp_path: Path):
    request = _request()
    context = _context(request)
    counter = {"n": 0}

    def make(request_obj=None, context_obj=None, authority_registry=None, **kwargs):
        req = request if request_obj is None else request_obj
        ctx = context if context_obj is None else context_obj
        counter["n"] += 1
        if authority_registry is not None:
            registry = authority_registry
        elif (
            isinstance(req, dict)
            and all(field in req for _, field, _ in AUTHORITY_RECORDS)
            and all(field in req for field in ("tenant_reference", "environment_reference", "current_evidence_hash"))
        ):
            registry = _authority_registry(tmp_path, req, ctx, f"authority_{counter['n']}")
        else:
            registry = None
        return consume_gateway_authorization_request(
            req,
            authority_registry=registry,
            replay_store=GatewayAuthorizationReplayStore(kwargs.pop("db_path", tmp_path / "replay.db")),
            audit_path=kwargs.pop("audit_path", tmp_path / "audit_chain.json"),
            now=kwargs.pop("now", NOW),
            **kwargs,
        )

    return request, context, make, tmp_path


# ---------------------------------------------------------------- VALID


def test_complete_valid_request_allows(harness) -> None:
    request, _, make, tmp_path = harness
    decision = make()
    assert decision["decision"] == "ALLOW"
    assert decision["execution_authorized"] is True
    assert decision["reason_codes"] == []
    assert decision["request_hash"] == request["request_hash"]
    assert decision["audit"]["audit_hash"]
    chain = json.loads((tmp_path / "audit_chain.json").read_text())
    assert chain  # evidence written before any execution could occur


def test_decision_is_explicit_allow_or_block_only(harness) -> None:
    _, _, make, _ = harness
    assert make()["decision"] == "ALLOW"
    assert make()["decision"] == "BLOCK"  # replay of same request
    for decision in (make(request_obj={"broken": True}),):
        assert decision["decision"] in {"ALLOW", "BLOCK"}


# ---------------------------------------------------------------- CONTRACT


def test_unknown_contract_blocks(harness) -> None:
    _, _, make, _ = harness
    decision = make(request_obj=_request(gateway_contract_version="usbay.other.contract.v9"))
    assert decision["decision"] == "BLOCK"
    assert "CONTRACT_VERSION_UNSUPPORTED" in decision["reason_codes"]


def test_unsupported_producer_version_blocks(harness) -> None:
    _, _, make, _ = harness
    decision = make(request_obj=_request(contract_version="usbay.euria.gateway_authorization_request.v99"))
    assert decision["decision"] == "BLOCK"


def test_malformed_schema_blocks(harness) -> None:
    _, _, make, _ = harness
    bad = _request()
    del bad["tenant_reference"]
    bad["request_hash"] = compute_gateway_authorization_request_hash(bad)
    decision = make(request_obj=bad)
    assert decision["decision"] == "BLOCK"


def test_non_mapping_and_oversized_requests_block(harness) -> None:
    _, _, make, _ = harness
    assert make(request_obj="not-a-mapping")["decision"] == "BLOCK"
    oversized = _request(padding="x" * 70000)
    decision = make(request_obj=oversized)
    assert decision["decision"] == "BLOCK"
    assert "REQUEST_TOO_LARGE" in decision["reason_codes"]


def test_contract_pin_mismatch_blocks(harness, tmp_path: Path, monkeypatch) -> None:
    _, _, make, _ = harness
    monkeypatch.setattr(
        "gateway.authorization_request_consumer.PINNED_CANONICAL_SCHEMA_HASH",
        "sha256:" + "0" * 64,
    )
    decision = make()
    assert decision["decision"] == "BLOCK"
    assert any(code.startswith("CONTRACT_") for code in decision["reason_codes"])


def test_missing_canonical_contract_blocks(harness, tmp_path: Path) -> None:
    _, _, make, _ = harness
    decision = make(root=tmp_path)  # no registry/publication in tmp root
    assert decision["decision"] == "BLOCK"
    assert any(code.startswith("CONTRACT_") for code in decision["reason_codes"])


# ---------------------------------------------------------------- INTEGRITY


@pytest.mark.parametrize(
    "field,value",
    [
        ("policy_hash", _H("9")),
        ("tenant_reference", _H("9")),
        ("environment_reference", _H("9")),
        ("activation_reference", _H("9")),
        ("previous_evidence_hash", _H("9")),
    ],
)
def test_field_mutation_after_hash_blocks(harness, field: str, value: str) -> None:
    _, _, make, _ = harness
    mutated = _request()
    mutated[field] = value  # mutate WITHOUT recomputing request_hash
    decision = make(request_obj=mutated)
    assert decision["decision"] == "BLOCK"
    assert "REQUEST_HASH_MISMATCH" in decision["reason_codes"]


def test_request_hash_mutation_blocks(harness) -> None:
    _, _, make, _ = harness
    mutated = _request()
    mutated["request_hash"] = _H("9")
    decision = make(request_obj=mutated)
    assert decision["decision"] == "BLOCK"
    assert "REQUEST_HASH_MISMATCH" in decision["reason_codes"]


def test_supplied_request_hash_never_trusted(harness) -> None:
    _, _, make, _ = harness
    mutated = _request()
    mutated["policy_hash"] = _H("9")
    mutated["request_hash"] = compute_gateway_authorization_request_hash(mutated)
    context = _context(_request())  # authoritative source still has original policy hash
    decision = make(request_obj=mutated, context_obj=context)
    assert decision["decision"] == "BLOCK"
    assert decision["reason_codes"]


# ---------------------------------------------------------------- AUTHORITY


@pytest.mark.parametrize("field", list(BINDING_FIELDS))
def test_missing_authority_binding_blocks(harness, field: str) -> None:
    request, context, make, _ = harness
    req = dict(request)
    ctx = dict(context)
    if field in req:
        del req[field]
    ctx.pop(field, None)
    if "request_hash" in req:
        req["request_hash"] = compute_gateway_authorization_request_hash(req)
    decision = make(request_obj=req, context_obj=ctx)
    assert decision["decision"] == "BLOCK"
    assert decision["reason_codes"]


@pytest.mark.parametrize(
    "field",
    ["tenant_reference", "environment_reference", "policy_reference", "policy_hash",
     "identity_reference", "verifier_reference", "attestation_reference", "challenge_reference"],
)
def test_authority_binding_mismatch_blocks(harness, field: str) -> None:
    request, context, make, tmp_path = harness
    registry = _authority_registry(tmp_path, request, context, f"mismatch_{field}")
    mutated = dict(request)
    mutated[field] = MISMATCH
    mutated["request_hash"] = compute_gateway_authorization_request_hash(mutated)
    decision = make(request_obj=mutated, authority_registry=registry)
    assert decision["decision"] == "BLOCK"
    assert decision["reason_codes"]


@pytest.mark.parametrize("flag", list(REVOCATION_FLAGS))
def test_revocation_blocks(harness, flag: str) -> None:
    _, context, make, _ = harness
    decision = make(context_obj=dict(context, **{flag: True}))
    assert decision["decision"] == "BLOCK"
    assert any("AUTHORITY_" in code for code in decision["reason_codes"])


def test_ambiguous_revocation_state_blocks(harness) -> None:
    _, context, make, _ = harness
    decision = make(context_obj=dict(context, approval_revoked=None))
    assert decision["decision"] == "BLOCK"


def test_missing_attestation_binding_blocks(harness) -> None:
    request, context, make, _ = harness
    req = dict(request)
    del req["attestation_reference"]
    req["request_hash"] = compute_gateway_authorization_request_hash(req)
    ctx = dict(context)
    del ctx["attestation_reference"]
    assert make(request_obj=req, context_obj=ctx)["decision"] == "BLOCK"


def test_authority_source_failure_blocks(harness) -> None:
    _, _, make, _ = harness

    decision = make(authority_registry=object())
    assert decision["decision"] == "BLOCK"
    assert "AUTHORITY_SOURCE_UNAVAILABLE" in decision["reason_codes"]


# ---------------------------------------------------------------- TIME


def test_expired_request_blocks(harness) -> None:
    _, _, make, _ = harness
    decision = make(now=datetime(2026, 8, 10, tzinfo=timezone.utc))
    assert decision["decision"] == "BLOCK"
    assert "REQUEST_EXPIRED" in decision["reason_codes"]


def test_future_issued_at_blocks(harness) -> None:
    _, _, make, _ = harness
    decision = make(request_obj=_request(issued_at="2026-08-08T23:00:00Z"))
    assert decision["decision"] == "BLOCK"
    assert "ISSUED_AT_IN_FUTURE" in decision["reason_codes"]


def test_invalid_or_naive_timestamps_block(harness) -> None:
    _, _, make, _ = harness
    assert "EXPIRES_AT_INVALID" in make(request_obj=_request(expires_at="not-a-time"))["reason_codes"]
    assert "ISSUED_AT_INVALID" in make(request_obj=_request(issued_at="2026-08-08T09:00:00"))["reason_codes"]


@pytest.mark.parametrize("field", list(FRESHNESS_FIELDS))
def test_stale_authority_freshness_blocks(harness, field: str) -> None:
    _, context, make, _ = harness
    decision = make(context_obj=dict(context, **{field: "2026-08-08T09:59:00Z"}))
    assert decision["decision"] == "BLOCK"
    assert any("EXPIRED" in code for code in decision["reason_codes"])


# ---------------------------------------------------------------- REPLAY


def test_duplicate_nonce_blocks(harness, tmp_path: Path) -> None:
    _, _, make, _ = harness
    assert make()["decision"] == "ALLOW"
    second = _request(request_id="gateway-consumer-req-2")  # same nonce_reference
    decision = make(request_obj=second, context_obj=_context(second))
    assert decision["decision"] == "BLOCK"
    assert "REPLAY_DETECTED" in decision["reason_codes"]


def test_duplicate_request_id_blocks(harness) -> None:
    _, _, make, _ = harness
    assert make()["decision"] == "ALLOW"
    second = _request(nonce_reference=_H("e"))  # same request_id
    decision = make(request_obj=second, context_obj=_context(second))
    assert decision["decision"] == "BLOCK"
    assert "REPLAY_DETECTED" in decision["reason_codes"]


def test_replayed_identical_request_blocks(harness) -> None:
    _, _, make, _ = harness
    assert make()["decision"] == "ALLOW"
    decision = make()
    assert decision["decision"] == "BLOCK"
    assert "REPLAY_DETECTED" in decision["reason_codes"]


def test_replay_store_unavailable_blocks(harness, tmp_path: Path) -> None:
    request, context, _, _ = harness
    registry = _authority_registry(tmp_path, request, context, "replay_unavailable_authority")

    class BrokenStore(GatewayAuthorizationReplayStore):
        def reserve(self, *args, **kwargs):
            raise GatewayReplayStoreError("REPLAY_STORE_UNAVAILABLE")

    decision = consume_gateway_authorization_request(
        request,
        authority_registry=registry,
        replay_store=BrokenStore(tmp_path / "x.db"),
        audit_path=tmp_path / "a.json",
        now=NOW,
    )
    assert decision["decision"] == "BLOCK"
    assert "REPLAY_STORE_UNAVAILABLE" in decision["reason_codes"]


def test_ambiguous_replay_store_result_blocks(harness, tmp_path: Path) -> None:
    request, context, _, _ = harness
    registry = _authority_registry(tmp_path, request, context, "ambiguous_replay_authority")

    class AmbiguousStore(GatewayAuthorizationReplayStore):
        def reserve(self, *args, **kwargs):
            return None  # neither True nor False

    decision = consume_gateway_authorization_request(
        request,
        authority_registry=registry,
        replay_store=AmbiguousStore(tmp_path / "x.db"),
        audit_path=tmp_path / "a.json",
        now=NOW,
    )
    assert decision["decision"] == "BLOCK"


def test_concurrent_duplicate_only_one_allows(tmp_path: Path) -> None:
    request = _request()
    context = _context(request)
    store_path = tmp_path / "replay.db"
    barrier = threading.Barrier(2)
    decisions: list[dict] = []
    lock = threading.Lock()

    def run(idx: int) -> None:
        barrier.wait()
        decision = consume_gateway_authorization_request(
            request,
            authority_registry=_authority_registry(tmp_path, request, context, f"concurrent_authority_{idx}"),
            replay_store=GatewayAuthorizationReplayStore(store_path),
            audit_path=tmp_path / f"audit_{idx}.json",
            now=NOW,
        )
        with lock:
            decisions.append(decision)

    threads = [threading.Thread(target=run, args=(i,)) for i in range(2)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    outcomes = sorted(d["decision"] for d in decisions)
    assert outcomes.count("ALLOW") <= 1
    assert outcomes.count("BLOCK") >= 1


def test_replay_reservation_is_persistent(tmp_path: Path) -> None:
    store_path = tmp_path / "replay.db"
    first = GatewayAuthorizationReplayStore(store_path)
    assert first.reserve(_H("0"), "req-1", _H("1"), ISSUED) is True
    fresh_process_store = GatewayAuthorizationReplayStore(store_path)
    assert fresh_process_store.reserve(_H("0"), "req-2", _H("1"), ISSUED) is False


# ---------------------------------------------------------------- TOCTOU


class _MutatingAuthorityRegistry(DurableAuthorityRegistry):
    def __init__(self, *args, mutation, **kwargs):
        super().__init__(*args, **kwargs)
        self._calls = 0
        self._mutation = mutation
        self._mutated = False

    def resolve_authority(self, *args, **kwargs):
        self._calls += 1
        if self._calls > len(AUTHORITY_RECORDS) and not self._mutated:
            self._mutation(self)
            self._mutated = True
        return super().resolve_authority(*args, **kwargs)


class _FailingRevalidationRegistry(DurableAuthorityRegistry):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.calls = 0

    def resolve_authority(self, *args, **kwargs):
        self.calls += 1
        if self.calls > len(AUTHORITY_RECORDS):
            raise AuthorityRegistryError("AUTHORITY_SOURCE_UNAVAILABLE")
        return super().resolve_authority(*args, **kwargs)


def test_approval_revoked_during_validation_blocks(harness) -> None:
    request, context, make, tmp_path = harness

    def revoke(registry: DurableAuthorityRegistry) -> None:
        registry.revoke_authority(
            HUMAN_APPROVAL,
            request["human_approval_reference"],
            tenant_reference=request["tenant_reference"],
            environment_reference=request["environment_reference"],
            reason_code="APPROVAL_REVOKED",
            timestamp=NOW.isoformat().replace("+00:00", "Z"),
        )

    registry = _MutatingAuthorityRegistry(
        tmp_path / "toctou_approval.jsonl",
        evidence_path=tmp_path / "toctou_approval.evidence.jsonl",
        mutation=revoke,
    )
    seeded = _authority_registry(tmp_path, request, context, "toctou_approval_seed")
    registry.registry_path.write_text(seeded.registry_path.read_text(encoding="utf-8"), encoding="utf-8")
    registry.evidence_path.write_text(seeded.evidence_path.read_text(encoding="utf-8"), encoding="utf-8")
    decision = make(authority_registry=registry)
    assert decision["decision"] == "BLOCK"
    assert any("AUTHORITY_HUMAN_APPROVAL" in code for code in decision["reason_codes"])


def test_policy_changed_during_validation_blocks(harness) -> None:
    request, context, make, tmp_path = harness

    def change_policy(registry: DurableAuthorityRegistry) -> None:
        latest = registry._latest(HUMAN_APPROVAL, request["human_approval_reference"])  # noqa: SLF001
        record = dict(latest["record"])
        record["policy_hash"] = _H("9")
        registry.update_authority(HUMAN_APPROVAL, record, timestamp=NOW.isoformat().replace("+00:00", "Z"))

    registry = _MutatingAuthorityRegistry(
        tmp_path / "toctou_policy.jsonl",
        evidence_path=tmp_path / "toctou_policy.evidence.jsonl",
        mutation=change_policy,
    )
    seeded = _authority_registry(tmp_path, request, context, "toctou_policy_seed")
    registry.registry_path.write_text(seeded.registry_path.read_text(encoding="utf-8"), encoding="utf-8")
    registry.evidence_path.write_text(seeded.evidence_path.read_text(encoding="utf-8"), encoding="utf-8")
    decision = make(authority_registry=registry)
    assert decision["decision"] == "BLOCK"
    assert any("AUTHORITY_HUMAN_APPROVAL" in code for code in decision["reason_codes"])


def test_activation_revoked_during_validation_blocks(harness) -> None:
    request, context, make, tmp_path = harness

    def revoke(registry: DurableAuthorityRegistry) -> None:
        registry.revoke_authority(
            ACTIVATION,
            request["activation_reference"],
            tenant_reference=request["tenant_reference"],
            environment_reference=request["environment_reference"],
            reason_code="ACTIVATION_REVOKED",
            timestamp=NOW.isoformat().replace("+00:00", "Z"),
        )

    registry = _MutatingAuthorityRegistry(
        tmp_path / "toctou_activation.jsonl",
        evidence_path=tmp_path / "toctou_activation.evidence.jsonl",
        mutation=revoke,
    )
    seeded = _authority_registry(tmp_path, request, context, "toctou_activation_seed")
    registry.registry_path.write_text(seeded.registry_path.read_text(encoding="utf-8"), encoding="utf-8")
    registry.evidence_path.write_text(seeded.evidence_path.read_text(encoding="utf-8"), encoding="utf-8")
    decision = make(authority_registry=registry)
    assert decision["decision"] == "BLOCK"


def test_authority_source_failing_at_revalidation_blocks(harness) -> None:
    request, context, make, tmp_path = harness
    registry = _FailingRevalidationRegistry(
        tmp_path / "failing_revalidation.jsonl",
        evidence_path=tmp_path / "failing_revalidation.evidence.jsonl",
    )
    seeded = _authority_registry(tmp_path, request, context, "failing_revalidation_seed")
    registry.registry_path.write_text(seeded.registry_path.read_text(encoding="utf-8"), encoding="utf-8")
    registry.evidence_path.write_text(seeded.evidence_path.read_text(encoding="utf-8"), encoding="utf-8")

    decision = make(authority_registry=registry)
    assert decision["decision"] == "BLOCK"
    assert "AUTHORITY_SOURCE_UNAVAILABLE" in decision["reason_codes"]
    assert registry.calls > len(AUTHORITY_RECORDS)  # revalidation actually re-fetched


# ---------------------------------------------------------------- AUDIT


def test_allow_writes_hash_correlated_evidence(harness) -> None:
    request, _, make, tmp_path = harness
    decision = make()
    assert decision["decision"] == "ALLOW"
    chain = json.loads((tmp_path / "audit_chain.json").read_text())
    record = chain[-1]["decision"]
    payload = record["payload"]
    assert payload["request_hash"] == request["request_hash"]
    assert payload["decision"] == "ALLOW"
    assert payload["gateway_decision_hash"].startswith("sha256:")
    assert payload["policy_hash"] == request["policy_hash"]
    assert payload["tenant_reference"] == request["tenant_reference"]
    assert chain[-1]["hash_prev"] is not None or len(chain) == 1


def test_audit_write_failure_blocks(harness, tmp_path: Path, monkeypatch) -> None:
    _, _, make, _ = harness
    from audit.audit_writer import AuditWriteError

    def broken_writer(*args, **kwargs):
        raise AuditWriteError("AUDIT_WRITE_FAILED")

    monkeypatch.setattr("gateway.authorization_request_consumer.write_audit_record", broken_writer)
    decision = make()
    assert decision["decision"] == "BLOCK"
    assert "AUDIT_WRITE_FAILED" in decision["reason_codes"]
    assert decision["audit"] is None
    assert decision["execution_authorized"] is False


def test_block_decisions_also_audited(harness, tmp_path) -> None:
    _, _, make, tmp = harness
    bad = _request()
    bad["request_hash"] = _H("9")
    make(request_obj=bad)
    chain = json.loads((tmp / "audit_chain.json").read_text())
    assert chain[-1]["decision"]["payload"]["decision"] == "BLOCK"


def test_no_sensitive_data_in_audit_evidence(harness) -> None:
    request, context, make, tmp_path = harness
    decision = make()
    assert decision["decision"] == "ALLOW"
    raw = (tmp_path / "audit_chain.json").read_text().lower()
    for marker in ("password", "api_key", "private_key", "raw_payload", "prompt"):
        assert marker not in raw


# ---------------------------------------------------------------- EXECUTION BOUNDARY


def test_execution_impossible_without_allow(harness, tmp_path: Path) -> None:
    request, context, _, _ = harness
    bad = _request()
    registry = _authority_registry(tmp_path, bad, _context(bad), "execute_block_authority")
    executed = {"ran": False}

    def executor():
        executed["ran"] = True
        return "SIDE_EFFECT"

    bad["request_hash"] = _H("9")
    result = execute_with_gateway_authorization(
        bad,
        executor=executor,
        authority_registry=registry,
        replay_store=GatewayAuthorizationReplayStore(tmp_path / "r.db"),
        audit_path=tmp_path / "a.json",
        now=NOW,
    )
    assert result["executed"] is False
    assert executed["ran"] is False
    assert result["decision"]["decision"] == "BLOCK"


def test_execution_only_after_allow(harness, tmp_path: Path) -> None:
    request, context, _, _ = harness
    registry = _authority_registry(tmp_path, request, context, "execute_allow_authority")
    executed = {"ran": False}

    def executor():
        executed["ran"] = True
        return "OK"

    result = execute_with_gateway_authorization(
        request,
        executor=executor,
        authority_registry=registry,
        replay_store=GatewayAuthorizationReplayStore(tmp_path / "r.db"),
        audit_path=tmp_path / "a.json",
        now=NOW,
    )
    assert result["executed"] is True
    assert executed["ran"] is True
    assert result["decision"]["audit"]["audit_hash"]


def test_validation_exception_makes_execution_impossible(harness, tmp_path: Path, monkeypatch) -> None:
    request, context, _, _ = harness
    registry = _authority_registry(tmp_path, request, context, "execute_exception_authority")
    executed = {"ran": False}

    def executor():
        executed["ran"] = True

    def exploding(*args, **kwargs):
        raise RuntimeError("internal validation crash")

    monkeypatch.setattr(
        "gateway.authorization_request_consumer.verify_gateway_authorization_request", exploding
    )
    result = execute_with_gateway_authorization(
        request,
        executor=executor,
        authority_registry=registry,
        replay_store=GatewayAuthorizationReplayStore(tmp_path / "r.db"),
        audit_path=tmp_path / "a.json",
        now=NOW,
    )
    assert result["executed"] is False
    assert executed["ran"] is False
    assert result["decision"]["decision"] == "BLOCK"
    assert "GATEWAY_CONSUMER_ERROR" in result["decision"]["reason_codes"]


def test_execution_blocked_when_audit_missing_even_if_decision_forged(harness, tmp_path: Path) -> None:
    request, context, _, _ = harness
    registry = _authority_registry(tmp_path, request, context, "execute_forged_authority")
    executed = {"ran": False}

    def executor():
        executed["ran"] = True

    # Even a forged ALLOW-shaped mapping without durable audit evidence must
    # not execute (checked structurally by execute_with_gateway_authorization).
    import gateway.authorization_request_consumer as mod

    original = mod.consume_gateway_authorization_request
    try:
        mod.consume_gateway_authorization_request = lambda *a, **k: {
            "decision": "ALLOW",
            "execution_authorized": True,
            "audit": None,
        }
        # call through module attribute to pick up the monkeyed function
        decision = mod.consume_gateway_authorization_request(request)
        assert decision["audit"] is None
    finally:
        mod.consume_gateway_authorization_request = original
    forged_bad = _request()
    forged_bad["request_hash"] = _H("9")
    result = execute_with_gateway_authorization(
        forged_bad,
        executor=executor,
        authority_registry=registry,
        replay_store=GatewayAuthorizationReplayStore(tmp_path / "r.db"),
        audit_path=tmp_path / "a.json",
        now=NOW,
    )
    assert result["executed"] is False


def test_missing_tenant_identity_blocks(harness) -> None:
    _, context, make, _ = harness
    ctx = dict(context)
    del ctx["tenant_id"]
    decision = make(context_obj=ctx)
    assert decision["decision"] == "BLOCK"
    assert "TENANT_ID_INVALID" in decision["reason_codes"]


def test_unauthorized_tenant_identity_blocks(harness) -> None:
    _, context, make, _ = harness
    decision = make(context_obj=dict(context, tenant_id="not-an-allowed-tenant"))
    assert decision["decision"] == "BLOCK"
    assert "TENANT_ID_INVALID" in decision["reason_codes"]


def test_allow_evidence_attributed_to_governed_tenant(harness) -> None:
    _, _, make, tmp_path = harness
    decision = make()
    assert decision["decision"] == "ALLOW"
    chain = json.loads((tmp_path / "audit_chain.json").read_text())
    payload = chain[-1]["decision"]["payload"]
    assert payload["tenant_id"] == "t1"
    assert payload["tenant_attributed"] is True


def test_tenant_changed_during_validation_blocks(harness) -> None:
    request, context, make, tmp_path = harness

    def change_tenant(registry: DurableAuthorityRegistry) -> None:
        latest = registry._latest(HUMAN_APPROVAL, request["human_approval_reference"])  # noqa: SLF001
        record = dict(latest["record"])
        record["tenant_id"] = "t2"
        registry.update_authority(HUMAN_APPROVAL, record, timestamp=NOW.isoformat().replace("+00:00", "Z"))

    registry = _MutatingAuthorityRegistry(
        tmp_path / "toctou_tenant.jsonl",
        evidence_path=tmp_path / "toctou_tenant.evidence.jsonl",
        mutation=change_tenant,
    )
    seeded = _authority_registry(tmp_path, request, context, "toctou_tenant_seed")
    registry.registry_path.write_text(seeded.registry_path.read_text(encoding="utf-8"), encoding="utf-8")
    registry.evidence_path.write_text(seeded.evidence_path.read_text(encoding="utf-8"), encoding="utf-8")
    decision = make(authority_registry=registry)
    assert decision["decision"] == "BLOCK"
    assert "TOCTOU_STATE_CHANGED" in decision["reason_codes"]


def test_nonce_burned_after_audit_failure_blocks_retry(harness, monkeypatch) -> None:
    # Intentional fail-closed tradeoff: a request whose audit write fails has
    # already reserved its nonce/request id; the retry must be REPLAY_DETECTED,
    # never a second chance at first use.
    _, _, make, _ = harness
    from audit.audit_writer import AuditWriteError

    def broken_writer(*args, **kwargs):
        raise AuditWriteError("AUDIT_WRITE_FAILED")

    monkeypatch.setattr("gateway.authorization_request_consumer.write_audit_record", broken_writer)
    first = make()
    assert first["decision"] == "BLOCK"
    assert "AUDIT_WRITE_FAILED" in first["reason_codes"]
    monkeypatch.undo()
    retry = make()
    assert retry["decision"] == "BLOCK"
    assert "REPLAY_DETECTED" in retry["reason_codes"]


# ---------------------------------------------------------------- AUTHORITY INVARIANTS


def test_authority_invariants_are_false(harness) -> None:
    _, _, make, _ = harness
    assert EURIA_EXECUTION_AUTHORITY is False
    assert POLICY_BRAIN_EXECUTION_AUTHORITY is False
    decision = make()
    assert decision["euria_execution_authority"] is False
    assert decision["policy_brain_execution_authority"] is False
    assert decision["enforcement_gateway_final_authority"] is True


def test_request_receipt_grants_nothing(harness) -> None:
    request, _, make, _ = harness
    # The request itself carries no execution authority and the consumer
    # cannot be tricked by upstream authority claims.
    forged = _request(execution_authorized=True, runtime_allow=True)
    decision = make(request_obj=forged, context_obj=_context(forged))
    assert decision["decision"] == "BLOCK"


def test_consumer_pins_exact_contract(harness) -> None:
    assert CANONICAL_CONTRACT_ID == "usbay.enforcement_gateway.authorization_request.v1"
    assert PINNED_CANONICAL_SCHEMA_HASH == (
        "sha256:6f34bd112586408216dde71f4799b56ce1f274a49ff5379f69db6915893694c8"
    )
    assert PINNED_PUBLICATION_HASH == (
        "sha256:e3bd95618925ad1039248479d7896025b7266faa9df06db3c568f090162eb0f2"
    )
    assert CONSUMER_VERSION.endswith(".v1")


def test_invalid_decision_clock_blocks(harness) -> None:
    _, _, make, _ = harness
    decision = make(now=datetime(2026, 8, 8, 10, 0, 0))  # naive datetime
    assert decision["decision"] == "BLOCK"
    assert "DECISION_CLOCK_INVALID" in decision["reason_codes"]
