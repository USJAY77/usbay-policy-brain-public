"""Synthetic lifecycle-boundary tests; no real adapter or application server.

The boundary harness replaces prior decision/Hydra validation with an explicitly
synthetic valid decision. The authorization consumer, signed audit ledger and
SQLite lifecycle store remain real. Existing endpoint/identity tests cover the
earlier validation path separately.
"""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
import sqlite3
import threading
from types import SimpleNamespace

import pytest

import gateway.app as gateway
import gateway.authorization_request_consumer as consumer
from governance.hashing import sha256_reference
from security import execution_lifecycle_store as lifecycle, gateway_lifecycle as binding_module
from security.decision_store import DecisionStoreTestDouble
from tests.provenance_helpers import install_runtime_authority
from tests.test_audit_exporter import isolated_anchor_keys
from tests.test_gateway_authorization_request_consumer import NOW, _request, _context, _authority_registry


@pytest.fixture
def boundary(tmp_path, monkeypatch):
    install_runtime_authority(monkeypatch, tmp_path)
    isolated_anchor_keys(tmp_path, monkeypatch)
    request = _request()
    registry = _authority_registry(tmp_path, request, _context(request), "authority")
    audit_path = tmp_path / "consumer.json"
    replay = consumer.GatewayAuthorizationReplayStore(tmp_path / "consumer.db")
    store = lifecycle.SQLiteExecutionLifecycleStore(tmp_path / "lifecycle.db", gateway_audit_path=audit_path)
    payload = {"action": "read", "tenant_id": "t1", "policy_version": "synthetic-v1",
               "compute_target": "cpu", "gateway_authorization_request": request}
    decisions = DecisionStoreTestDouble()
    decision = decisions.create_decision({
        "decision_id": "synthetic-decision-001", "decision": "ALLOW", "tenant_id": "t1",
        "policy_version": payload["policy_version"], "policy_hash": request["policy_hash"][7:],
        "request_hash": hashlib.sha256(gateway.request_signature_message(payload).encode()).hexdigest(),
        "actor_hash": "a" * 64, "nonce_hash": "b" * 64,
        "compute_policy_hash": "c" * 64, "compute_target": "cpu",
        "data_sensitivity": "low", "execution_location": "local",
        "policy_pubkey_id": "synthetic-policy-key", "policy_sequence": 1,
        "policy_valid_from": "2026-01-01T00:00:00Z", "policy_valid_until": "2030-01-01T00:00:00Z",
        "signature_valid": True,
    })
    payload["decision_id"] = decision["decision_id"]
    calls = []
    captured = []
    call_lock = threading.Lock()

    def validate(_payload):
        record = decisions.load_decision(decision["decision_id"])
        if record["used"]:
            return False, gateway.JSONResponse(status_code=403, content={"error": "replay_detected"})
        return True, {**record, "_canonical_gate_proof": {"synthetic": True}}

    def authorize(request, **kwargs):
        return consumer.consume_gateway_authorization_request(
            request, authority_registry=registry, replay_store=replay, audit_path=audit_path, now=NOW,
        )

    def adapter(_payload, _decision, **kwargs):
        with call_lock:
            calls.append("synthetic_adapter")
        return {"actual_execution_target": "cpu", "execution_verified": True,
                "compute_target": "cpu", "routing_status": "executed"}

    monkeypatch.setattr(gateway, "validate_execution_decision", validate)
    monkeypatch.setattr(gateway, "verify", lambda _payload: True)
    monkeypatch.setattr(gateway, "consume_gateway_authorization_request", authorize)
    monkeypatch.setattr(gateway.execution_lifecycle_store, "default_lifecycle_store", lambda: store)
    monkeypatch.setattr(gateway, "route_execution", adapter)
    monkeypatch.setattr(gateway, "decision_store", decisions)
    monkeypatch.setattr(gateway, "audit_governance_event", lambda event, value: captured.append((event, value)))
    monkeypatch.setattr(gateway, "audit_chain", SimpleNamespace(append=lambda *args: None))
    monkeypatch.setenv("USBAY_GATEWAY_AUTHZ_AUDIT_PATH", str(audit_path))
    return SimpleNamespace(payload=payload, decision=decision, decisions=decisions, calls=calls,
                           captured=captured, store=store, replay=replay, registry=registry,
                           audit_path=audit_path, tmp_path=tmp_path, authorize=authorize, validate=validate)


def _binding_from_store(boundary):
    with sqlite3.connect(boundary.store._db_path) as conn:
        evidence = json.loads(conn.execute("SELECT evidence_json FROM execution_lifecycle").fetchone()[0])
    return evidence["binding"]


def test_default_authorization_block_never_creates_lifecycle(boundary, monkeypatch):
    monkeypatch.setattr(gateway, "consume_gateway_authorization_request",
                        lambda *args, **kwargs: {"decision": "BLOCK", "execution_authorized": False})
    assert gateway.execute(dict(boundary.payload)).status_code == 403
    assert boundary.calls == []
    assert not boundary.store._db_path.exists()


def test_allow_builds_explicit_binding_and_completes(boundary):
    assert gateway.execute(dict(boundary.payload)) == {"status": "EXECUTED"}
    binding = _binding_from_store(boundary)
    assert binding_module.valid_binding(binding)
    assert "execution_authorization_hash" not in binding
    assert binding["authority_kind"] == "gateway_consumer_allow"
    assert binding["decision_id"] == boundary.decision["decision_id"]
    assert binding["nonce_reference"] == boundary.payload["gateway_authorization_request"]["nonce_reference"]
    assert boundary.store.recover(binding).state == lifecycle.COMPLETED
    with sqlite3.connect(boundary.store._db_path) as conn:
        assert conn.execute("SELECT execution_authorization_hash FROM execution_lifecycle").fetchone()[0] is None


def test_concurrent_identical_requests_enter_adapter_exactly_once(boundary, monkeypatch):
    barrier = threading.Barrier(32)

    def validate(payload):
        result = boundary.validate(payload)
        barrier.wait(timeout=10)
        return result

    monkeypatch.setattr(gateway, "validate_execution_decision", validate)
    with ThreadPoolExecutor(max_workers=32) as pool:
        responses = list(pool.map(lambda _: gateway.execute(dict(boundary.payload)), range(32)))
    assert boundary.calls == ["synthetic_adapter"]
    assert sum(response == {"status": "EXECUTED"} for response in responses) == 1
    assert sum(getattr(response, "status_code", None) == 403 for response in responses) == 31


@pytest.mark.parametrize("field,value", [
    ("decision_id", "different-decision"), ("tenant_id", "t2"),
    ("policy_version", "different-policy"), ("action", "write"),
])
def test_decision_tenant_policy_action_substitution_never_reaches_adapter(boundary, field, value):
    payload = {**boundary.payload, field: value}
    assert gateway.execute(payload).status_code == 403
    assert boundary.calls == []


def test_environment_substitution_blocks(boundary):
    request = {**boundary.payload["gateway_authorization_request"], "environment_reference": sha256_reference("other")}
    response = gateway.execute({**boundary.payload, "gateway_authorization_request": request})
    assert response.status_code == 403
    assert boundary.calls == []


def test_policy_hash_substitution_blocks(boundary):
    # The boundary harness deliberately omits the prior signature validator;
    # binding must still reject a different policy against committed ALLOW.
    boundary.decisions.records[boundary.decision["decision_id"]]["policy_hash"] = "f" * 64
    assert gateway.execute(dict(boundary.payload)).status_code == 403
    assert boundary.calls == []


@pytest.mark.parametrize("reuse", ["nonce_reference", "request_id"])
def test_request_and_nonce_reservations_block_independently(boundary, reuse):
    request = boundary.payload["gateway_authorization_request"]
    assert boundary.authorize(request)["decision"] == "ALLOW"
    other = _request(
        request_id="different-request" if reuse == "nonce_reference" else request["request_id"],
        nonce_reference=sha256_reference("different-nonce") if reuse == "request_id" else request["nonce_reference"],
    )
    other_registry = _authority_registry(boundary.tmp_path, other, _context(other), "other_authority")
    result = consumer.consume_gateway_authorization_request(
        other, authority_registry=other_registry, replay_store=boundary.replay,
        audit_path=boundary.audit_path, now=NOW,
    )
    assert result["decision"] == "BLOCK"
    assert "REPLAY_DETECTED" in result["reason_codes"]
    assert boundary.calls == []


def test_client_supplied_audit_hash_cannot_replace_consumer_evidence(boundary, monkeypatch):
    result = boundary.authorize(boundary.payload["gateway_authorization_request"])
    result["audit"]["audit_hash"] = "f" * 64
    monkeypatch.setattr(gateway, "consume_gateway_authorization_request", lambda *a, **k: result)
    assert gateway.execute(dict(boundary.payload)).status_code == 403
    assert boundary.calls == []


def test_adapter_exception_is_uncertain_and_never_reusable(boundary, monkeypatch):
    def failing_adapter(*args, **kwargs):
        boundary.calls.append("synthetic_failure")
        raise RuntimeError("synthetic-sensitive-adapter-detail")

    monkeypatch.setattr(gateway, "route_execution", failing_adapter)
    response = gateway.execute(dict(boundary.payload))
    assert response.status_code == 403
    binding = _binding_from_store(boundary)
    assert boundary.store.recover(binding).state == lifecycle.PARTIAL_UNKNOWN
    assert gateway.execute(dict(boundary.payload)).status_code == 403
    assert boundary.calls == ["synthetic_failure"]
    assert b"synthetic-sensitive-adapter-detail" not in response.body


def test_crash_after_acquisition_preserves_start_and_blocks_retry(boundary, monkeypatch):
    def interrupted(*args, **kwargs):
        raise SystemExit("synthetic interruption")

    monkeypatch.setattr(gateway, "route_execution", interrupted)
    with pytest.raises(SystemExit):
        gateway.execute(dict(boundary.payload))
    binding = _binding_from_store(boundary)
    reopened = lifecycle.SQLiteExecutionLifecycleStore(boundary.store._db_path, gateway_audit_path=boundary.audit_path)
    assert reopened.recover(binding).state == lifecycle.PARTIAL_UNKNOWN
    assert reopened.acquire_execution_start(binding, started_at="synthetic-retry").result != lifecycle.START_ACQUIRED
    assert gateway.execute(dict(boundary.payload)).status_code == 403


def test_terminal_write_failure_keeps_start_after_reopen(boundary, monkeypatch):
    monkeypatch.setattr(boundary.store, "record_terminal_outcome", lambda *a, **k: (_ for _ in ()).throw(OSError("synthetic")))
    assert gateway.execute(dict(boundary.payload)).status_code == 403
    binding = _binding_from_store(boundary)
    reopened = lifecycle.SQLiteExecutionLifecycleStore(boundary.store._db_path, gateway_audit_path=boundary.audit_path)
    assert reopened.recover(binding).state == lifecycle.PARTIAL_UNKNOWN
    assert gateway.execute(dict(boundary.payload)).status_code == 403
    assert boundary.calls == ["synthetic_adapter"]


def test_mark_used_failure_cannot_reopen_authority(boundary):
    boundary.decisions.fail_mark_used = True
    assert gateway.execute(dict(boundary.payload)).status_code == 403
    binding = _binding_from_store(boundary)
    assert boundary.store.recover(binding).state == lifecycle.COMPLETED
    assert gateway.execute(dict(boundary.payload)).status_code == 403
    assert boundary.calls == ["synthetic_adapter"]


@pytest.mark.parametrize("state", [lifecycle.COMPLETED, lifecycle.FAILED, lifecycle.PARTIAL_UNKNOWN])
def test_gateway_terminal_states_survive_reopen_and_never_reacquire(boundary, state):
    result = boundary.authorize(boundary.payload["gateway_authorization_request"])
    binding = binding_module.build_binding(boundary.payload, boundary.decision, result, audit_path=boundary.audit_path)
    assert boundary.store.acquire_execution_start(binding, started_at="synthetic-start").result == lifecycle.START_ACQUIRED
    outcome_hash = sha256_reference({"synthetic_verified_observation": state})
    evidence_hash = binding_module.record_outcome(binding, state=state, outcome_hash=outcome_hash,
                                                 tenant_id="t1", audit_path=boundary.audit_path)
    assert boundary.store.record_terminal_outcome(binding, outcome_state=state, outcome_hash=outcome_hash,
                                                  current_evidence_hash=evidence_hash,
                                                  completed_at="synthetic-completion").result == lifecycle.TERMINAL_RECORDED
    reopened = lifecycle.SQLiteExecutionLifecycleStore(boundary.store._db_path, gateway_audit_path=boundary.audit_path)
    assert reopened.recover(binding).state == state
    assert reopened.acquire_execution_start(binding, started_at="synthetic-retry").result != lifecycle.START_ACQUIRED


def test_conflicting_shape_does_not_escape_authority_namespace(boundary):
    result = boundary.authorize(boundary.payload["gateway_authorization_request"])
    binding = binding_module.build_binding(boundary.payload, boundary.decision, result, audit_path=boundary.audit_path)
    assert boundary.store.acquire_execution_start(binding, started_at="synthetic-start").result == lifecycle.START_ACQUIRED
    changed = {**binding, "action_hash": sha256_reference("different-action")}
    changed["binding_hash"] = binding_module.binding_hash(changed)
    assert boundary.store.acquire_execution_start(changed, started_at="synthetic-retry").result == lifecycle.LIFECYCLE_BINDING_MISMATCH


@pytest.mark.parametrize("failure", ["corrupt", "unavailable", "locked"])
def test_storage_failure_blocks_before_adapter(boundary, monkeypatch, failure):
    if failure == "corrupt":
        boundary.store._db_path.write_bytes(b"synthetic-corrupt-sqlite")
    else:
        def unavailable():
            raise sqlite3.OperationalError("database is locked" if failure == "locked" else "unavailable")
        monkeypatch.setattr(boundary.store, "_connect", unavailable)
    assert gateway.execute(dict(boundary.payload)).status_code == 403
    assert boundary.calls == []


def test_sensitive_adapter_output_is_excluded_from_new_evidence(boundary, monkeypatch):
    secret = "synthetic-sensitive-adapter-detail"
    monkeypatch.setattr(gateway, "route_execution", lambda *a, **k: {
        "actual_execution_target": "cpu", "execution_verified": True,
        "compute_target": "cpu", "routing_status": "executed", "raw_payload": secret,
    })
    response = gateway.execute(dict(boundary.payload))
    assert response == {"status": "EXECUTED"}
    assert secret not in json.dumps(boundary.captured)
    assert secret.encode() not in boundary.store._db_path.read_bytes()
    assert secret not in boundary.audit_path.read_text()


def test_terminal_signed_evidence_loss_is_not_treated_as_success(boundary):
    assert gateway.execute(dict(boundary.payload)) == {"status": "EXECUTED"}
    binding = _binding_from_store(boundary)
    from audit.immutable_ledger import ledger_path_for
    ledger_path_for(boundary.audit_path).write_text("synthetic-corrupt-ledger")
    assert boundary.store.recover(binding).result == lifecycle.LIFECYCLE_STATE_CORRUPTED


def test_hash_only_authority_cannot_acquire_start(boundary):
    result = boundary.authorize(boundary.payload["gateway_authorization_request"])
    binding = binding_module.build_binding(boundary.payload, boundary.decision, result, audit_path=boundary.audit_path)
    binding["authority_reference"] = sha256_reference("uncommitted-authority")
    binding["binding_hash"] = binding_module.binding_hash(binding)
    assert boundary.store.acquire_execution_start(binding, started_at="synthetic-start").result == lifecycle.LIFECYCLE_BINDING_INVALID
    assert not boundary.store._db_path.exists()


def test_gateway_union_preserves_existing_v1_start_evidence(boundary):
    from tests.test_execution_lifecycle_store import _binding

    existing = _binding()
    first = boundary.store.acquire_execution_start(existing, started_at="synthetic-v1-start")
    assert first.result == lifecycle.START_ACQUIRED
    with sqlite3.connect(boundary.store._db_path) as conn:
        before = conn.execute("SELECT * FROM execution_lifecycle WHERE execution_authorization_hash = ?",
                              (existing["execution_authorization_hash"],)).fetchone()
    assert gateway.execute(dict(boundary.payload)) == {"status": "EXECUTED"}
    with sqlite3.connect(boundary.store._db_path) as conn:
        after = conn.execute("SELECT * FROM execution_lifecycle WHERE execution_authorization_hash = ?",
                             (existing["execution_authorization_hash"],)).fetchone()
    assert before == after
    assert boundary.store.recover(existing).state == lifecycle.PARTIAL_UNKNOWN


def test_post_terminal_audit_failure_cannot_cause_second_adapter_entry(boundary, monkeypatch):
    def fail_audit(*args):
        raise OSError("synthetic-sensitive-path")

    monkeypatch.setattr(gateway, "audit_governance_event", fail_audit)
    response = gateway.execute(dict(boundary.payload))
    assert response.status_code == 403
    assert gateway.execute(dict(boundary.payload)).status_code == 403
    assert boundary.calls == ["synthetic_adapter"]
    assert b"synthetic-sensitive-path" not in response.body


def test_unsupported_lifecycle_backend_blocks_before_adapter(boundary, monkeypatch):
    monkeypatch.setattr(gateway.execution_lifecycle_store, "default_lifecycle_store",
                        lambda: lifecycle.UnsupportedExecutionLifecycleStore())
    assert gateway.execute(dict(boundary.payload)).status_code == 403
    assert boundary.calls == []
    assert not boundary.store._db_path.exists()
