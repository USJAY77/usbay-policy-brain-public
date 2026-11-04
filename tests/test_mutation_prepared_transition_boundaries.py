"""Bounded real-SQLite/real-ledger-adapter tests; providers and keys synthetic."""
from concurrent.futures import ThreadPoolExecutor
from copy import deepcopy
from threading import Barrier
import sqlite3

import pytest

from governance.mutation_currentness_source import (
    SQLiteMutationCurrentnessFence, _SQLiteMutationCurrentnessGuard,
    projection_payload_hash,
)
from governance.mutation_high_water_ledger import ImmutableLedgerMutationHighWater, _HeldLedgerAnchor
from governance.tenant_enrollment_contracts import canonical, digest, parse_json
from governance.mutation_adoption_finalization import verify_finalization_composition
from governance.mutation_adoption_finalization_writer import GovernedAdoptionFinalizationWriter
from governance.mutation_policy_revocation_writer import GovernedPolicyRevocationWriter
from governance.mutation_grant_revocation_writer import GovernedGrantRevocationWriter
from governance.mutation_adoption_revocation_writer import GovernedAdoptionRevocationWriter
from tests.test_mutation_currentness_source import projected_commit
from tests.test_mutation_high_water_ledger import SyntheticLedgerWriter, _record
from tests.test_mutation_real_sqlite_transitions import (
    _bundle, _successor_with_revocation, EnrollmentPolicy, EnrollmentGrant, PolicyAdoption,
    build_effect_for_mutation, build_grant_effect_for_mutation, build_adoption_effect_for_mutation,
    build_finalization_artifacts, SyntheticFinalizationSource, SyntheticTransitionSource,
    SyntheticGrantTransitionSource, SyntheticAdoptionTransitionSource, NOW,
)


@pytest.fixture(params=["FINALIZE_POLICY_ADOPTION", "REVOKE_POLICY_OBJECT",
                        "REVOKE_GRANT_OBJECT", "REVOKE_ADOPTION"])
def chain(request, tmp_path):
    action = request.param
    f, source, anchor = projected_commit(tmp_path, action=action)
    effect = None
    if action == "FINALIZE_POLICY_ADOPTION":
        artifacts, pending, pending_hash = build_finalization_artifacts(f)
        result = verify_finalization_composition(
            f.view.trust, previous_currentness=f.f.currentness(),
            previous_head=f.f.enrollment.head, pending_event=pending,
            pending_event_hash=pending_hash, artifacts=artifacts, now=NOW)
        assert result["decision"] == "ALLOW"
        state = deepcopy(f.state)
        state["witness_reference"] = digest({
            "h_witness_hash": result["composition"]["h_witness_hash"],
            "w_witness_hash": result["composition"]["w_witness_hash"]})
        state["finality_reference"] = result["composition_hash"]
        command = f.new_command(expected_state=state)
        with sqlite3.connect(f.path) as conn:
            projection = parse_json(conn.execute(
                "SELECT projection FROM mutation_currentness_projection").fetchone()[0])
            projection["target_state"] = state
            anchor.record["projection_hash"] = projection_payload_hash(projection)
            conn.execute("UPDATE mutation_currentness_projection SET projection=?,projection_hash=?",
                         (canonical(projection).decode(), anchor.record["projection_hash"]))
        table, columns = "adoption_finalization", (
            "adoption_id TEXT,adoption_version_hash TEXT,policy_id TEXT,policy_hash TEXT,"
            "previous_head TEXT,target_head TEXT,pending_event_hash TEXT,composition_hash TEXT,")
        writer = GovernedAdoptionFinalizationWriter(
            f.view, currentness_fence=source, artifact_source=SyntheticFinalizationSource(artifacts))
    else:
        model, effect_builder, writer_cls, provider_cls, table, specific = {
            "REVOKE_POLICY_OBJECT": (EnrollmentPolicy, build_effect_for_mutation,
                GovernedPolicyRevocationWriter, SyntheticTransitionSource, "policy_revocation_terminal", ""),
            "REVOKE_GRANT_OBJECT": (EnrollmentGrant, build_grant_effect_for_mutation,
                GovernedGrantRevocationWriter, SyntheticGrantTransitionSource, "grant_revocation_terminal",
                "target_grant_id TEXT,consumption_state TEXT,"),
            "REVOKE_ADOPTION": (PolicyAdoption, build_adoption_effect_for_mutation,
                GovernedAdoptionRevocationWriter, SyntheticAdoptionTransitionSource, "adoption_revocation_terminal",
                "adoption_id TEXT,policy_id TEXT,finalization_state TEXT,"),
        }[action]
        effect = effect_builder(f.f)
        f.view.trust = f.f.trust
        successor = _successor_with_revocation(f.f.enrollment, model, f.f.commit_target["payload"])
        command = f.new_command(revocation_effect_scope="ALL_VERSIONS_OF_OBJECT",
                               revocation_effect_grant_hash=digest(effect["grant"]["payload"]))
        columns = ("object_id TEXT,object_version_hash TEXT," + specific +
                   "revocation_reference TEXT,revocation_hash TEXT,"
                   "terminal_projection_hash TEXT,terminal_proof_hash TEXT,")
        writer = writer_cls(f.view, currentness_fence=source,
                            transition_source=provider_cls(_bundle(successor)))
    with sqlite3.connect(f.path) as conn:
        conn.execute("CREATE TABLE " + table + "(scope_hash TEXT," + columns +
                     "source_epoch INTEGER,source_version INTEGER,command_hash TEXT,transaction_id TEXT)")
    previous = deepcopy(anchor.record)
    boundary = digest({"synthetic-held-ledger": action})
    tenant = command["payload"]["tenant_id"]
    records = [_record(tenant, boundary, previous, digest({"genesis": previous["scope_hash"]}))]
    ledger = SyntheticLedgerWriter(records, boundary)
    high_water = ImmutableLedgerMutationHighWater(
        "unused", tenant_id=tenant, writer=ledger, storage_boundary_reference=boundary,
        reader=lambda _: deepcopy(records))
    source._high_water = high_water

    def run():
        kwargs = dict(proposal=f.f.proposal, reviews=f.f.reviews, grant=f.f.grant)
        if effect is not None:
            kwargs["revocation_effect"] = effect
        return writer.execute(command, **kwargs)
    return f, source, high_water, ledger, previous, run


def snapshot(f):
    with sqlite3.connect(f.path) as conn:
        return tuple(conn.iterdump())


def test_all_writers_commit_full_projection_once(chain):
    f, _, high_water, ledger, previous, run = chain
    with sqlite3.connect(f.path) as conn:
        before = SQLiteMutationCurrentnessFence._load(conn, previous["scope_hash"])[2]
    result = run()
    assert result["decision"] == "ALLOW", result
    with sqlite3.connect(f.path) as conn:
        epoch, version, after, projection_hash = SQLiteMutationCurrentnessFence._load(conn, previous["scope_hash"])
        f.view._snapshot(conn, require_finalized=False)
    assert set(after) == set(before)
    for k in set(before) - {"currentness", "target_state", "expected_current_head",
                           "revocation_reference", "authority_status"}:
        assert canonical(after[k]) == canonical(before[k])
    assert after["authority_status"] == dict(before["authority_status"], issuance_state="CONSUMED")
    assert high_water._current(previous["scope_hash"]) == dict(
        previous, source_epoch=epoch, source_version=version, projection_hash=projection_hash)
    assert version == 2
    stored = snapshot(f)
    assert run()["decision"] == "DENY"
    assert snapshot(f) == stored and len(ledger.records) == 2


@pytest.mark.parametrize("field", ["projection", "previous_position", "proposed_position",
                                  "command_hash", "action", "terminal", "prepared_hash"])
def test_returned_prepared_token_cannot_be_substituted(chain, monkeypatch, field):
    f, _, _, ledger, _, run = chain
    before = snapshot(f)
    original = _SQLiteMutationCurrentnessGuard.commit_transition_if_current
    def substituted(self, connection, **kwargs):
        token = kwargs["prepared_transition"]
        token[field] = {"substituted": True} if type(token[field]) is dict else "substituted"
        return original(self, connection, **kwargs)
    monkeypatch.setattr(_SQLiteMutationCurrentnessGuard, "commit_transition_if_current", substituted)
    result = run()
    assert result["decision"] == "DENY"
    assert snapshot(f) == before and len(ledger.records) == 1


@pytest.mark.parametrize("kind", ["update_id", "evidence_hash", "fence_command", "fence_epoch"])
def test_commit_metadata_is_exactly_bound(chain, monkeypatch, kind):
    f, _, _, ledger, _, run = chain
    before = snapshot(f)
    original = _SQLiteMutationCurrentnessGuard.commit_transition_if_current
    def altered(self, connection, **kwargs):
        if kind == "update_id": kwargs["update_id"] = "different-update"
        if kind == "evidence_hash": kwargs["transition_evidence_hash"] = digest({"unrelated-proof": 1})
        if kind == "fence_command": kwargs["fence"]["command_hash"] = digest({"other-command": 1})
        if kind == "fence_epoch": kwargs["fence"]["source_epoch"] += 1
        return original(self, connection, **kwargs)
    monkeypatch.setattr(_SQLiteMutationCurrentnessGuard, "commit_transition_if_current", altered)
    result = run()
    assert result["decision"] == "DENY", result
    assert snapshot(f) == before and len(ledger.records) == 1


@pytest.mark.parametrize("kind", ["post_state", "terminal", "successor_scope",
                                  "post_state_extra", "successor_signature"])
def test_preparation_descriptor_must_match_verified_action(chain, monkeypatch, kind):
    f, _, _, ledger, _, run = chain
    before = snapshot(f)
    original = _SQLiteMutationCurrentnessGuard.prepare_transition
    def altered(self, connection, **kwargs):
        if kind == "post_state": kwargs["post_state"]["status"] = "ACTIVE"
        if kind == "post_state_extra": kwargs["post_state"]["execution_authority"] = True
        if kind == "successor_signature": kwargs["successor_currentness"]["h"]["signature"] = "00" * 64
        if kind == "terminal": kwargs["terminal"] = not kwargs["terminal"]
        if kind == "successor_scope": kwargs["successor_currentness"]["expected"]["tenant_id"] = "different-tenant"
        return original(self, connection, **kwargs)
    monkeypatch.setattr(_SQLiteMutationCurrentnessGuard, "prepare_transition", altered)
    result = run()
    assert result["decision"] == "DENY", result
    assert snapshot(f) == before and len(ledger.records) == 1


def test_issuance_replay_consumption_is_required(chain, monkeypatch):
    f, _, _, ledger, _, run = chain
    before = snapshot(f)
    original = f.view._consume
    def omit_replay(conn, kind, payload):
        if kind != "mutation_issuance":
            return original(conn, kind, payload)
        # Inject a writer fault before the immutable event snapshots consumption.
        for label, value in (("grant_id", payload["grant_id"]), ("nonce", payload["nonce"])):
            conn.execute("INSERT INTO enrollment_uses VALUES(?,?)", (
                kind+":"+label, digest({"issuer": payload["issuer_id"], "value": value})))
    monkeypatch.setattr(f.view, "_consume", omit_replay)
    result = run()
    assert result["decision"] == "DENY", result
    assert snapshot(f) == before and len(ledger.records) == 1


def test_same_command_concurrency_consumes_once(chain):
    f, _, _, ledger, _, run = chain
    start = Barrier(2)
    def attempt():
        start.wait(timeout=5)
        return run()
    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [pool.submit(attempt) for _ in range(2)]
        results = [future.result(timeout=15) for future in futures]
    assert sorted(r["decision"] for r in results) == ["ALLOW", "DENY"]
    assert len(ledger.records) == 2
    with sqlite3.connect(f.path) as conn:
        f.view._snapshot(conn, require_finalized=False)


def test_lost_ack_is_unknown_and_not_retried(chain, monkeypatch):
    f, _, high_water, ledger, previous, run = chain
    original = _HeldLedgerAnchor.transition_and_commit
    def lost_ack(self, connection, **kwargs):
        original(self, connection, **kwargs)
        raise OSError("synthetic lost commit acknowledgement")
    monkeypatch.setattr(_HeldLedgerAnchor, "transition_and_commit", lost_ack)
    result = run()
    assert result["reason"] == "COMMIT_STATE_UNKNOWN"
    assert result["reconciliation_required"] is True
    with sqlite3.connect(f.path) as conn:
        epoch, version, _, h = SQLiteMutationCurrentnessFence._load(conn, previous["scope_hash"])
        f.view._snapshot(conn, require_finalized=False)
    assert high_water._current(previous["scope_hash"]) == dict(previous, source_epoch=epoch,
                                                            source_version=version, projection_hash=h)
    assert len(ledger.records) == 2


def test_ledger_ahead_sqlite_failure_is_unknown_and_blocks_reuse(chain, monkeypatch):
    f, _, high_water, ledger, previous, run = chain
    before = snapshot(f)
    original = _HeldLedgerAnchor.transition_and_commit
    def fail_commit(self, connection, **kwargs):
        class FailedCommit:
            def execute(self, sql, *args):
                if sql == "COMMIT": raise sqlite3.OperationalError("synthetic failed COMMIT")
                return connection.execute(sql, *args)
        return original(self, FailedCommit(), **kwargs)
    monkeypatch.setattr(_HeldLedgerAnchor, "transition_and_commit", fail_commit)
    result = run()
    assert result["reason"] == "COMMIT_STATE_UNKNOWN"
    assert snapshot(f) == before
    assert high_water._current(previous["scope_hash"])["source_version"] == 2
    assert run()["decision"] == "DENY"
    assert len(ledger.records) == 2


def test_exact_cas_zero_rows_rolls_back(chain):
    f, _, _, ledger, _, run = chain
    with sqlite3.connect(f.path) as conn:
        conn.execute("CREATE TRIGGER synthetic_ignore BEFORE UPDATE ON mutation_currentness_projection "
                     "BEGIN SELECT RAISE(IGNORE); END")
    before = snapshot(f)
    assert run()["decision"] == "DENY"
    assert snapshot(f) == before and len(ledger.records) == 1


@pytest.mark.parametrize("kind", ["wrong_position", "empty_event_hash"])
def test_bad_commit_receipt_is_unknown_without_retry(chain, monkeypatch, kind):
    _, _, _, ledger, _, run = chain
    original = _HeldLedgerAnchor.transition_and_commit
    def bad_receipt(self, connection, **kwargs):
        receipt = original(self, connection, **kwargs)
        if kind == "wrong_position": receipt["position"]["source_version"] += 1
        else: receipt["event_hash"] = ""
        return receipt
    monkeypatch.setattr(_HeldLedgerAnchor, "transition_and_commit", bad_receipt)
    result = run()
    assert result["reason"] == "COMMIT_STATE_UNKNOWN", result
    assert result["reconciliation_required"] is True
    assert len(ledger.records) == 2


def test_boolean_substitution_in_prepared_position_is_rejected(chain, monkeypatch):
    f, _, _, ledger, _, run = chain
    before = snapshot(f)
    original = _SQLiteMutationCurrentnessGuard.commit_transition_if_current
    def altered(self, connection, **kwargs):
        kwargs["prepared_transition"]["proposed_position"]["source_epoch"] = True
        return original(self, connection, **kwargs)
    monkeypatch.setattr(_SQLiteMutationCurrentnessGuard, "commit_transition_if_current", altered)
    assert run()["decision"] == "DENY"
    assert snapshot(f) == before and len(ledger.records) == 1
