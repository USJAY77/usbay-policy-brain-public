from copy import deepcopy
from datetime import timedelta
import multiprocessing
import sqlite3

import pytest

from governance.authority_registry import EnrollmentAuthorityView
from governance.tenant_enrollment_contracts import FLAGS, canonical, digest
from tests.helpers.tenant_enrollment import (
    NOW, synthetic_enrollment, native_enrollment_worker, native_adoption_worker, native_crash_worker,
)


def counts(path):
    with sqlite3.connect(path) as conn:
        return tuple(conn.execute("SELECT COUNT(*) FROM " + name).fetchone()[0] for name in
                     ("enrollment_events", "enrollment_uses", "enrollment_tenants"))


def test_missing_store_never_bootstraps(tmp_path):
    path = tmp_path / "missing.sqlite"
    view = EnrollmentAuthorityView(path)
    assert not path.exists()
    assert view.enroll({})["decision"] == "DENY"
    assert view.propose_adoption({})["decision"] == "DENY"
    assert view.history()["decision"] == "DENY"
    assert not path.exists()


def test_empty_existing_store_is_not_implicit_genesis(tmp_path):
    path = tmp_path / "empty.sqlite"
    sqlite3.connect(path).close()
    before = path.read_bytes()
    assert EnrollmentAuthorityView(path).enroll({})["decision"] == "DENY"
    assert path.read_bytes() == before


def test_single_local_commit_replay_and_no_operational_authority(tmp_path):
    f = synthetic_enrollment()
    path = tmp_path / "authority.sqlite"
    f.store(path)
    view = EnrollmentAuthorityView(path, f.trust, clock=lambda: NOW)
    result = view.enroll(f.inputs)
    assert result["registration_outcome"] == "COMMITTED_NON_EXECUTING"
    assert result["decision"] == "DENY" and result["reason"] == "SIGNED_RECEIPT_REQUIRED"
    assert result["retry_allowed"] is False
    assert result["authority_flags"] == dict.fromkeys(FLAGS, False)
    assert counts(path) == (1, 6, 1)
    for _ in range(2):
        assert view.enroll(f.inputs)["registration_outcome"] == "NOT_COMMITTED"
        assert counts(path) == (1, 6, 1)
    history = view.history()
    record = history["events"][0]["record"]
    assert record["allowed_actions"] == []
    assert record["authority_flags"] == dict.fromkeys(FLAGS, False)
    assert record["tenant_id"] != "usbay-mail-pilot-01-fbffedb3f5873e7e"
    # No runtime allowlist, mailbox, OAuth or provider API is involved.
    for name in ("runtime_admission", "send_email", "oauth", "recover", "reset", "release", "finalize"):
        assert not hasattr(view, name)


def test_failed_final_recheck_rolls_back_consumption_and_registration(tmp_path):
    f = synthetic_enrollment()
    path = tmp_path / "authority.sqlite"
    f.store(path)
    times = iter((NOW, NOW + timedelta(hours=2)))
    view = EnrollmentAuthorityView(path, f.trust, clock=lambda: next(times))
    assert view.enroll(f.inputs)["registration_outcome"] == "NOT_COMMITTED"
    assert counts(path) == (0, 0, 0)


@pytest.mark.parametrize("mutation", ["head", "revocation", "policy"])
def test_commit_boundary_mutation_cannot_use_prechecked_context(tmp_path, mutation):
    f = synthetic_enrollment()
    path = tmp_path / "authority.sqlite"
    f.store(path)
    calls = []

    def clock():
        calls.append(1)
        if len(calls) == 2:
            if mutation == "head":
                f.inputs["w"]["payload"]["head_hash"] = digest({"different": "head"})
            elif mutation == "policy":
                f.inputs["policy"]["payload"]["policy_version"] = "changed"
            else:
                f.inputs["revocations"]["payload"]["revocations"] = [{"invalid": "unsigned-mutation"}]
        return NOW

    result = EnrollmentAuthorityView(path, f.trust, clock=clock).enroll(f.inputs)
    assert result["registration_outcome"] == "NOT_COMMITTED"
    assert counts(path) == (0, 0, 0)


def test_adoption_and_head_advance_are_pending_not_current_and_not_reusable(tmp_path):
    f = synthetic_enrollment()
    path = tmp_path / "authority.sqlite"
    f.store(path)
    view = EnrollmentAuthorityView(path, f.trust, clock=lambda: NOW)
    proposal = f.next_adoption()
    result = view.propose_adoption(proposal)
    assert result.get("publication") == "PENDING"
    assert result["decision"] == "DENY"
    assert counts(path) == (1, 6, 0)
    assert view.propose_adoption(proposal)["decision"] == "DENY"
    assert view.enroll(f.inputs)["decision"] == "DENY"
    assert counts(path) == (1, 6, 0)


@pytest.mark.parametrize("kind", ["enrollment", "adoption", "advance"])
def test_preconsumed_grant_cannot_be_consumed_again(tmp_path, kind):
    f = synthetic_enrollment()
    path = tmp_path / "authority.sqlite"
    f.store(path)
    proposal = f.next_adoption()
    payload = f.inputs["grant"]["payload"] if kind == "enrollment" else proposal[kind]["payload"]
    with sqlite3.connect(path) as conn:
        EnrollmentAuthorityView._consume(conn, kind, payload)
    # Orphan consumption is uncertain history, never interpreted as unused.
    view = EnrollmentAuthorityView(path, f.trust, clock=lambda: NOW)
    result = view.enroll(f.inputs) if kind == "enrollment" else view.propose_adoption(proposal)
    assert result["decision"] == "DENY" and counts(path)[0] == 0
    assert counts(path)[1] == 3


@pytest.mark.parametrize("kind", ["enrollment", "adoption", "advance"])
def test_native_concurrent_first_commit_is_at_most_one(tmp_path, kind):
    f = synthetic_enrollment()
    path = tmp_path / "authority.sqlite"
    f.store(path)
    context = multiprocessing.get_context("spawn")
    queue = context.Queue()
    inputs = f.inputs if kind == "enrollment" else f.next_adoption()
    target = native_enrollment_worker if kind == "enrollment" else native_adoption_worker
    processes = [context.Process(target=target, args=(str(path), inputs, tuple(f.trust._keys.values()), queue)) for _ in range(4)]
    try:
        for process in processes:
            process.start()
        for process in processes:
            process.join(20)
            assert process.exitcode == 0
        results = [queue.get(timeout=3) for _ in processes]
        assert all(r["decision"] == "DENY" and r["retry_allowed"] is False for r in results)
        events, uses, tenants = counts(path)
        assert events <= 1 and uses == events * 6
        assert tenants == (events if kind == "enrollment" else 0)
    finally:
        for process in processes:
            if process.is_alive():
                process.terminate()
                process.join(5)
        queue.close()


@pytest.mark.parametrize("point,exitcode,expected", [
    ("before_commit", 73, (0, 0, 0)),
    ("after_reservation", 74, (0, 0, 0)),
    ("after_commit", 75, (1, 6, 1)),
])
def test_native_crash_reopen_preserves_atomicity_and_consumption(tmp_path, point, exitcode, expected):
    f = synthetic_enrollment()
    path = tmp_path / "authority.sqlite"
    f.store(path)
    context = multiprocessing.get_context("spawn")
    process = context.Process(target=native_crash_worker, args=(str(path), f.inputs, tuple(f.trust._keys.values()), point))
    try:
        process.start()
        process.join(20)
        assert process.exitcode == exitcode
        assert counts(path) == expected
        if point == "after_commit":
            result = EnrollmentAuthorityView(path, f.trust, clock=lambda: NOW).enroll(f.inputs)
            assert result["registration_outcome"] == "NOT_COMMITTED"
            assert counts(path) == expected
    finally:
        if process.is_alive():
            process.terminate()
            process.join(5)


def test_append_only_events_and_consumption_cannot_be_released(tmp_path):
    f = synthetic_enrollment()
    path = tmp_path / "authority.sqlite"
    f.store(path)
    assert EnrollmentAuthorityView(path, f.trust, clock=lambda: NOW).enroll(f.inputs)["registration_outcome"] == "COMMITTED_NON_EXECUTING"
    with sqlite3.connect(path) as conn:
        for sql in ("DELETE FROM enrollment_events", "UPDATE enrollment_events SET payload='{}'", "DELETE FROM enrollment_uses", "DELETE FROM enrollment_tenants"):
            with pytest.raises(sqlite3.IntegrityError):
                conn.execute(sql)


@pytest.mark.parametrize("kind", ["adoption", "advance"])
def test_exact_committed_authorization_replay_reaches_storage_unique_guard(tmp_path, kind, record_property):
    f = synthetic_enrollment()
    path = tmp_path / "authority.sqlite"
    f.store(path)
    view = EnrollmentAuthorityView(path, f.trust, clock=lambda: NOW)
    proposal = f.next_adoption()
    first = view.propose_adoption(proposal)
    assert first.get("publication") == "PENDING"
    before = counts(path)
    with sqlite3.connect(path) as conn:
        # Isolate the actual replay-consumption primitive, without clearing
        # PENDING or fabricating finalized witness history.
        with pytest.raises(sqlite3.IntegrityError, match="UNIQUE constraint failed: enrollment_uses.kind, enrollment_uses.identity"):
            view._consume(conn, kind, proposal[kind]["payload"])
    assert counts(path) == before == (1, 6, 0)
    public_repeat = view.propose_adoption(proposal)
    assert public_repeat["reason"] == "STOPPED_UNVERIFIED_POLICY_HEAD"
    assert public_repeat["internal_result"] == "REPLAY_DETECTED"
    assert public_repeat["internal_reasons"] == ["ADOPTION_REPLAY", "HEAD_ADVANCE_REPLAY"]
    record_property("boundary", "PUBLIC_DENY_WITH_VERIFIED_DURABLE_REPLAY_EVIDENCE")
    record_property("kind", kind)


def test_passive_history_read_preserves_all_database_state(tmp_path):
    f = synthetic_enrollment()
    path = tmp_path / "authority.sqlite"
    f.store(path)
    view = EnrollmentAuthorityView(path, f.trust, clock=lambda: NOW)
    assert view.enroll(f.inputs)["registration_outcome"] == "COMMITTED_NON_EXECUTING"
    with sqlite3.connect(path) as conn:
        before = list(conn.iterdump())
    result = view.history()
    assert result["reason"] == "HISTORY_ONLY" and len(result["events"]) == 1
    assert result["authority_flags"] == dict.fromkeys(FLAGS, False)
    with sqlite3.connect(path) as conn:
        assert list(conn.iterdump()) == before


@pytest.mark.parametrize("mutation", ["head_advance", "policy_revocation", "grant_revocation"])
def test_two_writer_fixture_model_rechecks_head_after_valid_precheck(tmp_path, record_property, mutation):
    """Deterministic stale-context race, not a deployed governed writer route."""
    from tests.helpers.tenant_enrollment import native_stale_precheck_worker
    from governance.tenant_enrollment_verification import evaluate_enrollment
    f = synthetic_enrollment()
    from governance.tenant_enrollment_contracts import EnrollmentPolicy, EnrollmentGrant
    from tests.helpers.tenant_enrollment import object_revocation
    entries = []
    if mutation != "head_advance":
        name = "policy" if mutation == "policy_revocation" else "grant"
        entries = [object_revocation(EnrollmentPolicy if name == "policy" else EnrollmentGrant, f.inputs[name]["payload"])]
    newer = synthetic_enrollment(private_keys=f.private, sequence=2, previous=f.head, revocations=entries)
    current = evaluate_enrollment(newer.trust, newer.inputs, expected=newer.head, now=NOW)
    if mutation == "head_advance":
        assert current.get("verification_valid") is True
    else:
        assert current["reason"] == ("POLICY_OBJECT_REVOCATION" if mutation == "policy_revocation" else "GRANT_OBJECT_REVOCATION")
    path = tmp_path / "authority.sqlite"
    f.store(path)
    context = multiprocessing.get_context("spawn")
    validated, writer_done, queue = context.Event(), context.Event(), context.Queue()
    worker = context.Process(target=native_stale_precheck_worker,
        args=(str(path), f.inputs, f.head, tuple(f.trust._keys.values()), validated, writer_done, queue))
    try:
        worker.start()
        assert validated.wait(10), "PRECHECK_BARRIER_TIMEOUT"
        # B is explicitly a synthetic test-fixture writer. No production
        # adoption/finalization API is added or implied by this model.
        with sqlite3.connect(path) as conn:
            conn.execute("BEGIN IMMEDIATE")
            import json
            state = json.loads(conn.execute("SELECT value FROM enrollment_meta WHERE name='state'").fetchone()[0])
            state["head"] = newer.head
            conn.execute("UPDATE enrollment_meta SET value=? WHERE name='state'", (canonical(state).decode(),))
        writer_done.set()
        worker.join(20)
        assert worker.exitcode == 0
        result = queue.get(timeout=3)
        assert result["reason"] == "STOPPED_UNVERIFIED_POLICY_HEAD"
        assert result["registration_outcome"] == "NOT_COMMITTED"
        assert counts(path) == (0, 0, 0)
    finally:
        writer_done.set()
        if worker.is_alive():
            worker.terminate()
            worker.join(5)
        queue.close()
    record_property("boundary", "WRITER_RACE_MODEL_LIMITATION_TEST_FIXTURE_WRITER_ONLY")
    record_property("state_transition", mutation)


@pytest.mark.parametrize("kind", ["adoption", "advance"])
def test_public_replay_diagnostics_are_exact_and_durable_without_admission_reordering(tmp_path, kind):
    f = synthetic_enrollment()
    path = tmp_path / "authority.sqlite"
    f.store(path)
    view = EnrollmentAuthorityView(path, f.trust, clock=lambda: NOW)
    inputs = f.next_adoption()
    assert view.propose_adoption(inputs).get("publication") == "PENDING"
    before = counts(path)
    repeated = deepcopy(inputs)
    if kind == "adoption":
        # Fresh independently signed B still binds the identical consumed A.
        # It has no consumed IDs; only A must be labelled as replay.
        b = repeated["advance"]["payload"]
        b.update(grant_id="fresh-b", nonce="fresh-b-nonce", replay_identity="fresh-b-replay")
        repeated["advance"] = f.sign(b)
        expected = ["ADOPTION_REPLAY"]
    else:
        # B cryptographically binds the consumed A core. Report both independently
        # checked consumed authorizations rather than masking B behind A/PENDING.
        expected = ["ADOPTION_REPLAY", "HEAD_ADVANCE_REPLAY"]
    def forbidden_mutation(*args):
        raise AssertionError("DENIED_REPLAY_MUST_NOT_CONSUME_AGAIN")
    view._consume = forbidden_mutation
    result = view.propose_adoption(repeated)
    assert result["decision"] == "DENY" and result["reason"] == "STOPPED_UNVERIFIED_POLICY_HEAD"
    assert result["internal_result"] == "REPLAY_DETECTED"
    assert result["internal_reasons"] == expected
    assert result["retry_allowed"] is False and counts(path) == before == (1, 6, 0)
    assert result["authority_flags"] == dict.fromkeys(FLAGS, False)
    assert set(result) == {"decision", "reason", "authority_flags", "retry_allowed", "adoption_outcome", "internal_result", "internal_reasons"}


def test_rolled_back_attempt_is_not_misclassified_as_durable_replay(tmp_path):
    f = synthetic_enrollment()
    path = tmp_path / "authority.sqlite"
    f.store(path)
    calls = []
    def clock():
        calls.append(1)
        if len(calls) == 2:
            raise RuntimeError("synthetic-final-check-failure")
        return NOW
    result = EnrollmentAuthorityView(path, f.trust, clock=clock).propose_adoption(f.next_adoption())
    assert result["decision"] == "DENY"
    assert result["internal_result"] == "NO_VERIFIED_REPLAY_EVIDENCE"
    assert result["internal_reasons"] == [] and counts(path) == (0, 0, 0)


def test_orphan_history_cannot_manufacture_verified_replay_diagnostics(tmp_path):
    f = synthetic_enrollment()
    path = tmp_path / "authority.sqlite"
    f.store(path)
    proposal = f.next_adoption()
    with sqlite3.connect(path) as conn:
        EnrollmentAuthorityView._consume(conn, "adoption", proposal["adoption"]["payload"])
    result = EnrollmentAuthorityView(path, f.trust, clock=lambda: NOW).propose_adoption(proposal)
    assert result["decision"] == "DENY"
    assert result["internal_result"] == "REPLAY_DIAGNOSTICS_UNAVAILABLE"
    assert result["internal_reasons"] == [] and counts(path) == (0, 3, 0)


def test_legacy_v2_storage_is_not_automatically_migrated(tmp_path):
    f = synthetic_enrollment()
    path = tmp_path / "authority.sqlite"
    f.store(path)
    with sqlite3.connect(path) as conn:
        import json
        state = json.loads(conn.execute("SELECT value FROM enrollment_meta WHERE name='state'").fetchone()[0])
        state["schema"] = "usbay.enrollment.storage.v2"
        conn.execute("UPDATE enrollment_meta SET value=? WHERE name='state'", (canonical(state).decode(),))
    before = path.read_bytes()
    assert EnrollmentAuthorityView(path, f.trust, clock=lambda: NOW).enroll(f.inputs)["decision"] == "DENY"
    assert path.read_bytes() == before
