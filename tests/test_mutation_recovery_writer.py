"""Synthetic-only tests for the bounded governed recovery writer."""
from contextlib import contextmanager
from copy import deepcopy
import sqlite3

from governance.mutation_recovery_writer import (
    GovernedMutationRecoveryWriter,
    MutationRecoveryCurrentnessGuard,
    MutationRecoveryCurrentnessSource,
)
from governance.mutation_high_water_ledger import (
    ImmutableLedgerMutationHighWater,
)
from governance.mutation_currentness_source import (
    projection_payload_hash, projection_scope_hash,
)
from governance.tenant_enrollment_contracts import canonical, digest, parse_json
from tests.test_mutation_currentness_source import (
    _stored_projection, projected_commit,
)
from tests.test_mutation_high_water_ledger import (
    SyntheticLedgerWriter, _record,
)
from tests.test_mutation_high_water_authority import _fixture as authority_fixture
from tests.helpers.tenant_enrollment import NOW


class SyntheticRecoveryGuard(MutationRecoveryCurrentnessGuard):
    def __init__(self, *, parent_authority_id, parent_authority_hash,
                 current_authority_status, continuity_hash):
        self.parent_authority_id = parent_authority_id
        self.parent_authority_hash = parent_authority_hash
        self.current_authority_status = deepcopy(current_authority_status)
        self.continuity_hash = continuity_hash
        self.last = None

    def verify(self, *, previous_projection, recovered_projection,
               previous_position, recovered_position):
        # Recovery may preserve or strengthen revocation but may never resurrect.
        for field in ("parent_status", "root_status", "issuer_status"):
            if self.current_authority_status[field] == "REVOKED":
                assert recovered_projection["authority_status"][field] == "REVOKED"
            if previous_projection["authority_status"][field] == "REVOKED":
                assert recovered_projection["authority_status"][field] == "REVOKED"
        assert (
            recovered_projection["currentness"]["revocations"]["payload"]
            == previous_projection["currentness"]["revocations"]["payload"]
        )
        evidence = {
            "decision": "ALLOW",
            "evidence_hash": digest({
                "current_authority_status": self.current_authority_status,
                "recovered_position": recovered_position,
            }),
            "continuity_hash": self.continuity_hash,
            "parent_authority_id": self.parent_authority_id,
            "parent_authority_hash": self.parent_authority_hash,
        }
        self.last = deepcopy(evidence)
        return evidence

    def recheck(self, *, evidence):
        return deepcopy(self.last)


class SyntheticRecoveryCurrentness(MutationRecoveryCurrentnessSource):
    def __init__(self, guard):
        self.guard = guard

    @contextmanager
    def hold(self, *, command, grant):
        yield self.guard


def _recovery_setup(tmp_path):
    f, _, _ = projected_commit(tmp_path)
    sqlite_old = _stored_projection(f)
    scope_hash = projection_scope_hash(f.command["payload"])
    sqlite_old_position = {
        "scope_hash": scope_hash,
        "source_epoch": 1,
        "source_version": 1,
        "projection_hash": projection_payload_hash(sqlite_old),
    }

    failed_projection = deepcopy(sqlite_old)
    failed_projection["authority_status"]["root_status"] = "REVOKED"
    failed_hash = projection_payload_hash(failed_projection)
    failed_ledger_position = {
        "scope_hash": scope_hash,
        "source_epoch": 1,
        "source_version": 2,
        "projection_hash": failed_hash,
    }

    boundary = digest({"storage": "synthetic-recovery-independent-ledger"})
    records = [_record(
        sqlite_old["scope"]["tenant_id"],
        boundary,
        sqlite_old_position,
        digest({"genesis": scope_hash}),
    )]
    writer = SyntheticLedgerWriter(records, boundary)
    high_water = ImmutableLedgerMutationHighWater(
        "unused",
        tenant_id=sqlite_old["scope"]["tenant_id"],
        writer=writer,
        storage_boundary_reference=boundary,
        reader=lambda _: deepcopy(records),
    )
    # Simulate ledger append succeeding while SQLite transaction rolls back.
    writer.append_position(
        tenant_id=sqlite_old["scope"]["tenant_id"],
        previous=sqlite_old_position,
        proposed=failed_ledger_position,
        update_id="failed-update-2",
    )
    failed_event_hash = records[-1]["current_event_hash"]

    recovered_projection = deepcopy(failed_projection)
    recovered_hash = projection_payload_hash(recovered_projection)
    recovered_position = {
        "scope_hash": scope_hash,
        "source_epoch": 2,
        "source_version": 3,
        "projection_hash": recovered_hash,
    }

    trust, proposal, reviews, grant, _, _, _ = authority_fixture(
        action="ADVANCE_MUTATION_RECOVERY_EPOCH",
        scope_hash_override=scope_hash,
        position_hash_override=digest(recovered_position),
        update_ref_override=digest({
            "recovery_operation_id": "recovery-operation-3"
        }),
        recovery_overrides={
            "previous_epoch": 1,
            "next_epoch": 2,
            "previous_source_version": 2,
            "next_source_version": 3,
            "previous_projection_hash": failed_hash,
            "recovered_projection_hash": recovered_hash,
            "previous_high_water_event_hash": failed_event_hash,
            "recovery_evidence_reference":
                digest({"recovery": "synthetic-evidence-3"}),
            "recovery_operation_id": "recovery-operation-3",
        },
    )
    f.view.trust = trust
    g = grant["payload"]
    guard = SyntheticRecoveryGuard(
        parent_authority_id=g["parent_authority_id"],
        parent_authority_hash=g["parent_authority_hash"],
        current_authority_status={
            "parent_status": "ACTIVE",
            "root_status": "REVOKED",
            "issuer_status": "ACTIVE",
        },
        continuity_hash=digest({"continuity": "independent"}),
    )
    currentness = SyntheticRecoveryCurrentness(guard)
    recovery = GovernedMutationRecoveryWriter(
        f.view,
        high_water=high_water,
        currentness_source=currentness,
    )
    failed_consumption = {
        "issuer_id": "synthetic-failed-update-issuer",
        "grant_id": "synthetic-failed-update-grant",
        "nonce": "synthetic-failed-update-nonce",
        "replay_identity": digest({"failed-update": 2}),
    }
    return (
        f, recovery, high_water, records, sqlite_old, failed_projection,
        recovered_projection, sqlite_old_position, failed_ledger_position,
        recovered_position, failed_consumption, proposal, reviews, grant,
    )


def test_governed_recovery_commits_epoch_transition(tmp_path):
    (
        f, recovery, high_water, records, _, _, recovered_projection,
        sqlite_old_position, failed_ledger_position, recovered_position,
        failed_consumption, proposal, reviews, grant,
    ) = _recovery_setup(tmp_path)

    result = recovery.recover(
        f.command["payload"],
        recovered_projection,
        failed_update_previous_position=sqlite_old_position,
        failed_update_ledger_position=failed_ledger_position,
        failed_update_consumption=failed_consumption,
        proposal=proposal,
        reviews=reviews,
        grant=grant,
    )
    assert result["decision"] == "ALLOW"
    assert result["source_epoch"] == 2
    assert result["source_version"] == 3

    with sqlite3.connect(f.path) as conn:
        row = conn.execute(
            "SELECT source_epoch,source_version,projection_hash "
            "FROM mutation_currentness_projection"
        ).fetchone()
        assert row == (2, 3, recovered_position["projection_hash"])
        events = [
            parse_json(x[0]) for x in
            conn.execute("SELECT payload FROM enrollment_events ORDER BY sequence")
        ]
    assert any(
        event.get("kind") == "MUTATION_CURRENTNESS_RECOVERED_NON_PRODUCTION"
        and event.get("source_epoch") == 2
        and event.get("source_version") == 3
        for event in events
    )
    assert high_water.current_evidence(
        recovered_position["scope_hash"])["position"] == recovered_position


def test_governed_recovery_grant_is_one_time(tmp_path):
    (
        f, recovery, _, _, _, _, recovered_projection,
        sqlite_old_position, failed_ledger_position, _,
        failed_consumption, proposal, reviews, grant,
    ) = _recovery_setup(tmp_path)
    first = recovery.recover(
        f.command["payload"], recovered_projection,
        failed_update_previous_position=sqlite_old_position,
        failed_update_ledger_position=failed_ledger_position,
        failed_update_consumption=failed_consumption,
        proposal=proposal, reviews=reviews, grant=grant,
    )
    assert first["decision"] == "ALLOW"
    second = recovery.recover(
        f.command["payload"], recovered_projection,
        failed_update_previous_position=sqlite_old_position,
        failed_update_ledger_position=failed_ledger_position,
        failed_update_consumption=failed_consumption,
        proposal=proposal, reviews=reviews, grant=grant,
    )
    assert second["decision"] == "DENY"


def test_governed_recovery_refuses_revoked_to_active(tmp_path):
    (
        f, recovery, _, _, _, _, recovered_projection,
        sqlite_old_position, failed_ledger_position, _,
        failed_consumption, proposal, reviews, grant,
    ) = _recovery_setup(tmp_path)
    bad = deepcopy(recovered_projection)
    bad["authority_status"]["root_status"] = "ACTIVE"
    result = recovery.recover(
        f.command["payload"], bad,
        failed_update_previous_position=sqlite_old_position,
        failed_update_ledger_position=failed_ledger_position,
        failed_update_consumption=failed_consumption,
        proposal=proposal, reviews=reviews, grant=grant,
    )
    assert result["decision"] == "DENY"


def test_governed_recovery_requires_recovery_required_classification(tmp_path):
    (
        f, recovery, _, _, _, _, recovered_projection,
        sqlite_old_position, failed_ledger_position, _,
        failed_consumption, proposal, reviews, grant,
    ) = _recovery_setup(tmp_path)
    # Pretend the ledger never advanced: reconciliation must not admit recovery.
    recovery.high_water.reader = lambda _: recovery.high_water.reader.__closure__[0].cell_contents[:1]
    result = recovery.recover(
        f.command["payload"], recovered_projection,
        failed_update_previous_position=sqlite_old_position,
        failed_update_ledger_position=failed_ledger_position,
        failed_update_consumption=failed_consumption,
        proposal=proposal, reviews=reviews, grant=grant,
    )
    assert result["decision"] == "DENY"
    assert result["reason"] == "RECOVERY_NOT_REQUIRED"


def test_governed_recovery_consumes_grant_nonce_replay_and_operation(tmp_path):
    (
        f, recovery, _, _, _, _, recovered_projection,
        sqlite_old_position, failed_ledger_position, _,
        failed_consumption, proposal, reviews, grant,
    ) = _recovery_setup(tmp_path)
    result = recovery.recover(
        f.command["payload"], recovered_projection,
        failed_update_previous_position=sqlite_old_position,
        failed_update_ledger_position=failed_ledger_position,
        failed_update_consumption=failed_consumption,
        proposal=proposal, reviews=reviews, grant=grant,
    )
    assert result["decision"] == "ALLOW"
    with sqlite3.connect(f.path) as conn:
        rows = list(conn.execute(
            "SELECT kind,identity FROM enrollment_uses "
            "WHERE kind LIKE 'mutation_recovery_authority:%'"))
    kinds = {row[0] for row in rows}
    assert {
        "mutation_recovery_authority:grant_id",
        "mutation_recovery_authority:nonce",
        "mutation_recovery_authority:replay_identity",
        "mutation_recovery_authority:operation_id",
    } <= kinds


def test_governed_recovery_uncertain_ledger_append_is_unknown(tmp_path):
    (
        f, recovery, high_water, _, _, _, recovered_projection,
        sqlite_old_position, failed_ledger_position, _,
        failed_consumption, proposal, reviews, grant,
    ) = _recovery_setup(tmp_path)
    high_water.writer.fail_uncertain = True
    result = recovery.recover(
        f.command["payload"], recovered_projection,
        failed_update_previous_position=sqlite_old_position,
        failed_update_ledger_position=failed_ledger_position,
        failed_update_consumption=failed_consumption,
        proposal=proposal, reviews=reviews, grant=grant,
    )
    assert result["decision"] == "DENY"
    assert result["reason"] == "RECOVERY_STATE_UNKNOWN"
    assert result["reconciliation_required"] is True
    with sqlite3.connect(f.path) as conn:
        row = conn.execute(
            "SELECT source_epoch,source_version,projection_hash "
            "FROM mutation_currentness_projection"
        ).fetchone()
    assert row == (
        sqlite_old_position["source_epoch"],
        sqlite_old_position["source_version"],
        sqlite_old_position["projection_hash"],
    )
