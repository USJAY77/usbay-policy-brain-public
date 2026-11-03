"""Synthetic-only tests for read-only mutation reconciliation."""
from copy import deepcopy
import sqlite3

from governance.mutation_reconciliation import inspect_mutation_reconciliation
from governance.mutation_currentness_source import (
    projection_payload_hash, projection_scope_hash,
)
from governance.tenant_enrollment_contracts import canonical, digest
from tests.test_mutation_currentness_source import (
    SyntheticUpdaterAuthority, _stored_projection, projected_commit,
)
from tests.test_mutation_high_water_ledger import (
    SyntheticLedgerWriter, _record,
)
from governance.mutation_high_water_ledger import ImmutableLedgerMutationHighWater
from governance.mutation_currentness_source import SQLiteMutationCurrentnessProjectionUpdater


def _setup(tmp_path):
    f, _, _ = projected_commit(tmp_path)
    previous = _stored_projection(f)
    scope_hash = projection_scope_hash(f.command["payload"])
    previous_hash = projection_payload_hash(previous)
    previous_position = {
        "scope_hash": scope_hash,
        "source_epoch": 1,
        "source_version": 1,
        "projection_hash": previous_hash,
    }
    proposed = deepcopy(previous)
    proposed["authority_status"]["root_status"] = "REVOKED"
    proposed_hash = projection_payload_hash(proposed)
    proposed_position = {
        "scope_hash": scope_hash,
        "source_epoch": 1,
        "source_version": 2,
        "projection_hash": proposed_hash,
    }
    boundary = digest({"storage": "synthetic-independent-ledger"})
    records = [_record(
        previous["scope"]["tenant_id"],
        boundary,
        previous_position,
        digest({"genesis": scope_hash}),
    )]
    writer = SyntheticLedgerWriter(records, boundary)
    high_water = ImmutableLedgerMutationHighWater(
        "unused",
        tenant_id=previous["scope"]["tenant_id"],
        writer=writer,
        storage_boundary_reference=boundary,
        reader=lambda _: deepcopy(records),
    )
    consumption = {
        "issuer_id": "synthetic-high-water-issuer",
        "grant_id": "synthetic-high-water-grant",
        "nonce": "synthetic-high-water-nonce",
        "replay_identity": digest({"synthetic-update": "reconcile-update"}),
    }
    return f, high_water, records, previous, proposed, previous_position, proposed_position, consumption


def _inspect(f, high_water, previous_position, proposed_position, consumption):
    return inspect_mutation_reconciliation(
        f.view,
        high_water,
        f.command["payload"],
        previous_position=previous_position,
        proposed_position=proposed_position,
        **consumption,
    )


def test_reconciliation_not_committed_when_both_old(tmp_path):
    f, high_water, _, _, _, previous_position, proposed_position, consumption = _setup(tmp_path)
    result = _inspect(f, high_water, previous_position, proposed_position, consumption)
    assert result["classification"] == "NOT_COMMITTED"
    assert result["retry_allowed"] is False


def test_reconciliation_recovery_required_when_ledger_new_sqlite_old(tmp_path):
    f, high_water, records, _, _, previous_position, proposed_position, consumption = _setup(tmp_path)
    records.append(_record(
        high_water.tenant_id,
        high_water.storage_boundary_reference,
        proposed_position,
        digest(previous_position),
    ))
    # Fix chain reference to the prior position hash, matching adapter semantics.
    records[-1]["decision"]["previous_position_hash"] = records[0]["decision"]["position_hash"]
    result = _inspect(f, high_water, previous_position, proposed_position, consumption)
    assert result["classification"] == "RECOVERY_REQUIRED"
    assert result["recovery_allowed"] is True
    assert result["retry_allowed"] is False


def test_reconciliation_committed_requires_sqlite_event_and_consumption(tmp_path):
    f, high_water, _, previous, proposed, previous_position, proposed_position, consumption = _setup(tmp_path)
    updater = SQLiteMutationCurrentnessProjectionUpdater(
        f.view,
        updater_authority=SyntheticUpdaterAuthority(),
        high_water=high_water,
    )
    result = updater.update(
        f.command["payload"],
        proposed,
        expected_epoch=1,
        expected_version=1,
        expected_projection_hash=previous_position["projection_hash"],
        update_id="reconcile-update",
    )
    assert result["decision"] == "ALLOW"
    committed = _inspect(f, high_water, previous_position, proposed_position, consumption)
    assert committed["classification"] == "COMMITTED"
    assert committed["retry_allowed"] is False


def test_reconciliation_sqlite_new_ledger_old_is_blocked(tmp_path):
    f, high_water, records, previous, proposed, previous_position, proposed_position, consumption = _setup(tmp_path)
    with sqlite3.connect(f.path) as conn:
        state = f.view._snapshot(conn, require_finalized=False)
        conn.execute(
            "UPDATE mutation_currentness_projection "
            "SET source_version=?,projection=?,projection_hash=? WHERE scope_hash=?",
            (2, canonical(proposed).decode(), proposed_position["projection_hash"],
             previous_position["scope_hash"]),
        )
        f.view._consume(conn, "mutation_high_water_authority", consumption)
        f.view._append(conn, state, {
            "kind": "MUTATION_CURRENTNESS_PROJECTED_NON_PRODUCTION",
            "scope_reference": proposed_position["scope_hash"],
            "source_epoch": 1,
            "previous_source_version": 1,
            "source_version": 2,
            "previous_projection_hash": previous_position["projection_hash"],
            "projection_hash": proposed_position["projection_hash"],
        })
    result = _inspect(f, high_water, previous_position, proposed_position, consumption)
    assert result["classification"] == "BLOCKED"


def test_reconciliation_missing_local_evidence_blocks_claimed_commit(tmp_path):
    f, high_water, records, _, proposed, previous_position, proposed_position, consumption = _setup(tmp_path)
    records.append(_record(
        high_water.tenant_id,
        high_water.storage_boundary_reference,
        proposed_position,
        records[0]["decision"]["position_hash"],
    ))
    with sqlite3.connect(f.path) as conn:
        conn.execute(
            "UPDATE mutation_currentness_projection "
            "SET source_version=?,projection=?,projection_hash=? WHERE scope_hash=?",
            (2, canonical(proposed).decode(), proposed_position["projection_hash"],
             previous_position["scope_hash"]),
        )
    result = _inspect(f, high_water, previous_position, proposed_position, consumption)
    assert result["classification"] == "BLOCKED"
