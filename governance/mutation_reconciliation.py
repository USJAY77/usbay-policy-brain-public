"""Read-only reconciliation for mutation currentness/high-water state.

This module never writes SQLite, ledger, authority, keys, recovery epochs,
or consumption. It only classifies already-durable state and fails closed.
"""
from __future__ import annotations

from copy import deepcopy
import sqlite3

from governance.mutation_currentness_source import projection_scope_hash
from governance.mutation_high_water_ledger import ImmutableLedgerMutationHighWater
from governance.tenant_enrollment_contracts import EnrollmentDenied, decision, digest, parse_json, require


def _consumed(conn, *, issuer_id, grant_id, nonce, replay_identity):
    for label, value in (
        ("grant_id", grant_id),
        ("nonce", nonce),
        ("replay_identity", replay_identity),
    ):
        identity = digest({"issuer": issuer_id, "value": value})
        row = conn.execute(
            "SELECT 1 FROM enrollment_uses WHERE kind=? AND identity=?",
            ("mutation_high_water_authority:" + label, identity),
        ).fetchone()
        if row is None:
            return False
    return True


def _matching_projection_event(conn, *, scope_hash, epoch, version, projection_hash):
    events = [
        parse_json(row[0])
        for row in conn.execute(
            "SELECT payload FROM enrollment_events ORDER BY sequence")
    ]
    matches = [
        event for event in events
        if event.get("kind") == "MUTATION_CURRENTNESS_PROJECTED_NON_PRODUCTION"
        and event.get("scope_reference") == scope_hash
        and event.get("source_epoch") == epoch
        and event.get("source_version") == version
        and event.get("projection_hash") == projection_hash
    ]
    return bool(matches)


def inspect_mutation_reconciliation(
        view, high_water, command, *,
        previous_position, proposed_position,
        issuer_id, grant_id, nonce, replay_identity):
    """Classify durable state without modifying either store."""
    conn = None
    try:
        require(isinstance(high_water, ImmutableLedgerMutationHighWater),
                "RECONCILIATION_BLOCKED")
        scope_hash = projection_scope_hash(command)
        require(previous_position["scope_hash"] == scope_hash
                and proposed_position["scope_hash"] == scope_hash,
                "TENANT_MISMATCH")
        conn = view._connect_existing(read_only=True)
        conn.execute("BEGIN")
        view._snapshot(conn, require_finalized=False)
        row = conn.execute(
            "SELECT source_epoch,source_version,projection_hash "
            "FROM mutation_currentness_projection WHERE scope_hash=?",
            (scope_hash,),
        ).fetchone()
        require(row is not None, "RECONCILIATION_BLOCKED")
        sqlite_position = {
            "scope_hash": scope_hash,
            "source_epoch": row[0],
            "source_version": row[1],
            "projection_hash": row[2],
        }

        try:
            ledger_position = high_water._current(scope_hash)
        except Exception:
            return decision(
                "RECONCILIATION_BLOCKED",
                classification="BLOCKED",
                recovery_allowed=False,
            )

        consumed = _consumed(
            conn,
            issuer_id=issuer_id,
            grant_id=grant_id,
            nonce=nonce,
            replay_identity=replay_identity,
        )
        proposed_event = _matching_projection_event(
            conn,
            scope_hash=scope_hash,
            epoch=proposed_position["source_epoch"],
            version=proposed_position["source_version"],
            projection_hash=proposed_position["projection_hash"],
        )

        if sqlite_position == proposed_position and ledger_position == proposed_position:
            if not consumed or not proposed_event:
                return decision(
                    "RECONCILIATION_BLOCKED",
                    classification="BLOCKED",
                        recovery_allowed=False,
                )
            return decision(
                "RECONCILIATION_COMMITTED",
                allowed=True,
                classification="COMMITTED",
                recovery_allowed=False,
                position=deepcopy(proposed_position),
            )

        if sqlite_position == previous_position and ledger_position == previous_position:
            if consumed or proposed_event:
                return decision(
                    "RECONCILIATION_BLOCKED",
                    classification="BLOCKED",
                        recovery_allowed=False,
                )
            return decision(
                "RECONCILIATION_NOT_COMMITTED",
                classification="NOT_COMMITTED",
                recovery_allowed=False,
                position=deepcopy(previous_position),
            )

        if sqlite_position == previous_position and ledger_position == proposed_position:
            if consumed or proposed_event:
                # SQLite rollback/partial evidence is ambiguous if local
                # consumption/event survived inconsistently.
                return decision(
                    "RECONCILIATION_BLOCKED",
                    classification="BLOCKED",
                        recovery_allowed=False,
                )
            return decision(
                "RECONCILIATION_RECOVERY_REQUIRED",
                classification="RECOVERY_REQUIRED",
                recovery_allowed=True,
                previous_position=deepcopy(previous_position),
                ledger_position=deepcopy(proposed_position),
            )

        return decision(
            "RECONCILIATION_BLOCKED",
            classification="BLOCKED",
            recovery_allowed=False,
        )
    except Exception as error:
        return decision(
            str(error) if type(error) is EnrollmentDenied
            else "RECONCILIATION_BLOCKED",
            classification="BLOCKED",
            recovery_allowed=False,
        )
    finally:
        if conn is not None:
            conn.close()
