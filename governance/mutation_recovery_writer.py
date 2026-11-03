"""Bounded non-production governed mutation recovery writer.

This module does not provision trust, signers, roots, storage or production
authority. Recovery requires:
- prior read-only classification RECOVERY_REQUIRED;
- one exact reviewed MutationRecoveryEpochGrantV1;
- an independently held current authority/continuity source;
- an independently retained high-water ledger capable of epoch transition.

Any ambiguity fails closed and never authorizes automatic retry.
"""
from __future__ import annotations

from contextlib import contextmanager
from copy import deepcopy
import sqlite3

from governance.mutation_currentness_source import projection_payload_hash, projection_scope_hash
from governance.mutation_high_water_authority import (
    verify_recovery_epoch_grant,
)
from governance.mutation_high_water_ledger import (
    ImmutableLedgerMutationHighWater,
)
from governance.mutation_reconciliation import inspect_mutation_reconciliation
from governance.tenant_enrollment_contracts import (
    EnrollmentDenied, canonical, decision, digest, require,
)


class MutationRecoveryCurrentnessSource:
    """Held independent current authority/continuity source; default denies."""

    @contextmanager
    def hold(self, *, command, grant):
        raise EnrollmentDenied("RECOVERY_CURRENTNESS_UNAVAILABLE")
        yield  # pragma: no cover


class MutationRecoveryCurrentnessGuard:
    def verify(self, *, previous_projection, recovered_projection,
               previous_position, recovered_position):
        raise EnrollmentDenied("RECOVERY_CURRENTNESS_UNAVAILABLE")

    def recheck(self, *, evidence):
        raise EnrollmentDenied("RECOVERY_CURRENTNESS_UNAVAILABLE")


def _recovery_consumption(grant_payload, recovered_position):
    return {
        "issuer_id": grant_payload["issuer_id"],
        "grant_id": grant_payload["grant_id"],
        "nonce": grant_payload["grant_nonce"],
        "replay_identity": digest({
            "grant_id": grant_payload["grant_id"],
            "recovery_operation_id": grant_payload["recovery_operation_id"],
            "recovered_position": recovered_position,
        }),
    }


def _consume_recovery_operation(conn, grant_payload):
    identity = digest({
        "issuer": grant_payload["issuer_id"],
        "value": grant_payload["recovery_operation_id"],
    })
    conn.execute(
        "INSERT INTO enrollment_uses(kind,identity) VALUES(?,?)",
        ("mutation_recovery_authority:operation_id", identity),
    )


class GovernedMutationRecoveryWriter:
    """One-shot non-production recovery writer."""

    def __init__(self, view, *, high_water, currentness_source):
        self.view = view
        self.high_water = high_water
        self.currentness_source = currentness_source

    def recover(
            self, command, recovered_projection, *,
            failed_update_previous_position,
            failed_update_ledger_position,
            failed_update_consumption,
            proposal, reviews, grant):
        conn = None
        ledger_appended = False
        commit_attempted = False
        try:
            require(isinstance(self.high_water, ImmutableLedgerMutationHighWater),
                    "RECOVERY_WRITER_UNAVAILABLE")
            require(isinstance(self.currentness_source,
                               MutationRecoveryCurrentnessSource),
                    "RECOVERY_CURRENTNESS_UNAVAILABLE")
            grant_payload = grant["payload"]
            scope_hash = projection_scope_hash(command)
            require(grant_payload["allowed_scope_hash"] == scope_hash,
                    "TENANT_MISMATCH")

            classification = inspect_mutation_reconciliation(
                self.view, self.high_water, command,
                previous_position=failed_update_previous_position,
                proposed_position=failed_update_ledger_position,
                **failed_update_consumption,
            )
            require(classification.get("classification") == "RECOVERY_REQUIRED",
                    "RECOVERY_NOT_REQUIRED")

            previous_high_water = deepcopy(failed_update_ledger_position)
            recovered_hash = projection_payload_hash(recovered_projection)
            recovered_position = {
                "scope_hash": scope_hash,
                "source_epoch": grant_payload["next_epoch"],
                "source_version": grant_payload["next_source_version"],
                "projection_hash": recovered_hash,
            }
            require(grant_payload["recovered_projection_hash"] == recovered_hash,
                    "RECOVERY_EPOCH_INVALID")
            require(grant_payload["previous_epoch"]
                    == previous_high_water["source_epoch"]
                    and grant_payload["previous_source_version"]
                    == previous_high_water["source_version"]
                    and grant_payload["previous_projection_hash"]
                    == previous_high_water["projection_hash"],
                    "RECOVERY_EPOCH_INVALID")

            current_evidence = self.high_water.current_evidence(scope_hash)
            require(current_evidence["position"] == previous_high_water,
                    "RECOVERY_STATE_STALE")
            require(current_evidence["event_hash"]
                    == grant_payload["previous_high_water_event_hash"],
                    "RECOVERY_EPOCH_INVALID")

            with self.currentness_source.hold(
                    command=deepcopy(command),
                    grant=deepcopy(grant)) as current_guard:
                require(isinstance(current_guard,
                                   MutationRecoveryCurrentnessGuard),
                        "RECOVERY_CURRENTNESS_UNAVAILABLE")
                authority = current_guard.verify(
                    previous_projection=self._load_projection(
                        failed_update_previous_position),
                    recovered_projection=deepcopy(recovered_projection),
                    previous_position=deepcopy(previous_high_water),
                    recovered_position=deepcopy(recovered_position),
                )
                require(type(authority) is dict
                        and set(authority) == {
                            "decision", "evidence_hash", "continuity_hash",
                            "parent_authority_id", "parent_authority_hash",
                        }
                        and authority["decision"] == "ALLOW"
                        and all(type(authority[k]) is str and bool(authority[k])
                                for k in (
                                    "evidence_hash", "continuity_hash",
                                    "parent_authority_id",
                                    "parent_authority_hash",
                                )),
                        "RECOVERY_CURRENTNESS_UNAVAILABLE")

                verified = verify_recovery_epoch_grant(
                    proposal, reviews, grant,
                    trust=self.view.trust,
                    now=self.view.clock(),
                    expected_scope_hash=scope_hash,
                    current_epoch=previous_high_water["source_epoch"],
                    current_source_version=previous_high_water["source_version"],
                    current_projection_hash=previous_high_water["projection_hash"],
                    expected_high_water_event_hash=current_evidence["event_hash"],
                    expected_next_source_version=recovered_position["source_version"],
                    expected_recovered_projection_hash=recovered_hash,
                    expected_recovery_state_hash=
                        grant_payload["proposed_recovery_state_hash"],
                    expected_parent_authority_id=
                        authority["parent_authority_id"],
                    expected_parent_authority_hash=
                        authority["parent_authority_hash"],
                )
                require(verified["decision"] == "ALLOW",
                        verified.get("reason", "RECOVERY_EPOCH_INVALID"))

                conn = self.view._connect_existing()
                conn.execute("BEGIN IMMEDIATE")
                state = self.view._snapshot(conn, require_finalized=False)
                row = conn.execute(
                    "SELECT source_epoch,source_version,projection_hash "
                    "FROM mutation_currentness_projection WHERE scope_hash=?",
                    (scope_hash,),
                ).fetchone()
                require(row is not None, "RECOVERY_STATE_STALE")
                sqlite_position = {
                    "scope_hash": scope_hash,
                    "source_epoch": row[0],
                    "source_version": row[1],
                    "projection_hash": row[2],
                }
                require(sqlite_position == failed_update_previous_position,
                        "RECOVERY_STATE_STALE")

                consumption = _recovery_consumption(
                    grant_payload, recovered_position)
                try:
                    self.view._consume(
                        conn, "mutation_recovery_authority", consumption)
                    _consume_recovery_operation(conn, grant_payload)
                except sqlite3.IntegrityError:
                    raise EnrollmentDenied(
                        "RECOVERY_GRANT_ALREADY_CONSUMED") from None

                with self.high_water.hold_recovery(
                        scope_hash=scope_hash,
                        previous=previous_high_water,
                        recovered=recovered_position,
                        recovery_state_hash=
                            grant_payload["proposed_recovery_state_hash"],
                        recovery_evidence_reference=
                            grant_payload["recovery_evidence_reference"],
                        recovery_operation_id=
                            grant_payload["recovery_operation_id"]) as ledger_guard:
                    receipt = ledger_guard.append_recovery()
                    ledger_appended = True

                    cursor = conn.execute(
                        "UPDATE mutation_currentness_projection "
                        "SET source_epoch=?,source_version=?,projection=?,"
                        "projection_hash=? "
                        "WHERE scope_hash=? AND source_epoch=? "
                        "AND source_version=? AND projection_hash=?",
                        (
                            recovered_position["source_epoch"],
                            recovered_position["source_version"],
                            canonical(recovered_projection).decode(),
                            recovered_hash,
                            scope_hash,
                            failed_update_previous_position["source_epoch"],
                            failed_update_previous_position["source_version"],
                            failed_update_previous_position["projection_hash"],
                        ),
                    )
                    require(cursor.rowcount == 1, "RECOVERY_STATE_STALE")
                    event_hash = self.view._append(
                        conn, state, {
                            "kind":
                                "MUTATION_CURRENTNESS_RECOVERED_NON_PRODUCTION",
                            "scope_reference": scope_hash,
                            "previous_ledger_position_hash":
                                digest(previous_high_water),
                            "recovered_position_hash":
                                digest(recovered_position),
                            "recovery_state_hash":
                                grant_payload["proposed_recovery_state_hash"],
                            "recovery_evidence_reference":
                                grant_payload["recovery_evidence_reference"],
                            "recovery_operation_id_reference":
                                digest({
                                    "recovery_operation_id":
                                        grant_payload[
                                            "recovery_operation_id"]
                                }),
                            "recovery_grant_hash": verified["grant_hash"],
                            "currentness_evidence_hash":
                                authority["evidence_hash"],
                            "continuity_hash":
                                authority["continuity_hash"],
                            "ledger_event_hash": receipt["event_hash"],
                            "source_epoch":
                                recovered_position["source_epoch"],
                            "source_version":
                                recovered_position["source_version"],
                            "projection_hash": recovered_hash,
                        })

                    recheck = current_guard.recheck(
                        evidence=deepcopy(authority))
                    require(recheck == authority,
                            "RECOVERY_CURRENTNESS_STALE")
                    require(self.high_water.current_evidence(
                        scope_hash)["position"] == recovered_position,
                        "RECOVERY_STATE_STALE")
                    commit_attempted = True
                    conn.execute("COMMIT")
                    require(not conn.in_transaction,
                            "RECOVERY_STATE_UNKNOWN")

            return decision(
                "RECOVERY_COMMITTED_NON_PRODUCTION",
                allowed=True,
                recovery_outcome="COMMITTED_NON_EXECUTING",
                mutation_executed=False,
                source_epoch=recovered_position["source_epoch"],
                source_version=recovered_position["source_version"],
                projection_hash=recovered_hash,
                recovery_event_hash=event_hash,
                ledger_event_hash=receipt["event_hash"],
            )
        except Exception as error:
            if conn is not None and conn.in_transaction:
                try:
                    conn.rollback()
                except Exception:
                    pass
            if ledger_appended or commit_attempted:
                return decision(
                    "RECOVERY_STATE_UNKNOWN",
                    recovery_outcome="UNKNOWN",
                    reconciliation_required=True,
                )
            return decision(
                str(error) if type(error) is EnrollmentDenied
                else "RECOVERY_INVALID",
                reconciliation_required=False,
            )
        finally:
            if conn is not None:
                conn.close()

    def _load_projection(self, position):
        conn = None
        try:
            conn = self.view._connect_existing(read_only=True)
            row = conn.execute(
                "SELECT projection FROM mutation_currentness_projection "
                "WHERE scope_hash=? AND source_epoch=? "
                "AND source_version=? AND projection_hash=?",
                (
                    position["scope_hash"],
                    position["source_epoch"],
                    position["source_version"],
                    position["projection_hash"],
                ),
            ).fetchone()
            require(row is not None, "RECOVERY_STATE_STALE")
            from governance.tenant_enrollment_contracts import parse_json
            return parse_json(row[0])
        finally:
            if conn is not None:
                conn.close()
