"""Non-production immutable-ledger high-water adapter for mutation currentness.

This module never generates or registers audit keys and never calls the public
append_evidence_event() helper. Ledger writes require a separately provisioned
writer whose authority and key lifecycle are outside this module.

The adapter provides rollback evidence only when the ledger is retained outside
the enrollment SQLite restore boundary. It cannot prove that storage property by
itself and therefore exposes it as a required composition contract.
"""
from __future__ import annotations

from contextlib import contextmanager
from copy import deepcopy
from threading import RLock

from audit.immutable_ledger import LedgerIntegrityError, verified_ledger_records
from governance.mutation_currentness_source import (
    MutationCurrentnessHighWater, MutationCurrentnessUpdateRejected,
    MutationCurrentnessUpdateUncertain,
)
from governance.tenant_enrollment_contracts import EnrollmentDenied, digest, require

HIGH_WATER_ACTION = "USBAY_MUTATION_CURRENTNESS_HIGH_WATER"
HIGH_WATER_SCHEMA = "usbay.mutation_currentness.high_water.v1"
HIGH_WATER_FIELDS = {
    "schema_version", "tenant_id", "scope_hash", "source_epoch",
    "source_version", "projection_hash", "update_id_reference",
    "previous_position_hash", "position_hash", "storage_boundary_reference",
}
POSITION_FIELDS = {"scope_hash", "source_epoch", "source_version", "projection_hash"}


def _position_hash(position):
    return digest({k: position[k] for k in (
        "scope_hash", "source_epoch", "source_version", "projection_hash")})


def _validate_position(position):
    require(type(position) is dict and set(position) == POSITION_FIELDS,
            "AUTHORITY_CURRENTNESS_UNPROVEN")
    require(type(position["scope_hash"]) is str
            and position["scope_hash"].startswith("sha256:"),
            "AUTHORITY_CURRENTNESS_UNPROVEN")
    require(type(position["projection_hash"]) is str
            and position["projection_hash"].startswith("sha256:"),
            "AUTHORITY_CURRENTNESS_UNPROVEN")
    require(type(position["source_epoch"]) is int
            and type(position["source_version"]) is int
            and position["source_epoch"] >= 1 and position["source_version"] >= 1,
            "AUTHORITY_CURRENTNESS_UNPROVEN")
    return deepcopy(position)


def _validate_record(record, *, tenant_id, scope_hash, storage_boundary_reference):
    require(type(record) is dict and record.get("action") == HIGH_WATER_ACTION,
            "AUTHORITY_CURRENTNESS_UNPROVEN")
    require(record.get("tenant_id") == tenant_id,
            "TENANT_MISMATCH")
    decision = record.get("decision")
    require(type(decision) is dict and set(decision) >= HIGH_WATER_FIELDS,
            "AUTHORITY_CURRENTNESS_UNPROVEN")
    require(decision["schema_version"] == HIGH_WATER_SCHEMA
            and decision["tenant_id"] == tenant_id
            and decision["scope_hash"] == scope_hash
            and decision["storage_boundary_reference"] == storage_boundary_reference,
            "AUTHORITY_CURRENTNESS_UNPROVEN")
    position = {
        "scope_hash": decision["scope_hash"],
        "source_epoch": decision["source_epoch"],
        "source_version": decision["source_version"],
        "projection_hash": decision["projection_hash"],
    }
    _validate_position(position)
    require(decision["position_hash"] == _position_hash(position),
            "AUTHORITY_CURRENTNESS_UNPROVEN")
    return position, decision


class MutationHighWaterLedgerWriter:
    """Privileged pre-provisioned writer contract; default denies.

    A conforming implementation must serialize every high-water writer for the
    same scope and append a signed HIGH_WATER_ACTION record without generating or
    registering new keys.
    """

    storage_boundary_reference: str

    @contextmanager
    def hold(self, *, tenant_id: str, scope_hash: str):
        raise EnrollmentDenied("AUTHORITY_CURRENTNESS_UPDATER_UNAVAILABLE")
        yield  # pragma: no cover

    def append_position(self, *, tenant_id: str, previous: dict,
                        proposed: dict, update_id: str) -> dict:
        raise EnrollmentDenied("AUTHORITY_CURRENTNESS_UPDATER_UNAVAILABLE")


class ImmutableLedgerMutationHighWater(MutationCurrentnessHighWater):
    """Read-verified high-water adapter over an independently retained ledger."""

    def __init__(self, ledger_path, *, tenant_id: str,
                 writer: MutationHighWaterLedgerWriter,
                 storage_boundary_reference: str,
                 reader=verified_ledger_records):
        require(type(tenant_id) is str and bool(tenant_id),
                "AUTHORITY_CURRENTNESS_UNPROVEN")
        require(type(storage_boundary_reference) is str
                and storage_boundary_reference.startswith("sha256:"),
                "AUTHORITY_CURRENTNESS_UNPROVEN")
        self.ledger_path = ledger_path
        self.tenant_id = tenant_id
        self.writer = writer
        self.storage_boundary_reference = storage_boundary_reference
        self.reader = reader

    def _records(self):
        try:
            records = self.reader(self.ledger_path)
        except LedgerIntegrityError as exc:
            raise EnrollmentDenied("AUTHORITY_CURRENTNESS_UNPROVEN") from exc
        require(type(records) is list, "AUTHORITY_CURRENTNESS_UNPROVEN")
        return records

    def _current(self, scope_hash):
        matches = []
        for record in self._records():
            if record.get("action") != HIGH_WATER_ACTION:
                continue
            try:
                position, decision = _validate_record(
                    record, tenant_id=self.tenant_id, scope_hash=scope_hash,
                    storage_boundary_reference=self.storage_boundary_reference)
            except EnrollmentDenied:
                continue
            matches.append((position, decision, record))
        require(bool(matches), "AUTHORITY_CURRENTNESS_UNPROVEN")
        previous = None
        previous_hash = digest({"genesis": scope_hash})
        for position, decision, _ in matches:
            if previous is not None:
                require(position["source_epoch"] == previous["source_epoch"],
                        "AUTHORITY_CURRENTNESS_UNPROVEN")
                require(position["source_version"]
                        == previous["source_version"] + 1,
                        "AUTHORITY_CURRENTNESS_UNPROVEN")
            require(decision["previous_position_hash"] == previous_hash,
                    "AUTHORITY_CURRENTNESS_UNPROVEN")
            previous = position
            previous_hash = decision["position_hash"]
        return deepcopy(previous)

    @contextmanager
    def hold(self, *, scope_hash: str):
        require(isinstance(self.writer, MutationHighWaterLedgerWriter),
                "AUTHORITY_CURRENTNESS_UNPROVEN")
        require(self.writer.storage_boundary_reference
                == self.storage_boundary_reference,
                "AUTHORITY_CURRENTNESS_UNPROVEN")
        with self.writer.hold(tenant_id=self.tenant_id,
                              scope_hash=scope_hash):
            anchor = _HeldLedgerAnchor(self, scope_hash)
            anchor.current()
            yield anchor

    @contextmanager
    def hold_update(self, *, scope_hash: str, expected: dict,
                    proposed: dict, update_id: str):
        require(isinstance(self.writer, MutationHighWaterLedgerWriter),
                "AUTHORITY_CURRENTNESS_UPDATER_UNAVAILABLE")
        require(self.writer.storage_boundary_reference
                == self.storage_boundary_reference,
                "AUTHORITY_CURRENTNESS_UNPROVEN")
        _validate_position(expected)
        _validate_position(proposed)
        require(expected["scope_hash"] == scope_hash
                and proposed["scope_hash"] == scope_hash,
                "TENANT_MISMATCH")
        require(proposed["source_epoch"] == expected["source_epoch"]
                and proposed["source_version"] == expected["source_version"] + 1,
                "CURRENTNESS_UPDATE_STALE")
        with self.writer.hold(tenant_id=self.tenant_id,
                              scope_hash=scope_hash):
            current = self._current(scope_hash)
            require(current == expected, "CURRENTNESS_UPDATE_STALE")
            yield _HeldLedgerUpdateAnchor(
                self, scope_hash, expected, proposed, update_id)


class _HeldLedgerAnchor:
    def __init__(self, source, scope_hash):
        self.source = source
        self.scope_hash = scope_hash

    def current(self):
        return self.source._current(self.scope_hash)

    def commit_if_unchanged(self, connection, *, expected):
        if self.current() != expected:
            raise MutationCurrentnessUpdateRejected("COMMIT_FENCE_STALE")
        connection.execute("COMMIT")


class _HeldLedgerUpdateAnchor(_HeldLedgerAnchor):
    def __init__(self, source, scope_hash, expected, proposed, update_id):
        super().__init__(source, scope_hash)
        self.expected = deepcopy(expected)
        self.proposed = deepcopy(proposed)
        self.update_id = update_id

    def commit_update(self, connection, *, expected, proposed, update_id):
        require(expected == self.expected and proposed == self.proposed
                and update_id == self.update_id,
                "CURRENTNESS_UPDATE_STALE")
        if self.current() != expected:
            raise MutationCurrentnessUpdateRejected("CURRENTNESS_UPDATE_STALE")
        try:
            receipt = self.source.writer.append_position(
                tenant_id=self.source.tenant_id,
                previous=deepcopy(expected),
                proposed=deepcopy(proposed),
                update_id=update_id,
            )
        except MutationCurrentnessUpdateUncertain:
            raise
        except Exception as exc:
            raise MutationCurrentnessUpdateRejected(
                "AUTHORITY_CURRENTNESS_UPDATER_UNAVAILABLE") from exc
        require(type(receipt) is dict
                and receipt.get("position") == proposed
                and type(receipt.get("event_hash")) is str
                and bool(receipt["event_hash"]),
                "AUTHORITY_CURRENTNESS_UPDATER_UNAVAILABLE")
        try:
            connection.execute("COMMIT")
        except Exception as exc:
            raise MutationCurrentnessUpdateUncertain() from exc
        # Lost acknowledgement after both writes must still be reconciled by the
        # caller; this adapter never converts uncertainty into a retry.
        if self.current() != proposed:
            raise MutationCurrentnessUpdateUncertain()
