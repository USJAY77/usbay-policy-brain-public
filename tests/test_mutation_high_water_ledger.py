"""Synthetic tests for the immutable-ledger mutation high-water adapter."""
from contextlib import contextmanager
from copy import deepcopy
from threading import RLock

import pytest

from governance.mutation_high_water_ledger import (
    HIGH_WATER_ACTION, HIGH_WATER_SCHEMA, ImmutableLedgerMutationHighWater,
    MutationHighWaterLedgerWriter, _position_hash,
)
from governance.mutation_currentness_source import (
    SQLiteMutationCurrentnessProjectionUpdater, projection_payload_hash,
    projection_scope_hash,
)
from governance.tenant_enrollment_contracts import EnrollmentDenied, digest
from tests.test_mutation_currentness_source import (
    SyntheticUpdaterAuthority, _stored_projection, projected_commit,
)


class SyntheticLedgerWriter(MutationHighWaterLedgerWriter):
    def __init__(self, records, storage_boundary_reference):
        self.records = records
        self.storage_boundary_reference = storage_boundary_reference
        self.lock = RLock()
        self.fail_uncertain = False

    @contextmanager
    def hold(self, *, tenant_id, scope_hash):
        with self.lock:
            yield self

    def append_position(self, *, tenant_id, previous, proposed, update_id):
        if self.fail_uncertain:
            from governance.mutation_currentness_source import (
                MutationCurrentnessUpdateUncertain,
            )
            raise MutationCurrentnessUpdateUncertain()
        previous_hash = (
            self.records[-1]["decision"]["position_hash"]
            if self.records else digest({"genesis": proposed["scope_hash"]})
        )
        decision = {
            "schema_version": HIGH_WATER_SCHEMA,
            "tenant_id": tenant_id,
            "scope_hash": proposed["scope_hash"],
            "source_epoch": proposed["source_epoch"],
            "source_version": proposed["source_version"],
            "projection_hash": proposed["projection_hash"],
            "update_id_reference": digest({"update_id": update_id}),
            "previous_position_hash": previous_hash,
            "position_hash": _position_hash(proposed),
            "storage_boundary_reference": self.storage_boundary_reference,
        }
        self.records.append({
            "action": HIGH_WATER_ACTION,
            "tenant_id": tenant_id,
            "decision": decision,
            "current_event_hash": digest({"event": len(self.records) + 1}),
        })
        return {
            "position": deepcopy(proposed),
            "event_hash": self.records[-1]["current_event_hash"],
        }


def _record(tenant, boundary, position, previous_hash):
    return {
        "action": HIGH_WATER_ACTION,
        "tenant_id": tenant,
        "decision": {
            "schema_version": HIGH_WATER_SCHEMA,
            "tenant_id": tenant,
            "scope_hash": position["scope_hash"],
            "source_epoch": position["source_epoch"],
            "source_version": position["source_version"],
            "projection_hash": position["projection_hash"],
            "update_id_reference": digest({"update_id": position["source_version"]}),
            "previous_position_hash": previous_hash,
            "position_hash": _position_hash(position),
            "storage_boundary_reference": boundary,
        },
        "current_event_hash": digest({"event": position["source_version"]}),
    }


def _fixture():
    tenant = "synthetic-enrollment-tenant"
    scope_hash = digest({"scope": "mutation"})
    boundary = digest({"storage": "synthetic-independent-ledger"})
    p1 = {
        "scope_hash": scope_hash,
        "source_epoch": 1,
        "source_version": 1,
        "projection_hash": digest({"projection": 1}),
    }
    records = [_record(
        tenant, boundary, p1, digest({"genesis": scope_hash}))]
    writer = SyntheticLedgerWriter(records, boundary)
    high_water = ImmutableLedgerMutationHighWater(
        "unused",
        tenant_id=tenant,
        writer=writer,
        storage_boundary_reference=boundary,
        reader=lambda _: deepcopy(records),
    )
    return high_water, writer, p1


def test_ledger_high_water_reads_exact_position():
    high_water, _, p1 = _fixture()
    with high_water.hold(scope_hash=p1["scope_hash"]) as anchor:
        assert anchor.current() == p1


def test_ledger_high_water_advances_monotonically():
    high_water, _, p1 = _fixture()
    p2 = dict(
        p1,
        source_version=2,
        projection_hash=digest({"projection": 2}),
    )
    with high_water.hold_update(
            scope_hash=p1["scope_hash"], expected=p1,
            proposed=p2, update_id="update-2") as anchor:
        class Connection:
            def execute(self, sql):
                assert sql == "COMMIT"
        anchor.commit_update(
            Connection(), expected=p1, proposed=p2, update_id="update-2")
    with high_water.hold(scope_hash=p1["scope_hash"]) as anchor:
        assert anchor.current() == p2


def test_ledger_high_water_rejects_version_skip():
    high_water, _, p1 = _fixture()
    p3 = dict(
        p1,
        source_version=3,
        projection_hash=digest({"projection": 3}),
    )
    with pytest.raises(EnrollmentDenied):
        with high_water.hold_update(
                scope_hash=p1["scope_hash"], expected=p1,
                proposed=p3, update_id="skip"):
            pass


def test_ledger_high_water_rejects_tenant_substitution():
    high_water, writer, p1 = _fixture()
    bad = deepcopy(writer.records)
    bad[0]["tenant_id"] = "other-tenant"
    bad[0]["decision"]["tenant_id"] = "other-tenant"
    high_water.reader = lambda _: bad
    with pytest.raises(EnrollmentDenied):
        with high_water.hold(scope_hash=p1["scope_hash"]):
            pass


def test_ledger_high_water_rejects_broken_position_chain():
    high_water, writer, p1 = _fixture()
    p2 = dict(
        p1,
        source_version=2,
        projection_hash=digest({"projection": 2}),
    )
    bad = deepcopy(writer.records)
    bad.append(_record(
        "synthetic-enrollment-tenant",
        high_water.storage_boundary_reference,
        p2,
        digest({"wrong": "previous"}),
    ))
    high_water.reader = lambda _: bad
    with pytest.raises(EnrollmentDenied):
        with high_water.hold(scope_hash=p1["scope_hash"]):
            pass


def test_ledger_high_water_requires_preprovisioned_writer():
    high_water, _, p1 = _fixture()
    high_water.writer = None
    with pytest.raises(EnrollmentDenied):
        with high_water.hold(scope_hash=p1["scope_hash"]):
            pass


def test_ledger_high_water_integrates_with_projection_updater(tmp_path):
    f, _, _ = projected_commit(tmp_path)
    previous = _stored_projection(f)
    scope_hash = projection_scope_hash(f.command["payload"])
    previous_position = {
        "scope_hash": scope_hash,
        "source_epoch": 1,
        "source_version": 1,
        "projection_hash": projection_payload_hash(previous),
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
    proposed = deepcopy(previous)
    proposed["authority_status"]["issuer_status"] = "REVOKED"
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
        update_id="ledger-integrated-update-2",
    )
    assert result["decision"] == "ALLOW"
    assert result["source_version"] == 2
    with high_water.hold(scope_hash=scope_hash) as anchor:
        assert anchor.current() == {
            "scope_hash": scope_hash,
            "source_epoch": 1,
            "source_version": 2,
            "projection_hash": projection_payload_hash(proposed),
        }
