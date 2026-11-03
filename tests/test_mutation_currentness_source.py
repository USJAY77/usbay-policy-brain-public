"""Synthetic-only tests for the SQLite currentness projection source."""
from contextlib import contextmanager
from copy import deepcopy
from threading import RLock
import sqlite3

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from governance.mutation_currentness_source import (
    MutationCurrentnessHighWater, MutationCurrentnessUpdaterAuthority,
    MutationProjectionSigner, SQLiteMutationCurrentnessFence,
    SQLiteMutationCurrentnessProjectionUpdater, PROJECTION_SCHEMA,
    projection_scope, projection_scope_hash, projection_payload_hash,
)
from governance.tenant_enrollment_contracts import canonical, digest, parse_json
from security.enrollment_policy_currentness import EnrollmentTrust, ScopedPublicKey
from tests.helpers.mutation_commit import synthetic_commit


class SyntheticSigner(MutationProjectionSigner):
    def __init__(self, issuer_id, key_id, private):
        self.issuer_id = issuer_id
        self.key_id = key_id
        self._private = private

    def sign(self, payload, *, role):
        return {
            "payload": deepcopy(payload),
            "signature": self._private.sign(canonical(payload)).hex(),
        }


class SyntheticAnchor(MutationCurrentnessHighWater):
    def __init__(self, record):
        self.record = deepcopy(record)
        self.lock = RLock()
        self.before_commit = None

    @contextmanager
    def hold(self, *, scope_hash):
        with self.lock:
            assert self.record["scope_hash"] == scope_hash
            yield self

    def current(self):
        return deepcopy(self.record)

    def commit_if_unchanged(self, connection, *, expected):
        if self.before_commit is not None:
            self.before_commit(self)
        if self.record != expected:
            from governance.mutation_commit import CommitFenceRejected
            raise CommitFenceRejected("COMMIT_FENCE_STALE")
        connection.execute("COMMIT")

    @contextmanager
    def hold_update(self, *, scope_hash, expected, proposed, update_id):
        with self.lock:
            assert self.record == expected
            self._proposed = deepcopy(proposed)
            yield self

    def commit_update(self, connection, *, expected, proposed, update_id):
        assert self.record == expected
        assert proposed == self._proposed
        connection.execute("COMMIT")
        self.record = deepcopy(proposed)


class SyntheticUpdaterAuthority(MutationCurrentnessUpdaterAuthority):
    def authorize_update(self, **kwargs):
        return {
            "decision": "ALLOW",
            "evidence_hash": digest({"synthetic-updater-evidence": kwargs["update_id"]}),
            "source_status_hash": digest({
                "previous": kwargs["previous_projection_hash"],
                "proposed": kwargs["proposed_projection_hash"],
            }),
            "consumption": {
                "grant_id": "synthetic-high-water-grant",
                "nonce": "synthetic-high-water-nonce",
                "replay_identity": digest({"synthetic-update": kwargs["update_id"]}),
            },
        }


def _add_key(f, issuer, key_id, roles):
    private = Ed25519PrivateKey.generate()
    base = f.command["payload"]
    key = ScopedPublicKey(
        issuer, key_id,
        private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw),
        tuple(roles), base["tenant_id"], base["registry_instance_reference"],
        "2026-01-01T00:00:00Z", "2026-01-03T00:00:00Z",
        digest({"synthetic-currentness-signer": key_id}),
    )
    f.f.trust = EnrollmentTrust(
        tuple(f.f.trust._keys.values()) + (key,), max_age_seconds=60)
    f.view.trust = f.f.trust
    return SyntheticSigner(issuer, key_id, private)


def projected_commit(tmp_path):
    f = synthetic_commit(tmp_path)
    parent = _add_key(
        f, "synthetic-parent-status", "test-parent-status",
        ("mutation_parent_currentness",))
    root = _add_key(
        f, "synthetic-root-status", "test-root-status",
        ("mutation_root_currentness",))
    commit = _add_key(
        f, "synthetic-projection-commit", "test-projection-commit",
        ("mutation_commit_fence",))

    command = f.command["payload"]
    currentness = f.f.currentness()
    projection = {
        "schema_version": PROJECTION_SCHEMA,
        "scope": projection_scope(command),
        "authority_domain": command["authority_domain"],
        "parent_artifact": deepcopy(f.f.parent),
        "root_authority": deepcopy(f.f.root_authority),
        "issuer_grant": deepcopy(f.f.issuer_grant),
        "review_policy": deepcopy(f.f.review_policy),
        "currentness": deepcopy(currentness),
        "target_object": deepcopy(f.f.commit_target),
        "target_state": deepcopy(command["expected_state"]),
        "parent_status_signer": {
            "issuer_id": parent.issuer_id,
            "issuer_key_id": parent.key_id,
        },
        "root_status_signer": {
            "issuer_id": root.issuer_id,
            "issuer_key_id": root.key_id,
        },
        "commit_fence_signer": {
            "issuer_id": commit.issuer_id,
            "issuer_key_id": commit.key_id,
        },
        "expected_current_head": command["expected_current_head"],
        "revocation_reference":
            currentness["revocations"]["payload"]["revocation_reference"],
        "authority_status": {
            "parent_status": "ACTIVE",
            "root_status": "ACTIVE",
            "issuer_status": "ACTIVE",
            "issuance_state": "AVAILABLE",
        },
    }
    scope_hash = projection_scope_hash(command)
    projection_hash = projection_payload_hash(projection)
    with sqlite3.connect(f.path) as conn:
        conn.execute(
            "CREATE TABLE mutation_currentness_projection("
            "scope_hash TEXT PRIMARY KEY,"
            "source_epoch INTEGER NOT NULL,"
            "source_version INTEGER NOT NULL,"
            "projection TEXT NOT NULL,"
            "projection_hash TEXT NOT NULL)"
        )
        conn.execute(
            "INSERT INTO mutation_currentness_projection VALUES(?,?,?,?,?)",
            (scope_hash, 1, 1, canonical(projection).decode(), projection_hash),
        )
    anchor = SyntheticAnchor({
        "scope_hash": scope_hash,
        "source_epoch": 1,
        "source_version": 1,
        "projection_hash": projection_hash,
    })
    source = SQLiteMutationCurrentnessFence(
        f.view,
        signers={
            "mutation_parent_currentness": parent,
            "mutation_root_currentness": root,
            "mutation_commit_fence": commit,
        },
        high_water=anchor,
    )
    return f, source, anchor


def test_projection_source_verifies_and_consumes_nonexecuting_attempt(tmp_path):
    f, source, _ = projected_commit(tmp_path)
    with f.view.mutation_attempt(currentness_fence=source) as tx:
        result = f.verify(tx)
        assert result["decision"] == "ALLOW"
        result = tx.commit()
        assert result["decision"] == "ALLOW"
        assert result["mutation_executed"] is False


def test_projection_missing_high_water_fails_closed(tmp_path):
    f, source, _ = projected_commit(tmp_path)
    source._high_water = None
    with f.view.mutation_attempt(currentness_fence=source) as tx:
        result = f.verify(tx)
        assert result["decision"] == "DENY"
        assert result["reason"] == "AUTHORITY_CURRENTNESS_UNPROVEN"


def test_projection_rollback_below_anchor_fails_closed(tmp_path):
    f, source, anchor = projected_commit(tmp_path)
    anchor.record["source_version"] = 2
    with f.view.mutation_attempt(currentness_fence=source) as tx:
        result = f.verify(tx)
        assert result["decision"] == "DENY"
        assert result["reason"] == "AUTHORITY_CURRENTNESS_UNPROVEN"


def test_projection_anchor_change_before_commit_is_stale(tmp_path):
    f, source, anchor = projected_commit(tmp_path)
    with f.view.mutation_attempt(currentness_fence=source) as tx:
        assert f.verify(tx)["decision"] == "ALLOW"
        anchor.before_commit = lambda a: a.record.update(source_version=2)
        result = tx.commit()
        assert result["decision"] == "DENY"
        assert result["reason"] == "COMMIT_FENCE_STALE"


def test_projection_tenant_substitution_denied(tmp_path):
    f, source, _ = projected_commit(tmp_path)
    command = deepcopy(f.command["payload"])
    command["tenant_id"] = "other-tenant"
    command = f.seal_command(command)
    with f.view.mutation_attempt(currentness_fence=source) as tx:
        result = f.verify(tx, command)
        assert result["decision"] == "DENY"


def test_projection_table_is_never_autocreated(tmp_path):
    f = synthetic_commit(tmp_path)
    source = SQLiteMutationCurrentnessFence(
        f.view,
        signers={},
        high_water=SyntheticAnchor({
            "scope_hash": projection_scope_hash(f.command["payload"]),
            "source_epoch": 1,
            "source_version": 1,
            "projection_hash": digest({"absent": True}),
        }),
    )
    with f.view.mutation_attempt(currentness_fence=source) as tx:
        result = f.verify(tx)
        assert result["decision"] == "DENY"
        assert result["reason"] == "COMMIT_FENCE_UNAVAILABLE"
    with sqlite3.connect(f.path) as conn:
        tables = {
            row[0] for row in
            conn.execute("SELECT name FROM sqlite_master WHERE type='table'")
        }
    assert "mutation_currentness_projection" not in tables


def _stored_projection(f):
    with sqlite3.connect(f.path) as conn:
        encoded = conn.execute(
            "SELECT projection FROM mutation_currentness_projection"
        ).fetchone()[0]
    return parse_json(encoded)


def test_projection_status_is_not_inferred_active(tmp_path):
    f, source, anchor = projected_commit(tmp_path)
    projection = _stored_projection(f)
    projection["authority_status"]["root_status"] = "REVOKED"
    new_hash = projection_payload_hash(projection)
    with sqlite3.connect(f.path) as conn:
        conn.execute(
            "UPDATE mutation_currentness_projection "
            "SET projection=?,projection_hash=? WHERE source_version=1",
            (canonical(projection).decode(), new_hash),
        )
    anchor.record["projection_hash"] = new_hash
    with f.view.mutation_attempt(currentness_fence=source) as tx:
        result = f.verify(tx)
        assert result["decision"] == "DENY"
        assert result["reason"] == "ROOT_AUTHORITY_REVOKED"


def test_projection_updater_advances_version_and_binds_audit(tmp_path):
    f, source, anchor = projected_commit(tmp_path)
    previous = _stored_projection(f)
    previous_hash = projection_payload_hash(previous)
    proposed = deepcopy(previous)
    proposed["authority_status"]["root_status"] = "REVOKED"
    updater = SQLiteMutationCurrentnessProjectionUpdater(
        f.view,
        updater_authority=SyntheticUpdaterAuthority(),
        high_water=anchor,
    )
    result = updater.update(
        f.command["payload"], proposed,
        expected_epoch=1,
        expected_version=1,
        expected_projection_hash=previous_hash,
        update_id="synthetic-update-1",
    )
    assert result["decision"] == "ALLOW"
    assert result["source_epoch"] == 1
    assert result["source_version"] == 2
    assert anchor.record["source_version"] == 2
    with sqlite3.connect(f.path) as conn:
        row = conn.execute(
            "SELECT source_epoch,source_version,projection_hash "
            "FROM mutation_currentness_projection"
        ).fetchone()
        assert row == (1, 2, projection_payload_hash(proposed))
        events = [
            parse_json(x[0]) for x in
            conn.execute("SELECT payload FROM enrollment_events ORDER BY sequence")
        ]
    event = [
        e for e in events
        if e.get("kind") == "MUTATION_CURRENTNESS_PROJECTED_NON_PRODUCTION"
    ][-1]
    assert event["source_epoch"] == 1
    assert event["previous_source_version"] == 1
    assert event["source_version"] == 2
    assert event["previous_projection_hash"] == previous_hash
    assert event["projection_hash"] == projection_payload_hash(proposed)
    with f.view.mutation_attempt(currentness_fence=source) as tx:
        denied = f.verify(tx)
        assert denied["decision"] == "DENY"
        assert denied["reason"] == "ROOT_AUTHORITY_REVOKED"


def test_projection_updater_stale_cas_fails_closed(tmp_path):
    f, _, anchor = projected_commit(tmp_path)
    previous = _stored_projection(f)
    proposed = deepcopy(previous)
    proposed["authority_status"]["issuer_status"] = "REVOKED"
    updater = SQLiteMutationCurrentnessProjectionUpdater(
        f.view,
        updater_authority=SyntheticUpdaterAuthority(),
        high_water=anchor,
    )
    result = updater.update(
        f.command["payload"], proposed,
        expected_epoch=1,
        expected_version=2,
        expected_projection_hash=projection_payload_hash(previous),
        update_id="synthetic-stale-update",
    )
    assert result["decision"] == "DENY"
    assert result["reason"] == "CURRENTNESS_UPDATE_STALE"


def test_projection_updater_without_authority_fails_closed(tmp_path):
    f, _, anchor = projected_commit(tmp_path)
    previous = _stored_projection(f)
    proposed = deepcopy(previous)
    proposed["authority_status"]["parent_status"] = "REVOKED"
    updater = SQLiteMutationCurrentnessProjectionUpdater(
        f.view,
        updater_authority=None,
        high_water=anchor,
    )
    result = updater.update(
        f.command["payload"], proposed,
        expected_epoch=1,
        expected_version=1,
        expected_projection_hash=projection_payload_hash(previous),
        update_id="synthetic-no-authority",
    )
    assert result["decision"] == "DENY"
    assert result["reason"] == "AUTHORITY_CURRENTNESS_UPDATER_UNAVAILABLE"


def test_projection_updater_reuses_no_high_water_grant(tmp_path):
    f, _, anchor = projected_commit(tmp_path)
    previous = _stored_projection(f)
    previous_hash = projection_payload_hash(previous)
    proposed = deepcopy(previous)
    proposed["authority_status"]["issuer_status"] = "REVOKED"
    updater = SQLiteMutationCurrentnessProjectionUpdater(
        f.view,
        updater_authority=SyntheticUpdaterAuthority(),
        high_water=anchor,
    )
    first = updater.update(
        f.command["payload"], proposed,
        expected_epoch=1,
        expected_version=1,
        expected_projection_hash=previous_hash,
        update_id="synthetic-one-time-update",
    )
    assert first["decision"] == "ALLOW"

    with sqlite3.connect(f.path) as conn:
        current = conn.execute(
            "SELECT source_epoch,source_version,projection_hash "
            "FROM mutation_currentness_projection"
        ).fetchone()
    rollback = deepcopy(previous)
    rollback["authority_status"]["issuer_status"] = "ACTIVE"
    second = updater.update(
        f.command["payload"], rollback,
        expected_epoch=current[0],
        expected_version=current[1],
        expected_projection_hash=current[2],
        update_id="synthetic-one-time-update-2",
    )
    assert second["decision"] == "DENY"
    assert second["reason"] in ("REPLAY_DETECTED", "GRANT_ALREADY_CONSUMED")
