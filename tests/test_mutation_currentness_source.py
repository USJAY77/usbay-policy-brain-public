"""Synthetic-only tests for the SQLite currentness projection source."""
from contextlib import contextmanager
from copy import deepcopy
from threading import RLock
import sqlite3

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from governance.mutation_currentness_source import (
    MutationCurrentnessHighWater, MutationProjectionSigner,
    SQLiteMutationCurrentnessFence, PROJECTION_SCHEMA,
    projection_scope, projection_scope_hash, projection_payload_hash,
)
from governance.tenant_enrollment_contracts import canonical, digest
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
