"""Synthetic-only tests for concrete bounded policy revocation writer."""
from contextlib import contextmanager
from copy import deepcopy
import sqlite3

from governance.mutation_policy_revocation_writer import (
    GovernedPolicyRevocationWriter,
    PolicyRevocationTransitionGuard,
    PolicyRevocationTransitionSource,
)
from governance.tenant_enrollment_contracts import (
    EnrollmentPolicy, canonical, digest, object_id, parse_json,
)
from tests.helpers.mutation_commit import synthetic_commit
from tests.helpers.mutation_policy_revocation_effect import (
    build_effect_for_mutation,
)
from tests.helpers.tenant_enrollment import (
    object_revocation, synthetic_enrollment,
)


def _bundle(f):
    return {
        "policy": f.inputs["policy"],
        "adoption": f.inputs["adoption"],
        "h": f.inputs["h"],
        "w": f.inputs["w"],
        "revocations": f.inputs["revocations"],
        "expected": deepcopy(f.head),
        "challenge": f.inputs["request"]["payload"]["nonce"],
        "request_digest": digest(f.inputs["request"]["payload"]),
    }


class SyntheticTransitionGuard(PolicyRevocationTransitionGuard):
    def __init__(self, bundle):
        self.bundle = deepcopy(bundle)
        self.evidence = {
            "revoked_currentness": deepcopy(bundle),
            "continuity_hash": digest({"continuity": bundle["revocations"]["payload"]["revocation_reference"]}),
        }

    def successor(self, *, previous_currentness):
        return deepcopy(self.evidence)

    def recheck(self, *, evidence):
        return deepcopy(self.evidence)


class SyntheticTransitionSource(PolicyRevocationTransitionSource):
    def __init__(self, bundle):
        self.guard = SyntheticTransitionGuard(bundle)

    @contextmanager
    def hold(self, *, command, effect_grant):
        yield self.guard


def _prepare(tmp_path):
    f = synthetic_commit(tmp_path, action="REVOKE_POLICY_OBJECT")
    effect = build_effect_for_mutation(f.f)
    f.view.trust = f.f.trust
    old = f.f.enrollment
    old_policy = old.inputs["policy"]["payload"]
    prior = {
        "policy_hash": digest(old_policy),
        "head_hash": old.head["head_hash"],
    }
    entries = deepcopy(old.inputs["revocations"]["payload"]["revocations"])
    entries.append(object_revocation(EnrollmentPolicy, old_policy))
    successor = synthetic_enrollment(
        private_keys=old.private,
        sequence=2,
        previous=prior,
        revocations=entries,
    )
    command = f.new_command(
        revocation_effect_scope="ALL_VERSIONS_OF_OBJECT",
        revocation_effect_grant_hash=digest(effect["grant"]["payload"]),
    )
    with sqlite3.connect(f.path) as conn:
        conn.execute(
            "CREATE TABLE policy_revocation_terminal("
            "scope_hash TEXT NOT NULL,"
            "object_id TEXT NOT NULL,"
            "object_version_hash TEXT NOT NULL,"
            "revocation_reference TEXT NOT NULL,"
            "revocation_hash TEXT NOT NULL,"
            "terminal_projection_hash TEXT NOT NULL,"
            "terminal_proof_hash TEXT NOT NULL,"
            "source_epoch INTEGER NOT NULL,"
            "source_version INTEGER NOT NULL,"
            "command_hash TEXT NOT NULL,"
            "transaction_id TEXT NOT NULL,"
            "PRIMARY KEY(scope_hash,object_id))"
        )
    source = SyntheticTransitionSource(_bundle(successor))
    writer = GovernedPolicyRevocationWriter(
        f.view,
        currentness_fence=f.source,
        transition_source=source,
    )
    return f, effect, command, successor, source, writer


def test_policy_revocation_writer_commits_terminal_revocation(tmp_path):
    f, effect, command, successor, _, writer = _prepare(tmp_path)
    result = writer.execute(
        command,
        proposal=f.f.proposal,
        reviews=f.f.reviews,
        grant=f.f.grant,
        revocation_effect=effect,
    )
    assert result["decision"] == "ALLOW"
    assert result["reason"] == "POLICY_OBJECT_REVOKED_NON_PRODUCTION"
    assert result["mutation_executed"] is True
    assert result["source_epoch"] == 1
    assert result["source_version"] == 2

    with sqlite3.connect(f.path) as conn:
        row = conn.execute(
            "SELECT object_id,source_epoch,source_version,terminal_proof_hash "
            "FROM policy_revocation_terminal"
        ).fetchone()
        assert row[0] == command["payload"]["object_id"]
        assert row[1:3] == (1, 2)
        assert row[3] == result["terminal_proof_hash"]
        # Snapshot must prove materialization == terminal event.
        f.view._snapshot(conn, require_finalized=False)
        events = [
            parse_json(x[0]) for x in
            conn.execute("SELECT payload FROM enrollment_events ORDER BY sequence")
        ]
    assert any(e.get("kind") == "POLICY_REVOCATION_TERMINAL_NON_PRODUCTION" for e in events)


def test_policy_revocation_writer_consumes_mutation_and_effect_grants(tmp_path):
    f, effect, command, _, _, writer = _prepare(tmp_path)
    result = writer.execute(
        command,
        proposal=f.f.proposal,
        reviews=f.f.reviews,
        grant=f.f.grant,
        revocation_effect=effect,
    )
    assert result["decision"] == "ALLOW"
    with sqlite3.connect(f.path) as conn:
        kinds = {row[0] for row in conn.execute("SELECT kind FROM enrollment_uses")}
    assert "mutation:grant" in kinds
    assert "policy_revocation_effect:grant_id" in kinds
    assert "policy_revocation_effect:nonce" in kinds
    assert "policy_revocation_effect:replay_identity" in kinds


def test_policy_revocation_writer_rolls_back_invalid_successor(tmp_path):
    f, effect, command, successor, source, writer = _prepare(tmp_path)
    bad = deepcopy(source.guard.evidence)
    payload = deepcopy(bad["revoked_currentness"]["revocations"]["payload"])
    payload["revocations"] = []
    payload["revocation_reference"] = digest({
        k: v for k, v in payload.items() if k != "revocation_reference"})
    bad["revoked_currentness"]["revocations"] = successor.sign(payload)
    source.guard.evidence = bad
    result = writer.execute(
        command,
        proposal=f.f.proposal,
        reviews=f.f.reviews,
        grant=f.f.grant,
        revocation_effect=effect,
    )
    assert result["decision"] == "DENY"
    with sqlite3.connect(f.path) as conn:
        assert conn.execute(
            "SELECT count(*) FROM policy_revocation_terminal"
        ).fetchone()[0] == 0
        assert conn.execute(
            "SELECT count(*) FROM enrollment_uses "
            "WHERE kind LIKE 'policy_revocation_effect:%'"
        ).fetchone()[0] == 0


def test_policy_revocation_writer_missing_transition_source_fails_closed(tmp_path):
    f, effect, command, _, _, _ = _prepare(tmp_path)
    writer = GovernedPolicyRevocationWriter(
        f.view,
        currentness_fence=f.source,
        transition_source=None,
    )
    result = writer.execute(
        command,
        proposal=f.f.proposal,
        reviews=f.f.reviews,
        grant=f.f.grant,
        revocation_effect=effect,
    )
    assert result["decision"] == "DENY"
    assert result["reason"] == "POLICY_REVOCATION_TRANSITION_UNAVAILABLE"


def test_policy_revocation_writer_cannot_reopen_terminal_policy(tmp_path):
    f, effect, command, _, _, writer = _prepare(tmp_path)
    first = writer.execute(
        command,
        proposal=f.f.proposal,
        reviews=f.f.reviews,
        grant=f.f.grant,
        revocation_effect=effect,
    )
    assert first["decision"] == "ALLOW"
    second = writer.execute(
        command,
        proposal=f.f.proposal,
        reviews=f.f.reviews,
        grant=f.f.grant,
        revocation_effect=effect,
    )
    assert second["decision"] == "DENY"
    assert second["reason"] in (
        "POLICY_OBJECT_REVOCATION",
        "GRANT_ALREADY_CONSUMED",
        "COMMIT_FENCE_UNAVAILABLE",
    )


def test_policy_revocation_writer_lost_commit_ack_is_unknown(tmp_path):
    f, effect, command, _, _, writer = _prepare(tmp_path)
    f.source.fail_after_commit = True
    result = writer.execute(
        command,
        proposal=f.f.proposal,
        reviews=f.f.reviews,
        grant=f.f.grant,
        revocation_effect=effect,
    )
    assert result["decision"] == "DENY"
    assert result["reason"] == "COMMIT_STATE_UNKNOWN"
    assert result["reconciliation_required"] is True
