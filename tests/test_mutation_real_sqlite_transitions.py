"""Real-SQLite integration tests for bounded mutation currentness transitions.

These tests use the production SQLiteMutationCurrentnessFence and projection
table with test-only ephemeral signers/high-water storage. No production schema,
signer, provider or live authority is provisioned.
"""
from copy import deepcopy
import sqlite3

from governance.mutation_adoption_finalization import (
    verify_finalization_composition,
)
from governance.mutation_adoption_finalization_writer import (
    GovernedAdoptionFinalizationWriter,
)
from governance.mutation_adoption_revocation_writer import (
    GovernedAdoptionRevocationWriter,
)
from governance.mutation_grant_revocation_writer import (
    GovernedGrantRevocationWriter,
)
from governance.mutation_policy_revocation_writer import (
    GovernedPolicyRevocationWriter,
)
from governance.mutation_currentness_source import (
    projection_payload_hash,
)
from governance.tenant_enrollment_contracts import (
    EnrollmentGrant, EnrollmentPolicy, PolicyAdoption, canonical, digest,
    parse_json,
)
from tests.helpers.mutation_adoption_finalization import (
    build_finalization_artifacts,
)
from tests.helpers.mutation_adoption_revocation_effect import (
    build_adoption_effect_for_mutation,
)
from tests.helpers.mutation_grant_revocation_effect import (
    build_grant_effect_for_mutation,
)
from tests.helpers.mutation_policy_revocation_effect import (
    build_effect_for_mutation,
)
from tests.helpers.tenant_enrollment import (
    NOW, object_revocation, synthetic_enrollment,
)
from tests.test_mutation_adoption_finalization_writer import (
    SyntheticFinalizationSource,
)
from tests.test_mutation_adoption_revocation_writer import (
    SyntheticAdoptionTransitionSource,
)
from tests.test_mutation_currentness_source import projected_commit
from tests.test_mutation_grant_revocation_writer import (
    SyntheticGrantTransitionSource,
)
from tests.test_mutation_policy_revocation_writer import (
    SyntheticTransitionSource,
)


IMMUTABLE_PROJECTION_FIELDS = (
    "schema_version", "scope", "authority_domain", "parent_artifact",
    "root_authority", "issuer_grant", "review_policy", "target_object",
    "parent_status_signer", "root_status_signer", "commit_fence_signer",
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


def _projection_state(path):
    with sqlite3.connect(path) as conn:
        row = conn.execute(
            "SELECT scope_hash,source_epoch,source_version,projection,"
            "projection_hash FROM mutation_currentness_projection"
        ).fetchone()
        events = [
            parse_json(item[0]) for item in
            conn.execute(
                "SELECT payload FROM enrollment_events ORDER BY sequence")
        ]
    return {
        "scope_hash": row[0],
        "source_epoch": row[1],
        "source_version": row[2],
        "projection": parse_json(row[3]),
        "projection_hash": row[4],
        "events": events,
    }


def _assert_transition(f, anchor, before, result, *, terminal):
    assert result["decision"] == "ALLOW"
    after = _projection_state(f.path)
    assert after["source_epoch"] == before["source_epoch"] == 1
    assert after["source_version"] == before["source_version"] + 1 == 2
    assert after["projection_hash"] == projection_payload_hash(
        after["projection"])
    assert anchor.record == {
        "scope_hash": after["scope_hash"],
        "source_epoch": after["source_epoch"],
        "source_version": after["source_version"],
        "projection_hash": after["projection_hash"],
    }
    for name in IMMUTABLE_PROJECTION_FIELDS:
        assert canonical(after["projection"][name]) == canonical(
            before["projection"][name])
    assert after["projection"]["authority_status"]["parent_status"] == (
        before["projection"]["authority_status"]["parent_status"])
    assert after["projection"]["authority_status"]["root_status"] == (
        before["projection"]["authority_status"]["root_status"])
    assert after["projection"]["authority_status"]["issuer_status"] == (
        before["projection"]["authority_status"]["issuer_status"])
    assert after["projection"]["authority_status"]["issuance_state"] == (
        "CONSUMED")
    projected = [
        event for event in after["events"]
        if event.get("kind")
        == "MUTATION_CURRENTNESS_PROJECTED_NON_PRODUCTION"
    ]
    assert len(projected) == 1
    event = projected[0]
    assert event["previous_source_version"] == 1
    assert event["source_version"] == 2
    assert event["previous_projection_hash"] == before["projection_hash"]
    assert event["projection_hash"] == after["projection_hash"]
    assert event["terminal"] is terminal
    assert event["transition_evidence_hash"].startswith("sha256:")


def _successor_with_revocation(old, model, target):
    entries = deepcopy(
        old.inputs["revocations"]["payload"]["revocations"])
    entries.append(object_revocation(model, target))
    return synthetic_enrollment(
        private_keys=old.private,
        sequence=2,
        previous={
            "policy_hash": digest(old.inputs["policy"]["payload"]),
            "head_hash": old.head["head_hash"],
        },
        revocations=entries,
    )


def test_real_sqlite_policy_revocation_transition_is_atomic(tmp_path):
    f, source, anchor = projected_commit(
        tmp_path, action="REVOKE_POLICY_OBJECT")
    before = _projection_state(f.path)
    effect = build_effect_for_mutation(f.f)
    f.view.trust = f.f.trust
    successor = _successor_with_revocation(
        f.f.enrollment, EnrollmentPolicy,
        f.f.enrollment.inputs["policy"]["payload"])
    with sqlite3.connect(f.path) as conn:
        conn.execute("""CREATE TABLE policy_revocation_terminal(
            scope_hash TEXT NOT NULL,object_id TEXT NOT NULL,
            object_version_hash TEXT NOT NULL,revocation_reference TEXT NOT NULL,
            revocation_hash TEXT NOT NULL,terminal_projection_hash TEXT NOT NULL,
            terminal_proof_hash TEXT NOT NULL,source_epoch INTEGER NOT NULL,
            source_version INTEGER NOT NULL,command_hash TEXT NOT NULL,
            transaction_id TEXT NOT NULL,PRIMARY KEY(scope_hash,object_id))""")
    command = f.new_command(
        revocation_effect_scope="ALL_VERSIONS_OF_OBJECT",
        revocation_effect_grant_hash=digest(effect["grant"]["payload"]),
    )
    writer = GovernedPolicyRevocationWriter(
        f.view, currentness_fence=source,
        transition_source=SyntheticTransitionSource(_bundle(successor)))
    result = writer.execute(
        command, proposal=f.f.proposal, reviews=f.f.reviews,
        grant=f.f.grant, revocation_effect=effect)
    _assert_transition(f, anchor, before, result, terminal=True)
    after = _projection_state(f.path)
    assert after["projection"]["currentness"]["revocations"]["payload"][
        "revocation_reference"
    ] == successor.inputs["revocations"]["payload"]["revocation_reference"]
    assert after["projection"]["target_state"]["status"] == (
        "REVOKED_NON_PRODUCTION")


def test_real_sqlite_grant_revocation_transition_is_atomic(tmp_path):
    f, source, anchor = projected_commit(
        tmp_path, action="REVOKE_GRANT_OBJECT")
    before = _projection_state(f.path)
    effect = build_grant_effect_for_mutation(f.f)
    f.view.trust = f.f.trust
    successor = _successor_with_revocation(
        f.f.enrollment, EnrollmentGrant,
        f.f.enrollment.inputs["grant"]["payload"])
    with sqlite3.connect(f.path) as conn:
        conn.execute("""CREATE TABLE grant_revocation_terminal(
            scope_hash TEXT NOT NULL,object_id TEXT NOT NULL,
            object_version_hash TEXT NOT NULL,target_grant_id TEXT NOT NULL,
            consumption_state TEXT NOT NULL,revocation_reference TEXT NOT NULL,
            revocation_hash TEXT NOT NULL,terminal_projection_hash TEXT NOT NULL,
            terminal_proof_hash TEXT NOT NULL,source_epoch INTEGER NOT NULL,
            source_version INTEGER NOT NULL,command_hash TEXT NOT NULL,
            transaction_id TEXT NOT NULL,PRIMARY KEY(scope_hash,object_id))""")
    command = f.new_command(
        revocation_effect_scope="ALL_VERSIONS_OF_OBJECT",
        revocation_effect_grant_hash=digest(effect["grant"]["payload"]),
    )
    writer = GovernedGrantRevocationWriter(
        f.view, currentness_fence=source,
        transition_source=SyntheticGrantTransitionSource(_bundle(successor)))
    result = writer.execute(
        command, proposal=f.f.proposal, reviews=f.f.reviews,
        grant=f.f.grant, revocation_effect=effect)
    _assert_transition(f, anchor, before, result, terminal=False)
    after = _projection_state(f.path)
    assert after["projection"]["target_state"]["status"] == (
        "GRANT_REVOKED_NON_PRODUCTION")
    assert after["projection"]["target_state"]["consumption_state"] == (
        "UNCONSUMED")


def test_real_sqlite_adoption_revocation_transition_is_atomic(tmp_path):
    f, source, anchor = projected_commit(
        tmp_path, action="REVOKE_ADOPTION")
    before = _projection_state(f.path)
    effect = build_adoption_effect_for_mutation(f.f)
    f.view.trust = f.f.trust
    successor = _successor_with_revocation(
        f.f.enrollment, PolicyAdoption,
        f.f.enrollment.inputs["adoption"]["payload"])
    with sqlite3.connect(f.path) as conn:
        conn.execute("""CREATE TABLE adoption_revocation_terminal(
            scope_hash TEXT NOT NULL,object_id TEXT NOT NULL,
            object_version_hash TEXT NOT NULL,adoption_id TEXT NOT NULL,
            policy_id TEXT NOT NULL,finalization_state TEXT NOT NULL,
            revocation_reference TEXT NOT NULL,revocation_hash TEXT NOT NULL,
            terminal_projection_hash TEXT NOT NULL,
            terminal_proof_hash TEXT NOT NULL,source_epoch INTEGER NOT NULL,
            source_version INTEGER NOT NULL,command_hash TEXT NOT NULL,
            transaction_id TEXT NOT NULL,PRIMARY KEY(scope_hash,object_id))""")
    command = f.new_command(
        revocation_effect_scope="ALL_VERSIONS_OF_OBJECT",
        revocation_effect_grant_hash=digest(effect["grant"]["payload"]),
    )
    writer = GovernedAdoptionRevocationWriter(
        f.view, currentness_fence=source,
        transition_source=SyntheticAdoptionTransitionSource(
            _bundle(successor)))
    result = writer.execute(
        command, proposal=f.f.proposal, reviews=f.f.reviews,
        grant=f.f.grant, revocation_effect=effect)
    _assert_transition(f, anchor, before, result, terminal=True)
    after = _projection_state(f.path)
    assert after["projection"]["target_state"]["status"] == (
        "ADOPTION_REVOKED_NON_PRODUCTION")


def test_real_sqlite_adoption_finalization_transition_is_atomic(tmp_path):
    f, source, anchor = projected_commit(
        tmp_path, action="FINALIZE_POLICY_ADOPTION")
    artifacts, pending_event, pending_event_hash = (
        build_finalization_artifacts(f))
    composition = verify_finalization_composition(
        f.view.trust,
        previous_currentness=f.f.currentness(),
        previous_head=f.f.enrollment.head,
        pending_event=pending_event,
        pending_event_hash=pending_event_hash,
        artifacts=artifacts,
        now=NOW,
    )
    assert composition["decision"] == "ALLOW"
    state = deepcopy(f.state)
    state["witness_reference"] = digest({
        "h_witness_hash":
            composition["composition"]["h_witness_hash"],
        "w_witness_hash":
            composition["composition"]["w_witness_hash"],
    })
    state["finality_reference"] = composition["composition_hash"]
    command = f.new_command(expected_state=state)

    # The projection is the authoritative observed pre-state, so bind it to
    # the exact finalized command before opening the protected attempt.
    with sqlite3.connect(f.path) as conn:
        row = conn.execute(
            "SELECT projection FROM mutation_currentness_projection"
        ).fetchone()
        projection = parse_json(row[0])
        projection["target_state"] = deepcopy(state)
        new_hash = projection_payload_hash(projection)
        conn.execute(
            "UPDATE mutation_currentness_projection "
            "SET projection=?,projection_hash=? WHERE source_version=1",
            (canonical(projection).decode(), new_hash))
        conn.execute("""CREATE TABLE adoption_finalization(
            scope_hash TEXT NOT NULL,adoption_id TEXT NOT NULL,
            adoption_version_hash TEXT NOT NULL,policy_id TEXT NOT NULL,
            policy_hash TEXT NOT NULL,previous_head TEXT NOT NULL,
            target_head TEXT NOT NULL,pending_event_hash TEXT NOT NULL,
            composition_hash TEXT NOT NULL,source_epoch INTEGER NOT NULL,
            source_version INTEGER NOT NULL,command_hash TEXT NOT NULL,
            transaction_id TEXT NOT NULL,PRIMARY KEY(scope_hash,adoption_id))""")
    anchor.record["projection_hash"] = new_hash
    before = _projection_state(f.path)

    writer = GovernedAdoptionFinalizationWriter(
        f.view, currentness_fence=source,
        artifact_source=SyntheticFinalizationSource(artifacts))
    result = writer.execute(
        command, proposal=f.f.proposal,
        reviews=f.f.reviews, grant=f.f.grant)
    _assert_transition(f, anchor, before, result, terminal=False)
    after = _projection_state(f.path)
    assert after["projection"]["target_state"]["status"] == (
        "FINALIZED_NON_PRODUCTION")
    assert after["projection"]["expected_current_head"] == (
        artifacts["expected"]["head_hash"])
