"""Synthetic-only tests for concrete bounded adoption finalization writer."""
from contextlib import contextmanager
from copy import deepcopy
import sqlite3

from governance.mutation_adoption_finalization import (
    verify_finalization_composition,
)
from governance.mutation_adoption_finalization_writer import (
    AdoptionFinalizationArtifactGuard,
    AdoptionFinalizationArtifactSource,
    GovernedAdoptionFinalizationWriter,
)
from governance.tenant_enrollment_contracts import canonical,parse_json,digest
from tests.helpers.mutation_adoption_finalization import (
    build_finalization_artifacts,
)
from tests.helpers.mutation_commit import synthetic_commit
from tests.helpers.tenant_enrollment import NOW


class SyntheticFinalizationGuard(AdoptionFinalizationArtifactGuard):
    def __init__(self,artifacts):
        self.evidence={
            "artifacts":deepcopy(artifacts),
            "continuity_hash":digest({
                "finalization-continuity":
                    artifacts["expected"]["head_hash"]}),
        }
    def artifacts(self,*,previous_currentness,pending_event):
        return deepcopy(self.evidence)
    def recheck(self,*,evidence):
        return deepcopy(self.evidence)


class SyntheticFinalizationSource(AdoptionFinalizationArtifactSource):
    def __init__(self,artifacts):
        self.guard=SyntheticFinalizationGuard(artifacts)
    @contextmanager
    def hold(self,*,command):
        yield self.guard


def _prepare(tmp_path):
    f=synthetic_commit(tmp_path,action="FINALIZE_POLICY_ADOPTION")
    artifacts,pending_event,pending_event_hash=build_finalization_artifacts(f)
    composition=verify_finalization_composition(
        f.view.trust,
        previous_currentness=f.f.currentness(),
        previous_head=f.f.enrollment.head,
        pending_event=pending_event,
        pending_event_hash=pending_event_hash,
        artifacts=artifacts,
        now=NOW,
    )
    assert composition["decision"]=="ALLOW"
    state=deepcopy(f.state)
    state["witness_reference"]=digest({
        "h_witness_hash":composition["composition"]["h_witness_hash"],
        "w_witness_hash":composition["composition"]["w_witness_hash"],
    })
    state["finality_reference"]=composition["composition_hash"]
    with sqlite3.connect(f.path) as conn:
        conn.execute("""CREATE TABLE adoption_finalization(
            scope_hash TEXT NOT NULL,adoption_id TEXT NOT NULL,
            adoption_version_hash TEXT NOT NULL,policy_id TEXT NOT NULL,
            policy_hash TEXT NOT NULL,previous_head TEXT NOT NULL,
            target_head TEXT NOT NULL,pending_event_hash TEXT NOT NULL,
            composition_hash TEXT NOT NULL,source_epoch INTEGER NOT NULL,
            source_version INTEGER NOT NULL,command_hash TEXT NOT NULL,
            transaction_id TEXT NOT NULL,PRIMARY KEY(scope_hash,adoption_id))""")
        conn.execute(
            "UPDATE synthetic_mutation_target SET state=? "
            "WHERE tenant=? AND object_id=?",
            (canonical(state).decode(),
             f.command["payload"]["tenant_id"],
             f.command["payload"]["object_id"]))
    command=f.new_command(expected_state=state)
    source=SyntheticFinalizationSource(artifacts)
    writer=GovernedAdoptionFinalizationWriter(
        f.view,currentness_fence=f.source,artifact_source=source)
    return f,artifacts,composition,state,command,source,writer


def _run(f,command,writer):
    return writer.execute(
        command,
        proposal=f.f.proposal,
        reviews=f.f.reviews,
        grant=f.f.grant,
    )


def test_adoption_finalization_writer_commits_pending_to_finalized(tmp_path):
    f,artifacts,composition,_,command,_,writer=_prepare(tmp_path)
    result=_run(f,command,writer)
    assert result["decision"]=="ALLOW"
    assert result["reason"]=="POLICY_ADOPTION_FINALIZED_NON_PRODUCTION"
    assert result["target_head"]==artifacts["expected"]["head_hash"]
    assert result["composition_hash"]==composition["composition_hash"]
    assert result["source_epoch"]==1
    assert result["source_version"]==2
    with sqlite3.connect(f.path) as conn:
        state=parse_json(conn.execute(
            "SELECT value FROM enrollment_meta WHERE name='state'").fetchone()[0])
        assert state["publication"]=="FINALIZED"
        assert state["head"]["head_hash"]==artifacts["expected"]["head_hash"]
        row=conn.execute(
            "SELECT adoption_id,target_head,composition_hash,"
            "source_epoch,source_version FROM adoption_finalization"
        ).fetchone()
        assert row==(
            composition["composition"]["adoption_id"],
            artifacts["expected"]["head_hash"],
            composition["composition_hash"],1,2)
        f.view._snapshot(conn,require_finalized=True)


def test_adoption_finalization_preserves_adoption_and_advance_consumption(tmp_path):
    f,_,_,_,command,_,writer=_prepare(tmp_path)
    target=f.f.pending["adoption"]["payload"]
    advance=f.f.pending["advance"]["payload"]
    with sqlite3.connect(f.path) as conn:
        before=set(conn.execute(
            "SELECT kind,identity FROM enrollment_uses "
            "WHERE kind LIKE 'adoption:%' OR kind LIKE 'advance:%'"))
    assert len(before)==6
    result=_run(f,command,writer)
    assert result["decision"]=="ALLOW"
    with sqlite3.connect(f.path) as conn:
        after=set(conn.execute(
            "SELECT kind,identity FROM enrollment_uses "
            "WHERE kind LIKE 'adoption:%' OR kind LIKE 'advance:%'"))
    assert after==before


def test_adoption_finalization_missing_artifact_source_denies(tmp_path):
    f,_,_,_,command,_,_=_prepare(tmp_path)
    writer=GovernedAdoptionFinalizationWriter(
        f.view,currentness_fence=f.source,artifact_source=None)
    result=_run(f,command,writer)
    assert result["decision"]=="DENY"
    assert result["reason"]=="FINALIZATION_EVIDENCE_UNAVAILABLE"


def test_adoption_finalization_wrong_finality_reference_denies(tmp_path):
    f,_,_,state,_,source,writer=_prepare(tmp_path)
    bad=deepcopy(state)
    bad["finality_reference"]=digest({"wrong":"finality"})
    with sqlite3.connect(f.path) as conn:
        conn.execute(
            "UPDATE synthetic_mutation_target SET state=? "
            "WHERE tenant=? AND object_id=?",
            (canonical(bad).decode(),
             f.command["payload"]["tenant_id"],
             f.command["payload"]["object_id"]))
    command=f.new_command(expected_state=bad)
    result=_run(f,command,writer)
    assert result["decision"]=="DENY"
    assert result["reason"]=="FINALIZATION_EVIDENCE_INVALID"


def test_adoption_finalization_rejects_missing_prior_consumption(tmp_path):
    f,_,_,_,command,_,writer=_prepare(tmp_path)
    with sqlite3.connect(f.path) as conn:
        conn.execute(
            "DELETE FROM enrollment_uses WHERE kind='advance:nonce'")
        state=parse_json(conn.execute(
            "SELECT value FROM enrollment_meta WHERE name='state'").fetchone()[0])
        events=[
            (seq,parse_json(payload),event_hash)
            for seq,payload,event_hash in conn.execute(
                "SELECT sequence,payload,event_hash FROM enrollment_events "
                "ORDER BY sequence")
        ]
        # This test intentionally creates inconsistent storage; snapshot must
        # fail closed before finalization rather than repairing consumption.
    result=_run(f,command,writer)
    assert result["decision"]=="DENY"


def test_adoption_finalization_lost_commit_ack_is_unknown(tmp_path):
    f,_,_,_,command,_,writer=_prepare(tmp_path)
    f.source.fail_after_commit=True
    result=_run(f,command,writer)
    assert result["decision"]=="DENY"
    assert result["reason"]=="COMMIT_STATE_UNKNOWN"
    assert result["reconciliation_required"] is True
