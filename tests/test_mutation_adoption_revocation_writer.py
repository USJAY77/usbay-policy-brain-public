"""Synthetic-only tests for concrete bounded PolicyAdoption revocation writer."""
from contextlib import contextmanager
from copy import deepcopy
import sqlite3

from governance.mutation_adoption_revocation_writer import (
    GovernedAdoptionRevocationWriter,
    AdoptionRevocationTransitionGuard,
    AdoptionRevocationTransitionSource,
)
from governance.tenant_enrollment_contracts import PolicyAdoption,digest,parse_json
from tests.helpers.mutation_commit import synthetic_commit
from tests.helpers.mutation_adoption_revocation_effect import build_adoption_effect_for_mutation
from tests.helpers.tenant_enrollment import object_revocation,synthetic_enrollment

def _bundle(f):
    return dict(policy=f.inputs["policy"],adoption=f.inputs["adoption"],h=f.inputs["h"],w=f.inputs["w"],
        revocations=f.inputs["revocations"],expected=deepcopy(f.head),
        challenge=f.inputs["request"]["payload"]["nonce"],request_digest=digest(f.inputs["request"]["payload"]))

class SyntheticAdoptionTransitionGuard(AdoptionRevocationTransitionGuard):
    def __init__(self,bundle):
        self.evidence={"revoked_currentness":deepcopy(bundle),
            "continuity_hash":digest({"adoption-continuity":bundle["revocations"]["payload"]["revocation_reference"]})}
    def successor(self,*,previous_currentness): return deepcopy(self.evidence)
    def recheck(self,*,evidence): return deepcopy(self.evidence)

class SyntheticAdoptionTransitionSource(AdoptionRevocationTransitionSource):
    def __init__(self,bundle): self.guard=SyntheticAdoptionTransitionGuard(bundle)
    @contextmanager
    def hold(self,*,command,effect_grant): yield self.guard

def _prepare(tmp_path):
    f=synthetic_commit(tmp_path,action="REVOKE_ADOPTION")
    effect=build_adoption_effect_for_mutation(f.f)
    f.view.trust=f.f.trust
    old=f.f.enrollment
    target=old.inputs["adoption"]["payload"]
    entries=deepcopy(old.inputs["revocations"]["payload"]["revocations"])
    entries.append(object_revocation(PolicyAdoption,target))
    successor=synthetic_enrollment(private_keys=old.private,sequence=2,
        previous={"policy_hash":digest(old.inputs["policy"]["payload"]),"head_hash":old.head["head_hash"]},
        revocations=entries)
    command=f.new_command(
        revocation_effect_scope="ALL_VERSIONS_OF_OBJECT",
        revocation_effect_grant_hash=digest(effect["grant"]["payload"]))
    with sqlite3.connect(f.path) as conn:
        conn.execute("""CREATE TABLE adoption_revocation_terminal(
            scope_hash TEXT NOT NULL,object_id TEXT NOT NULL,object_version_hash TEXT NOT NULL,
            adoption_id TEXT NOT NULL,policy_id TEXT NOT NULL,finalization_state TEXT NOT NULL,
            revocation_reference TEXT NOT NULL,revocation_hash TEXT NOT NULL,
            terminal_projection_hash TEXT NOT NULL,terminal_proof_hash TEXT NOT NULL,
            source_epoch INTEGER NOT NULL,source_version INTEGER NOT NULL,
            command_hash TEXT NOT NULL,transaction_id TEXT NOT NULL,
            PRIMARY KEY(scope_hash,object_id))""")
    source=SyntheticAdoptionTransitionSource(_bundle(successor))
    writer=GovernedAdoptionRevocationWriter(
        f.view,currentness_fence=f.source,transition_source=source)
    return f,effect,command,successor,source,writer

def _run(f,effect,command,writer):
    return writer.execute(command,proposal=f.f.proposal,reviews=f.f.reviews,
        grant=f.f.grant,revocation_effect=effect)

def test_adoption_revocation_writer_commits_finalized_terminal(tmp_path):
    f,e,c,_,_,w=_prepare(tmp_path)
    r=_run(f,e,c,w)
    assert r["decision"]=="ALLOW"
    assert r["reason"]=="ADOPTION_REVOKED_NON_PRODUCTION"
    assert r["finalization_state"]=="FINALIZED"
    assert r["source_epoch"]==1 and r["source_version"]==2
    with sqlite3.connect(f.path) as conn:
        row=conn.execute(
            "SELECT adoption_id,finalization_state,source_epoch,source_version,"
            "terminal_proof_hash FROM adoption_revocation_terminal").fetchone()
        assert row[0]==c["payload"]["expected_state"]["adoption_id"]
        assert row[1:4]==("FINALIZED",1,2)
        assert row[4]==r["terminal_proof_hash"]
        f.view._snapshot(conn,require_finalized=False)

def test_adoption_revocation_writer_preserves_existing_consumption(tmp_path):
    f,e,c,_,_,w=_prepare(tmp_path)
    with sqlite3.connect(f.path) as conn:
        before=list(conn.execute(
            "SELECT kind,identity FROM enrollment_uses ORDER BY kind,identity"))
    r=_run(f,e,c,w)
    assert r["decision"]=="ALLOW"
    with sqlite3.connect(f.path) as conn:
        after=list(conn.execute(
            "SELECT kind,identity FROM enrollment_uses "
            "WHERE kind NOT LIKE 'mutation:%' "
            "AND kind NOT LIKE 'mutation_issuance:%' "
            "AND kind NOT LIKE 'adoption_revocation_effect:%' "
            "ORDER BY kind,identity"))
    assert after==before

def test_adoption_revocation_writer_pending_storage_denied(tmp_path):
    f,e,c,_,_,w=_prepare(tmp_path)
    with sqlite3.connect(f.path) as conn:
        state=parse_json(conn.execute(
            "SELECT value FROM enrollment_meta WHERE name='state'").fetchone()[0])
        state["publication"]="PENDING"
        conn.execute("UPDATE enrollment_meta SET value=? WHERE name='state'",
            (__import__("governance.tenant_enrollment_contracts",fromlist=["canonical"]).canonical(state).decode(),))
    r=_run(f,e,c,w)
    assert r["decision"]=="DENY"
    assert r["reason"]=="ADOPTION_FINALIZATION_STATE_INVALID"

def test_adoption_revocation_writer_missing_transition_source_denies(tmp_path):
    f,e,c,_,_,_=_prepare(tmp_path)
    w=GovernedAdoptionRevocationWriter(
        f.view,currentness_fence=f.source,transition_source=None)
    r=_run(f,e,c,w)
    assert r["decision"]=="DENY"
    assert r["reason"]=="ADOPTION_REVOCATION_TRANSITION_UNAVAILABLE"

def test_adoption_revocation_writer_second_attempt_denies_and_source_terminal(tmp_path):
    f,e,c,_,_,w=_prepare(tmp_path)
    first=_run(f,e,c,w)
    assert first["decision"]=="ALLOW"
    assert f.source.terminal is True
    second=_run(f,e,c,w)
    assert second["decision"]=="DENY"

def test_adoption_revocation_writer_invalid_successor_rolls_back(tmp_path):
    f,e,c,successor,source,w=_prepare(tmp_path)
    bad=deepcopy(source.guard.evidence)
    payload=deepcopy(bad["revoked_currentness"]["revocations"]["payload"])
    payload["revocations"]=[]
    payload["revocation_reference"]=digest({k:v for k,v in payload.items() if k!="revocation_reference"})
    bad["revoked_currentness"]["revocations"]=successor.sign(payload)
    source.guard.evidence=bad
    r=_run(f,e,c,w)
    assert r["decision"]=="DENY"
    with sqlite3.connect(f.path) as conn:
        assert conn.execute("SELECT count(*) FROM adoption_revocation_terminal").fetchone()[0]==0
        assert conn.execute(
            "SELECT count(*) FROM enrollment_uses "
            "WHERE kind LIKE 'adoption_revocation_effect:%'").fetchone()[0]==0

def test_adoption_revocation_writer_lost_commit_ack_is_unknown(tmp_path):
    f,e,c,_,_,w=_prepare(tmp_path)
    f.source.fail_after_commit=True
    r=_run(f,e,c,w)
    assert r["decision"]=="DENY"
    assert r["reason"]=="COMMIT_STATE_UNKNOWN"
    assert r["reconciliation_required"] is True
