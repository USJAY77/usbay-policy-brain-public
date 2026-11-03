"""Synthetic-only tests for concrete bounded EnrollmentGrant revocation writer."""
from contextlib import contextmanager
from copy import deepcopy
import sqlite3

from governance.mutation_grant_revocation_writer import (
    GovernedGrantRevocationWriter,GrantRevocationTransitionGuard,GrantRevocationTransitionSource,
)
from governance.tenant_enrollment_contracts import EnrollmentGrant,digest,parse_json
from tests.helpers.mutation_commit import synthetic_commit
from tests.helpers.mutation_grant_revocation_effect import build_grant_effect_for_mutation
from tests.helpers.tenant_enrollment import object_revocation,synthetic_enrollment

def _bundle(f):
    return dict(policy=f.inputs["policy"],adoption=f.inputs["adoption"],h=f.inputs["h"],w=f.inputs["w"],
        revocations=f.inputs["revocations"],expected=deepcopy(f.head),
        challenge=f.inputs["request"]["payload"]["nonce"],request_digest=digest(f.inputs["request"]["payload"]))

class SyntheticGrantTransitionGuard(GrantRevocationTransitionGuard):
    def __init__(self,bundle):
        self.evidence={"revoked_currentness":deepcopy(bundle),
            "continuity_hash":digest({"grant-continuity":bundle["revocations"]["payload"]["revocation_reference"]})}
    def successor(self,*,previous_currentness): return deepcopy(self.evidence)
    def recheck(self,*,evidence): return deepcopy(self.evidence)

class SyntheticGrantTransitionSource(GrantRevocationTransitionSource):
    def __init__(self,bundle): self.guard=SyntheticGrantTransitionGuard(bundle)
    @contextmanager
    def hold(self,*,command,effect_grant): yield self.guard

def _prepare(tmp_path,*,consumed=False):
    f=synthetic_commit(tmp_path,action="REVOKE_GRANT_OBJECT",grant_consumed=consumed)
    effect=build_grant_effect_for_mutation(f.f)
    f.view.trust=f.f.trust
    old=f.f.enrollment
    target=old.inputs["grant"]["payload"]
    entries=deepcopy(old.inputs["revocations"]["payload"]["revocations"])
    entries.append(object_revocation(EnrollmentGrant,target))
    successor=synthetic_enrollment(private_keys=old.private,sequence=2,
        previous={"policy_hash":digest(old.inputs["policy"]["payload"]),"head_hash":old.head["head_hash"]},
        revocations=entries)
    command=f.new_command(revocation_effect_scope="ALL_VERSIONS_OF_OBJECT",
        revocation_effect_grant_hash=digest(effect["grant"]["payload"]))
    with sqlite3.connect(f.path) as conn:
        conn.execute("""CREATE TABLE grant_revocation_terminal(
            scope_hash TEXT NOT NULL,object_id TEXT NOT NULL,object_version_hash TEXT NOT NULL,
            target_grant_id TEXT NOT NULL,consumption_state TEXT NOT NULL,
            revocation_reference TEXT NOT NULL,revocation_hash TEXT NOT NULL,
            terminal_projection_hash TEXT NOT NULL,terminal_proof_hash TEXT NOT NULL,
            source_epoch INTEGER NOT NULL,source_version INTEGER NOT NULL,
            command_hash TEXT NOT NULL,transaction_id TEXT NOT NULL,
            PRIMARY KEY(scope_hash,object_id))""")
    source=SyntheticGrantTransitionSource(_bundle(successor))
    writer=GovernedGrantRevocationWriter(f.view,currentness_fence=f.source,transition_source=source)
    return f,effect,command,successor,source,writer

def _run(f,effect,command,writer):
    return writer.execute(command,proposal=f.f.proposal,reviews=f.f.reviews,
        grant=f.f.grant,revocation_effect=effect)

def test_grant_revocation_writer_commits_unconsumed(tmp_path):
    f,e,c,_,_,w=_prepare(tmp_path,consumed=False)
    r=_run(f,e,c,w)
    assert r["decision"]=="ALLOW"
    assert r["reason"]=="GRANT_OBJECT_REVOKED_NON_PRODUCTION"
    assert r["consumption_state"]=="UNCONSUMED"
    assert r["source_epoch"]==1 and r["source_version"]==2
    with sqlite3.connect(f.path) as conn:
        row=conn.execute("SELECT target_grant_id,consumption_state,source_epoch,source_version FROM grant_revocation_terminal").fetchone()
        assert row==(c["payload"]["expected_state"]["grant_id"],"UNCONSUMED",1,2)
        f.view._snapshot(conn,require_finalized=False)

def test_grant_revocation_writer_commits_consumed_without_reset(tmp_path):
    f,e,c,_,_,w=_prepare(tmp_path,consumed=True)
    r=_run(f,e,c,w)
    assert r["decision"]=="ALLOW"
    assert r["consumption_state"]=="CONSUMED"
    target=f.f.enrollment.inputs["grant"]["payload"]
    with sqlite3.connect(f.path) as conn:
        for label in ("grant_id","nonce","replay_identity"):
            identity=digest({"issuer":target["issuer_id"],"value":target[label]})
            assert conn.execute("SELECT 1 FROM enrollment_uses WHERE kind=? AND identity=?",
                ("enrollment:"+label,identity)).fetchone() is not None

def test_grant_revocation_writer_partial_target_consumption_blocks(tmp_path):
    f,e,c,_,_,w=_prepare(tmp_path,consumed=False)
    target=f.f.enrollment.inputs["grant"]["payload"]
    with sqlite3.connect(f.path) as conn:
        conn.execute("BEGIN IMMEDIATE")
        state=parse_json(conn.execute("SELECT value FROM enrollment_meta WHERE name='state'").fetchone()[0])
        identity=digest({"issuer":target["issuer_id"],"value":target["grant_id"]})
        conn.execute("INSERT INTO enrollment_uses(kind,identity) VALUES(?,?)",("enrollment:grant_id",identity))
        f.view._append(conn,state,{"kind":"SYNTHETIC_PARTIAL_GRANT_CONSUMPTION"})
        conn.execute("COMMIT")
    r=_run(f,e,c,w)
    assert r["decision"]=="DENY"
    assert r["reason"]=="GRANT_CONSUMPTION_STATE_INVALID"

def test_grant_revocation_writer_missing_transition_source_denies(tmp_path):
    f,e,c,_,_,_=_prepare(tmp_path)
    w=GovernedGrantRevocationWriter(f.view,currentness_fence=f.source,transition_source=None)
    r=_run(f,e,c,w)
    assert r["decision"]=="DENY"
    assert r["reason"]=="GRANT_REVOCATION_TRANSITION_UNAVAILABLE"

def test_grant_revocation_writer_second_attempt_denies_without_closing_policy(tmp_path):
    f,e,c,_,_,w=_prepare(tmp_path)
    first=_run(f,e,c,w)
    assert first["decision"]=="ALLOW"
    assert f.source.terminal is False
    second=_run(f,e,c,w)
    assert second["decision"]=="DENY"

def test_grant_revocation_writer_lost_commit_ack_is_unknown(tmp_path):
    f,e,c,_,_,w=_prepare(tmp_path)
    f.source.fail_after_commit=True
    r=_run(f,e,c,w)
    assert r["decision"]=="DENY"
    assert r["reason"]=="COMMIT_STATE_UNKNOWN"
    assert r["reconciliation_required"] is True

def test_grant_revocation_writer_invalid_successor_rolls_back(tmp_path):
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
        assert conn.execute("SELECT count(*) FROM grant_revocation_terminal").fetchone()[0]==0
        assert conn.execute("SELECT count(*) FROM enrollment_uses WHERE kind LIKE 'grant_revocation_effect:%'").fetchone()[0]==0
