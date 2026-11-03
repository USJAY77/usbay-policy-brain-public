"""TEST ONLY: synchronized ephemeral authority projection, no live provider.

A real RLock shared by test revocation/currentness updaters is held from source
observation through SQLite commit. Test state is in a temporary DB, using the
existing enrollment view and history/consumption primitives. No policy/head/
witness/finalization writer is implemented by this fixture.
"""
from contextlib import contextmanager
from copy import deepcopy
from dataclasses import dataclass
from threading import RLock
import sqlite3

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding,PublicFormat
from governance.authority_registry import EnrollmentAuthorityView
from governance.mutation_authority import COMMON
from governance.mutation_commit import (
    MutationAuthorityCurrentnessFence,MutationFenceGuard,CommitFenceRejected,commit_fingerprint,
)
from governance.mutation_issuer_authority import identity_reference
from governance.tenant_enrollment_contracts import canonical,digest,instant,object_id,PolicyAdoption
from security.enrollment_policy_currentness import EnrollmentTrust,ScopedPublicKey
from tests.helpers.mutation_authority import synthetic_mutation
from tests.helpers.mutation_issuer_authority import attach_synthetic_issuance
from tests.helpers.tenant_enrollment import NOW


class SyntheticCurrentnessFence(MutationAuthorityCurrentnessFence):
    def __init__(self,f,state,path):
        self.f=f
        self.lock=RLock()
        self.version=1
        self.epoch=1
        self.path=path
        self.clock=lambda:NOW
        self.alter_proof=None
        self.before_confirm=None
        self.fail_after_commit=False
        self.installed_state=deepcopy(state)
        self.guard_active=False

    def update(self,*,root_status=None,epoch=False):
        with self.lock:
            if root_status is not None:self.f.root_source.root_status=root_status
            if epoch:self.epoch+=1
            else:self.version+=1

    @contextmanager
    def hold(self,connection,*,command,challenge):
        with self.lock:
            self.guard_active=True
            try:yield SyntheticGuard(self,connection,command,challenge)
            finally:self.guard_active=False


class SyntheticGuard(MutationFenceGuard):
    def __init__(self,source,conn,command,challenge):
        self.source=source;self.conn=conn
        self.position=(source.epoch,source.version)
        self.command=deepcopy(command);self.challenge=challenge

    def authority_material(self):
        f=self.source.f
        return dict(parent_artifact=f.parent,parent_source=f.parent_source,root_authority=f.root_authority,
            issuer_grant=f.issuer_grant,review_policy=f.review_policy,root_source=f.root_source,
            currentness=f.currentness(),target_object=f.commit_target)

    def read_state(self,connection,command):
        assert connection is self.conn and connection.in_transaction and self.source.guard_active
        # Independent installed state, looked up by exact tenant+object. Never
        # return the caller's expected_state as if it were an observation.
        row=connection.execute('SELECT state FROM synthetic_mutation_target WHERE tenant=? AND object_id=?',
            (command['tenant_id'],command['object_id'])).fetchone()
        if row is None:
            from governance.tenant_enrollment_contracts import EnrollmentDenied
            raise EnrollmentDenied('OBJECT_ID_MISMATCH')
        import json
        return json.loads(row[0])

    def evidence(self,*,command,bindings,now):
        f=self.source.f
        p={k:deepcopy(command[k]) for k in COMMON}
        p.update(schema_version='usbay.mutation_commit.fence.v1',issuer_id='synthetic-commit-source',
            issuer_key_id='test-commit-source',**deepcopy(bindings),source_version=self.source.version,
            source_epoch=self.source.epoch,issued_at=now.strftime('%Y-%m-%dT%H:%M:%SZ'),
            valid_from=now.strftime('%Y-%m-%dT%H:%M:%SZ'),fence_created_at=now.strftime('%Y-%m-%dT%H:%M:%SZ'),
            valid_until=bindings['verification_valid_until'],fence_valid_until=bindings['verification_valid_until'])
        if self.source.alter_proof is not None:p=self.source.alter_proof(p)
        p['fence_fingerprint']=commit_fingerprint(p,'fence')
        return f.sign(p)

    def commit_if_current(self,connection,*,fence,now):
        assert connection is self.conn and self.source.guard_active
        if self.source.before_confirm is not None:self.source.before_confirm(self.source)
        # This test-only synchronized projection is the same source used above.
        # Updaters cannot race between this check and actual COMMIT under RLock.
        if self.position!=(self.source.epoch,self.source.version):raise CommitFenceRejected('COMMIT_FENCE_STALE')
        if self.source.f.root_source.root_status!='ACTIVE':raise CommitFenceRejected('MUTATION_AUTHORITY_REVOKED')
        if not (instant(fence['valid_from'])<=self.source.clock()<instant(fence['fence_valid_until'])):
            raise CommitFenceRejected('COMMIT_FENCE_STALE')
        connection.execute('COMMIT')
        if self.source.fail_after_commit:raise OSError('synthetic lost commit acknowledgment')


@dataclass
class SyntheticCommit:
    f:object
    view:object
    source:object
    command:dict
    state:dict
    path:object

    def seal_command(self,p):
        p=deepcopy(p);p['command_fingerprint']=commit_fingerprint(p,'command')
        return self.f.sign(p)

    def verify(self,attempt,command=None):
        from governance.mutation_commit import verify_mutation_for_commit
        return verify_mutation_for_commit(attempt,self.command if command is None else command,
            proposal=self.f.proposal,reviews=self.f.reviews,grant=self.f.grant)

    def new_command(self,**changes):
        p=deepcopy(self.command['payload']);p.update(changes)
        return self.seal_command(p)


def synthetic_commit(tmp_path, *, action="FINALIZE_POLICY_ADOPTION"):
    f=synthetic_mutation()
    pending=f.enrollment.next_adoption();f.pending=pending
    a=pending['adoption']['payload'];p=pending['policy']['payload']
    if action=='FINALIZE_POLICY_ADOPTION':
        for envelope in (f.parent,f.proposal,f.grant):
            envelope['payload'].update(allowed_action='FINALIZE_POLICY_ADOPTION',resource_type='POLICY_ADOPTION',
                resource_id=object_id(PolicyAdoption,a),object_id=object_id(PolicyAdoption,a),object_version_hash=digest(a),
                adoption_id=object_id(PolicyAdoption,a),target_grant_id=None)
        attach_synthetic_issuance(f)
        f.commit_target=pending['adoption']
    else:
        assert action=='REVOKE_POLICY_OBJECT'
        f.commit_target=f.enrollment.inputs['policy']
    private=Ed25519PrivateKey.generate();f.private['test-commit-source']=private
    base=f.grant['payload']
    key=ScopedPublicKey('synthetic-commit-source','test-commit-source',private.public_key().public_bytes(Encoding.Raw,PublicFormat.Raw),
        ('mutation_commit_fence',),base['tenant_id'],base['registry_instance_reference'],
        '2026-01-01T00:00:00Z','2026-01-03T00:00:00Z',digest({'synthetic-commit-source':1}))
    f.trust=EnrollmentTrust(tuple(f.trust._keys.values())+(key,),max_age_seconds=60)
    path=tmp_path/'synthetic-fence.sqlite';f.enrollment.store(path)
    view=EnrollmentAuthorityView(path,f.trust,clock=lambda:NOW)
    if action=='FINALIZE_POLICY_ADOPTION':
        result=view.propose_adoption(pending)
        assert result['publication']=='PENDING'
    # Read-only authority lookup may inspect a valid pending publication; it
    # does not admit enrollment or finalize that publication.
    class SyntheticPendingAuthorityView(EnrollmentAuthorityView):
        @staticmethod
        def _snapshot(conn,**kwargs):
            return EnrollmentAuthorityView._snapshot(conn,require_finalized=False)
    f.root_source.attach_store(SyntheticPendingAuthorityView(path))
    state=dict(tenant_id=base['tenant_id'],object_id=base['object_id'],object_version_hash=base['object_version_hash'],
        expected_current_head=base['expected_current_head'],adoption_id=base['adoption_id'],adoption_version_hash=digest(a),
        policy_id=p['policy_id'],policy_version=p['policy_version'],policy_hash=digest(p),expected_publication_state='PENDING',
        proposed_new_head=pending['advance']['payload']['head_hash'],
        witness_reference=digest({'synthetic-pending-witness-requirement':1}),finality_reference=digest({'synthetic-finality-requirement':1}))
    if action=='REVOKE_POLICY_OBJECT':
        state=dict(tenant_id=base['tenant_id'],object_id=base['object_id'],object_version_hash=base['object_version_hash'],
            expected_current_head=base['expected_current_head'],policy_id=base['policy_id'],
            policy_version=f.enrollment.inputs['policy']['payload']['policy_version'],
            policy_hash=base['object_version_hash'],revocation_effect_scope='ALL_VERSIONS_OF_OBJECT',
            expected_revocation_state='NOT_REVOKED')
    # TEST ONLY projection table. No production schema/bootstrap is added.
    with sqlite3.connect(path) as conn:
        conn.execute('CREATE TABLE synthetic_mutation_target(tenant TEXT,object_id TEXT,state TEXT,PRIMARY KEY(tenant,object_id))')
        conn.execute('INSERT INTO synthetic_mutation_target VALUES(?,?,?)',(base['tenant_id'],base['object_id'],canonical(state).decode()))
    source=SyntheticCurrentnessFence(f,state,path)
    common={k:deepcopy(base[k]) for k in COMMON}
    common.update(schema_version='usbay.mutation_commit.command.v1',issuer_id='synthetic-actor',issuer_key_id='test-proposer')
    command=dict(common,command_id='synthetic-command',transaction_id='synthetic-transaction',actor_id='synthetic-actor',
        action=base['allowed_action'],resource_type=base['resource_type'],resource_id=base['resource_id'],
        object_id=base['object_id'],object_version_hash=base['object_version_hash'],expected_current_head=base['expected_current_head'],
        expected_state=state,mutation_authority_grant_id=base['grant_id'],mutation_authority_grant_hash=digest(base),
        issuer_authority_id=f.issuer_grant['payload']['issuer_grant_id'],issuer_authority_hash=digest(f.issuer_grant['payload']),
        parent_authority_id=f.root_authority['payload']['root_authority_id'],parent_authority_hash=digest(f.root_authority['payload']),
        proposal_hash=base['proposal_hash'],reviewer_a_decision_hash=base['reviewer_a_decision_hash'],
        reviewer_b_decision_hash=base['reviewer_b_decision_hash'],nonce='synthetic-command-nonce',
        caller_identity_binding=identity_reference(f.trust._keys['test-proposer']))
    result=SyntheticCommit(f,view,source,{},state,path)
    result.command=result.seal_command(command)
    return result
