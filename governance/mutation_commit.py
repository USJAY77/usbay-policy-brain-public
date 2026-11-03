"""Dormant mutation transaction contracts. No policy/revocation/finality writer.

The only default currentness provider is unavailable. A future governed provider
must hold *all* relevant authority/currentness state under a linearization fence
through SQLite COMMIT, not merely re-read a signed snapshot. No such live source,
projection updater, authority or schema deployment is provisioned here.
"""
from contextlib import contextmanager
from dataclasses import dataclass
from copy import deepcopy
import secrets
import sqlite3

from governance.mutation_authority import (
    ACTION_RESOURCES, COMMON, _signed, verify_mutation_authority_grant,
)
from governance.mutation_issuer_authority import identity_reference
from governance.tenant_enrollment_contracts import (
    FLAGS, PURPOSE, SCOPE_FIELDS, EnrollmentDenied, canonical, decision, digest,
    instant, parse_json, require,
)

STATE_COMMON = {'tenant_id', 'object_id', 'object_version_hash', 'expected_current_head'}
STATE_FIELDS = {
    'FINALIZE_POLICY_ADOPTION': STATE_COMMON | {'adoption_id','adoption_version_hash',
        'policy_id','policy_version','policy_hash','expected_publication_state','proposed_new_head',
        'witness_reference','finality_reference'},
    'REVOKE_POLICY_OBJECT': STATE_COMMON | {'policy_id','policy_version','policy_hash',
        'revocation_effect_scope','expected_revocation_state'},
    'REVOKE_GRANT_OBJECT': STATE_COMMON | {'grant_id','grant_version_hash',
        'expected_consumption_state','expected_revocation_state','revocation_effect_scope'},
    'REVOKE_ADOPTION': STATE_COMMON | {'adoption_id','adoption_version_hash',
        'expected_finalization_state','expected_revocation_state','revocation_effect_scope'},
}
COMMAND_FIELDS = {'command_id','transaction_id','actor_id','action','resource_type','resource_id',
    'object_id','object_version_hash','expected_current_head','expected_state',
    'mutation_authority_grant_id','mutation_authority_grant_hash','issuer_authority_id','issuer_authority_hash',
    'parent_authority_id','parent_authority_hash','proposal_hash','reviewer_a_decision_hash','reviewer_b_decision_hash',
    'nonce','command_fingerprint','caller_identity_binding'}
FENCE_FIELDS = {'transaction_id','command_hash','action','resource_id','object_id','mutation_grant_hash',
    'issuer_authority_hash','parent_authority_hash','authority_challenge_id','expected_current_head',
    'expected_object_version','expected_state','currentness_snapshot_identity','authority_evidence_hash',
    'source_version','source_epoch','storage_event_tip','replay_reservation_identity',
    'fence_created_at','fence_valid_until','verification_valid_until','fence_fingerprint'}
REVOCATION_EFFECT_FIELDS = {'revocation_effect_scope','revocation_effect_grant_hash'}


def _text(value):
    return type(value) is str and 0 < len(value) <= 256 and '*' not in value


def _hash(value):
    import re
    return type(value) is str and re.fullmatch(r'sha256:[0-9a-f]{64}',value) is not None


def validate_expected_state(action, state):
    require(action in STATE_FIELDS and type(state) is dict and set(state)==STATE_FIELDS[action], 'EXPECTED_STATE_MISMATCH')
    canonical(state)
    require(all(_text(v) for v in state.values()), 'EXPECTED_STATE_MISMATCH')
    for field,value in state.items():
        if field.endswith(('_hash','_reference')) or field in ('object_id','expected_current_head','proposed_new_head'):
            require(_hash(value), 'EXPECTED_STATE_MISMATCH')
    if action=='FINALIZE_POLICY_ADOPTION':
        require(state['expected_publication_state']=='PENDING'
                and state['adoption_id']==state['object_id'] and state['adoption_version_hash']==state['object_version_hash'],
                'EXPECTED_STATE_MISMATCH')
    else:
        require(state['revocation_effect_scope']=='ALL_VERSIONS_OF_OBJECT'
                and state['expected_revocation_state']=='NOT_REVOKED', 'REVOCATION_SCOPE_MISMATCH')
        if action=='REVOKE_POLICY_OBJECT':
            require(state['policy_hash']==state['object_version_hash'],'EXPECTED_STATE_MISMATCH')
        if action=='REVOKE_GRANT_OBJECT':
            require(state['grant_version_hash']==state['object_version_hash']
                    and state['expected_consumption_state'] in ('UNCONSUMED','CONSUMED'), 'EXPECTED_STATE_MISMATCH')
        if action=='REVOKE_ADOPTION':
            require(state['adoption_id']==state['object_id'] and state['adoption_version_hash']==state['object_version_hash']
                    and state['expected_finalization_state'] in ('PENDING','FINALIZED'), 'EXPECTED_STATE_MISMATCH')
    return deepcopy(state)


def exact_mutation_cas(action, expected, observed):
    """Structural CAS only, never authority or an authoritative state reader."""
    e=validate_expected_state(action,expected)
    o=validate_expected_state(action,observed)
    for field,reason in [('tenant_id','TENANT_MISMATCH'),('object_id','OBJECT_ID_MISMATCH'),
        ('object_version_hash','OBJECT_VERSION_MISMATCH'),('expected_current_head','EXPECTED_HEAD_MISMATCH')]:
        require(e[field]==o[field],reason)
    require(canonical(e)==canonical(o),'EXPECTED_STATE_MISMATCH')
    return digest(o)


def commit_fingerprint(payload, kind):
    field='command_fingerprint' if kind=='command' else 'fence_fingerprint'
    return digest({k:v for k,v in payload.items() if k!=field})


@dataclass(frozen=True)
class _CommitContract:
    encoded: bytes
    kind=''

    @property
    def payload(self):
        return parse_json(self.encoded)

    @classmethod
    def from_payload(cls,p):
        fields=COMMAND_FIELDS if cls.kind=='command' else FENCE_FIELDS
        require(type(p) is dict,'MUTATION_COMMAND_INVALID' if cls.kind=='command' else 'COMMIT_FENCE_MISMATCH')
        effect_required=p.get('action')=='REVOKE_POLICY_OBJECT'
        if effect_required:
            require(REVOCATION_EFFECT_FIELDS <= set(p),'REVOCATION_SCOPE_MISMATCH')
        expected_fields=COMMON|fields|(REVOCATION_EFFECT_FIELDS if effect_required else set())
        require(set(p)==expected_fields,'MUTATION_COMMAND_INVALID' if cls.kind=='command' else 'COMMIT_FENCE_MISMATCH')
        canonical(p)
        require(p['schema_version']=='usbay.mutation_commit.'+cls.kind+'.v1','MUTATION_COMMAND_INVALID')
        from governance.mutation_authority import AUTHORITY_DOMAIN
        from governance.tenant_enrollment_contracts import TRUST_DOMAIN,POLICY_DOMAIN
        require(p['authority_domain']==AUTHORITY_DOMAIN and p['trust_domain']==TRUST_DOMAIN
                and p['policy_domain']==POLICY_DOMAIN and p['purpose']==PURPOSE
                and p['environment']=='non-production','PURPOSE_MISMATCH')
        require(type(p['authority_flags']) is dict and set(p['authority_flags'])==set(FLAGS)
                and all(v is False for v in p['authority_flags'].values()),'MUTATION_COMMAND_INVALID')
        import re
        require(type(p['tenant_id']) is str and re.fullmatch(r'[a-z0-9][a-z0-9_-]{0,63}',p['tenant_id']) is not None,'TENANT_MISMATCH')
        for k,v in p.items():
            if k in ('authority_flags','expected_state','source_version','source_epoch'):
                continue
            require(_text(v),'MUTATION_COMMAND_INVALID')
            if k.endswith(('_hash','_fingerprint','_reference')) or k in ('resource_id','object_id','expected_current_head',
                    'expected_object_version','authority_challenge_id','currentness_snapshot_identity',
                    'authority_evidence_hash','storage_event_tip','replay_reservation_identity','caller_identity_binding'):
                require(_hash(v),'MUTATION_COMMAND_INVALID')
        require(p['action'] in ACTION_RESOURCES,'ACTION_NOT_AUTHORIZED')
        require(p['resource_id']==p['object_id'],'RESOURCE_NOT_AUTHORIZED')
        state=validate_expected_state(p['action'],p['expected_state'])
        require(all(state[k]==p[k] for k in STATE_COMMON if k!='object_version_hash'),'EXPECTED_STATE_MISMATCH')
        if effect_required:
            require(p['revocation_effect_scope']==state['revocation_effect_scope']=='ALL_VERSIONS_OF_OBJECT',
                    'REVOCATION_SCOPE_MISMATCH')
            require(_hash(p['revocation_effect_grant_hash']),'MUTATION_COMMAND_INVALID')
        version=p['object_version_hash'] if cls.kind=='command' else p['expected_object_version']
        require(state['object_version_hash']==version,'OBJECT_VERSION_MISMATCH')
        require(p['algorithm']=='Ed25519' and instant(p['valid_from'])<instant(p['valid_until'])
                and instant(p['issued_at'])<instant(p['valid_until']),'MUTATION_COMMAND_INVALID')
        if cls.kind=='command':
            require(p['issuer_id']==p['actor_id'],'ACTOR_MISMATCH')
            require(p['resource_type']==ACTION_RESOURCES[p['action']],'RESOURCE_NOT_AUTHORIZED')
        else:
            require(all(type(p[k]) is int and p[k]>=1 for k in ('source_version','source_epoch')),'COMMIT_FENCE_MISMATCH')
            require(p['fence_created_at']==p['issued_at'] and p['fence_valid_until']==p['valid_until'], 'COMMIT_FENCE_MISMATCH')
        field='command_fingerprint' if cls.kind=='command' else 'fence_fingerprint'
        require(p[field]==commit_fingerprint(p,cls.kind),'MUTATION_COMMAND_INVALID')
        return cls(canonical(p))


class GovernanceMutationCommandV1(_CommitContract):
    kind='command'


class MutationCommitFenceV1(_CommitContract):
    kind='fence'


class MutationAuthorityCurrentnessFence:
    """Privileged composition boundary; default C: unavailable, never TOFU.

    A future governed implementation must provide an authenticated monotonic
    source, obtain authority/currentness and target state independently, and hold
    a fence shared with EVERY relevant updater through commit_if_current. Mere
    snapshot freshness, two verifications or an arbitrary CAS token are unsafe.
    No A/B live implementation or updater is provided by this module.
    """
    @contextmanager
    def hold(self, connection, *, command, challenge):
        raise EnrollmentDenied('COMMIT_FENCE_UNAVAILABLE')
        yield  # pragma: no cover -- contextmanager shape; never a success path


class CommitFenceRejected(EnrollmentDenied):
    """Provider proves rejection BEFORE attempting SQLite COMMIT."""


class MutationFenceGuard:
    """Interface for a transaction-owned held source fence; default always denies.

    Implementations must authenticate their observations with the pinned
    mutation_commit_fence key AND preserve the shared lock/atomic fence until
    commit_if_current returns. Signed tokens alone cannot implement this API.
    """
    def authority_material(self):
        raise EnrollmentDenied('AUTHORITY_CURRENTNESS_UNPROVEN')

    def read_state(self, connection, command):
        raise EnrollmentDenied('AUTHORITY_CURRENTNESS_UNPROVEN')

    def evidence(self, **bindings):
        raise EnrollmentDenied('COMMIT_FENCE_UNAVAILABLE')

    def commit_if_current(self, connection, *, fence, now):
        raise EnrollmentDenied('COMMIT_FENCE_UNAVAILABLE')

    def commit_transition_if_current(
            self, connection, *, fence, now, proposed_position, update_id):
        raise EnrollmentDenied('COMMIT_FENCE_UNAVAILABLE')


def reservation_identity(command):
    return digest({k:command[k] for k in ('tenant_id','mutation_authority_grant_id','transaction_id',
        'action','resource_id','object_id')} | {'command_hash':digest(command)})


class MutationAttempt:
    """Adapter of EnrollmentAuthorityView's existing transaction/storage fence.

    No policy/head/revocation/witness mutation methods. Its sole durable operation
    records a verified NON_EXECUTING attempt consumption; future mutation writers
    must integrate their writes in this same protected transaction, not afterwards.
    A successful verification result cannot be reused outside this live attempt.
    """
    def __init__(self, view, source=None):
        self._view=view
        self._source=MutationAuthorityCurrentnessFence() if source is None else source
        self._conn=None
        self._guard=None
        self._holder=None
        self._prepared=None
        self._closed=False
        self._poisoned=False
        self._challenge=digest({'fresh_attempt_challenge':secrets.token_hex(32)})

    def __enter__(self):
        require(not self._closed and self._conn is None,'TRANSACTION_CONFLICT')
        self._conn=self._view._connect_existing()
        try:
            self._conn.execute('BEGIN IMMEDIATE')
            self._view._snapshot(self._conn,require_finalized=False)
        except Exception:
            self._conn.close();self._conn=None
            raise
        return self

    def __exit__(self,*exc):
        # Closing rolls back reservations unless COMMIT actually completed.
        if self._conn is not None:
            self._conn.close();self._conn=None
        if self._holder is not None:
            self._holder.__exit__(*exc)
        self._closed=True

    def _replay(self,c):
        # Grant uniqueness is scoped by tenant + domain, not by command/transaction;
        # the same grant cannot evade single-use by changing either identifier.
        scope=digest({k:c[k] for k in (*SCOPE_FIELDS,'authority_domain')})
        keys=[('command',digest({'scope':scope,'command_id':c['command_id']}),'COMMAND_REPLAY'),
              ('grant',digest({'scope':scope,'grant_id':c['mutation_authority_grant_id']}),'GRANT_ALREADY_CONSUMED'),
              ('nonce',digest({'scope':scope,'nonce':c['nonce']}),'COMMAND_REPLAY'),
              ('transaction',digest({'scope':scope,'transaction_id':c['transaction_id']}),'TRANSACTION_CONFLICT'),
              ('attempt',reservation_identity(c),'COMMAND_REPLAY')]
        for kind,identity,reason in keys:
            require(self._conn.execute('SELECT 1 FROM enrollment_uses WHERE kind=? AND identity=?',
                ('mutation:'+kind,identity)).fetchone() is None,reason)
        return keys

    def _evaluate(self,bundle):
        require(not self._closed and not self._poisoned and self._conn is not None and self._conn.in_transaction,'TRANSACTION_CONFLICT')
        now=self._view.clock()
        try:
            c,key=_signed(self._view.trust,bundle['command'],GovernanceMutationCommandV1,'request',now)
        except EnrollmentDenied as error:
            raise EnrollmentDenied('MUTATION_COMMAND_EXPIRED' if str(error)=='MUTATION_AUTHORITY_EXPIRED' else str(error)) from None
        require(c['caller_identity_binding']==identity_reference(key),'ACTOR_MISMATCH')
        self._command_hash=digest(c)
        require(bundle['grant'] is not None and bundle['proposal'] is not None,'MUTATION_AUTHORITY_MISSING')
        require(isinstance(self._source,MutationAuthorityCurrentnessFence),'COMMIT_FENCE_UNAVAILABLE')
        if self._guard is None:
            self._holder=self._source.hold(self._conn,command=deepcopy(c),challenge=self._challenge)
            self._guard=self._holder.__enter__()
            require(isinstance(self._guard,MutationFenceGuard),'COMMIT_FENCE_UNAVAILABLE')
        state=self._view._snapshot(self._conn,require_finalized=False)
        require(all(state['head'][k]==c[k] for k in SCOPE_FIELDS),'TENANT_MISMATCH')
        require(state['head']['head_hash']==c['expected_current_head'],'EXPECTED_HEAD_MISMATCH')
        observed=self._guard.read_state(self._conn,deepcopy(c))
        observed_hash=exact_mutation_cas(c['action'],c['expected_state'],observed)
        if c['action']=='FINALIZE_POLICY_ADOPTION':
            require(state['publication']=='PENDING','EXPECTED_STATE_MISMATCH')
            events=[parse_json(row[0]) for row in self._conn.execute('SELECT payload FROM enrollment_events ORDER BY sequence')]
            require(any(e['kind']=='ADOPTION_PENDING' and e['adoption_core_hash']==c['object_version_hash']
                        and e['policy_hash']==c['expected_state']['policy_hash']
                        and e['target_head']==c['expected_state']['proposed_new_head'] for e in events),'EXPECTED_STATE_MISMATCH')
        material=self._guard.authority_material()
        require(type(material) is dict and set(material)=={'parent_artifact','parent_source','root_authority',
            'issuer_grant','review_policy','root_source','currentness','target_object'},'AUTHORITY_CURRENTNESS_UNPROVEN')
        require(material['currentness']['expected']==state['head'],'EXPECTED_HEAD_MISMATCH')
        g=bundle['grant']['payload']
        if c['action'] not in ('FINALIZE_POLICY_ADOPTION','REVOKE_POLICY_OBJECT'):
            # Existing v1 grants remain insufficient for other revocation actions.
            require(g.get('revocation_effect_scope')==c['expected_state']['revocation_effect_scope'],
                    'REVOCATION_SCOPE_MISMATCH')
        result=verify_mutation_authority_grant(bundle['proposal'],bundle['reviews'],bundle['grant'],
            trust=self._view.trust,now=now,**material)
        if result['reason']=='ISSUANCE_REPLAY':
            self._replay(c)
        require(result['decision']=='ALLOW',result['reason'])
        effect_result=None
        if c['action']=='REVOKE_POLICY_OBJECT':
            effect=bundle.get('revocation_effect')
            require(type(effect) is dict
                    and set(effect)=={'parent','proposal','reviews','grant'},
                    'REVOCATION_SCOPE_MISMATCH')
            from governance.mutation_policy_revocation_effect import (
                verify_policy_revocation_effect,
            )
            effect_result=verify_policy_revocation_effect(
                mutation_proposal=bundle['proposal'],
                mutation_reviews=bundle['reviews'],
                mutation_grant=bundle['grant'],
                mutation_material=material,
                effect_parent=effect['parent'],
                effect_proposal=effect['proposal'],
                effect_reviews=effect['reviews'],
                effect_grant=effect['grant'],
                trust=self._view.trust,
                now=now,
                expected_state=c['expected_state'],
            )
            require(effect_result['decision']=='ALLOW',
                    effect_result.get('reason','REVOCATION_SCOPE_MISMATCH'))
            require(c['revocation_effect_scope']==effect_result['effect_scope']
                    and c['revocation_effect_grant_hash']
                        == effect_result['effect_grant_hash'],
                    'REVOCATION_SCOPE_MISMATCH')
        if c['action']=='FINALIZE_POLICY_ADOPTION':
            target=material['target_object']['payload']
            require(all(c['expected_state'][k]==target[k] for k in ('policy_id','policy_version','policy_hash')),
                    'EXPECTED_STATE_MISMATCH')
        bindings={'actor_id':'actor_id','action':'allowed_action','resource_type':'resource_type',
            'resource_id':'resource_id','object_id':'object_id','object_version_hash':'object_version_hash',
            'expected_current_head':'expected_current_head','mutation_authority_grant_id':'grant_id',
            'proposal_hash':'proposal_hash','reviewer_a_decision_hash':'reviewer_a_decision_hash',
            'reviewer_b_decision_hash':'reviewer_b_decision_hash'}
        reasons={'actor_id':'ACTOR_MISMATCH','action':'ACTION_NOT_AUTHORIZED','resource_type':'RESOURCE_NOT_AUTHORIZED',
            'resource_id':'RESOURCE_NOT_AUTHORIZED','object_id':'OBJECT_ID_MISMATCH','object_version_hash':'OBJECT_VERSION_MISMATCH',
            'expected_current_head':'EXPECTED_HEAD_MISMATCH'}
        for field,target in bindings.items():require(c[field]==g[target],reasons.get(field,'MUTATION_COMMAND_INVALID'))
        require(all(c[k]==g[k] for k in SCOPE_FIELDS),'TENANT_MISMATCH')
        require(c['mutation_authority_grant_hash']==digest(g)
                and c['issuer_authority_id']==material['issuer_grant']['payload']['issuer_grant_id']
                and c['issuer_authority_hash']==digest(material['issuer_grant']['payload'])
                and c['parent_authority_id']==material['root_authority']['payload']['root_authority_id']
                and c['parent_authority_hash']==digest(material['root_authority']['payload']), 'MUTATION_AUTHORITY_INVALID')
        require(instant(c['valid_from'])>=instant(g['valid_from']) and instant(c['valid_until'])<=instant(g['valid_until']), 'MUTATION_COMMAND_INVALID')
        keys=self._replay(c)
        expected=dict(transaction_id=c['transaction_id'],command_hash=digest(c),tenant_id=c['tenant_id'],action=c['action'],
            resource_id=c['resource_id'],object_id=c['object_id'],mutation_grant_hash=digest(g),
            issuer_authority_hash=c['issuer_authority_hash'],parent_authority_hash=c['parent_authority_hash'],
            authority_challenge_id=self._challenge,expected_current_head=c['expected_current_head'],
            expected_object_version=c['object_version_hash'],expected_state=c['expected_state'],storage_event_tip=state['event_tip'],
            replay_reservation_identity=reservation_identity(c),authority_evidence_hash=digest(result['issuance_evidence']),
            currentness_snapshot_identity=digest({'currentness':material['currentness'],
                'authority_evidence_hash':digest(result['issuance_evidence'])}),
            verification_valid_until=result['verification_valid_until'])
        if c['action']=='REVOKE_POLICY_OBJECT':
            expected.update(
                revocation_effect_scope=c['revocation_effect_scope'],
                revocation_effect_grant_hash=c['revocation_effect_grant_hash'])
        proof=self._guard.evidence(command=deepcopy(c),bindings=deepcopy(expected),now=now)
        try:
            fence,_=_signed(self._view.trust,proof,MutationCommitFenceV1,'mutation_commit_fence',now)
        except EnrollmentDenied as error:
            raise EnrollmentDenied('COMMIT_FENCE_STALE' if str(error)=='MUTATION_AUTHORITY_EXPIRED' else 'COMMIT_FENCE_MISMATCH') from None
        require(all(fence[k]==v for k,v in expected.items()),'COMMIT_FENCE_MISMATCH')
        require(all(fence[k]==c[k] for k in SCOPE_FIELDS),'COMMIT_FENCE_MISMATCH')
        require(fence['verification_valid_until']==result['verification_valid_until'],'COMMIT_FENCE_MISMATCH')
        require(instant(fence['valid_until'])<=min(instant(c['valid_until']),instant(result['verification_valid_until'])),
                'COMMIT_FENCE_MISMATCH')
        if hasattr(self,'_source_position'):
            require((fence['source_epoch'],fence['source_version'])==self._source_position,'COMMIT_FENCE_STALE')
        self._source_position=(fence['source_epoch'],fence['source_version'])
        evidence=dict(command_hash=digest(c),grant_hash=digest(g),issuer_hash=c['issuer_authority_hash'],
            parent_hash=c['parent_authority_hash'],proposal_hash=c['proposal_hash'],transaction_id=c['transaction_id'],
            reviewer_a_hash=c['reviewer_a_decision_hash'],reviewer_b_hash=c['reviewer_b_decision_hash'],
            tenant_reference=digest({'tenant':c['tenant_id']}),action=c['action'],resource_id=c['resource_id'],object_id=c['object_id'],
            expected_state_hash=digest(c['expected_state']),observed_state_hash=observed_hash,cas='MATCH',
            fence_hash=digest(fence),currentness_snapshot_identity=fence['currentness_snapshot_identity'],replay='AVAILABLE')
        if effect_result is not None:
            evidence.update(
                revocation_effect_scope=effect_result['effect_scope'],
                revocation_effect_grant_hash=effect_result['effect_grant_hash'],
                revocation_effect_parent_hash=
                    effect_result['parent_effect_authority_hash'])
        return c,keys,fence,evidence

    def verify(self,command,*,proposal,reviews,grant,revocation_effect=None):
        try:
            require(self._prepared is None,'TRANSACTION_CONFLICT')
            # Immutable copies prevent caller mutation between verification and commit.
            bundle=deepcopy(dict(command=command,proposal=proposal,reviews=reviews,grant=grant,
                revocation_effect=revocation_effect))
            _,_,_,evidence=self._evaluate(bundle)
            self._prepared=bundle
            return decision('COMMIT_FENCE_VERIFIED',allowed=True,evidence=evidence)
        except Exception as error:
            self._poisoned=True
            reason=str(error) if type(error) is EnrollmentDenied else 'MUTATION_COMMAND_INVALID'
            return decision(reason,evidence=dict(command_hash=getattr(self,'_command_hash',None),
                final_governance_decision='DENY',reason=reason))

    def _writer_context(self):
        require(self._prepared is not None and not self._closed
                and not self._poisoned and self._conn is not None
                and self._conn.in_transaction,'TRANSACTION_CONFLICT')
        c,keys,fence,evidence=self._evaluate(self._prepared)
        return c,keys,fence,evidence,self._conn,self._guard

    def commit(self):
        attempted=False
        try:
            require(self._prepared is not None,'TRANSACTION_CONFLICT')
            c,keys,fence,evidence=self._evaluate(self._prepared)
            for kind,identity,_ in keys:
                self._conn.execute('INSERT INTO enrollment_uses(kind,identity) VALUES(?,?)',('mutation:'+kind,identity))
            # Issuer certificates are one-time too; use existing durable primitives.
            material=self._guard.authority_material()
            issuer=material['issuer_grant']['payload']
            self._view._consume(self._conn,'mutation_issuance',dict(issuer_id=issuer['issuer_id'],
                grant_id=issuer['issuer_grant_id'],nonce=issuer['issuance_nonce'],replay_identity=evidence['command_hash']))
            # Snapshot before inserting consumption is verified by _evaluate;
            # append couples those reservations to the same history transaction.
            state=parse_json(self._conn.execute("SELECT value FROM enrollment_meta WHERE name='state'").fetchone()[0])
            evidence.update(replay='CONSUMED',final_governance_decision='ALLOW',reason='NON_EXECUTING_ATTEMPT_CONSUMED')
            event_hash=self._view._append(self._conn,state,dict(kind='MUTATION_ATTEMPT_CONSUMED_NON_EXECUTING',evidence=evidence))
            attempted=True
            # Only the held source may complete COMMIT after an atomic currentness
            # confirmation; the default guard cannot commit anything.
            self._guard.commit_if_current(self._conn,fence=deepcopy(fence),now=self._view.clock())
            require(not self._conn.in_transaction,'COMMIT_STATE_UNKNOWN')
            self._prepared=None
            return decision('NON_EXECUTING_ATTEMPT_CONSUMED',allowed=True,event_hash=event_hash,
                            mutation_executed=False,evidence=evidence)
        except Exception as error:
            self._poisoned=True
            if type(error) is CommitFenceRejected:
                self._conn.rollback()
                return decision(str(error))
            reason=str(error) if type(error) is EnrollmentDenied else 'TRANSACTION_CONFLICT'
            if attempted:
                return decision('COMMIT_STATE_UNKNOWN',commit_outcome='UNKNOWN',reconciliation_required=True,
                    evidence=dict(command_hash=self._command_hash,event_hash=event_hash,replay='UNKNOWN'))
            return decision(reason)


def verify_mutation_for_commit(attempt,command,**bundle):
    if type(attempt) is not MutationAttempt:
        return decision('TRANSACTION_CONFLICT')
    return attempt.verify(command,**bundle)
