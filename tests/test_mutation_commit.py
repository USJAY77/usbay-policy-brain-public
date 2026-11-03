"""Dormant commit infrastructure on task-owned synthetic SQLite state only."""
from copy import deepcopy
from datetime import timedelta
from threading import Barrier,Event
from concurrent.futures import ThreadPoolExecutor
import hashlib
import sqlite3
import json

import pytest

from governance.mutation_commit import (
    GovernanceMutationCommandV1,MutationCommitFenceV1,MutationAuthorityCurrentnessFence,
    exact_mutation_cas,verify_mutation_for_commit,
)
from governance.mutation_authority import fingerprint
from governance.tenant_enrollment_contracts import FLAGS,EnrollmentDenied,canonical,digest,instant,parse_json
from tests.helpers.mutation_commit import synthetic_commit
from tests.helpers.mutation_policy_revocation_effect import build_effect_for_mutation
from tests.helpers.mutation_grant_revocation_effect import build_grant_effect_for_mutation
from tests.helpers.mutation_adoption_revocation_effect import build_adoption_effect_for_mutation
from tests.helpers.tenant_enrollment import NOW


def deny(result,reason=None):
    assert result['decision']=='DENY'
    assert result['authority_flags']==dict.fromkeys(FLAGS,False)
    assert result['retry_allowed'] is False
    if reason is not None:assert result['reason']==reason


def verify(f,command=None,source=True):
    with f.view.mutation_attempt(currentness_fence=f.source if source else None) as tx:
        return f.verify(tx,command)


def uses(f):
    with sqlite3.connect(f.path) as conn:
        return conn.execute('SELECT kind,identity FROM enrollment_uses ORDER BY kind,identity').fetchall()


def test_command_canonicalization_and_complete_synthetic_held_fence(tmp_path):
    f=synthetic_commit(tmp_path)
    c=GovernanceMutationCommandV1.from_payload(f.command['payload'])
    assert c.encoded==canonical(c.payload)
    assert digest(dict(reversed(list(c.payload.items()))))==digest(c.payload)
    before=uses(f)
    with f.view.mutation_attempt(currentness_fence=f.source) as tx:
        result=f.verify(tx)
        assert result['decision']=='ALLOW' and result['reason']=='COMMIT_FENCE_VERIFIED'
        assert result['authority_flags']==dict.fromkeys(FLAGS,False)
        assert uses(f)==before  # Verification is not durable consumption.
        result=tx.commit()
        assert result['decision']=='ALLOW' and result['mutation_executed'] is False
    assert len(uses(f))==len(before)+8
    with sqlite3.connect(f.path) as conn:
        state=parse_json(conn.execute("SELECT value FROM enrollment_meta WHERE name='state'").fetchone()[0])
        assert state['publication']=='PENDING' and state['head']['head_hash']==f.state['expected_current_head']
        event=parse_json(conn.execute('SELECT payload FROM enrollment_events ORDER BY sequence DESC LIMIT 1').fetchone()[0])
        assert event['kind']=='MUTATION_ATTEMPT_CONSUMED_NON_EXECUTING'
        evidence=event['evidence']
        assert evidence['cas']=='MATCH' and evidence['replay']=='CONSUMED'
        assert evidence['final_governance_decision']=='ALLOW'
        assert not any(k in evidence for k in ('request','payload','signature','token','prompt','content'))
    deny(verify(f),'COMMAND_REPLAY')


def test_no_source_denies_even_complete_authority_command_and_state(tmp_path):
    f=synthetic_commit(tmp_path)
    before=f.path.read_bytes()
    deny(verify(f,source=False),'COMMIT_FENCE_UNAVAILABLE')
    assert f.path.read_bytes()==before
    assert type(MutationAuthorityCurrentnessFence()) is MutationAuthorityCurrentnessFence


def test_every_protected_command_field_missing_or_changed_is_rejected(tmp_path):
    f=synthetic_commit(tmp_path)
    original=f.command['payload']
    for field in original:
        p=deepcopy(original);del p[field]
        with pytest.raises(EnrollmentDenied):GovernanceMutationCommandV1.from_payload(p)
        p=deepcopy(original);p[field]=None
        with pytest.raises(EnrollmentDenied):GovernanceMutationCommandV1.from_payload(p)
    with pytest.raises(EnrollmentDenied):GovernanceMutationCommandV1.from_payload(dict(original,approved=True))


@pytest.mark.parametrize('field,value', [('tenant_id','*'),('actor_id',''),('resource_id','*'),
    ('action','ROOT_TRUST_CHANGE'),('purpose','OTHER_PURPOSE'),('issuer_id','different-actor'),
    ('caller_identity_binding','sha256:'+'e'*64),('mutation_authority_grant_hash','sha256:'+'e'*64),
    ('issuer_authority_hash','sha256:'+'e'*64),('parent_authority_hash','sha256:'+'e'*64),
    ('proposal_hash','sha256:'+'e'*64),('reviewer_a_decision_hash','sha256:'+'e'*64)])
def test_signed_wrong_command_scope_or_authority_binding_denies(tmp_path,field,value):
    f=synthetic_commit(tmp_path)
    deny(verify(f,f.new_command(**{field:value})))


@pytest.mark.parametrize('field,value,reason', [('tenant_id','different-tenant','TENANT_MISMATCH'),
    ('object_id','sha256:'+'a'*64,'OBJECT_ID_MISMATCH'),
    ('object_version_hash','sha256:'+'b'*64,'OBJECT_VERSION_MISMATCH'),
    ('expected_current_head','sha256:'+'c'*64,'EXPECTED_HEAD_MISMATCH'),
    ('policy_version','wrong-version','EXPECTED_STATE_MISMATCH')])
def test_exact_cas_rejects_wrong_observation(tmp_path,field,value,reason):
    f=synthetic_commit(tmp_path);observed=deepcopy(f.state)
    observed[field]=value
    if field=='object_id':observed['adoption_id']=value
    if field=='object_version_hash':observed['adoption_version_hash']=value
    with pytest.raises(EnrollmentDenied,match='^'+reason+'$'):
        exact_mutation_cas('FINALIZE_POLICY_ADOPTION',f.state,observed)


@pytest.mark.parametrize('field,value', [('policy_version','changed-version'),('policy_hash','sha256:'+'e'*64),
    ('witness_reference','sha256:'+'f'*64),('finality_reference','sha256:'+'d'*64)])
def test_signed_expected_state_substitution_does_not_change_observation(tmp_path,field,value):
    f=synthetic_commit(tmp_path);state=deepcopy(f.state);state[field]=value
    deny(verify(f,f.new_command(expected_state=state)),'EXPECTED_STATE_MISMATCH')


def test_valid_exact_v1_revocation_grant_cannot_authorize_all_versions(tmp_path):
    f=synthetic_commit(tmp_path,action='REVOKE_POLICY_OBJECT')
    # Confirm this is otherwise a real complete exact-object authority chain.
    assert f.f.verify()['decision']=='ALLOW'
    deny(verify(f),'REVOCATION_SCOPE_MISMATCH')
    assert uses(f)==[]


@pytest.mark.parametrize('field,value', [('transaction_id','other-transaction'),('command_hash','sha256:'+'e'*64),
    ('tenant_id','other-tenant'),('authority_challenge_id','sha256:'+'e'*64),
    ('currentness_snapshot_identity','sha256:'+'e'*64),('replay_reservation_identity','sha256:'+'e'*64)])
def test_signed_fence_for_other_attempt_is_rejected(tmp_path,field,value):
    f=synthetic_commit(tmp_path)
    f.source.alter_proof=lambda p:dict(p,**{field:value})
    deny(verify(f),'COMMIT_FENCE_MISMATCH')


def test_stale_fence_and_expired_command_at_equality_deny(tmp_path):
    f=synthetic_commit(tmp_path)
    f.source.alter_proof=lambda p:dict(p,valid_from='2026-01-02T11:59:59Z',issued_at='2026-01-02T11:59:59Z',
        fence_created_at='2026-01-02T11:59:59Z',valid_until='2026-01-02T12:00:00Z',fence_valid_until='2026-01-02T12:00:00Z')
    deny(verify(f),'COMMIT_FENCE_STALE')
    f.source.alter_proof=None
    deny(verify(f,f.new_command(valid_until='2026-01-02T12:00:00Z')),'MUTATION_COMMAND_EXPIRED')


def test_authority_revoked_before_fence_denies(tmp_path):
    f=synthetic_commit(tmp_path)
    f.source.update(root_status='REVOKED')
    deny(verify(f),'ROOT_AUTHORITY_REVOKED')


def test_revocation_after_initial_verification_before_confirmation_denies(tmp_path):
    f=synthetic_commit(tmp_path)
    before=uses(f)
    with f.view.mutation_attempt(currentness_fence=f.source) as tx:
        assert f.verify(tx)['decision']=='ALLOW'
        # Deterministic hook at the final source confirmation, no sleeps.
        f.source.before_confirm=lambda source:source.update(root_status='REVOKED')
        deny(tx.commit(),'COMMIT_FENCE_STALE')
    assert uses(f)==before


def test_changed_currentness_epoch_invalidates_held_attempt(tmp_path):
    f=synthetic_commit(tmp_path)
    with f.view.mutation_attempt(currentness_fence=f.source) as tx:
        assert f.verify(tx)['decision']=='ALLOW'
        f.source.update(epoch=True)
        deny(tx.commit(),'COMMIT_FENCE_STALE')


def test_other_thread_revocation_cannot_linearize_before_held_commit(tmp_path):
    f=synthetic_commit(tmp_path)
    started=Event();finished=Event()
    def revoke():
        started.set();f.source.update(root_status='REVOKED');finished.set()
    with ThreadPoolExecutor(max_workers=1) as pool:
        with f.view.mutation_attempt(currentness_fence=f.source) as tx:
            assert f.verify(tx)['decision']=='ALLOW'
            task=pool.submit(revoke);assert started.wait(3)
            assert not finished.is_set()
            assert tx.commit()['decision']=='ALLOW'
            assert not finished.is_set()  # Guard held through the actual COMMIT.
        task.result(timeout=3)
    assert finished.is_set()


def test_rollback_leaves_no_consumption_and_valid_retry_can_verify(tmp_path):
    f=synthetic_commit(tmp_path);before=uses(f)
    with f.view.mutation_attempt(currentness_fence=f.source) as tx:
        assert f.verify(tx)['decision']=='ALLOW'
    assert uses(f)==before
    assert verify(f)['decision']=='ALLOW'


def test_same_grant_with_different_command_denies_after_commit(tmp_path):
    f=synthetic_commit(tmp_path)
    with f.view.mutation_attempt(currentness_fence=f.source) as tx:
        assert f.verify(tx)['decision']=='ALLOW';assert tx.commit()['decision']=='ALLOW'
    deny(verify(f,f.new_command(command_id='other-command',transaction_id='other-transaction',nonce='other-nonce')),
         'GRANT_ALREADY_CONSUMED')
    deny(verify(f,f.new_command(transaction_id='other-transaction')),'COMMAND_REPLAY')


def test_uncertain_commit_has_no_automatic_retry(tmp_path):
    f=synthetic_commit(tmp_path);f.source.fail_after_commit=True
    with f.view.mutation_attempt(currentness_fence=f.source) as tx:
        assert f.verify(tx)['decision']=='ALLOW'
        result=tx.commit()
        deny(result,'COMMIT_STATE_UNKNOWN')
        assert result['commit_outcome']=='UNKNOWN' and result['reconciliation_required'] is True
        deny(tx.commit(),'TRANSACTION_CONFLICT')
    # Durable fact can be reconciled; uncertainty did not release reservations.
    deny(verify(f),'COMMAND_REPLAY')


def test_two_concurrent_attempts_have_at_most_one_durable_consumption(tmp_path):
    f=synthetic_commit(tmp_path);barrier=Barrier(2)
    def attempt():
        barrier.wait(timeout=5)
        try:
            with f.view.mutation_attempt(currentness_fence=f.source) as tx:
                result=f.verify(tx)
                return tx.commit() if result['decision']=='ALLOW' else result
        except sqlite3.OperationalError:
            return {'decision':'DENY','reason':'TRANSACTION_CONFLICT'}
    with ThreadPoolExecutor(max_workers=2) as pool:
        results=list(pool.map(lambda _:attempt(),range(2)))
    assert sum(r['decision']=='ALLOW' for r in results)==1
    with sqlite3.connect(f.path) as conn:
        rows=[parse_json(row[0]) for row in conn.execute('SELECT payload FROM enrollment_events')]
    assert sum(e['kind']=='MUTATION_ATTEMPT_CONSUMED_NON_EXECUTING' for e in rows)==1


def test_no_commit_outside_verified_live_transaction(tmp_path):
    f=synthetic_commit(tmp_path)
    deny(verify_mutation_for_commit(True,f.command),'TRANSACTION_CONFLICT')
    tx=f.view.mutation_attempt(currentness_fence=f.source)
    deny(f.verify(tx),'TRANSACTION_CONFLICT')
    with f.view.mutation_attempt(currentness_fence=f.source) as tx:
        deny(tx.commit(),'TRANSACTION_CONFLICT')


def test_missing_authority_or_currentness_evidence_denies(tmp_path):
    f=synthetic_commit(tmp_path)
    with f.view.mutation_attempt(currentness_fence=f.source) as tx:
        deny(verify_mutation_for_commit(tx,f.command,proposal=f.f.proposal,reviews=f.f.reviews,grant=None),
             'MUTATION_AUTHORITY_MISSING')


def test_actual_rolled_back_reservations_do_not_block_later_valid_attempt(tmp_path):
    f=synthetic_commit(tmp_path);before=uses(f)
    with f.view.mutation_attempt(currentness_fence=f.source) as tx:
        assert f.verify(tx)['decision']=='ALLOW'
        f.source.before_confirm=lambda source:source.update(epoch=True)
        deny(tx.commit(),'COMMIT_FENCE_STALE')
    assert uses(f)==before
    f.source.before_confirm=None
    assert verify(f)['decision']=='ALLOW'


@pytest.mark.parametrize('action',['REVOKE_POLICY_OBJECT','REVOKE_GRANT_OBJECT','REVOKE_ADOPTION'])
def test_revocation_cas_contract_requires_exact_states_and_effect_scope(tmp_path,action):
    from governance.mutation_commit import validate_expected_state
    f=synthetic_commit(tmp_path)
    common={k:f.state[k] for k in ('tenant_id','object_id','object_version_hash','expected_current_head')}
    state=dict(common,revocation_effect_scope='ALL_VERSIONS_OF_OBJECT',expected_revocation_state='NOT_REVOKED')
    if action=='REVOKE_POLICY_OBJECT':state.update(policy_id='synthetic-policy',policy_version='v1',policy_hash=common['object_version_hash'])
    if action=='REVOKE_GRANT_OBJECT':state.update(grant_id='synthetic-grant',grant_version_hash=common['object_version_hash'],expected_consumption_state='UNCONSUMED')
    if action=='REVOKE_ADOPTION':state.update(adoption_id=common['object_id'],adoption_version_hash=common['object_version_hash'],expected_finalization_state='FINALIZED')
    assert exact_mutation_cas(action,state,deepcopy(state))==digest(state)
    with pytest.raises(EnrollmentDenied):validate_expected_state(action,dict(state,revocation_effect_scope='EXACT_OBJECT_VERSION'))
    missing=dict(state);del missing['expected_revocation_state']
    with pytest.raises(EnrollmentDenied):validate_expected_state(action,missing)


def test_complete_stored_head_must_match_verified_currentness_not_hash_alone(tmp_path):
    f=synthetic_commit(tmp_path)
    with f.view.mutation_attempt(currentness_fence=f.source) as tx:
        assert f.verify(tx)['decision']=='ALLOW'
        state=parse_json(tx._conn.execute("SELECT value FROM enrollment_meta WHERE name='state'").fetchone()[0])
        state['head']['sequence']+=1
        tx._conn.execute("UPDATE enrollment_meta SET value=? WHERE name='state'",(canonical(state).decode(),))
        deny(tx.commit(),'EXPECTED_HEAD_MISMATCH')


def test_projection_policy_fields_cannot_disagree_with_signed_adoption(tmp_path):
    f=synthetic_commit(tmp_path)
    state=dict(f.state,policy_version='different-version')
    with sqlite3.connect(f.path) as conn:
        conn.execute('UPDATE synthetic_mutation_target SET state=?',(canonical(state).decode(),))
    deny(verify(f,f.new_command(expected_state=state)),'EXPECTED_STATE_MISMATCH')


def test_review_expiry_after_verification_before_commit_is_stale(tmp_path):
    f=synthetic_commit(tmp_path)
    review=f.f.reviews[0]
    payload=deepcopy(review['payload']);payload['valid_until']='2026-01-02T12:00:01Z'
    payload['decision_fingerprint']=fingerprint(payload,'review')
    f.f.reviews[0]=f.f.sign(payload)
    grant=deepcopy(f.f.grant['payload'])
    field='reviewer_a_decision_hash' if payload['reviewer_id']=='USBAY-AUDIT' else 'reviewer_b_decision_hash'
    grant[field]=digest(payload);grant['grant_fingerprint']=fingerprint(grant,'grant')
    f.f.grant=f.f.sign(grant)
    command=deepcopy(f.command['payload'])
    command['reviewer_a_decision_hash']=grant['reviewer_a_decision_hash']
    command['reviewer_b_decision_hash']=grant['reviewer_b_decision_hash']
    command['mutation_authority_grant_hash']=digest(grant)
    f.command=f.seal_command(command)
    with f.view.mutation_attempt(currentness_fence=f.source) as tx:
        assert f.verify(tx)['decision']=='ALLOW'
        f.source.before_confirm=lambda source:setattr(source,'clock',lambda:instant('2026-01-02T12:00:02Z'))
        deny(tx.commit(),'COMMIT_FENCE_STALE')


def test_freshness_expiry_after_verification_before_commit_is_stale(tmp_path):
    f=synthetic_commit(tmp_path)
    with f.view.mutation_attempt(currentness_fence=f.source) as tx:
        assert f.verify(tx)['decision']=='ALLOW'
        f.source.before_confirm=lambda source:setattr(source,'clock',lambda:NOW+timedelta(seconds=61))
        deny(tx.commit(),'COMMIT_FENCE_STALE')


def test_audit_event_records_exact_transaction_id(tmp_path):
    f=synthetic_commit(tmp_path)
    with f.view.mutation_attempt(currentness_fence=f.source) as tx:
        assert f.verify(tx)['decision']=='ALLOW'
        result=tx.commit();assert result['decision']=='ALLOW'
    with sqlite3.connect(f.path) as conn:
        payloads=[json.loads(row[0]) for row in conn.execute('SELECT payload FROM enrollment_events ORDER BY sequence')]
    event=next(e for e in reversed(payloads) if e.get('kind')=='MUTATION_ATTEMPT_CONSUMED_NON_EXECUTING')
    assert event['evidence']['transaction_id']=='synthetic-transaction'


def test_policy_revocation_effect_extension_allows_commit_fence(tmp_path):
    f=synthetic_commit(tmp_path,action='REVOKE_POLICY_OBJECT')
    effect=build_effect_for_mutation(f.f)
    f.view.trust=f.f.trust
    command=f.new_command(
        revocation_effect_scope='ALL_VERSIONS_OF_OBJECT',
        revocation_effect_grant_hash=digest(effect['grant']['payload']),
    )
    with f.view.mutation_attempt(currentness_fence=f.source) as tx:
        result=f.verify(tx,command,revocation_effect=effect)
    assert result['decision']=='ALLOW'
    assert result['reason']=='COMMIT_FENCE_VERIFIED'
    assert result['evidence']['revocation_effect_scope']=='ALL_VERSIONS_OF_OBJECT'
    assert result['evidence']['revocation_effect_grant_hash']==digest(effect['grant']['payload'])


def test_policy_revocation_command_with_effect_fields_but_no_effect_bundle_denies(tmp_path):
    f=synthetic_commit(tmp_path,action='REVOKE_POLICY_OBJECT')
    effect=build_effect_for_mutation(f.f)
    f.view.trust=f.f.trust
    command=f.new_command(
        revocation_effect_scope='ALL_VERSIONS_OF_OBJECT',
        revocation_effect_grant_hash=digest(effect['grant']['payload']),
    )
    with f.view.mutation_attempt(currentness_fence=f.source) as tx:
        result=f.verify(tx,command)
    deny(result,'REVOCATION_SCOPE_MISMATCH')


def test_policy_revocation_effect_grant_hash_mismatch_denies(tmp_path):
    f=synthetic_commit(tmp_path,action='REVOKE_POLICY_OBJECT')
    effect=build_effect_for_mutation(f.f)
    f.view.trust=f.f.trust
    command=f.new_command(
        revocation_effect_scope='ALL_VERSIONS_OF_OBJECT',
        revocation_effect_grant_hash='sha256:'+'e'*64,
    )
    with f.view.mutation_attempt(currentness_fence=f.source) as tx:
        result=f.verify(tx,command,revocation_effect=effect)
    deny(result,'REVOCATION_SCOPE_MISMATCH')


def test_grant_revocation_effect_extension_allows_commit_fence(tmp_path):
    f=synthetic_commit(tmp_path,action='REVOKE_GRANT_OBJECT')
    effect=build_grant_effect_for_mutation(f.f)
    f.view.trust=f.f.trust
    command=f.new_command(
        revocation_effect_scope='ALL_VERSIONS_OF_OBJECT',
        revocation_effect_grant_hash=digest(effect['grant']['payload']),
    )
    with f.view.mutation_attempt(currentness_fence=f.source) as tx:
        result=f.verify(tx,command,revocation_effect=effect)
    assert result['decision']=='ALLOW'
    assert result['reason']=='COMMIT_FENCE_VERIFIED'
    assert result['evidence']['revocation_effect_scope']=='ALL_VERSIONS_OF_OBJECT'
    assert result['evidence']['revocation_effect_grant_hash']==digest(effect['grant']['payload'])


def test_grant_revocation_missing_effect_bundle_denies(tmp_path):
    f=synthetic_commit(tmp_path,action='REVOKE_GRANT_OBJECT')
    effect=build_grant_effect_for_mutation(f.f)
    f.view.trust=f.f.trust
    command=f.new_command(
        revocation_effect_scope='ALL_VERSIONS_OF_OBJECT',
        revocation_effect_grant_hash=digest(effect['grant']['payload']),
    )
    with f.view.mutation_attempt(currentness_fence=f.source) as tx:
        result=f.verify(tx,command)
    deny(result,'REVOCATION_SCOPE_MISMATCH')


def test_policy_effect_bundle_cannot_authorize_grant_revocation(tmp_path):
    f=synthetic_commit(tmp_path,action='REVOKE_GRANT_OBJECT')
    policy_effect=build_effect_for_mutation(f.f)
    f.view.trust=f.f.trust
    command=f.new_command(
        revocation_effect_scope='ALL_VERSIONS_OF_OBJECT',
        revocation_effect_grant_hash=digest(policy_effect['grant']['payload']),
    )
    with f.view.mutation_attempt(currentness_fence=f.source) as tx:
        result=f.verify(tx,command,revocation_effect=policy_effect)
    deny(result)


def test_adoption_revocation_effect_extension_allows_commit_fence(tmp_path):
    f=synthetic_commit(tmp_path,action='REVOKE_ADOPTION')
    effect=build_adoption_effect_for_mutation(f.f)
    f.view.trust=f.f.trust
    command=f.new_command(
        revocation_effect_scope='ALL_VERSIONS_OF_OBJECT',
        revocation_effect_grant_hash=digest(effect['grant']['payload']),
    )
    with f.view.mutation_attempt(currentness_fence=f.source) as tx:
        result=f.verify(tx,command,revocation_effect=effect)
    assert result['decision']=='ALLOW'
    assert result['reason']=='COMMIT_FENCE_VERIFIED'
    assert result['evidence']['revocation_effect_scope']=='ALL_VERSIONS_OF_OBJECT'
    assert result['evidence']['revocation_effect_grant_hash']==digest(effect['grant']['payload'])


def test_adoption_revocation_missing_effect_bundle_denies(tmp_path):
    f=synthetic_commit(tmp_path,action='REVOKE_ADOPTION')
    effect=build_adoption_effect_for_mutation(f.f)
    f.view.trust=f.f.trust
    command=f.new_command(
        revocation_effect_scope='ALL_VERSIONS_OF_OBJECT',
        revocation_effect_grant_hash=digest(effect['grant']['payload']),
    )
    with f.view.mutation_attempt(currentness_fence=f.source) as tx:
        result=f.verify(tx,command)
    deny(result,'REVOCATION_SCOPE_MISMATCH')


def test_policy_effect_bundle_cannot_authorize_adoption_revocation(tmp_path):
    f=synthetic_commit(tmp_path,action='REVOKE_ADOPTION')
    effect=build_effect_for_mutation(f.f)
    f.view.trust=f.f.trust
    command=f.new_command(
        revocation_effect_scope='ALL_VERSIONS_OF_OBJECT',
        revocation_effect_grant_hash=digest(effect['grant']['payload']),
    )
    with f.view.mutation_attempt(currentness_fence=f.source) as tx:
        result=f.verify(tx,command,revocation_effect=effect)
    deny(result)


def test_grant_effect_bundle_cannot_authorize_adoption_revocation(tmp_path):
    f=synthetic_commit(tmp_path,action='REVOKE_ADOPTION')
    effect=build_grant_effect_for_mutation(f.f)
    f.view.trust=f.f.trust
    command=f.new_command(
        revocation_effect_scope='ALL_VERSIONS_OF_OBJECT',
        revocation_effect_grant_hash=digest(effect['grant']['payload']),
    )
    with f.view.mutation_attempt(currentness_fence=f.source) as tx:
        result=f.verify(tx,command,revocation_effect=effect)
    deny(result)
