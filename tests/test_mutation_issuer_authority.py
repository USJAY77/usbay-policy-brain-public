"""Synthetic root/issuer verification only; no live authority is created."""
from copy import deepcopy
from concurrent.futures import ThreadPoolExecutor
from threading import Barrier
import sqlite3

import pytest

from governance.mutation_issuer_authority import (
    ROOT_AUTHORITIES, MUTATION_ISSUER_AUTHORITIES, MUTATION_AUTHORITY_GRANTS,
    LIVE_REVIEWER_DECISIONS, verify_mutation_authority_issuer,
)
from governance.tenant_enrollment_contracts import FLAGS, digest
from tests.helpers.mutation_authority import synthetic_mutation
from tests.helpers.mutation_issuer_authority import seal_authority


def denied(result, reason=None):
    assert result['decision'] == 'DENY'
    assert result['authority_flags'] == dict.fromkeys(FLAGS, False)
    if reason is not None:
        assert result['reason'] == reason


def change(f, attr, kind, **fields):
    p = deepcopy(getattr(f, attr)['payload'])
    p.update(fields)
    setattr(f, attr, seal_authority(f, p, kind))


def test_complete_synthetic_root_issuer_review_child_chain_allows_read_only():
    f = synthetic_mutation()
    result = f.verify()
    assert result['decision'] == 'ALLOW'
    assert result['authority_flags'] == dict.fromkeys(FLAGS, False)
    evidence = result['issuance_evidence']
    assert evidence['attenuation'] == 'CHILD_SUBSET_PARENT'
    assert evidence['proposal_hash'] == digest(f.proposal['payload'])
    assert evidence['review_hashes'] == {r['payload']['reviewer_id']:digest(r['payload']) for r in f.reviews}
    assert evidence['replay_state'] == 'AVAILABLE_NOT_CONSUMED'
    assert ROOT_AUTHORITIES == MUTATION_ISSUER_AUTHORITIES == MUTATION_AUTHORITY_GRANTS == LIVE_REVIEWER_DECISIONS == ()


@pytest.mark.parametrize('missing', ['root_authority','issuer_grant','root_source','review_policy'])
def test_missing_authority_despite_valid_child_signature_and_reviews_denies(missing):
    denied(synthetic_mutation().verify(**{missing:None}))


def test_owner_label_or_account_or_approved_boolean_cannot_be_root():
    f = synthetic_mutation()
    for root in ('USBAY_OWNER_ROOT', {'issuer_id':'USBAY_OWNER_ROOT','approved':True}, {'verified':True}):
        denied(f.verify(root_authority=root))
    result = verify_mutation_authority_issuer()
    denied(result, 'MUTATION_AUTHORITY_MISSING')
    assert result['authority_reason'] == 'ROOT_AUTHORITY_MISSING'


def test_signature_and_reviews_with_empty_default_trust_do_not_grant_authority():
    from security.enrollment_policy_currentness import EnrollmentTrust
    denied(synthetic_mutation().verify(trust=EnrollmentTrust()))


def test_wrong_root_signer_denies_even_with_valid_signature():
    f = synthetic_mutation()
    change(f,'root_authority','root',issuer_id='synthetic-parent-signer',issuer_key_id='test-parent-assertion')
    denied(f.verify(), 'ROOT_AUTHORITY_INVALID')


def test_expired_root_denies():
    f = synthetic_mutation()
    change(f,'root_authority','root',valid_until='2026-01-02T12:00:00Z')
    denied(f.verify(), 'ROOT_AUTHORITY_INVALID')


@pytest.mark.parametrize('state,reason', [('root_status','ROOT_AUTHORITY_REVOKED'),('issuer_status','ISSUER_AUTHORITY_REVOKED')])
def test_authoritative_record_revocation_denies_descendant(state,reason):
    f = synthetic_mutation()
    setattr(f.root_source,state,'REVOKED')
    denied(f.verify(),reason)


@pytest.mark.parametrize('field,value,reason', [
    ('authority_domain','OTHER_DOMAIN','ISSUER_DOMAIN_MISMATCH'),
    ('tenant_id','different-tenant',None),
    ('allowed_actor_scope',['synthetic-actor','another-actor'],'ISSUER_ACTOR_SCOPE_MISMATCH'),
    ('allowed_purpose_scope',['ANOTHER_PURPOSE'],'ISSUER_PURPOSE_SCOPE_MISMATCH'),
    ('allowed_actions',['ROOT_TRUST_CHANGE'],'ISSUER_ACTION_SCOPE_MISMATCH'),
    ('allowed_resource_scope',['sha256:'+'1'*64],None),
    ('allowed_object_scope',[],None),
    ('valid_from','2026-01-02T10:59:59Z','AUTHORITY_SCOPE_BROADENING'),
    ('valid_until','2026-01-02T13:00:01Z','AUTHORITY_SCOPE_BROADENING'),
    ('redelegation_allowed',True,'PROHIBITED_REDELEGATION'),
    ('allowed_actor_scope',['*'],None),
    ('allowed_object_scope',[{}],None),
    ('allowed_grant_scope',['ungranted-id'],'ISSUER_OBJECT_SCOPE_MISMATCH'),
    ('allowed_adoption_scope',['ungranted-adoption'],'ISSUER_OBJECT_SCOPE_MISMATCH'),
])
def test_root_to_issuer_scope_broadening_denies(field,value,reason):
    f = synthetic_mutation()
    change(f,'issuer_grant','issuer',**{field:value})
    denied(f.verify(),reason)


def test_other_permitted_mutation_action_still_cannot_broaden_narrow_root():
    f = synthetic_mutation()
    change(f,'issuer_grant','issuer',allowed_actions=['REVOKE_POLICY_OBJECT','REVOKE_ADOPTION'],
           allowed_resource_types=['POLICY_OBJECT','ADOPTION_RECORD'])
    denied(f.verify(),'ISSUER_ACTION_SCOPE_MISMATCH')


def test_well_formed_extra_resource_object_cannot_broaden_root():
    f = synthetic_mutation()
    obj = deepcopy(f.issuer_grant['payload']['allowed_object_scope'][0])
    obj['resource_id'] = obj['object_id'] = 'sha256:'+'f'*64
    change(f,'issuer_grant','issuer',allowed_resource_scope=[f.grant['payload']['resource_id'],obj['resource_id']],
           allowed_object_scope=f.issuer_grant['payload']['allowed_object_scope']+[obj])
    denied(f.verify())


def test_changed_object_version_is_not_an_allowed_object():
    f = synthetic_mutation()
    objects = deepcopy(f.issuer_grant['payload']['allowed_object_scope'])
    objects[0]['object_version_hash'] = 'sha256:'+'e'*64
    change(f,'issuer_grant','issuer',allowed_object_scope=objects)
    denied(f.verify(),'ISSUER_OBJECT_SCOPE_MISMATCH')


def test_issuer_expiry_at_equality_denies():
    f = synthetic_mutation()
    change(f,'issuer_grant','issuer',valid_until='2026-01-02T12:00:00Z')
    denied(f.verify(),'ISSUER_AUTHORITY_EXPIRED')


@pytest.mark.parametrize('mode', ['one','duplicate','reject','different-proposal'])
def test_review_gate_requires_two_independent_exact_approvals(mode):
    f = synthetic_mutation()
    if mode == 'one':
        f.reviews = f.reviews[:1]
    elif mode == 'duplicate':
        f.reviews = [f.reviews[0],deepcopy(f.reviews[0])]
    else:
        p = deepcopy(f.reviews[1]['payload'])
        p.update({'decision':'REJECT'} if mode == 'reject' else {'proposal_hash':'sha256:'+'f'*64})
        f.reviews[1] = f.seal(p,'review')
    denied(f.verify())


@pytest.mark.parametrize('field,value', [('threshold',1),('required',1),('distinct_reviewers',False),
    ('required_reviewers',['USBAY-AUDIT','replacement']),('proposal_binding','ANY_PROPOSAL')])
def test_review_policy_cannot_weaken_existing_gate(field,value):
    f = synthetic_mutation()
    change(f,'review_policy','review_policy',**{field:value})
    denied(f.verify(),'REVIEW_POLICY_NOT_SATISFIED')


def test_captured_root_proof_cannot_be_reused_for_fresh_challenge():
    f = synthetic_mutation()
    real = f.root_source
    class Captured:
        proof = None
        def read_issuer_authority(self,**kw):
            if self.proof is None:
                self.proof = real.read_issuer_authority(**kw)
            return deepcopy(self.proof)
    reader = Captured()
    assert f.verify(root_source=reader)['decision'] == 'ALLOW'
    denied(f.verify(root_source=reader),'ROOT_AUTHORITY_INVALID')


@pytest.mark.parametrize('field,value', [('issued_at','2026-01-02T11:58:00Z'),
    ('root_authority_hash','sha256:'+'b'*64),('issuer_grant_hash','sha256:'+'b'*64),
    ('revocation_reference','sha256:'+'b'*64),('tenant_id','different-tenant'),
    ('expected_current_head','sha256:'+'b'*64)])
def test_even_signed_freshness_or_lineage_substitution_is_rejected(field,value):
    f = synthetic_mutation()
    source = f.root_source
    class Altered:
        def read_issuer_authority(self,**kw):
            p = source.read_issuer_authority(**kw)['payload']
            p[field] = value
            return seal_authority(f,p,'status')
    denied(f.verify(root_source=Altered()),'ROOT_AUTHORITY_INVALID')


def test_source_does_not_endorse_caller_selected_root_or_lineage():
    f = synthetic_mutation()
    change(f,'root_authority','root',lineage_reference=digest({'caller-selected-lineage':1}))
    change(f,'issuer_grant','issuer',parent_authority_hash=digest(f.root_authority['payload']))
    f.parent['payload']['parent_authority_hash'] = digest(f.issuer_grant['payload'])
    f.refresh()
    f.parent_source.install_test_record(f)
    denied(f.verify(),'ROOT_AUTHORITY_INVALID')


@pytest.mark.parametrize('part', ['root_authority','issuer_grant','grant'])
def test_mutated_protected_signed_bytes_fail_integrity(part):
    f = synthetic_mutation()
    field = {'root_authority':'lineage_reference','issuer_grant':'issuance_nonce','grant':'grant_nonce'}[part]
    getattr(f,part)['payload'][field] = 'tampered'
    denied(f.verify())


def test_subject_identity_reference_is_not_a_caller_account_claim():
    f = synthetic_mutation()
    change(f,'issuer_grant','issuer',issuer_identity_reference=digest({'owner-account':True}))
    denied(f.verify(),'ISSUER_AUTHORITY_INVALID')


def make_store(f,tmp_path):
    from governance.authority_registry import EnrollmentAuthorityView
    path = tmp_path/'synthetic-authority.sqlite'
    f.enrollment.store(path)
    f.root_source.attach_store(EnrollmentAuthorityView(path))
    return path


def test_consumed_one_time_issuance_remains_consumed_on_reopen(tmp_path):
    from governance.authority_registry import EnrollmentAuthorityView
    f = synthetic_mutation()
    path = make_store(f,tmp_path)
    result = f.verify()
    assert result['decision'] == 'ALLOW'
    f.root_source.reserve_for_test(result['issuance_evidence']['issuance_binding'])
    f.root_source.attach_store(EnrollmentAuthorityView(path))
    denied(f.verify(),'ISSUANCE_REPLAY')
    # New child/proposal bytes cannot evade the consumed issuer ID and nonce.
    f.proposal['payload']['proposal_nonce'] = 'fresh-proposal-nonce'
    f.refresh()
    denied(f.verify(),'ISSUANCE_REPLAY')


def test_rolled_back_reservation_is_not_replay_evidence(tmp_path):
    f = synthetic_mutation()
    path = make_store(f,tmp_path)
    result = f.verify()
    assert result['decision'] == 'ALLOW'
    f.root_source.reserve_for_test(result['issuance_evidence']['issuance_binding'],rollback=True)
    assert f.verify()['decision'] == 'ALLOW'
    with sqlite3.connect(path) as conn:
        assert conn.execute('SELECT COUNT(*) FROM enrollment_uses').fetchone()[0] == 0
        assert conn.execute('SELECT COUNT(*) FROM enrollment_events').fetchone()[0] == 0


def test_orphan_consumption_cannot_be_treated_as_trusted_available_history(tmp_path):
    f = synthetic_mutation()
    make_store(f,tmp_path)
    conn = f.root_source.store._connect_existing()
    try:
        f.root_source.store._consume(conn,'mutation_issuance',f.root_source.consumption_payload(digest({})))
    finally:
        conn.close()
    denied(f.verify(),'ROOT_AUTHORITY_INVALID')


def test_concurrent_one_time_consumption_has_one_durable_winner(tmp_path):
    f = synthetic_mutation()
    path = make_store(f,tmp_path)
    binding = f.verify()['issuance_evidence']['issuance_binding']
    barrier = Barrier(2)
    def consume():
        barrier.wait(timeout=5)
        try:
            f.root_source.reserve_for_test(binding)
            return 'committed'
        except sqlite3.Error:
            return 'blocked'
    with ThreadPoolExecutor(max_workers=2) as pool:
        outcomes = list(pool.map(lambda _:consume(),range(2)))
    assert sorted(outcomes) == ['blocked','committed']
    with sqlite3.connect(path) as conn:
        assert conn.execute('SELECT COUNT(*) FROM enrollment_uses').fetchone()[0] == 3
        assert conn.execute('SELECT COUNT(*) FROM enrollment_events').fetchone()[0] == 1
    denied(f.verify(),'ISSUANCE_REPLAY')


@pytest.mark.parametrize('attr,kind,model', [
    ('root_authority','root','RootMutationAuthorityV1'),
    ('issuer_grant','issuer','MutationAuthorityIssuerGrantV1'),
    ('review_policy','review_policy','MutationReviewPolicyV1')])
def test_closed_issuance_models_reject_missing_extra_and_changed_fields(attr,kind,model):
    import governance.mutation_issuer_authority as module
    from governance.tenant_enrollment_contracts import EnrollmentDenied
    f = synthetic_mutation()
    original = getattr(f,attr)['payload']
    contract = getattr(module,model)
    contract.from_payload(original)
    for field in original:
        missing = deepcopy(original)
        del missing[field]
        with pytest.raises(EnrollmentDenied):
            contract.from_payload(missing)
        changed = deepcopy(original)
        changed[field] = None
        with pytest.raises(EnrollmentDenied):
            contract.from_payload(changed)
    with pytest.raises(EnrollmentDenied):
        contract.from_payload(dict(original,approved=True))


def test_root_source_failure_or_unsigned_claim_remains_fail_closed():
    f = synthetic_mutation()
    class Failed:
        def read_issuer_authority(self,**kw):
            raise OSError('synthetic unavailable')
    class Unsigned:
        def read_issuer_authority(self,**kw):
            return {'approved':True,'root_status':'ACTIVE'}
    denied(f.verify(root_source=Failed()),'ROOT_AUTHORITY_INVALID')
    denied(f.verify(root_source=Unsigned()),'ROOT_AUTHORITY_INVALID')


def test_standalone_issuer_verifier_reuses_real_review_and_currentness_contracts():
    from tests.helpers.tenant_enrollment import NOW
    f = synthetic_mutation()
    kwargs = dict(proposal=f.proposal,reviewer_decisions=f.reviews,grant=f.grant,parent_artifact=f.parent,
                  trust=f.trust,root_source=f.root_source,currentness=f.currentness(),now=NOW)
    result = verify_mutation_authority_issuer(f.root_authority,f.issuer_grant,f.review_policy,**kwargs)
    assert result['decision'] == 'ALLOW'
    assert result['authority_flags'] == dict.fromkeys(FLAGS,False)
    kwargs['reviewer_decisions'] = f.reviews[:1]
    denied(verify_mutation_authority_issuer(f.root_authority,f.issuer_grant,f.review_policy,**kwargs))


@pytest.mark.parametrize('part,reason', [('root_authority','ROOT_AUTHORITY_REVOKED'),
    ('proposal','MUTATION_AUTHORITY_REVOKED'),('parent','PARENT_AUTHORITY_REVOKED'),
    ('review_a','MUTATION_AUTHORITY_REVOKED'),('review_b','MUTATION_AUTHORITY_REVOKED'),
    ('grant','ISSUER_AUTHORITY_REVOKED'),('source','ROOT_AUTHORITY_REVOKED')])
def test_standalone_issuer_verifier_honors_all_scoped_key_revocations(part,reason):
    from governance.tenant_enrollment_contracts import SCOPE_FIELDS,key_id
    from tests.helpers.tenant_enrollment import NOW,synthetic_enrollment
    from tests.helpers.mutation_issuer_authority import attach_synthetic_issuance
    f = synthetic_mutation()
    envelope = f.root_source.read_issuer_authority(request_binding=digest({}),challenge='a'*64) if part == 'source' else f.reviews[0] if part == 'review_a' else f.reviews[1] if part == 'review_b' else getattr(f,part)
    payload = envelope['payload']
    entry = dict(kind='KEY_REVOCATION',target_id=key_id(payload),target_scope={k:payload[k] for k in SCOPE_FIELDS},
                 coverage='EXACT_KEY_ID',effective_at='2026-01-02T12:00:00Z')
    f.rebind_enrollment(synthetic_enrollment(private_keys=f.enrollment.private,revocations=[entry]))
    # Explicit synthetic setup, not a production/request-driven root update.
    attach_synthetic_issuance(f)
    result = verify_mutation_authority_issuer(f.root_authority,f.issuer_grant,f.review_policy,
        proposal=f.proposal,reviewer_decisions=f.reviews,grant=f.grant,parent_artifact=f.parent,
        trust=f.trust,root_source=f.root_source,currentness=f.currentness(),now=NOW)
    denied(result,reason)
