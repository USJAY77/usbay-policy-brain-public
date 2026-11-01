"""Synthetic declarations with real Gateway signatures and durable replay state."""
from __future__ import annotations

import concurrent.futures
import copy
import json
import sqlite3
import subprocess
import sys
from dataclasses import replace
from datetime import datetime, timezone

import pytest

from gateway.intent_governance import FLAGS, consume_declared_intent
from governance.hashing import sha256_reference
from security.declared_intent import FIELDS, IntentError, SCHEMA, intent_hash, validate_declaration
from security.intent_replay_store import IntentReplayStore, IntentStoreError
from security.request_signing import sign_request_payload
from tests.test_gateway_request_identity import (
    NOW, PUBKEY_ID, PURPOSE as AUTHENTICATED_PURPOSE, _authenticate, _setup,
)

pytestmark = [pytest.mark.governance, pytest.mark.regression]
CLOCK = datetime(2026, 10, 16, 12, tzinfo=timezone.utc)
RESOURCE = 'sha256:' + 'a' * 64
POLICY = 'sha256:' + 'b' * 64
DECISION = 'sha256:' + 'c' * 64


def _request():
    intent = dict(schema_version=SCHEMA, declaration_source='human_declared',
                  intent_id='intent-001', request_id='request-001', correlation_id='correlation-001',
                  tenant_id='t1', actor_id='synthetic-reviewer', environment='test',
                  purpose=AUTHENTICATED_PURPOSE, action_class='read', resource_scope=[RESOURCE],
                  issued_at='2026-10-16T11:59:00Z', expires_at='2026-10-16T12:03:00Z',
                  nonce='intent-nonce-001', intent_hash='')
    intent['intent_hash'] = intent_hash(intent)
    return {**intent, 'operation':dict(purpose=AUTHENTICATED_PURPOSE, action_class='read', resource_reference=RESOURCE)}


def _resign(material, request):
    result = {**material, 'body':request}
    credential = {k:v for k,v in material['signed'].items() if k not in ('signature',)}
    credential['request_body_hash'] = sha256_reference(request)
    credential['request_id'] = request['request_id']
    credential['correlation_id'] = request['correlation_id']
    result['signed'] = sign_request_payload(credential, material['private_pem'], PUBKEY_ID)
    return result


@pytest.fixture
def case(tmp_path):
    material = _resign(_setup(tmp_path/'identity'), _request())
    return material, _authenticate(material), IntentReplayStore.provision(tmp_path/'intent.db')


def _consume(material, identity, store, **kw):
    return consume_declared_intent(material['body'], authenticated_identity=identity,
                                   replay_store=store, prior_decision=kw.pop('prior_decision','ALLOW'),
                                   policy_hash=POLICY, decision_reference=DECISION, now=CLOCK, **kw)


def _rehash(request):
    request['intent_hash'] = intent_hash({k:v for k,v in request.items() if k in FIELDS})


def _assert_block(result, reason=None):
    assert result['decision']=='BLOCK'
    if reason:assert result['reason_code']==reason
    assert all(result[k] is False for k in FLAGS)


def test_valid_signed_declaration_is_non_executing(case):
    material, identity, store = case
    assert identity.purpose == material['body']['purpose'] == material['body']['operation']['purpose']
    result = _consume(material,identity,store)
    assert result['decision']=='ALLOW'
    assert result['intent_hash']==material['body']['intent_hash']
    assert all(result[k] is False for k in FLAGS)
    assert result['evidence_hash']==sha256_reference({k:v for k,v in result.items() if k!='evidence_hash'})
    assert len(sqlite3.connect(store.path).execute('SELECT * FROM consumed').fetchall())==2
    _assert_block(_consume(material,identity,store),'INTENT_REPLAY')


def test_authenticated_identity_accepts_offset_and_fractional_validity_times(tmp_path):
    material = _resign(_setup(tmp_path/'identity'), _request())
    credential = {k:v for k,v in material['signed'].items() if k != 'signature'}
    credential.update(valid_from='2026-10-16T11:59:00.000Z', valid_until='2026-10-16T12:04:00+00:00')
    material['signed'] = sign_request_payload(credential, material['private_pem'], PUBKEY_ID)
    identity = _authenticate(material)
    result = _consume(material, identity, IntentReplayStore.provision(tmp_path/'intent.db'))
    assert result['decision'] == 'ALLOW'


@pytest.mark.parametrize('field,value', [
    ('tenant_id', 'tenant/@id'), ('actor_id', 'reviewer/@id'),
    ('request_id', 'request/@id'), ('correlation_id', 'correlation/@id'),
    ('environment', 'Test/Prod'),
])
def test_declaration_accepts_authenticated_identity_identifier_alphabet(tmp_path, field, value):
    from governance.durable_authority_registries import IDENTITY
    material = _setup(tmp_path/'identity')
    record = dict(material['record'])
    if field in ('tenant_id', 'actor_id'):
        record[field] = value
    elif field == 'environment':
        record['environments'] = [value]
        credential = {k:v for k,v in material['signed'].items() if k != 'signature'}
        credential['environment'] = value
        material['signed'] = sign_request_payload(credential, material['private_pem'], PUBKEY_ID)
    if field in ('tenant_id', 'actor_id', 'environment'):
        material['registry'].update_authority(IDENTITY, record, timestamp=NOW)
    request = _request()
    request[field] = value
    _rehash(request)
    material = _resign(material, request)
    identity = _authenticate(
        material, expected_environment=value if field == 'environment' else 'test',
    )
    result = _consume(material, identity, IntentReplayStore.provision(tmp_path/'intent.db'))
    assert result['decision'] == 'ALLOW'


@pytest.mark.parametrize('field,value',[
    ('purpose','other'),('tenant_id','t2'),('actor_id','other'),('request_id','other'),
    ('correlation_id','other'),('environment','staging'),('action_class','write'),
    ('resource_scope',['sha256:'+'d'*64]),
])
def test_mutation_after_intent_hash_fails(case, field, value):
    material, identity, store = case
    request=copy.deepcopy(material['body']);request[field]=value
    # A valid outer request signature must not replace the declaration hash.
    changed=_resign(material,request)
    if field in ('tenant_id','actor_id'):
        # Existing authenticator rejects false principal claims even earlier.
        from gateway.request_identity import RequestIdentityError
        with pytest.raises(RequestIdentityError):_authenticate(changed)
        declaration={k:v for k,v in request.items() if k in FIELDS}
        with pytest.raises(IntentError, match='INTENT_HASH_MISMATCH'):
            validate_declaration(declaration,now=CLOCK)
    else:
        changed_identity=_authenticate(changed)
        _assert_block(_consume(changed,changed_identity,store),'INTENT_HASH_MISMATCH')


@pytest.mark.parametrize('field,value', [('tenant_id','t2'),('actor_id','other'),('request_id','other'),('correlation_id','other')])
def test_authenticated_context_cannot_be_substituted(case,field,value):
    material,identity,store=case
    _assert_block(_consume(material,replace(identity,**{field:value}),store),'INTENT_IDENTITY_UNVERIFIED')
    assert sqlite3.connect(store.path).execute('SELECT count(*) FROM consumed').fetchone()==(0,)


def test_caller_nested_identity_never_overrides(case):
    material,identity,store=case
    request=copy.deepcopy(material['body']);request['operation']['identity']={'tenant_id':'t2','actor_id':'other'}
    changed=_resign(material,request)
    from gateway.request_identity import RequestIdentityError
    with pytest.raises(RequestIdentityError,match='REQUEST_IDENTITY_CLIENT_CLAIM_LOCATION_INVALID'):_authenticate(changed)
    _assert_block(_consume(changed,identity,store),'INTENT_REQUEST_BINDING_MISMATCH')


@pytest.mark.parametrize('field,value',[
    ('expires_at','2026-10-16T12:00:00Z'),('expires_at','2026-10-16T11:59:59Z'),
    ('issued_at','2026-10-16T12:00:01Z'),('issued_at','bad-time'),
    ('expires_at','2026-10-16T12:03:00'),('issued_at','2026-02-30T12:00:00Z'),
])
def test_freshness_is_fail_closed(case,field,value):
    material,identity,store=case
    request=copy.deepcopy(material['body']);request[field]=value;_rehash(request)
    changed=_resign(material,request)
    _assert_block(_consume(changed,_authenticate(changed),store))


@pytest.mark.parametrize('preserve', ['intent_id','nonce'])
def test_either_replay_identifier_is_consumed(case,preserve):
    material,identity,store=case
    assert _consume(material,identity,store)['decision']=='ALLOW'
    request=copy.deepcopy(material['body'])
    request['request_id']='request-002';request['correlation_id']='correlation-002'
    request['nonce']='new-nonce' if preserve!='nonce' else request['nonce']
    request['intent_id']='new-intent' if preserve!='intent_id' else request['intent_id']
    _rehash(request);changed=_resign(material,request)
    _assert_block(_consume(changed,_authenticate(changed),store),'INTENT_REPLAY')


def test_concurrent_first_use_exactly_one_winner(case):
    material,identity,store=case
    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
        results=list(pool.map(lambda _: _consume(material,identity,IntentReplayStore(store.path)),range(8)))
    assert sum(r['decision']=='ALLOW' for r in results)==1
    assert all(r['decision'] in ('ALLOW','BLOCK') for r in results)
    _assert_block(_consume(material,identity,IntentReplayStore(store.path)),'INTENT_REPLAY')


@pytest.mark.parametrize('failure',['missing','corrupt','locked','contract','lost_commit_reply'])
def test_uncertain_store_blocks_and_never_repairs(case,monkeypatch,failure):
    material,identity,store=case
    held=None
    if failure=='missing':store.path.unlink()
    elif failure=='corrupt':store.path.write_bytes(b'not-a-sqlite-database')
    elif failure=='locked':
        held=sqlite3.connect(store.path);held.execute('BEGIN EXCLUSIVE')
    elif failure=='contract':
        with sqlite3.connect(store.path) as conn:conn.execute('DELETE FROM contract')
    else:
        original=store.reserve
        def lost(**kw):
            assert original(**kw)
            raise IntentStoreError('INTENT_STORE_UNAVAILABLE')
        monkeypatch.setattr(store,'reserve',lost)
    before=store.path.read_bytes() if store.path.exists() else None
    try:_assert_block(_consume(material,identity,store),'INTENT_STORE_UNAVAILABLE')
    finally:
        if held:held.rollback();held.close()
    if failure=='lost_commit_reply':
        _assert_block(_consume(material,identity,IntentReplayStore(store.path)),'INTENT_REPLAY')
    else:assert (store.path.read_bytes() if store.path.exists() else None)==before


@pytest.mark.parametrize('field,value',[('purpose','research_all'),('action_class','write'),('resource_reference','sha256:'+'d'*64)])
def test_outside_declared_scope_blocks(case,field,value):
    material,identity,store=case
    request=copy.deepcopy(material['body']);request['operation'][field]=value
    changed=_resign(material,request)
    _assert_block(_consume(changed,_authenticate(changed),store),'INTENT_SCOPE_MISMATCH')


@pytest.mark.parametrize('prior',['BLOCK','REVIEW'])
def test_intent_does_not_upgrade_prior_decision(case,prior):
    material,identity,store=case
    result=_consume(material,identity,store,prior_decision=prior)
    assert result['decision']==prior
    assert all(result[k] is False for k in FLAGS)
    assert sqlite3.connect(store.path).execute('SELECT count(*) FROM consumed').fetchone()==(0,)


@pytest.mark.parametrize('extra',['prompt','body','customer_content','identity','execution_authorized'])
def test_unknown_or_sensitive_fields_rejected(case,extra):
    material,identity,store=case
    request=copy.deepcopy(material['body']);request[extra]='SENSITIVE_CANARY'
    changed=_resign(material,request)
    result=_consume(changed,_authenticate(changed),store)
    _assert_block(result,'INTENT_FIELDS_INVALID')
    assert 'SENSITIVE_CANARY' not in json.dumps(result)
    assert b'SENSITIVE_CANARY' not in store.path.read_bytes()


def test_privacy_of_persisted_and_returned_evidence(case):
    material,identity,store=case
    result=_consume(material,identity,store)
    values=json.dumps(result)
    for raw in ['synthetic-reviewer','intent-nonce-001','intent-001','request-001','correlation-001',material['body']['purpose'],RESOURCE]:
        assert raw not in values
        assert raw.encode() not in store.path.read_bytes()
    assert result['tenant_reference']==sha256_reference({'tenant_id':'t1'})


@pytest.mark.parametrize('raw',['[]','null','{"intent_id":"a","intent_id":"b"}', '{"x":NaN}', '{"x":Infinity}', '{"x":1e999}', {'x':float('nan')}, {'x':float('inf')}, {'x':'a'*8193}])
def test_strict_json_contract_rejects_ambiguous_input(raw):
    with pytest.raises(IntentError):validate_declaration(raw,now=CLOCK)


def test_unverified_identity_cannot_consume(case):
    material,identity,store=case
    _assert_block(_consume(material,identity.as_mapping(),store),'INTENT_IDENTITY_UNVERIFIED')


def test_reopen_and_independent_process_preserve_consumption(case):
    material,identity,store=case
    assert _consume(material,identity,store)['decision']=='ALLOW'
    # New interpreter and connection inspect the real committed replay store.
    code='''import sys
from security.intent_replay_store import IntentReplayStore
assert IntentReplayStore(sys.argv[1]).reserve(intent_reference=sys.argv[2],nonce_reference=sys.argv[3],evidence="{}")==False
'''
    result=subprocess.run([sys.executable,'-s','-c',code,str(store.path),
                           sha256_reference({'tenant':'t1','intent_id':'intent-001'}),
                           sha256_reference({'tenant':'t1','nonce':'intent-nonce-001'})],capture_output=True,timeout=15)
    assert result.returncode==0,result.stderr.decode()


def test_foreign_tenant_cannot_consume_existing_intent_state(case,tmp_path):
    from governance.durable_authority_registries import IDENTITY
    material,identity,store=case
    assert _consume(material,identity,store)['decision']=='ALLOW'
    before=store.path.read_bytes()
    foreign=_setup(tmp_path/'foreign')
    foreign['registry'].update_authority(IDENTITY,{**foreign['record'],'tenant_id':'t2'},timestamp=NOW)
    request=_request();request['tenant_id']='t2';_rehash(request)
    foreign=_resign(foreign,request);foreign_identity=_authenticate(foreign)
    # Real authenticated B context cannot substitute for A on A's signed body.
    _assert_block(_consume(material,foreign_identity,store),'INTENT_REQUEST_BINDING_MISMATCH')
    assert store.path.read_bytes()==before
    # A's tombstone still blocks A after the foreign attempt.
    _assert_block(_consume(material,identity,IntentReplayStore(store.path)),'INTENT_REPLAY')


@pytest.mark.parametrize('source',['model_inferred','model_output','telemetry','',None])
def test_nonhuman_or_missing_declaration_source_is_rejected(case,source):
    material,identity,store=case
    request=copy.deepcopy(material['body']);request['declaration_source']=source;_rehash(request)
    changed=_resign(material,request)
    _assert_block(_consume(changed,_authenticate(changed),store),'INTENT_DECLARATION_REQUIRED')


@pytest.mark.parametrize('bad',[None,[],{},[RESOURCE,RESOURCE],[3],['*']])
def test_resource_scope_is_bounded_unambiguous_and_opaque(case,bad):
    material,identity,store=case
    request=copy.deepcopy(material['body']);request['resource_scope']=bad;_rehash(request)
    changed=_resign(material,request)
    _assert_block(_consume(changed,_authenticate(changed),store),'INTENT_RESOURCE_SCOPE_INVALID')


def test_missing_declaration_cannot_consume(case):
    material,identity,store=case
    material={**material,'body':{}}
    _assert_block(_consume(material,identity,store),'INTENT_FIELDS_INVALID')


@pytest.mark.parametrize("failure", [
    "non_mapping", "missing_field", "duplicate_keys", "malformed_time", "expired",
    "unverified_identity", "tenant_mismatch", "actor_mismatch", "replay",
    "storage", "unexpected_exception", "invalid_clock",
])
def test_every_early_or_uncertain_block_has_a_decision_timestamp(case, monkeypatch, failure):
    import gateway.intent_governance as consumer
    material, identity, store = case
    request = copy.deepcopy(material["body"])
    comparison_time = CLOCK
    if failure == "non_mapping":request = []
    elif failure == "missing_field":request.pop("intent_id")
    elif failure == "duplicate_keys":request = '{"intent_id":"a","intent_id":"b"}'
    elif failure in ("malformed_time", "expired"):
        request["issued_at" if failure == "malformed_time" else "expires_at"] = (
            "bad-time" if failure == "malformed_time" else NOW)
        _rehash(request)
        material = _resign(material, request);identity = _authenticate(material)
    elif failure == "unverified_identity":identity = identity.as_mapping()
    elif failure in ("tenant_mismatch", "actor_mismatch"):
        # Recomputed hash alone must not replace the authenticated principal.
        request["tenant_id" if failure == "tenant_mismatch" else "actor_id"] = "other"
        _rehash(request)
    elif failure == "replay":assert _consume(material, identity, store)["decision"] == "ALLOW"
    elif failure == "storage":store.path.unlink()
    elif failure == "unexpected_exception":
        def broken_parser(_raw):raise RuntimeError("SENSITIVE_EXCEPTION_CANARY")
        monkeypatch.setattr(consumer, "parse_object", broken_parser)
    elif failure == "invalid_clock":comparison_time = datetime(2026, 10, 16, 12)
    calls = []
    def fixed_utc_clock():
        calls.append(True)
        return CLOCK
    monkeypatch.setattr(consumer, "_utc_now", fixed_utc_clock)
    result = consumer.consume_declared_intent(
        request, authenticated_identity=identity, replay_store=store,
        prior_decision="ALLOW", policy_hash=POLICY, decision_reference=DECISION,
        now=comparison_time,
    )
    _assert_block(result)
    assert result["timestamp"] == NOW
    assert datetime.fromisoformat(result["timestamp"].replace("Z", "+00:00")) == CLOCK
    assert calls == ([True] if failure == "invalid_clock" else [])
    assert "SENSITIVE_EXCEPTION_CANARY" not in json.dumps(result)
    assert result["evidence_hash"] == sha256_reference({k:v for k,v in result.items() if k != "evidence_hash"})


def test_default_decision_clock_is_read_once_for_early_block(case, monkeypatch):
    import gateway.intent_governance as consumer
    material, identity, store = case
    calls = []
    def clock():
        calls.append(True)
        return CLOCK
    monkeypatch.setattr(consumer, "_utc_now", clock)
    result = consumer.consume_declared_intent(
        None, authenticated_identity=identity, replay_store=store,
        prior_decision="ALLOW", policy_hash=POLICY, decision_reference=DECISION,
    )
    _assert_block(result)
    assert result["timestamp"] == NOW
    assert calls == [True]


@pytest.mark.parametrize("operation_matches_declaration", [False, True])
def test_declared_purpose_is_bound_before_replay(case, operation_matches_declaration):
    material, identity, store = case
    request = copy.deepcopy(material["body"])
    request["purpose"] = "customer_scope_canary"
    if operation_matches_declaration:
        request["operation"]["purpose"] = request["purpose"]
    _rehash(request)
    changed = _resign(material, request)
    authenticated = _authenticate(changed)
    # Real authentication succeeds, but grants only the original purpose.
    assert authenticated.purpose == AUTHENTICATED_PURPOSE
    assert request["purpose"] != authenticated.purpose
    assert changed["body"]["intent_hash"] == intent_hash(
        {k:v for k,v in changed["body"].items() if k in FIELDS})
    before = store.path.read_bytes()
    result = _consume(changed, authenticated, store)
    _assert_block(result, "INTENT_IDENTITY_BINDING_MISMATCH")
    assert store.path.read_bytes() == before
    with sqlite3.connect(store.path) as connection:
        assert connection.execute("SELECT count(*) FROM consumed").fetchone() == (0,)
    assert "customer_scope_canary" not in json.dumps(result)
    assert AUTHENTICATED_PURPOSE not in json.dumps(result)
    assert result["timestamp"] == NOW
    # The rejected declaration did not burn these intent_id/nonce values.
    valid = _consume(material, identity, IntentReplayStore(store.path))
    assert valid["decision"] == "ALLOW"
    assert all(valid[flag] is False for flag in FLAGS)
    _assert_block(_consume(material, identity, store), "INTENT_REPLAY")
