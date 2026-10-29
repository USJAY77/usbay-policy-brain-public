"""Synthetic signatures; positive evidence verification is never admission."""
from copy import deepcopy
from dataclasses import FrozenInstanceError, replace
import hashlib
import json

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from security import hydra_operational_contracts as c
from security.hydra_continuity_contracts import canonical

pytestmark = [pytest.mark.governance, pytest.mark.regression]


def encode(value):
    return canonical(value)


def digest(value):
    return hashlib.sha256(encode(value)).hexdigest()


@pytest.fixture
def material():
    private = Ed25519PrivateKey.generate()
    public = private.public_key().public_bytes(serialization.Encoding.PEM,
                                              serialization.PublicFormat.SubjectPublicKeyInfo).decode()
    scope = c.EvidenceScope(**{k: 'sha256:' + hashlib.sha256(k.encode()).hexdigest()
                              for k in c.SCOPE_FIELDS - {'generation', 'authority_epoch'}},
                            generation=3, authority_epoch=7)
    keys = tuple(c.VerificationKey('synthetic-signer', 'ephemeral-key', p, public)
                 for p in (c.ANCHOR_PURPOSE, c.PREFIX_PURPOSE))
    context = c.VerifierContext(scope, c.ANCHOR_PURPOSE, 'c' * 64, 100, keys)
    record = dict(schema=c.PREFIX+'.record', sequence=11, previous='0'*64, event_hash='a'*64)
    record['head'] = digest(record)
    prefix = dict(schema=c.PREFIX, records=[record], commitment=dict(record_count=1, first_sequence=11,
        previous='0'*64, last_head=record['head'], records_hash=digest([record])))
    anchor = dict(schema=c.ANCHOR, observation_id='b'*64, sequence=11, head=record['head'], witness_head='d'*64)

    def packet(payload, purpose=c.ANCHOR_PURPOSE, *, selected_scope=None):
        signed = dict(schema=c.ENVELOPE, purpose=purpose, signer_id='synthetic-signer', key_id='ephemeral-key',
                      scope=(selected_scope or scope).fields(), issued_at=90, expires_at=110,
                      challenge='c'*64, payload=deepcopy(payload))
        return dict(signed=signed, signature=private.sign(encode(signed)).hex())

    def resign(value):
        value['signature'] = private.sign(encode(value['signed'])).hex()
        return encode(value)

    a, p = packet(anchor), packet(prefix, c.PREFIX_PURPOSE)
    verified = [c.verify_evidence(encode(a), context),
                c.verify_evidence(encode(p), replace(context, purpose=c.PREFIX_PURPOSE))]
    plan = dict(schema=c.PLAN, purpose=c.PLAN_PURPOSE, scope=scope.fields(), challenge='c'*64,
                issued_at=90, expires_at=110, state='STOPPED_RECONCILIATION_ONLY', proposed_epoch=8,
                anchor_reference=verified[0].reference, prefix_reference=verified[1].reference,
                expected_sequence=11, expected_head=record['head'])
    return dict(private=private, context=context, anchor=a, prefix=p, packet=packet, resign=resign,
                verified=verified, plan=plan)


def review(m, plan=None, records=None, context=None):
    return c.validate_recovery_plan(encode(m['plan'] if plan is None else plan),
        m['verified'] if records is None else records,
        context or replace(m['context'], purpose=c.PLAN_PURPOSE))


@pytest.mark.parametrize('purpose', [c.ANCHOR_PURPOSE, c.PREFIX_PURPOSE])
def test_valid_real_signature_and_review_only_positive_control(material, purpose):
    m = material
    result = c.verify_evidence(encode(m['anchor' if purpose == c.ANCHOR_PURPOSE else 'prefix']),
                               replace(m['context'], purpose=purpose))
    assert result.status == 'AUTHENTICITY_ONLY' and result.unresolved == c.UNRESOLVED
    assert result.content['purpose'] == purpose
    assert review(m).state == 'STOPPED_RECONCILIATION_ONLY'
    assert review(m).unresolved == c.UNRESOLVED
    assert not any(hasattr(result, attr) for attr in ('allow', 'ready_to_resume', 'authorization'))


@pytest.mark.parametrize('field', sorted(c.SCOPE_FIELDS))
def test_resigned_scope_substitution(material, field):
    m = material; packet = deepcopy(m['anchor'])
    packet['signed']['scope'][field] = 999 if field in ('generation', 'authority_epoch') else 'sha256:'+'f'*64
    with pytest.raises(c.EvidenceInvalid): c.verify_evidence(m['resign'](packet), m['context'])


def test_two_independently_valid_tenant_contexts_cannot_be_exchanged(material):
    m = material
    other = replace(m['context'].scope, tenant_reference='sha256:'+'f'*64)
    alternate = m['packet'](m['anchor']['signed']['payload'], selected_scope=other)
    ctx = replace(m['context'], scope=other)
    assert c.verify_evidence(encode(alternate), ctx).status == 'AUTHENTICITY_ONLY'
    for packet, expected in [(alternate, m['context']), (m['anchor'], ctx)]:
        with pytest.raises(c.EvidenceInvalid): c.verify_evidence(encode(packet), expected)


@pytest.mark.parametrize('field,value', [
    ('schema', c.ENVELOPE.replace('v1', 'v2')), ('purpose', c.PREFIX_PURPOSE),
    ('challenge', 'd'*64), ('signer_id', 'unknown'), ('key_id', 'unknown'),
    ('issued_at', True), ('expires_at', False), ('issued_at', -1),
    ('issued_at', 110), ('expires_at', 90), ('expires_at', 100),
])
def test_resigned_wrong_envelope(material, field, value):
    m = material; packet = deepcopy(m['anchor']); packet['signed'][field] = value
    with pytest.raises(c.EvidenceInvalid): c.verify_evidence(m['resign'](packet), m['context'])


@pytest.mark.parametrize('now,accepted', [(89, False), (90, True), (100, True), (110, False)])
def test_exact_validity_boundaries(material, now, accepted):
    m = material; ctx = replace(m['context'], now=now)
    if accepted: assert c.verify_evidence(encode(m['anchor']), ctx).status == 'AUTHENTICITY_ONLY'
    else:
        with pytest.raises(c.EvidenceInvalid): c.verify_evidence(encode(m['anchor']), ctx)


@pytest.mark.parametrize('where', ['packet', 'signed', 'scope', 'payload'])
@pytest.mark.parametrize('operation', ['missing', 'extra'])
def test_exact_fields(material, where, operation):
    m = material; value = deepcopy(m['anchor'])
    target = value if where == 'packet' else value['signed'] if where == 'signed' else value['signed'][where]
    if operation == 'missing': target.pop(next(iter(target)))
    else: target['sensitive-sentinel'] = 'must-not-escape'
    with pytest.raises(c.EvidenceInvalid): c.verify_evidence(encode(value), m['context'])


@pytest.mark.parametrize('signature', ['00', 'G'*128, 'A'*128, ' '*128, None, True])
def test_malformed_signatures(material, signature):
    m = material; packet = deepcopy(m['anchor']); packet['signature'] = signature
    with pytest.raises(c.EvidenceInvalid): c.verify_evidence(encode(packet), m['context'])


def test_tamper_and_unknown_verification_key(material):
    m = material; packet = deepcopy(m['anchor']); packet['signed']['payload']['head'] = 'f'*64
    with pytest.raises(c.EvidenceInvalid): c.verify_evidence(encode(packet), m['context'])
    public = Ed25519PrivateKey.generate().public_key().public_bytes(serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo).decode()
    ctx = replace(m['context'], keys=(replace(m['context'].keys[0], public_key_pem=public),))
    with pytest.raises(c.EvidenceInvalid): c.verify_evidence(encode(m['anchor']), ctx)


@pytest.mark.parametrize('raw', [b'{"signed":{},"signed":{}}', b'{"x":{"a":1,"a":2}}',
    b'{"n":NaN}', b'{"n":Infinity}', b'{"n":1e9999}', b'{"n":9007199254740992}',
    b'\xff', b'{} trailing', b'['*13+b'0'+b']'*13, b' '* (c.MAX_BYTES+1),
    b'{"x":['+b'0,'*256+b'0]}', b'{"x":"'+b'x'*4097+b'"}', b''])
def test_bounded_strict_decode(material, raw):
    with pytest.raises(c.EvidenceInvalid): c.verify_evidence(raw, material['context'])


@pytest.mark.parametrize('value', [True, -1, 2**53, float('inf'), float('nan')])
def test_invalid_verifier_time(material, value):
    with pytest.raises(c.EvidenceInvalid):
        c.verify_evidence(encode(material['anchor']), replace(material['context'], now=value))


def test_verifier_trust_not_selected_from_packet(material):
    m = material; packet = deepcopy(m['anchor']); packet['public_key'] = m['context'].keys[0].public_key_pem
    with pytest.raises(c.EvidenceInvalid): c.verify_evidence(encode(packet), m['context'])
    with pytest.raises(c.EvidenceInvalid): c.verify_evidence(encode(m['anchor']), replace(m['context'], keys=()))


@pytest.mark.parametrize('field,value', [('generation', True), ('authority_epoch', True), ('policy_hash', 'bad')])
def test_invalid_trusted_scope(material, field, value):
    m = material
    with pytest.raises(c.EvidenceInvalid):
        c.verify_evidence(encode(m['anchor']), replace(m['context'], scope=replace(m['context'].scope, **{field:value})))


@pytest.mark.parametrize('field', ['record_count', 'first_sequence', 'previous', 'last_head', 'records_hash'])
def test_preservation_commitment_mismatch(material, field):
    m = material; packet = deepcopy(m['prefix']); val = packet['signed']['payload']['commitment'][field]
    packet['signed']['payload']['commitment'][field] = val+1 if type(val) is int else 'e'*64
    with pytest.raises(c.EvidenceInvalid):
        c.verify_evidence(m['resign'](packet), replace(m['context'], purpose=c.PREFIX_PURPOSE))


@pytest.mark.parametrize('field,value', [('sequence', True), ('previous', 'e'*64), ('event_hash', 'e'*64),
                                        ('head', 'bad'), ('schema', c.PREFIX)])
def test_preservation_record_mismatch_even_with_updated_list_hash(material, field, value):
    m = material; packet = deepcopy(m['prefix']); payload = packet['signed']['payload']
    payload['records'][0][field] = value
    payload['commitment']['records_hash'] = digest(payload['records'])
    with pytest.raises(c.EvidenceInvalid):
        c.verify_evidence(m['resign'](packet), replace(m['context'], purpose=c.PREFIX_PURPOSE))


@pytest.mark.parametrize('field,value', [('proposed_epoch',7), ('proposed_epoch',True), ('expected_sequence',12),
    ('anchor_reference','f'*64), ('prefix_reference','f'*64), ('expected_head','f'*64),
    ('state','READY_TO_RESUME'), ('purpose',c.ANCHOR_PURPOSE), ('expires_at',100), ('challenge','f'*64)])
def test_review_plan_mismatch_and_no_readiness(material, field, value):
    plan = deepcopy(material['plan']); plan[field] = value
    with pytest.raises(c.EvidenceInvalid): review(material, plan)


def test_review_scope_references_and_untrusted_wrappers(material):
    m = material
    for records in [m['verified'][:1], m['verified']*2, [m['verified'][0]]*2]:
        with pytest.raises(c.EvidenceInvalid): review(m, records=records)
    forged = replace(m['verified'][0], packet=encode(m['prefix']))
    with pytest.raises(c.EvidenceInvalid): review(m, records=[forged, m['verified'][1]])
    plan = deepcopy(m['plan']); plan['scope']['tenant_reference'] = 'sha256:'+'f'*64
    with pytest.raises(c.EvidenceInvalid): review(m, plan)
    plan = deepcopy(m['plan']); plan['currentness_verified'] = True
    with pytest.raises(c.EvidenceInvalid): review(m, plan)


def test_deeply_immutable_detached_results(material):
    m = material; mutable = deepcopy(m['anchor']); raw = encode(mutable)
    evidence = c.verify_evidence(raw, m['context']); result = review(m)
    mutable['signed']['scope']['generation'] = 999; m['plan']['proposed_epoch'] = 999
    assert evidence.content['scope']['generation'] == 3 and result.content['proposed_epoch'] == 8
    prefix = m['verified'][1]
    for target, key in [(evidence.content,'scope'), (evidence.content['scope'],'generation'),
                        (prefix.content['payload']['records'][0],'head'), (result.content,'state')]:
        with pytest.raises(TypeError): target[key] = 'mutated'
    with pytest.raises(TypeError): prefix.content['payload']['records'][0] = {}
    with pytest.raises(FrozenInstanceError): result.state = 'READY_TO_RESUME'
    with pytest.raises(FrozenInstanceError): evidence.reference = 'f'*64


def test_identifiers_are_exact_not_normalized(material):
    m = material
    packet = deepcopy(m['anchor']); packet['signed']['signer_id'] = 'node1'
    ctx = replace(m['context'], keys=(replace(m['context'].keys[0], signer_id='node-1'),))
    with pytest.raises(c.EvidenceInvalid): c.verify_evidence(m['resign'](packet), ctx)


def test_invalid_errors_and_logs_do_not_disclose_packet_or_key(material, caplog):
    sentinel = 'PRIVATE KEY sensitive-sentinel'
    with pytest.raises(c.EvidenceInvalid) as error:
        c.verify_evidence(json.dumps({'secret':sentinel}), material['context'])
    assert str(error.value) == 'HYDRA_OPERATIONAL_EVIDENCE_INVALID'
    assert sentinel not in str(error.value) and caplog.text == ''


def duplicate_member_json(control, object_path, member):
    """Emit a duplicate at one exact object path; never round-trip target bytes."""
    inserted = 0

    def emit(value, path):
        nonlocal inserted
        if type(value) is dict:
            pieces = []
            for key in sorted(value):
                piece = encode(key) + b':' + emit(value[key], path + (key,))
                pieces.append(piece)
                if path == object_path and key == member:
                    pieces.append(piece)  # Same raw member: first/last wins agree.
                    inserted += 1
            return b'{' + b','.join(pieces) + b'}'
        if type(value) is list:
            return b'[' + b','.join(emit(item, path + (index,))
                                   for index, item in enumerate(value)) + b']'
        return encode(value)

    raw = emit(control, ())
    assert inserted == 1
    return raw


@pytest.mark.parametrize('kind,path,member', [
    pytest.param('anchor', (), 'signature', id='envelope'),
    pytest.param('anchor', ('signed',), 'purpose', id='signed-content'),
    pytest.param('anchor', ('signed', 'scope'), 'tenant_reference', id='signed-scope'),
    pytest.param('anchor', ('signed', 'payload'), 'head', id='anchor-payload'),
    pytest.param('prefix', ('signed', 'payload'), 'schema', id='prefix-payload'),
    pytest.param('prefix', ('signed', 'payload', 'commitment'), 'records_hash', id='prefix-commitment'),
    pytest.param('prefix', ('signed', 'payload', 'records', 0), 'event_hash', id='prefix-record'),
    pytest.param('plan', (), 'proposed_epoch', id='review-plan'),
    pytest.param('plan', ('scope',), 'tenant_reference', id='review-plan-scope'),
])
def test_duplicate_members_in_otherwise_valid_controls(material, kind, path, member):
    m = material
    control = m[kind]
    purpose = {'anchor': c.ANCHOR_PURPOSE, 'prefix': c.PREFIX_PURPOSE,
               'plan': c.PLAN_PURPOSE}[kind]
    context = replace(m['context'], purpose=purpose)

    def verify(raw):
        if kind == 'plan':
            return c.validate_recovery_plan(raw, m['verified'], context)
        return c.verify_evidence(raw, context)

    accepted = verify(encode(control))  # Real signature verification, no stub.
    assert accepted.reference == digest(control)
    raw = duplicate_member_json(control, path, member)
    assert len(raw) <= c.MAX_BYTES

    def container_depth(value):
        if type(value) is dict:
            return 1 + max((container_depth(v) for v in value.values()), default=0)
        if type(value) is list:
            return 1 + max((container_depth(v) for v in value), default=0)
        return 0

    # Duplicate members add no nesting; the otherwise-valid control and raw
    # duplicate form have identical maximum container depth.
    assert container_depth(control) <= c.MAX_DEPTH

    def first_wins(items):
        decoded = {}
        for key, value in items:
            decoded.setdefault(key, value)
        return decoded

    # Both permissive interpretations retain every required field and exactly
    # the accepted logical content. Duplication cannot invalidate the signature.
    for decoded in (json.loads(raw), json.loads(raw, object_pairs_hook=first_wins)):
        assert decoded == control
        if kind != 'plan':
            m['private'].public_key().verify(bytes.fromhex(decoded['signature']),
                                            encode(decoded['signed']))
    assert 90 <= context.now < 110
    with pytest.raises(c.EvidenceInvalid) as rejected:
        verify(raw)  # Submit duplicate-bearing bytes, not permissively decoded data.
    # No production error API is added: inspect the retained exception chain to
    # distinguish duplicate-hook rejection from schema/signature/time failures.
    origin = rejected.value.__context__
    assert isinstance(origin, c.EvidenceInvalid)
    trace = origin.__traceback__
    frames = []
    while trace is not None:
        frames.append((trace.tb_frame.f_code.co_filename, trace.tb_frame.f_code.co_name))
        trace = trace.tb_next
    assert (c.__file__, 'pairs') in frames
