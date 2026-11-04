"""Detached proposal contract: synthetic producer; no live signing or activation."""
from copy import deepcopy
from dataclasses import replace
from datetime import datetime, timezone
import base64
import hashlib
from types import SimpleNamespace

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from security import runtime_evidence_supplement as supplement
from security.runtime_artifact_provenance import (
    ProducerTrust, RuntimeArtifactError, canonical_bytes, public_key_id,
    manifest_digest, signature_payload, MANIFEST_SCHEMA, PRODUCER_CONTRACT,
)

pytestmark=pytest.mark.governance


@pytest.fixture
def bundle(tmp_path):
    root=tmp_path/'source';root.mkdir()
    source=b'# synthetic source only\n';(root/'main.py').write_bytes(source)
    private=Ed25519PrivateKey.generate()
    public=private.public_key().public_bytes(serialization.Encoding.Raw,serialization.PublicFormat.Raw)
    trust=ProducerTrust(public,public_key_id(public),'test','test')
    entries=[dict(path='main.py',mode='100644',sha256=hashlib.sha256(source).hexdigest(),size=len(source))]
    manifest=dict(schema_version=MANIFEST_SCHEMA,producer_contract=PRODUCER_CONTRACT,
        producer_key_id=trust.key_id,producer_scope='test',source_commit='a'*40,
        source_tree_reference='b'*40,managed_files=entries,
        managed_set_hash=hashlib.sha256(canonical_bytes(entries)).hexdigest(),build_reference=None,
        created_at=datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ'),manifest_id='c'*32)
    manifest['manifest_digest']=manifest_digest(manifest)
    manifest['signature']=base64.b64encode(private.sign(signature_payload(manifest))).decode('ascii')
    (root/'runtime_source_manifest.json').write_bytes(canonical_bytes(manifest))
    data=dict(schema_version=supplement.SCHEMA,purpose=supplement.PURPOSE,
        producer_key_id=trust.key_id,producer_scope='test',source_artifact_digest=manifest['manifest_digest'],
        source_commit='a'*40,source_tree_reference='b'*40,
        evidence_references={name:('1'*64 if name!='image_claim' else None)
                             for name in supplement.REFERENCE_FIELDS})
    f=SimpleNamespace(root=root,private=private,trust=trust,manifest=manifest,data=data)
    def signed(data=None):
        value=deepcopy(f.data if data is None else data)
        value['manifest_digest']=manifest_digest(value)
        value['signature']=base64.b64encode(f.private.sign(signature_payload(value))).decode('ascii')
        return canonical_bytes(value)
    f.signed=signed
    return f


def verify(f,raw=None,**changes):
    return supplement.verify_evidence_supplement(f.signed() if raw is None else raw,f.root,
        trust=f.trust,expected_source_commit=changes.get('commit','a'*40),
        expected_source_tree=changes.get('tree','b'*40))


def test_detached_claim_authenticity_never_grants_authority_or_truth(bundle):
    f=bundle
    before={p.name:p.read_bytes() for p in f.root.iterdir()}
    result=verify(f)
    assert result.source_artifact_digest==f.manifest['manifest_digest']
    assert result.status=='AUTHENTICATED_CLAIM_ONLY'
    assert result.contract_status=='PROPOSAL_REVIEW_REQUIRED'
    assert result.execution_authorized is False
    assert result.evidence_truth_verified is False
    assert result.freshness_verified is False
    assert result.image_identity_verified is False
    assert result.runtime_equivalence_proven is False
    assert {p.name:p.read_bytes() for p in f.root.iterdir()}==before
    assert set(before)=={'main.py','runtime_source_manifest.json'}
    with pytest.raises(TypeError):supplement.AuthenticatedEvidenceSupplement(*(['x']*5),execution_authorized=True)


def test_image_claim_and_replayed_signature_are_not_freshness_or_image_proof(bundle):
    bundle.data['evidence_references']['image_claim']='2'*64
    raw=bundle.signed()
    first=verify(bundle,raw);second=verify(bundle,raw)
    assert first==second
    assert first.image_identity_verified is False and second.freshness_verified is False
    assert second.execution_authorized is False


@pytest.mark.parametrize('name',sorted(supplement.FIELDS-{'manifest_digest','signature'}))
def test_required_fields_missing_are_rejected(bundle,name):
    del bundle.data[name]
    with pytest.raises(RuntimeArtifactError):verify(bundle)


@pytest.mark.parametrize('kind',['schema','purpose','extra_field','producer','scope','source_commit','source_tree','artifact','reference'])
def test_signed_inconsistent_contract_is_rejected(bundle,kind):
    f=bundle
    if kind=='schema':f.data['schema_version']='usbay.runtime_source_manifest.v1'
    if kind=='purpose':f.data['purpose']='execute'
    if kind=='extra_field':f.data['execution_authorized']=True
    if kind=='producer':f.data['producer_key_id']='sha256:'+'f'*64
    if kind=='scope':f.data['producer_scope']='production'
    if kind=='source_commit':f.data['source_commit']='d'*40
    if kind=='source_tree':f.data['source_tree_reference']='d'*40
    if kind=='artifact':f.data['source_artifact_digest']='d'*64
    if kind=='reference':f.data['evidence_references']['python']='*'
    with pytest.raises(RuntimeArtifactError):verify(f)


@pytest.mark.parametrize('name',sorted(supplement.REFERENCE_FIELDS))
def test_all_reference_names_are_required(bundle,name):
    del bundle.data['evidence_references'][name]
    with pytest.raises(RuntimeArtifactError):verify(bundle)


@pytest.mark.parametrize('kind',['missing','other_key','production','test_in_production'])
def test_independent_trust_is_required_and_production_is_rejected(bundle,kind):
    if kind=='missing':bundle.trust=None
    if kind=='other_key':
        raw=Ed25519PrivateKey.generate().public_key().public_bytes(serialization.Encoding.Raw,serialization.PublicFormat.Raw)
        bundle.trust=ProducerTrust(raw,public_key_id(raw),'test','test')
    if kind=='production':bundle.trust=replace(bundle.trust,mode='production',producer_scope='production')
    if kind=='test_in_production':bundle.trust=replace(bundle.trust,mode='production')
    with pytest.raises(RuntimeArtifactError):verify(bundle)


@pytest.mark.parametrize('kind',['signature','digest','malformed','duplicate','non_finite','overflow','empty','oversize'])
def test_invalid_envelopes_fail_closed(bundle,kind):
    import json
    raw=bundle.signed()
    if kind in {'signature','digest'}:
        data=json.loads(raw)
        if kind=='signature':data['signature']=base64.b64encode(bytes(64)).decode('ascii')
        else:
            data['manifest_digest']='0'*64
            data['signature']=base64.b64encode(bundle.private.sign(signature_payload(data))).decode('ascii')
        raw=canonical_bytes(data)
    if kind=='malformed':raw=raw[:-1]
    if kind=='duplicate':raw=raw[:-1]+b',"purpose":"duplicate"}'
    if kind=='non_finite':raw=raw[:-1]+b',"x":NaN}'
    if kind=='overflow':raw=raw[:-1]+b',"x":1e999}'
    if kind=='empty':raw=b''
    if kind=='oversize':raw=b'x'*(supplement.MAX_BYTES+1)
    with pytest.raises(RuntimeArtifactError):verify(bundle,raw)


@pytest.mark.parametrize('field',['commit','tree'])
@pytest.mark.parametrize('value',[None,True,'*','../source','f'*40])
def test_expected_source_pins_are_mandatory(bundle,field,value):
    with pytest.raises(RuntimeArtifactError):verify(bundle,**{field:value})


def test_source_content_tamper_invalidates_supplement_acceptance(bundle):
    raw=bundle.signed();(bundle.root/'main.py').write_bytes(b'tampered')
    with pytest.raises(RuntimeArtifactError):verify(bundle,raw)


def test_missing_source_manifest_does_not_accept_signed_supplement_alone(bundle):
    raw=bundle.signed();(bundle.root/'runtime_source_manifest.json').unlink()
    with pytest.raises(RuntimeArtifactError):verify(bundle,raw)
