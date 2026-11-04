"""Synthetic producer only; real files, interpreter and dependency observations."""
from copy import deepcopy
from dataclasses import replace, FrozenInstanceError
from datetime import datetime, timezone
import base64
import hashlib
import json
from pathlib import Path
from types import SimpleNamespace

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from security import runtime_validation_evidence as binding
from security.runtime_artifact_provenance import (
    ProducerTrust, RuntimeArtifactError, MANIFEST_SCHEMA, PRODUCER_CONTRACT,
    canonical_bytes, public_key_id, manifest_digest, signature_payload,
)


pytestmark = pytest.mark.governance


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


@pytest.fixture
def artifact(tmp_path):
    root = tmp_path / "artifact"
    root.mkdir()
    private = Ed25519PrivateKey.generate()
    public = private.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    trust = ProducerTrust(public, public_key_id(public), "test", "test")
    patch = b"synthetic patch bytes; not a claim of applied Git patch\n"
    observed = binding._dependency_observation()
    repo = Path(__file__).resolve().parents[1]
    locks = [repo/'requirements-ci.txt', repo/'staging/requirements-python311.lock']
    lock = next(p.read_bytes() for p in locks if binding._locked_versions(p.read_bytes()) == observed)
    expected = binding.CandidateBinding("a"*40, "b"*40, "c"*40, "d"*40, sha(patch))
    data = {
        "schema_version": binding.SCHEMA, "candidate": vars(expected).copy(),
        "patch_path": "candidate.patch", "lock_path": "requirements.lock",
        "lock_sha256": sha(lock), "python": binding._python_observation(),
        "distributions": observed, "image_digest": None,
    }
    (root/'candidate.patch').write_bytes(patch)
    (root/'requirements.lock').write_bytes(lock)
    (root/'main.py').write_bytes(b"# synthetic source file\n")
    state = SimpleNamespace(root=root, private=private, trust=trust, expected=expected, data=data)

    def sign(*, raw_evidence=None, omit=(), manifest_change=None):
        (root/binding.EVIDENCE_NAME).write_bytes(
            canonical_bytes(state.data) if raw_evidence is None else raw_evidence)
        entries = []
        for p in sorted(root.iterdir()):
            if p.name == 'runtime_source_manifest.json' or p.name in omit:
                continue
            if p.is_symlink():
                continue
            raw = p.read_bytes()
            entries.append(dict(path=p.name,mode='100644',sha256=sha(raw),size=len(raw)))
        manifest = dict(schema_version=MANIFEST_SCHEMA, producer_contract=PRODUCER_CONTRACT,
                        producer_key_id=trust.key_id, producer_scope='test',
                        source_commit='a'*40, source_tree_reference='b'*40,
                        managed_files=entries, managed_set_hash=sha(canonical_bytes(entries)),
                        build_reference=None, created_at=datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ'),
                        manifest_id='e'*32)
        if manifest_change:
            manifest_change(manifest)
        manifest['manifest_digest']=manifest_digest(manifest)
        manifest['signature']=base64.b64encode(private.sign(signature_payload(manifest))).decode('ascii')
        (root/'runtime_source_manifest.json').write_bytes(canonical_bytes(manifest))
        state.manifest=manifest
    state.sign=sign
    sign()
    return state


def verify(f):
    return binding.verify_runtime_validation_evidence(f.root,trust=f.trust,expected=f.expected)


def test_signed_companion_matches_real_runtime_but_never_authorizes(artifact):
    f=artifact
    before={p.name:p.read_bytes() for p in f.root.iterdir()}
    result=verify(f)
    assert result.status=='EVIDENCE_VERIFIED_PARTIAL'
    assert result.patch_sha256==f.expected.patch_sha256
    assert result.execution_authorized is False
    assert result.runtime_equivalence_proven is False
    assert result.image_identity_verified is False
    assert result.patch_application_verified is False
    assert {p.name:p.read_bytes() for p in f.root.iterdir()}==before
    with pytest.raises(FrozenInstanceError):result.status='ALLOW'
    with pytest.raises(TypeError):binding.RuntimeValidationEvidence(*(['x']*6),execution_authorized=True)


def test_signed_image_claim_does_not_prove_image_identity(artifact):
    artifact.data['image_digest']='sha256:'+'1'*64
    artifact.sign()
    result=verify(artifact)
    assert result.image_identity_verified is False
    assert result.runtime_equivalence_proven is False


@pytest.mark.parametrize('name',['source_commit','source_tree','base_commit','base_tree','patch_sha256'])
def test_other_candidate_denied(artifact,name):
    old=getattr(artifact.expected,name)
    artifact.expected=replace(artifact.expected,**{name:'f'*len(old)})
    with pytest.raises(RuntimeArtifactError):verify(artifact)


@pytest.mark.parametrize('name',['source_commit','source_tree','base_commit','base_tree','patch_sha256'])
@pytest.mark.parametrize('bad',[None,True,'*','ABC','../other'])
def test_missing_or_ambiguous_candidate_denied(artifact,name,bad):
    artifact.expected=replace(artifact.expected,**{name:bad})
    with pytest.raises(RuntimeArtifactError):verify(artifact)


@pytest.mark.parametrize('kind',['unknown_key','production','test_key_in_production','missing_trust','bad_signature'])
def test_missing_or_substituted_producer_trust_denied(artifact,kind):
    if kind=='unknown_key':
        raw=Ed25519PrivateKey.generate().public_key().public_bytes(serialization.Encoding.Raw,serialization.PublicFormat.Raw)
        artifact.trust=ProducerTrust(raw,public_key_id(raw),'test','test')
    elif kind=='production':artifact.trust=replace(artifact.trust,mode='production',producer_scope='production')
    elif kind=='test_key_in_production':artifact.trust=replace(artifact.trust,mode='production')
    elif kind=='missing_trust':artifact.trust=None
    else:
        artifact.manifest['signature']=base64.b64encode(bytes(64)).decode('ascii')
        (artifact.root/'runtime_source_manifest.json').write_bytes(canonical_bytes(artifact.manifest))
    with pytest.raises(RuntimeArtifactError):verify(artifact)


@pytest.mark.parametrize('field',['schema_version','candidate','patch_path','lock_path','lock_sha256','python','distributions','image_digest'])
def test_required_companion_fields_cannot_be_omitted(artifact,field):
    del artifact.data[field]
    artifact.sign()
    with pytest.raises(RuntimeArtifactError):verify(artifact)


@pytest.mark.parametrize('kind',['extra_field','python_version','python_binary','dependency_version','dependency_extra',
                                  'lock_hash','patch_hash','path_traversal','path_alias','image_format'])
def test_signed_but_inconsistent_evidence_denied(artifact,kind):
    f=artifact
    if kind=='extra_field':f.data['allow_execution']=True
    elif kind=='python_version':f.data['python']['version']='3.12.0'
    elif kind=='python_binary':f.data['python']['executable_sha256']='0'*64
    elif kind=='dependency_version':f.data['distributions']['pytest']='0.0.0'
    elif kind=='dependency_extra':f.data['distributions']['unobserved-package']='1.0'
    elif kind=='lock_hash':f.data['lock_sha256']='0'*64
    elif kind=='patch_hash':(f.root/'candidate.patch').write_bytes(b'other signed bytes')
    elif kind=='path_traversal':f.data['patch_path']='../candidate.patch'
    elif kind=='path_alias':f.data['lock_path']=f.data['patch_path']
    elif kind=='image_format':f.data['image_digest']='latest'
    f.sign()
    with pytest.raises(RuntimeArtifactError):verify(f)


@pytest.mark.parametrize('kind',['duplicate_field','nan','infinite_overflow','truncated','list'])
def test_malformed_companion_rejected_after_valid_signature(artifact,kind):
    raw=canonical_bytes(artifact.data)
    if kind=='duplicate_field':raw=raw[:-1]+b',"schema_version":"duplicate"}'
    elif kind=='nan':raw=raw[:-1]+b',"image_digest":NaN}'
    elif kind=='infinite_overflow':raw=raw.replace(b'"image_digest":null',b'"image_digest":1e999')
    elif kind=='truncated':raw=raw[:-1]
    else:raw=b'[]'
    artifact.sign(raw_evidence=raw)
    with pytest.raises(RuntimeArtifactError):verify(artifact)


@pytest.mark.parametrize('path',['candidate.patch','requirements.lock',binding.EVIDENCE_NAME,'main.py'])
def test_post_signature_tampering_fails_closed(artifact,path):
    (artifact.root/path).write_bytes(b'tampered\n')
    with pytest.raises(RuntimeArtifactError):verify(artifact)


def test_unmanaged_companion_never_counts_as_signed_evidence(artifact):
    artifact.sign(omit=[binding.EVIDENCE_NAME])
    with pytest.raises(RuntimeArtifactError):verify(artifact)


def test_symlinked_evidence_is_not_followed(artifact,tmp_path):
    path=artifact.root/binding.EVIDENCE_NAME
    target=tmp_path/'other-data';target.write_bytes(path.read_bytes())
    path.unlink();path.symlink_to(target)
    with pytest.raises(RuntimeArtifactError):verify(artifact)


def test_change_during_runtime_observation_is_rejected(artifact,monkeypatch):
    original=binding._dependency_observation
    def change():
        result=original()
        (artifact.root/'main.py').write_bytes(b'changed after initial verification\n')
        return result
    monkeypatch.setattr(binding,'_dependency_observation',change)
    with pytest.raises(RuntimeArtifactError):verify(artifact)


@pytest.mark.parametrize('raw',[b'pytest>=1\n',b'-r other.lock\n',b'pytest==9.1.1\n',
    b'--index-url https://example.invalid\n',b'pytest==9.1.1; python_version > "3"\n',
    b'pytest==9.1.1 \\\n--hash=sha256:'+b'0'*64+b'\nPyTest==9.1.1 \\\n--hash=sha256:'+b'0'*64+b'\n'])
def test_unpinned_or_ambiguous_lock_rejected(raw):
    with pytest.raises(RuntimeArtifactError):binding._locked_versions(raw)
