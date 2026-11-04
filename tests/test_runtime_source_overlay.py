"""Real temporary Git objects/index, signed ephemeral artifacts, no project commit."""
from copy import deepcopy
from dataclasses import replace
import hashlib
import os
from pathlib import Path
import subprocess

import pytest

from security import runtime_validation_evidence as binding
from security import runtime_source_overlay as source
from security.runtime_artifact_provenance import RuntimeArtifactError
from tests.test_runtime_validation_evidence import artifact

pytestmark = pytest.mark.governance


def git(repo, *args, data=None):
    # Fixture construction only; no branch/ref or Git commit command is used.
    return subprocess.check_output(['/usr/bin/git','-C',str(repo),*args],input=data,
                                   stderr=subprocess.DEVNULL,env=source._environment())


def tree(repo, files):
    entries=[]
    for path,(mode,raw) in sorted(files.items()):
        oid=git(repo,'hash-object','-w','--stdin',data=raw).strip()
        entries.append(mode.encode()+b' blob '+oid+b'\t'+path.encode()+b'\n')
    return git(repo,'mktree',data=b''.join(entries)).decode().strip()


def all_files(root):
    return {p.relative_to(root).as_posix():p.read_bytes() for p in root.rglob('*') if p.is_file()}


@pytest.fixture
def overlay(artifact,tmp_path):
    f=artifact
    repo=tmp_path/'reference.git';repo.mkdir()
    git(repo,'init','--bare','--quiet','--template=')
    old=tree(repo,{'main.py':('100644',b'before\n')})
    # Content-addressed synthetic commit object; no real project history/ref is changed.
    raw=(f'tree {old}\nauthor Synthetic <test@example.invalid> 0 +0000\n'
         'committer Synthetic <test@example.invalid> 0 +0000\n\nsynthetic baseline\n').encode()
    commit=git(repo,'hash-object','-w','-t','commit','--stdin',data=raw).decode().strip()
    after=tree(repo,{'main.py':('100644',b'after\n')})
    patch=b'diff --git a/main.py b/main.py\n--- a/main.py\n+++ b/main.py\n@@ -1 +1 @@\n-before\n+after\n'
    f.expected=binding.CandidateBinding(commit,after,commit,old,hashlib.sha256(patch).hexdigest())
    f.data['candidate']=vars(f.expected).copy()
    (f.root/'candidate.patch').write_bytes(patch)
    (f.root/'main.py').write_bytes(b'after\n')
    original_sign=f.sign
    def sign(**kwargs):
        change=kwargs.pop('manifest_change',None)
        def manifest_change(m):
            m.update(source_commit=f.expected.source_commit,source_tree_reference=f.expected.source_tree)
            if change:change(m)
        original_sign(manifest_change=manifest_change,**kwargs)
    f.sign=sign
    sign()
    f.reference=repo
    return f


def verify(f):
    return binding.verify_runtime_validation_evidence(f.root,trust=f.trust,
        expected=f.expected,reference_repository=f.reference)


def test_source_reconstruction_verified_without_mutating_reference(overlay):
    f=overlay
    reference_before=all_files(f.reference)
    artifact_before=all_files(f.root)
    result=verify(f)
    assert result.patch_application_verified is True
    assert result.runtime_equivalence_proven is False
    assert result.image_identity_verified is False
    assert result.execution_authorized is False
    assert result.status=='EVIDENCE_VERIFIED_PARTIAL'
    assert all_files(f.reference)==reference_before
    assert all_files(f.root)==artifact_before
    assert not (f.reference/'index').exists()
    assert not [p for p in (f.reference/'refs').rglob('*') if p.is_file()]


@pytest.mark.parametrize('kind',['base_commit','base_tree','result_tree','source_commit'])
def test_signed_but_wrong_source_identity_is_rejected(overlay,kind):
    f=overlay
    if kind=='base_commit':f.expected=replace(f.expected,base_commit='f'*40,source_commit='f'*40)
    if kind=='base_tree':f.expected=replace(f.expected,base_tree='f'*40)
    if kind=='result_tree':f.expected=replace(f.expected,source_tree='f'*40)
    if kind=='source_commit':f.expected=replace(f.expected,source_commit='f'*40)
    f.data['candidate']=vars(f.expected).copy();f.sign()
    with pytest.raises(RuntimeArtifactError):verify(f)


@pytest.mark.parametrize('kind',['content','extra_source','missing_source','wrong_mode'])
def test_signed_inventory_must_exactly_match_reconstructed_tree(overlay,kind):
    f=overlay
    if kind=='content':(f.root/'main.py').write_bytes(b'unapplied source\n')
    if kind=='extra_source':(f.root/'extra.py').write_bytes(b'unreviewed\n')
    if kind=='missing_source':(f.root/'main.py').unlink()
    if kind=='wrong_mode':
        (f.root/'main.py').chmod(0o755)
        def change(m):
            for e in m['managed_files']:
                if e['path']=='main.py':e['mode']='100755'
            from security.runtime_artifact_provenance import canonical_bytes
            m['managed_set_hash']=hashlib.sha256(canonical_bytes(m['managed_files'])).hexdigest()
        f.sign(manifest_change=change)
    else:f.sign()
    with pytest.raises(RuntimeArtifactError):verify(f)


@pytest.mark.parametrize('raw',[b'not a patch',b'--- a/main.py\n+++ b/main.py\n@@ -1 +1 @@\n-wrong base\n+after\n',
                               b'diff --git a/../escape b/../escape\n--- /dev/null\n+++ b/../escape\n@@ -0,0 +1 @@\n+bad\n'])
def test_invalid_or_nonapplicable_signed_patch_does_not_fall_back(overlay,raw):
    f=overlay
    (f.root/'candidate.patch').write_bytes(raw)
    f.expected=replace(f.expected,patch_sha256=hashlib.sha256(raw).hexdigest())
    f.data['candidate']=vars(f.expected).copy();f.sign()
    with pytest.raises(RuntimeArtifactError):verify(f)
    assert not (f.root.parent/'escape').exists()


def test_missing_git_fails_closed(overlay,monkeypatch):
    monkeypatch.setattr(source.shutil,'which',lambda *a,**k:None)
    with pytest.raises(RuntimeArtifactError,match='runtime_overlay_git_unavailable'):verify(overlay)


def test_git_timeout_fails_closed(overlay,monkeypatch):
    def timeout(*a,**k):raise subprocess.TimeoutExpired('git',30)
    monkeypatch.setattr(source.subprocess,'run',timeout)
    with pytest.raises(RuntimeArtifactError,match='runtime_overlay_git_unavailable'):verify(overlay)


def test_inherited_git_overrides_are_not_used(overlay,monkeypatch,tmp_path):
    before=all_files(overlay.reference)
    wrong=tmp_path/'must-not-write';wrong.mkdir()
    monkeypatch.setenv('GIT_INDEX_FILE',str(wrong/'index'))
    monkeypatch.setenv('GIT_OBJECT_DIRECTORY',str(wrong/'objects'))
    monkeypatch.setenv('GIT_DIR',str(wrong))
    monkeypatch.setenv('GIT_CONFIG_COUNT','1')
    monkeypatch.setenv('GIT_CONFIG_KEY_0','core.hooksPath')
    monkeypatch.setenv('GIT_CONFIG_VALUE_0',str(wrong))
    assert verify(overlay).patch_application_verified is True
    assert not list(wrong.iterdir()) and all_files(overlay.reference)==before


def test_reference_hooks_and_filters_are_not_executed(overlay,tmp_path):
    marker=tmp_path/'MUST_NOT_EXIST'
    hook=overlay.reference/'hooks'/'post-index-change'
    hook.parent.mkdir(exist_ok=True)
    hook.write_text('#!/bin/sh\ntouch '+str(marker)+'\n');hook.chmod(0o755)
    # Local reference configuration is never used for the isolated apply.
    git(overlay.reference,'config','filter.evil.clean','touch '+str(marker))
    before=all_files(overlay.reference)
    assert verify(overlay).patch_application_verified is True
    assert not marker.exists() and all_files(overlay.reference)==before


def test_reference_symlink_is_rejected(overlay,tmp_path):
    alias=tmp_path/'alias';alias.symlink_to(overlay.reference,target_is_directory=True)
    overlay.reference=alias
    with pytest.raises(RuntimeArtifactError,match='runtime_overlay_reference_invalid'):verify(overlay)


def test_temporary_index_and_objects_are_removed(overlay,monkeypatch):
    seen=[]
    original=source.tempfile.TemporaryDirectory
    def capture(*a,**k):
        obj=original(*a,**k);seen.append(Path(obj.name));return obj
    monkeypatch.setattr(source.tempfile,'TemporaryDirectory',capture)
    assert verify(overlay).patch_application_verified
    assert seen and all(not p.exists() for p in seen)


def test_temporary_storage_is_removed_after_rejection(overlay,monkeypatch):
    seen=[];original=source.tempfile.TemporaryDirectory
    def capture(*a,**k):
        obj=original(*a,**k);seen.append(Path(obj.name));return obj
    monkeypatch.setattr(source.tempfile,'TemporaryDirectory',capture)
    overlay.expected=replace(overlay.expected,source_tree='f'*40)
    overlay.data['candidate']=vars(overlay.expected).copy();overlay.sign()
    with pytest.raises(RuntimeArtifactError):verify(overlay)
    assert seen and all(not p.exists() for p in seen)


def test_corrupted_reference_blob_cannot_change_patch_base(overlay):
    import zlib
    f=overlay
    old_oid=git(f.reference,'ls-tree',f.expected.base_tree).split()[2].decode()
    path=f.reference/'objects'/old_oid[:2]/old_oid[2:]
    raw=b'shadow\n'
    path.chmod(0o600)
    path.write_bytes(zlib.compress(b'blob '+str(len(raw)).encode()+b'\0'+raw))
    patch=b'diff --git a/main.py b/main.py\n--- a/main.py\n+++ b/main.py\n@@ -1 +1 @@\n-shadow\n+after\n'
    (f.root/'candidate.patch').write_bytes(patch)
    f.expected=replace(f.expected,patch_sha256=hashlib.sha256(patch).hexdigest())
    f.data['candidate']=vars(f.expected).copy();f.sign()
    with pytest.raises(RuntimeArtifactError):verify(f)
