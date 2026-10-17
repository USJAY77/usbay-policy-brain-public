from __future__ import annotations

import json
import multiprocessing
import os
import queue

import pytest

import governance.durable_authority_registries as registries
from governance.durable_authority_registries import AuthorityRegistryError, DurableAuthorityRegistry, HUMAN_APPROVAL, UNKNOWN
from tests.test_durable_authority_registries import DOMAIN_REFS, ISSUED, NOW, TENANT, ENVIRONMENT, _criteria, _record

pytestmark = pytest.mark.governance

def _revoke(store):
    return store.revoke_authority(HUMAN_APPROVAL, DOMAIN_REFS[HUMAN_APPROVAL], tenant_reference=TENANT, environment_reference=ENVIRONMENT, reason_code='SYNTHETIC_REVOKE', timestamp=NOW)

def _read_in_new_process(path, output):
    result=DurableAuthorityRegistry(path).resolve_human_approval(DOMAIN_REFS[HUMAN_APPROVAL], **_criteria(HUMAN_APPROVAL))
    output.put(result['status'])

def _read_and_signal(path, started, output):
    started.set()
    _read_in_new_process(path, output)

def _create_paused_after_intent(path, entered, release):
    class Paused(DurableAuthorityRegistry):
        def _begin_intent(self, previous_hash):
            super()._begin_intent(previous_hash)
            entered.set()
            if not release.wait(10):
                raise RuntimeError('parent timeout')
    Paused(path).create_authority(HUMAN_APPROVAL, _record(HUMAN_APPROVAL), timestamp=ISSUED)

def test_missing_lookup_is_side_effect_free(tmp_path):
    path=tmp_path/'missing'/'authority.jsonl'
    store=DurableAuthorityRegistry(path)
    before=set(tmp_path.rglob('*'))
    result=store.resolve_human_approval(DOMAIN_REFS[HUMAN_APPROVAL], **_criteria(HUMAN_APPROVAL))
    assert result['status'] == registries.MISSING
    assert set(tmp_path.rglob('*')) == before

def test_reader_serializes_with_concurrent_first_creation(tmp_path):
    ctx=multiprocessing.get_context('fork');path=tmp_path/'authority.jsonl'
    entered,release,reader_started=ctx.Event(),ctx.Event(),ctx.Event();output=ctx.Queue()
    writer=ctx.Process(target=_create_paused_after_intent,args=(path,entered,release))
    reader=ctx.Process(target=_read_and_signal,args=(path,reader_started,output))
    writer.start()
    try:
        assert entered.wait(5)
        reader.start();assert reader_started.wait(5)
        with pytest.raises(queue.Empty):
            output.get(timeout=0.25)
    finally:
        release.set();writer.join(10)
        if reader.pid is not None:reader.join(10)
    assert writer.exitcode==reader.exitcode==0
    assert output.get(timeout=2)==registries.VALID

def test_existing_store_without_lock_fails_closed_without_recreating_lock(tmp_path):
    path=tmp_path/'authority.jsonl';store=DurableAuthorityRegistry(path)
    store.create_authority(HUMAN_APPROVAL, _record(HUMAN_APPROVAL), timestamp=ISSUED)
    store._lock_path.unlink()
    result=DurableAuthorityRegistry(path).resolve_human_approval(
        DOMAIN_REFS[HUMAN_APPROVAL], **_criteria(HUMAN_APPROVAL)
    )
    assert result['status']==UNKNOWN
    assert result['reason_code']=='AUTHORITY_STORAGE_LOCK_UNAVAILABLE'
    assert not store._lock_path.exists()

@pytest.mark.parametrize('failure_position', range(1, 8))
def test_any_commit_fsync_failure_blocks_lookup_after_reopen(tmp_path, monkeypatch, failure_position):
    path = tmp_path/'authority.jsonl'
    store = DurableAuthorityRegistry(path)
    store.create_authority(HUMAN_APPROVAL, _record(HUMAN_APPROVAL), timestamp=ISSUED)
    original = os.fsync
    calls = 0
    def fail_once(fd):
        nonlocal calls
        calls += 1
        if calls == failure_position:
            raise OSError('synthetic fsync failure')
        return original(fd)
    monkeypatch.setattr(os, 'fsync', fail_once)
    with pytest.raises(AuthorityRegistryError):
        _revoke(store)
    reopened = DurableAuthorityRegistry(path)
    assert reopened.resolve_human_approval(DOMAIN_REFS[HUMAN_APPROVAL], **_criteria(HUMAN_APPROVAL))['status'] == UNKNOWN
    with pytest.raises(AuthorityRegistryError):
        _revoke(reopened)
    assert path.with_suffix('.jsonl.uncertain').exists()
    ctx=multiprocessing.get_context('spawn');output=ctx.Queue()
    child=ctx.Process(target=_read_in_new_process,args=(path,output))
    child.start();child.join(10)
    assert child.exitcode==0
    assert output.get(timeout=2)==UNKNOWN

def _die_between_pair(path):
    class Interrupted(DurableAuthorityRegistry):
        def _write_evidence(self, *args, **kwargs):
            super()._write_evidence(*args, **kwargs)
            os._exit(0)
    _revoke(Interrupted(path))

def test_process_exit_between_evidence_and_registry_never_reuses_old_authority(tmp_path):
    path=tmp_path/'authority.jsonl'
    store=DurableAuthorityRegistry(path)
    store.create_authority(HUMAN_APPROVAL, _record(HUMAN_APPROVAL), timestamp=ISSUED)
    child=multiprocessing.get_context('fork').Process(target=_die_between_pair,args=(path,))
    child.start();child.join(10)
    assert child.exitcode == 0
    reopened=DurableAuthorityRegistry(path)
    result=reopened.resolve_human_approval(DOMAIN_REFS[HUMAN_APPROVAL], **_criteria(HUMAN_APPROVAL))
    assert result['status'] == UNKNOWN
    assert len(path.read_text().splitlines()) == 1
    assert len(reopened.evidence_path.read_text().splitlines()) == 2

@pytest.mark.parametrize('mutation', ['delete', 'truncate', 'tamper', 'extra'])
def test_missing_or_divergent_evidence_blocks_valid_registry(tmp_path, mutation):
    store=DurableAuthorityRegistry(tmp_path/'authority.jsonl')
    store.create_authority(HUMAN_APPROVAL, _record(HUMAN_APPROVAL), timestamp=ISSUED)
    if mutation=='delete':store.evidence_path.unlink()
    elif mutation=='truncate':store.evidence_path.write_text('')
    elif mutation=='extra':store.evidence_path.write_text(store.evidence_path.read_text()*2)
    else:
        event=json.loads(store.evidence_path.read_text());event['tenant_reference']='sha256:'+'f'*64
        store.evidence_path.write_text(json.dumps(event)+'\n')
    assert store.resolve_human_approval(DOMAIN_REFS[HUMAN_APPROVAL], **_criteria(HUMAN_APPROVAL))['status']==UNKNOWN

def _writer(path, number, entered, release, started, done):
    class Paused(DurableAuthorityRegistry):
        def _write_evidence(self,*args,**kwargs):
            result=super()._write_evidence(*args,**kwargs)
            if number==1:
                entered.set()
                if not release.wait(10):raise RuntimeError('parent timeout')
            return result
    started.set()
    Paused(path).create_authority(HUMAN_APPROVAL,_record(HUMAN_APPROVAL,authority_reference='sha256:'+str(number)*64),timestamp=ISSUED)
    done.set()

def test_second_process_writer_waits_for_complete_pair(tmp_path):
    ctx=multiprocessing.get_context('fork');path=tmp_path/'authority.jsonl'
    entered,release,start1,start2,done1,done2=[ctx.Event() for _ in range(6)]
    a=ctx.Process(target=_writer,args=(path,1,entered,release,start1,done1))
    b=ctx.Process(target=_writer,args=(path,2,entered,release,start2,done2))
    a.start()
    try:
        assert entered.wait(5)
        b.start();assert start2.wait(5)
        assert not done2.wait(0.25), 'second writer entered an unfinished transaction'
    finally:
        release.set();a.join(10)
        if b.pid is not None:b.join(10)
    assert a.exitcode==b.exitcode==0
    assert len(DurableAuthorityRegistry(path).current_authority_records(HUMAN_APPROVAL))==2

@pytest.mark.parametrize('suffix', ['', '.lock', '.uncertain'])
def test_evidence_path_cannot_alias_registry_or_control_files(tmp_path,suffix):
    path=tmp_path/'authority.jsonl'
    with pytest.raises(AuthorityRegistryError,match='AUTHORITY_STORAGE_PATH_CONFLICT'):
        DurableAuthorityRegistry(path,evidence_path=path.with_name(path.name+suffix))
