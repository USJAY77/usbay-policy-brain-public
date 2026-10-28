"""Synthetic local POSIX tests; no production authority or power-loss claim."""
from __future__ import annotations

import hashlib
import json
import multiprocessing
import os
from pathlib import Path
import signal
import threading

import pytest

from audit import hash_chain as chain
from audit import immutable_ledger as ledger


def seed(tmp_path):
    path = tmp_path / "chain.json"
    chain.append_event("seed", {"tenant_id": "t1"}, path)
    assert chain.verify_chain(path)
    return path, ledger.ledger_path_for(path)


def snapshot(root):
    return {p.name: p.read_bytes() for p in root.iterdir() if p.is_file()}


def process(target):
    return multiprocessing.get_context("fork").Process(target=target)


def finish(child, expected=0):
    child.join(8)
    if child.is_alive():
        child.kill()
        child.join(2)
        pytest.fail("synthetic process deadline exceeded")
    assert child.exitcode == expected


def test_direct_ledger_append_preserves_bound_chain_and_updates_completion(tmp_path):
    path, evidence = seed(tmp_path)
    before = path.read_bytes()
    ledger.append_evidence_event(evidence, action="direct", decision={"tenant_id": "t1"})
    chain.append_event("paired", {"tenant_id": "t1"}, path)
    assert len(json.loads(path.read_text())) == 2
    assert len(ledger.verified_ledger_records(evidence)) == 3
    records = [json.loads(line) for line in ledger._log_path(evidence).read_text().splitlines()]
    assert len(records) == 6
    assert records[2]["payload"]["operation"] == "ledger_append"
    assert records[2]["payload"]["before"]["chain"] == records[2]["payload"]["after"]["chain"]
    assert records[2]["payload"]["after"]["chain"]["sha256"] == hashlib.sha256(before).hexdigest()
    assert chain.verify_chain(path)


def test_initial_ledger_only_then_first_pair_binds_chain(tmp_path):
    path = tmp_path / "chain.json"
    evidence = ledger.ledger_path_for(path)
    ledger.append_evidence_event(evidence, action="legacy-direct", decision={"tenant_id": "t1"})
    assert ledger._read_log(evidence)[1] is None
    chain.append_event("paired", {"tenant_id": "t1"}, path)
    assert ledger._read_log(evidence)[1] == path.name
    assert len(ledger.verified_ledger_records(evidence)) == 2
    assert chain.verify_chain(path)


def test_valid_no_log_legacy_history_is_not_rewritten_on_read(tmp_path):
    path, evidence = seed(tmp_path)
    # Deliberately construct a historical fixture. Runtime never deletes the log.
    ledger._log_path(evidence).unlink()
    before = snapshot(tmp_path)
    assert chain.verify_chain(path)
    assert snapshot(tmp_path) == before
    prefix = evidence.read_bytes()
    chain.append_event("first-v1", {"tenant_id": "t1"}, path)
    assert evidence.read_bytes().startswith(prefix)
    assert chain.verify_chain(path)


@pytest.mark.parametrize("direct", [False, True])
def test_two_process_writers_serialize_without_lost_events(tmp_path, direct):
    path, evidence = seed(tmp_path)
    ctx = multiprocessing.get_context("fork")
    start = ctx.Barrier(3, timeout=5)

    def writer(action, ledger_only):
        start.wait()
        if ledger_only:
            ledger.append_evidence_event(evidence, action=action, decision={"tenant_id": "t1"})
        else:
            chain.append_event(action, {"tenant_id": "t1"}, path)

    first = process(lambda: writer("first", False))
    second = process(lambda: writer("second", direct))
    first.start()
    second.start()
    try:
        start.wait()
        finish(first)
        finish(second)
    finally:
        for child in (first, second):
            if child.is_alive():
                child.kill()
                child.join(2)
    assert len(json.loads(path.read_text())) == (2 if direct else 3)
    assert {r["action"] for r in ledger.verified_ledger_records(evidence)} == {"seed", "first", "second"}
    assert chain.verify_chain(path)


def test_nested_lock_is_rejected_before_second_flock(tmp_path):
    _, evidence = seed(tmp_path)
    with ledger._ledger_lock(evidence, exclusive=True):
        with pytest.raises(ledger.LedgerIntegrityError, match="ledger_nested_lock_rejected"):
            ledger.append_evidence_event(
                evidence, action="nested", decision={"tenant_id": "t1"})


@pytest.mark.parametrize("boundary", range(1, 9))
def test_process_kill_after_each_fsync_preserves_detection(tmp_path, boundary):
    path, evidence = seed(tmp_path)

    def worker():
        real = ledger.os.fsync
        calls = 0

        def kill_after(descriptor):
            nonlocal calls
            real(descriptor)
            calls += 1
            if calls == boundary:
                os.kill(os.getpid(), signal.SIGKILL)

        ledger.os.fsync = kill_after
        chain.append_event("interrupted", {"tenant_id": "t1"}, path)
        os._exit(97)  # Every expected boundary must actually be reached.

    child = process(worker)
    child.start()
    finish(child, -signal.SIGKILL)
    # A separate process reopens storage; process-local state cannot approve it.
    receiver, sender = multiprocessing.get_context("fork").Pipe(duplex=False)

    def reader():
        sender.send(chain.verify_chain(path))

    reader_process = process(reader)
    reader_process.start()
    finish(reader_process)
    assert receiver.poll(1)
    assert receiver.recv() is (boundary >= 7)
    before = snapshot(tmp_path)
    if boundary < 7:
        with pytest.raises(ledger.LedgerIntegrityError):
            chain.append_event("retry", {"tenant_id": "t1"}, path)
        assert snapshot(tmp_path) == before
    receiver.close()
    sender.close()


@pytest.mark.parametrize("boundary", range(1, 9))
def test_fsync_failure_never_reports_success(tmp_path, monkeypatch, boundary):
    path, evidence = seed(tmp_path)
    real, calls = ledger.os.fsync, 0

    def fail_after(descriptor):
        nonlocal calls
        real(descriptor)
        calls += 1
        if calls == boundary:
            raise OSError("synthetic fsync failure")

    monkeypatch.setattr(ledger.os, "fsync", fail_after)
    with pytest.raises(ledger.LedgerIntegrityError, match="ledger_write_uncertain"):
        chain.append_event("failure", {"tenant_id": "t1"}, path)
    monkeypatch.setattr(ledger.os, "fsync", real)
    assert calls == boundary
    assert chain.verify_chain(path) is (boundary >= 7)
    assert ledger._log_path(evidence).exists()


@pytest.mark.parametrize("fault", ["empty", "tail", "unknown_version", "duplicate_key", "orphan", "digest", "oversize"])
def test_invalid_control_log_blocks_without_repair(tmp_path, fault):
    path, evidence = seed(tmp_path)
    control = ledger._log_path(evidence)
    original = control.read_bytes()
    if fault == "empty":
        damaged = b""
    elif fault == "tail":
        damaged = original + b'{"incomplete":'
    elif fault == "duplicate_key":
        damaged = original.replace(b'"version":1', b'"version":1,"version":1', 1)
    elif fault == "orphan":
        damaged = original.splitlines(keepends=True)[-1]
    elif fault == "oversize":
        damaged = b"x" * ledger._RECORD_LIMIT + b"\n"
    else:
        records = [json.loads(line) for line in original.splitlines()]
        records[0]["version" if fault == "unknown_version" else "record_sha256"] = 2 if fault == "unknown_version" else "0" * 64
        damaged = b"".join(ledger._encode(r) + b"\n" for r in records)
    control.write_bytes(damaged)
    before = snapshot(tmp_path)
    assert not chain.verify_chain(path)
    assert not ledger.verify_ledger(evidence)
    with pytest.raises(ledger.LedgerIntegrityError):
        chain.append_event("blocked", {"tenant_id": "t1"}, path)
    assert snapshot(tmp_path) == before


@pytest.mark.parametrize("decision", [{}, {"tenant_id": "t1", "raw_nonce": "synthetic"},
                                      {"tenant_id": "t1", "tenant_hash": "wrong"},
                                      {"tenant_id": "t1", "value": float("inf")}])
def test_prewrite_rejection_does_not_append_intent(tmp_path, decision):
    path, evidence = seed(tmp_path)
    before = snapshot(tmp_path)
    with pytest.raises(ledger.LedgerIntegrityError):
        chain.append_event("rejected", decision, path)
    assert snapshot(tmp_path) == before
    assert chain.verify_chain(path)


def test_corrupt_chain_is_never_treated_as_empty(tmp_path):
    path, _ = seed(tmp_path)
    path.write_text('{"not": "a chain"}')
    before = snapshot(tmp_path)
    with pytest.raises(ledger.LedgerIntegrityError):
        chain.append_event("rejected", {"tenant_id": "t1"}, path)
    assert snapshot(tmp_path) == before
    assert not chain.verify_chain(path)


def test_short_writes_complete_but_zero_write_blocks(tmp_path, monkeypatch):
    path, evidence = seed(tmp_path)
    real = ledger.os.write
    monkeypatch.setattr(ledger.os, "write", lambda fd, value: real(fd, value[:max(1, len(value) // 2)]))
    chain.append_event("short", {"tenant_id": "t1"}, path)
    assert chain.verify_chain(path)
    before = path.read_bytes(), evidence.read_bytes()
    monkeypatch.setattr(ledger.os, "write", lambda *_: 0)
    with pytest.raises(ledger.LedgerIntegrityError, match="ledger_write_uncertain"):
        chain.append_event("zero", {"tenant_id": "t1"}, path)
    assert (path.read_bytes(), evidence.read_bytes()) == before


def test_reader_waits_for_writer_and_sees_completed_snapshot(tmp_path):
    path, _ = seed(tmp_path)
    ctx = multiprocessing.get_context("fork")
    intent_ready, release = ctx.Event(), ctx.Event()
    reader_started, reader_done = ctx.Event(), ctx.Event()

    def writer():
        original = ledger._publish_chain

        def pause(*args):
            intent_ready.set()
            assert release.wait(5)
            return original(*args)

        ledger._publish_chain = pause
        chain.append_event("paused", {"tenant_id": "t1"}, path)

    def reader():
        # A nonblocking lock probe proves the writer currently owns exclusion.
        import fcntl
        descriptor = os.open(str(ledger.ledger_path_for(path)) + ".lock", os.O_RDWR)
        try:
            with pytest.raises(BlockingIOError):
                fcntl.flock(descriptor, fcntl.LOCK_SH | fcntl.LOCK_NB)
        finally:
            os.close(descriptor)
        reader_started.set()
        assert chain.verify_chain(path)
        assert len(json.loads(path.read_text())) == 2
        reader_done.set()

    writing = process(writer)
    reading = process(reader)
    writing.start()
    try:
        assert intent_ready.wait(5)
        reading.start()
        assert reader_started.wait(5)
        assert not reader_done.is_set()
        release.set()
        finish(writing)
        finish(reading)
        assert reader_done.is_set()
    finally:
        release.set()
        for child in (writing, reading):
            if child.pid and child.is_alive():
                child.kill()
                child.join(2)


def test_raw_save_cannot_bypass_coordinator(tmp_path):
    path, _ = seed(tmp_path)
    before = snapshot(tmp_path)
    with pytest.raises(ledger.LedgerIntegrityError, match="uncoordinated_chain_write_unsupported"):
        chain.save_chain([], path)
    assert snapshot(tmp_path) == before


@pytest.mark.parametrize("target", ["chain", "ledger", "control", "lock"])
@pytest.mark.parametrize("link", ["symlink", "hardlink"])
def test_path_identity_links_are_rejected(tmp_path, target, link):
    path, evidence = seed(tmp_path)
    candidate = {"chain": path, "ledger": evidence, "control": ledger._log_path(evidence),
                 "lock": Path(str(evidence) + ".lock")}[target]
    other = tmp_path / "other"
    if link == "symlink":
        candidate.rename(other)
        candidate.symlink_to(other)
    else:
        os.link(candidate, other)
    before = snapshot(tmp_path)
    assert not chain.verify_chain(path)
    with pytest.raises(ledger.LedgerIntegrityError):
        chain.append_event("rejected", {"tenant_id": "t1"}, path)
    assert snapshot(tmp_path) == before


@pytest.mark.parametrize("fault", ["replace", "open", "signing", "log_limit"])
def test_failure_boundaries_preserve_history(tmp_path, monkeypatch, fault):
    path, evidence = seed(tmp_path)
    before_chain, before_ledger = path.read_bytes(), evidence.read_bytes()
    control = ledger._log_path(evidence)
    previous_control = control.read_bytes()

    def denied(*args, **kwargs):
        raise OSError("synthetic boundary failure")

    if fault == "replace":
        monkeypatch.setattr(ledger.os, "replace", denied)
    elif fault == "signing":
        monkeypatch.setattr(ledger, "get_signing_key", denied)
    elif fault == "log_limit":
        monkeypatch.setattr(ledger, "_LOG_LIMIT", len(previous_control) + 1)
    else:
        real = ledger.os.open

        def fail_control_append(candidate, flags, *args, **kwargs):
            if Path(candidate) == control and flags & os.O_WRONLY:
                raise OSError("synthetic open failure")
            return real(candidate, flags, *args, **kwargs)

        monkeypatch.setattr(ledger.os, "open", fail_control_append)
    with pytest.raises(ledger.LedgerIntegrityError):
        chain.append_event("rejected", {"tenant_id": "t1"}, path)
    assert path.read_bytes() == before_chain
    assert evidence.read_bytes() == before_ledger
    if fault != "replace":
        assert control.read_bytes() == previous_control
    else:
        assert control.read_bytes().startswith(previous_control)
        assert not chain.verify_chain(path)


def test_record_chain_binding_cannot_change_or_be_forged(tmp_path):
    path, evidence = seed(tmp_path)
    control = ledger._log_path(evidence)
    records = [json.loads(line) for line in control.read_bytes().splitlines()]
    # Keep all record hashes valid, but make COMPLETE describe different bytes.
    records[-1]["payload"]["after"]["ledger"]["sha256"] = "0" * 64
    unsigned = {k: v for k, v in records[-1].items() if k != "record_sha256"}
    records[-1]["record_sha256"] = hashlib.sha256(ledger._encode(unsigned)).hexdigest()
    control.write_bytes(b"".join(ledger._encode(r) + b"\n" for r in records))
    assert not chain.verify_chain(path)
    assert not ledger.verify_ledger(evidence)


def test_writable_storage_parent_is_refused(tmp_path):
    path, evidence = seed(tmp_path)
    before = snapshot(tmp_path)
    mode = tmp_path.stat().st_mode & 0o777
    tmp_path.chmod(0o777)
    try:
        assert not chain.verify_chain(path)
        with pytest.raises(ledger.LedgerIntegrityError):
            ledger.append_evidence_event(evidence, action="rejected", decision={"tenant_id": "t1"})
        assert snapshot(tmp_path) == before
    finally:
        tmp_path.chmod(mode)


def test_public_append_cannot_accept_nonfinite_evidence(tmp_path):
    _, evidence = seed(tmp_path)
    before = snapshot(tmp_path)
    with pytest.raises(ledger.LedgerIntegrityError):
        ledger.append_evidence_event(evidence, action="rejected", decision={"tenant_id": "t1", "number": float("inf")})
    assert snapshot(tmp_path) == before


def test_forked_reader_does_not_keep_dead_writer_lock_alive(tmp_path):
    path, evidence = seed(tmp_path)
    ctx = multiprocessing.get_context("fork")
    receiver, sender = ctx.Pipe(duplex=False)
    release = ctx.Event()

    def writer_parent():
        with ledger._ledger_lock(evidence, exclusive=True):
            grandchild = os.fork()
            if grandchild:
                sender.send(("pid", grandchild))
                os._exit(91)  # No unlock/finally; only the child could retain it.
            if not release.wait(5):
                os._exit(92)
            sender.send(("verified", chain.verify_chain(path)))
            os._exit(0)

    writer = process(writer_parent)
    writer.start()
    grandchild = None
    try:
        assert receiver.poll(5)
        kind, grandchild = receiver.recv()
        assert kind == "pid"
        # The fork child also inherits multiprocessing's sentinel pipe. Waiting
        # for Process.join before releasing it can itself prevent EOF, unrelated
        # to the audit lock. Let it verify first, then collect the parent's exit.
        release.set()
        assert receiver.poll(5), "fork child retained a dead writer's lock"
        assert receiver.recv() == ("verified", True)
        finish(writer, 91)
    finally:
        release.set()
        if writer.is_alive():
            writer.kill()
            writer.join(2)
        if grandchild is not None:
            try:
                os.kill(grandchild, signal.SIGKILL)
            except ProcessLookupError:
                pass
        receiver.close()
        sender.close()


@pytest.mark.governance
@pytest.mark.parametrize("boundary", ["open_before_register", "close_before_unregister"])
def test_fork_during_descriptor_bookkeeping_does_not_inherit_or_close_wrong_fd(tmp_path, boundary):
    path, evidence = seed(tmp_path)
    receiver, sender = multiprocessing.get_context("fork").Pipe(duplex=False)
    release_child = multiprocessing.get_context("fork").Event()

    def writer_parent():
        lock_path = evidence.with_suffix(evidence.suffix + ".lock")
        writer_pid = os.getpid()
        paused, resume, fork_returned = threading.Event(), threading.Event(), threading.Event()
        acquired, finished = threading.Event(), threading.Event()
        original_open, original_close = os.open, os.close
        state = {}

        def paused_open(target, *args, **kwargs):
            descriptor = original_open(target, *args, **kwargs)
            if Path(target) == lock_path:
                state["lock_fd"] = descriptor
                if boundary == "open_before_register":
                    paused.set()
                    if not resume.wait(5):
                        os._exit(92)
            return descriptor

        def paused_close(descriptor):
            original_close(descriptor)
            if (os.getpid() == writer_pid and boundary == "close_before_unregister"
                    and descriptor == state.get("lock_fd")):
                # Reuse the just-closed number before the registry can discard
                # it. The child must not close this unrelated descriptor.
                probe = original_open(path, os.O_RDONLY)
                if probe != descriptor:
                    os._exit(93)
                state["probe"] = probe
                paused.set()
                if not resume.wait(5):
                    os._exit(92)

        os.open, os.close = paused_open, paused_close

        def writer_thread():
            with ledger._ledger_lock(evidence, exclusive=True):
                acquired.set()
                if boundary == "open_before_register":
                    threading.Event().wait(10)
            finished.set()

        worker = threading.Thread(target=writer_thread, daemon=True)
        worker.start()
        if not paused.wait(5):
            os._exit(94)

        def unblock_bookkeeping():
            # Old code forks while bookkeeping is paused. Correct code waits
            # in its before-fork hook; release it after this bounded interval.
            fork_returned.wait(1)
            resume.set()

        threading.Thread(target=unblock_bookkeeping, daemon=True).start()
        grandchild = os.fork()
        if grandchild:
            fork_returned.set()
            if not (acquired if boundary == "open_before_register" else finished).wait(5):
                os._exit(95)
            sender.send(("pid", grandchild))
            os._exit(91)  # Deliberately no context unwinding in the open case.

        # Restore the native functions before reading in the fork child.
        os.open, os.close = original_open, original_close
        if not release_child.wait(5):
            os._exit(96)
        probe_valid = True
        if boundary == "close_before_unregister":
            try:
                os.fstat(state["probe"])
            except OSError:
                probe_valid = False
        sender.send(("verified", chain.verify_chain(path), probe_valid))
        os._exit(0)

    writer = process(writer_parent)
    writer.start()
    grandchild = None
    try:
        assert receiver.poll(7)
        kind, grandchild = receiver.recv()
        assert kind == "pid"
        release_child.set()
        assert receiver.poll(5), "fork child retained an unregistered audit lock"
        assert receiver.recv() == ("verified", True, True)
        finish(writer, 91)
    finally:
        release_child.set()
        if writer.is_alive():
            writer.kill()
            writer.join(2)
        if grandchild is not None:
            try:
                os.kill(grandchild, signal.SIGKILL)
            except ProcessLookupError:
                pass
        receiver.close()
        sender.close()
