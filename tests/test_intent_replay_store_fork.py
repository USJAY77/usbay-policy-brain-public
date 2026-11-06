"""Bounded POSIX-fork checks using synthetic, task-owned replay databases."""
import concurrent.futures
import os
import select
import signal
import sqlite3
import threading

import pytest

import security.intent_replay_store as replay

pytestmark = [pytest.mark.governance, pytest.mark.regression,
              pytest.mark.skipif(not hasattr(os, 'fork'), reason='POSIX fork required')]


@pytest.mark.parametrize('held_lock', ['database', 'registry'])
@pytest.mark.parametrize('sqlite_locked', [False, True])
def test_child_drops_inherited_python_locks_but_preserves_sqlite_fence(tmp_path, held_lock, sqlite_locked):
    store = replay.IntentReplayStore.provision(tmp_path / 'intent.db')
    ready = threading.Event()
    release = threading.Event()
    uri = store.path.absolute().as_uri()

    def hold_parent_lock():
        context = replay._reservation_slot(store.path) if held_lock == 'database' else replay._RESERVATION_GATES_LOCK
        with context:
            ready.set()
            if not release.wait(10):
                raise RuntimeError('TEST_PARENT_RELEASE_TIMEOUT')

    connection = sqlite3.connect(store.path) if sqlite_locked else None
    if connection is not None:
        connection.execute('BEGIN EXCLUSIVE')
    child = None
    read_fd, write_fd = os.pipe()
    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
        holder = pool.submit(hold_parent_lock)
        try:
            assert ready.wait(5)
            child = os.fork()
            if child == 0:
                os.close(read_fd)
                try:
                    try:
                        allowed = replay.IntentReplayStore(store.path).reserve(
                            intent_reference='fork-intent', nonce_reference='fork-nonce', evidence='{}')
                        result = b'A' if allowed else b'R'
                    except replay.IntentStoreError:
                        result = b'D'
                    except BaseException:
                        result = b'E'
                    os.write(write_fd, result)
                finally:
                    os._exit(0)
            os.close(write_fd)
            write_fd = None
            readable, _, _ = select.select([read_fd], [], [], 5)
            assert readable, 'CHILD_RESERVATION_TIMEOUT'
            assert os.read(read_fd, 1) == (b'D' if sqlite_locked else b'A')
            # Resetting the child must not unlock or remove the parent's gate.
            parent_lock = (replay._RESERVATION_GATES[uri].lock if held_lock == 'database'
                           else replay._RESERVATION_GATES_LOCK)
            acquired = parent_lock.acquire(blocking=False)
            if acquired:
                parent_lock.release()
            assert not acquired
        finally:
            if child is not None and child > 0:
                pid, _ = os.waitpid(child, os.WNOHANG)
                if pid == 0:
                    os.kill(child, signal.SIGKILL)
                    os.waitpid(child, 0)
            release.set()
            holder.result(timeout=5)
            os.close(read_fd)
            if write_fd is not None:
                os.close(write_fd)
            if connection is not None:
                connection.rollback()
                connection.close()
    with sqlite3.connect(store.path) as check:
        assert check.execute('SELECT count(*) FROM consumed').fetchone() == ((0,) if sqlite_locked else (2,))
