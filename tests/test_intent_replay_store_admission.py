"""Real SQLite checks for local admission; no execution authority is granted."""
import concurrent.futures
import sqlite3
import threading

import pytest

import security.intent_replay_store as replay

pytestmark = [pytest.mark.governance, pytest.mark.regression]


def reserve(store, suffix="one"):
    return store.reserve(intent_reference="intent-" + suffix,
                         nonce_reference="nonce-" + suffix, evidence="{}")


def test_local_contention_opens_no_second_connection_and_other_database_progresses(tmp_path, monkeypatch):
    store = replay.IntentReplayStore.provision(tmp_path / "first.db")
    other = replay.IntentReplayStore.provision(tmp_path / "second.db")
    target = store.path.absolute().as_uri() + "?mode=rw"
    real_connect = sqlite3.connect
    reached_commit = threading.Event()
    finish_commit = threading.Event()
    opened = []

    class HeldCommit:
        def __init__(self, connection):
            self.connection = connection

        def __getattr__(self, name):
            return getattr(self.connection, name)

        def commit(self):
            reached_commit.set()
            if not finish_commit.wait(5):
                raise RuntimeError("TEST_COMMIT_RELEASE_TIMEOUT")
            return self.connection.commit()

    def connect(database, *args, **kwargs):
        connection = real_connect(database, *args, **kwargs)
        if database == target:
            opened.append(True)
            return HeldCommit(connection)
        return connection

    monkeypatch.setattr(replay.sqlite3, "connect", connect)
    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
        first = pool.submit(reserve, store)
        try:
            assert reached_commit.wait(5)
            with pytest.raises(replay.IntentStoreError, match="^INTENT_STORE_UNAVAILABLE$"):
                reserve(replay.IntentReplayStore(store.path))
            assert len(opened) == 1
            assert reserve(other) is True
        finally:
            finish_commit.set()
        assert first.result(timeout=5) is True
    assert reserve(replay.IntentReplayStore(store.path)) is False
    assert not replay._RESERVATION_GATES


def test_connection_failure_releases_local_slot_without_automatic_retry(tmp_path, monkeypatch):
    store = replay.IntentReplayStore.provision(tmp_path / "intent.db")
    real_connect = sqlite3.connect
    attempts = []

    def unavailable(*args, **kwargs):
        attempts.append(True)
        raise sqlite3.OperationalError("TEST_UNAVAILABLE")

    monkeypatch.setattr(replay.sqlite3, "connect", unavailable)
    with pytest.raises(replay.IntentStoreError, match="^INTENT_STORE_UNAVAILABLE$"):
        reserve(store)
    assert attempts == [True]
    assert not replay._RESERVATION_GATES
    monkeypatch.setattr(replay.sqlite3, "connect", real_connect)
    # An explicit test invocation checks cleanup; production never retries.
    assert reserve(store) is True
    assert not replay._RESERVATION_GATES
