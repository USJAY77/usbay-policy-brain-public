from __future__ import annotations

import hashlib
import threading

import pytest

import security.redis_store as redis_store


@pytest.fixture(autouse=True)
def reset_redis_client():
    redis_store._reset_client()
    yield
    redis_store._reset_client()


class FakeRedisClient:
    def __init__(self, set_result=True, now=1_710_000_000):
        self.set_result = set_result
        self.set_calls = []
        self.values = {}
        self.now = now
        self.fail = False
        self.lock = threading.Lock()

    def set(self, key, value, nx=False, ex=None):
        if self.fail:
            raise ConnectionError("redis unavailable")
        with self.lock:
            self._expire()
            self.set_calls.append(
                {
                    "key": key,
                    "value": value,
                    "nx": nx,
                    "ex": ex,
                }
            )
            if self.set_result is not True:
                return self.set_result
            if nx and key in self.values:
                return None
            expires_at = self.now + int(ex) if ex else None
            self.values[str(key)] = (value, expires_at)
            return True

    def exists(self, key):
        if self.fail:
            raise ConnectionError("redis unavailable")
        with self.lock:
            self._expire()
            return 1 if key in self.values else 0

    def _expire(self):
        expired = [
            key
            for key, (_value, expires_at) in self.values.items()
            if expires_at is not None and expires_at <= self.now
        ]
        for key in expired:
            self.values.pop(key, None)


def test_store_nonce_uses_set_nx_ex_and_returns_true(monkeypatch):
    client = FakeRedisClient(set_result=True)
    monkeypatch.setattr(redis_store, "_client", client)
    monkeypatch.setenv("USBAY_NONCE_TTL_SECONDS", "123")
    expected_nonce_hash = hashlib.sha256(b"abc").hexdigest()

    assert redis_store.store_nonce("abc", 1710000000) is True
    assert client.set_calls == [
        {
            "key": f"nonce:{expected_nonce_hash}",
            "value": 1710000000,
            "nx": True,
            "ex": 123,
        }
    ]
    assert "abc" not in client.set_calls[0]["key"]
    assert isinstance(redis_store.store_nonce("def", 1710000001), bool)


def test_duplicate_nonce_rejected_by_set_nx(monkeypatch):
    client = FakeRedisClient()
    monkeypatch.setattr(redis_store, "_client", client)
    monkeypatch.setenv("USBAY_NONCE_TTL_SECONDS", "300")

    assert redis_store.store_nonce("abc", 1710000000) is True
    assert redis_store.store_nonce("abc", 1710000001) is False
    assert [call["nx"] for call in client.set_calls] == [True, True]
    assert [call["ex"] for call in client.set_calls] == [300, 300]


@pytest.mark.parametrize("set_result", [None, False, 0])
def test_store_nonce_returns_false_when_redis_does_not_store(monkeypatch, set_result):
    client = FakeRedisClient(set_result=set_result)
    monkeypatch.setattr(redis_store, "_client", client)

    result = redis_store.store_nonce("abc", 1710000000)

    assert result is False
    assert isinstance(result, bool)


def test_store_nonce_returns_false_on_connection_failure(monkeypatch):
    client = FakeRedisClient()
    client.fail = True
    monkeypatch.setattr(redis_store, "_client", client)

    assert redis_store.store_nonce("abc", 1710000000) is False


@pytest.mark.parametrize("nonce", ["", "   ", None, b"bytes"])
def test_store_nonce_rejects_malformed_nonce_without_redis_write(monkeypatch, nonce):
    client = FakeRedisClient()
    monkeypatch.setattr(redis_store, "_client", client)

    assert redis_store.store_nonce(nonce, 1710000000) is False
    assert client.set_calls == []


def test_nonce_exists_rejects_malformed_nonce_fail_closed(monkeypatch):
    client = FakeRedisClient()
    monkeypatch.setattr(redis_store, "_client", client)

    with pytest.raises(RuntimeError, match="Redis nonce lookup failed"):
        redis_store.nonce_exists("")

    assert client.set_calls == []


def test_nonce_expiration_allows_new_insert_after_ttl(monkeypatch):
    client = FakeRedisClient(now=1_710_000_000)
    monkeypatch.setattr(redis_store, "_client", client)
    monkeypatch.setenv("USBAY_NONCE_TTL_SECONDS", "5")

    assert redis_store.store_nonce("ttl-nonce", 1710000000) is True
    assert redis_store.store_nonce("ttl-nonce", 1710000001) is False
    client.now += 6

    assert redis_store.store_nonce("ttl-nonce", 1710000006) is True


def test_replay_rejection_is_deterministic_under_concurrency(monkeypatch):
    client = FakeRedisClient()
    monkeypatch.setattr(redis_store, "_client", client)
    monkeypatch.setenv("USBAY_NONCE_TTL_SECONDS", "300")
    results = []
    lock = threading.Lock()

    def store() -> None:
        result = redis_store.store_nonce("concurrent-replay", 1710000000)
        with lock:
            results.append(result)

    threads = [threading.Thread(target=store) for _ in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert results.count(True) == 1
    assert results.count(False) == 7
    assert all(isinstance(result, bool) for result in results)


def test_nonce_exists_returns_deterministic_boolean(monkeypatch):
    client = FakeRedisClient()
    monkeypatch.setattr(redis_store, "_client", client)

    assert redis_store.store_nonce("exists-nonce", 1710000000) is True
    result = redis_store.nonce_exists("exists-nonce")

    assert result is True
    assert isinstance(result, bool)
