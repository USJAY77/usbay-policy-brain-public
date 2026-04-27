from __future__ import annotations

import pytest

import security.redis_store as redis_store


class FakeRedisClient:
    def __init__(self, set_result=True):
        self.set_result = set_result
        self.set_calls = []

    def set(self, key, value, nx=False, ex=None):
        self.set_calls.append(
            {
                "key": key,
                "value": value,
                "nx": nx,
                "ex": ex,
            }
        )
        return self.set_result


def test_store_nonce_uses_set_nx_ex_and_returns_true(monkeypatch):
    client = FakeRedisClient(set_result=True)
    monkeypatch.setattr(redis_store, "_client", client)
    monkeypatch.setenv("USBAY_NONCE_TTL_SECONDS", "123")

    assert redis_store.store_nonce("abc", 1710000000) is True
    assert client.set_calls == [
        {
            "key": "nonce:abc",
            "value": 1710000000,
            "nx": True,
            "ex": 123,
        }
    ]


@pytest.mark.parametrize("set_result", [None, False])
def test_store_nonce_returns_false_when_nonce_already_exists(monkeypatch, set_result):
    client = FakeRedisClient(set_result=set_result)
    monkeypatch.setattr(redis_store, "_client", client)

    assert redis_store.store_nonce("abc", 1710000000) is False


def test_store_nonce_raises_runtime_error_on_connection_failure(monkeypatch):
    class FailingRedisClient:
        def set(self, key, value, nx=False, ex=None):
            raise ConnectionError("redis unavailable")

    monkeypatch.setattr(redis_store, "_client", FailingRedisClient())

    with pytest.raises(RuntimeError, match="Redis nonce store failed"):
        redis_store.store_nonce("abc", 1710000000)
