"""Tests for the USBAY Governance Simulator storage adapters (training-only)."""

import json

import pytest

from simulator.storage import (
    MAX_VALUE_BYTES,
    LocalFileStorageAdapter,
    PostgresStorageAdapter,
    SqliteStorageAdapter,
    StorageUnavailable,
    StorageValidationError,
    get_storage_adapter,
)


def _round_trip(adapter):
    key = "operator_demo"
    payload = json.dumps({"xp": 120, "rank": "Auditor"})
    assert adapter.get(key) is None
    adapter.set(key, payload)
    assert adapter.get(key) == payload
    # Overwrite
    payload2 = json.dumps({"xp": 240, "rank": "Lead Auditor"})
    adapter.set(key, payload2)
    assert adapter.get(key) == payload2
    # Delete
    adapter.delete(key)
    assert adapter.get(key) is None
    # Delete of an absent key must not raise
    adapter.delete(key)


def test_local_round_trip(tmp_path):
    adapter = LocalFileStorageAdapter(base_dir=str(tmp_path))
    _round_trip(adapter)
    h = adapter.health()
    assert h["backend"] == "local"
    assert h["available"] is True
    assert h["writable"] is True


def test_sqlite_round_trip():
    adapter = SqliteStorageAdapter(db_path=":memory:")
    _round_trip(adapter)
    h = adapter.health()
    assert h["backend"] == "sqlite"
    assert h["available"] is True


def test_sqlite_file_round_trip(tmp_path):
    db = str(tmp_path / "sim.db")
    adapter = SqliteStorageAdapter(db_path=db)
    _round_trip(adapter)


def test_postgres_fails_closed_without_dsn():
    with pytest.raises(StorageUnavailable):
        PostgresStorageAdapter()


def test_postgres_fails_closed_even_with_dsn():
    with pytest.raises(StorageUnavailable):
        PostgresStorageAdapter(dsn="postgresql://example/db")


def test_factory_default_is_local(tmp_path):
    adapter = get_storage_adapter("local", base_dir=str(tmp_path))
    assert adapter.backend == "local"


def test_factory_sqlite():
    adapter = get_storage_adapter("sqlite", db_path=":memory:")
    assert adapter.backend == "sqlite"


def test_factory_postgres_fails_closed():
    with pytest.raises(StorageUnavailable):
        get_storage_adapter("postgres")


def test_factory_unknown_backend_fails_closed():
    with pytest.raises(StorageUnavailable):
        get_storage_adapter("redis")


def test_invalid_key_rejected(tmp_path):
    adapter = LocalFileStorageAdapter(base_dir=str(tmp_path))
    for bad in ["", "has space", "../escape", "a/b", "x" * 200]:
        with pytest.raises(StorageValidationError):
            adapter.set(bad, json.dumps({"ok": True}))


def test_non_json_value_rejected(tmp_path):
    adapter = LocalFileStorageAdapter(base_dir=str(tmp_path))
    with pytest.raises(StorageValidationError):
        adapter.set("k", "not-json{")


def test_oversize_value_rejected(tmp_path):
    adapter = LocalFileStorageAdapter(base_dir=str(tmp_path))
    big = json.dumps({"blob": "x" * (MAX_VALUE_BYTES + 10)})
    with pytest.raises(StorageValidationError):
        adapter.set("k", big)


def test_sqlite_invalid_key_rejected():
    adapter = SqliteStorageAdapter(db_path=":memory:")
    with pytest.raises(StorageValidationError):
        adapter.get("bad key")
