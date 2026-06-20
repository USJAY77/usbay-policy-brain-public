"""USBAY Governance Simulator — backend persistence storage adapters.

Training-only. Fail-closed by design. This module provides a tiny key/value
storage abstraction so simulator progress can be persisted behind a single
interface, independent of the concrete backend:

  - ``local``    : one JSON file per key on local disk (default)
  - ``sqlite``   : a local SQLite database (single kv table)
  - ``postgres`` : reserved for a future deployment; NOT configured in the
                   training build -> any attempt fails closed.

Design rules honoured here:
  * No crypto, no gambling, no real-money, no marketplace.
  * No PII beyond an opaque, caller-supplied display name embedded in the
    JSON blob (the storage layer never inspects it).
  * Stored values are opaque strings (validated as JSON, never executed).
  * SQL is always parameterised.
  * Every backend exposes ``health()`` so callers can fail closed cleanly.
"""

from __future__ import annotations

import abc
import json
import os
import sqlite3
import threading
import time
from pathlib import Path
from typing import Optional

__all__ = [
    "StorageError",
    "StorageUnavailable",
    "StorageValidationError",
    "StorageAdapter",
    "LocalFileStorageAdapter",
    "SqliteStorageAdapter",
    "PostgresStorageAdapter",
    "get_storage_adapter",
    "MAX_VALUE_BYTES",
    "MAX_KEY_LENGTH",
]

# A key is a short, filesystem/SQL-safe identifier (slug-like).
MAX_KEY_LENGTH = 128
# Stored values are capped to keep the training store small and safe.
MAX_VALUE_BYTES = 256 * 1024  # 256 KiB

_ALLOWED_KEY_CHARS = set(
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.:-"
)
_VALID_BACKENDS = ("local", "sqlite", "postgres")


class StorageError(RuntimeError):
    """Base class for all storage errors."""


class StorageUnavailable(StorageError):
    """The requested backend is not configured/available — fail closed."""


class StorageValidationError(StorageError):
    """A key or value failed validation."""


def _validate_key(key: str) -> str:
    if not isinstance(key, str) or not key:
        raise StorageValidationError("storage key must be a non-empty string")
    if len(key) > MAX_KEY_LENGTH:
        raise StorageValidationError(
            "storage key exceeds %d characters" % MAX_KEY_LENGTH
        )
    for ch in key:
        if ch not in _ALLOWED_KEY_CHARS:
            raise StorageValidationError(
                "storage key contains an unsupported character"
            )
    return key


def _validate_value(value: str) -> str:
    if not isinstance(value, str):
        raise StorageValidationError("storage value must be a string")
    encoded = value.encode("utf-8")
    if len(encoded) > MAX_VALUE_BYTES:
        raise StorageValidationError(
            "storage value exceeds %d bytes" % MAX_VALUE_BYTES
        )
    # Values must be valid JSON. We only validate; we never execute or eval.
    try:
        json.loads(value)
    except (ValueError, TypeError) as exc:
        raise StorageValidationError("storage value must be valid JSON") from exc
    return value


class StorageAdapter(abc.ABC):
    """Abstract key/value storage backend."""

    backend = "base"

    @abc.abstractmethod
    def get(self, key: str) -> Optional[str]:
        """Return the stored value for ``key`` or ``None`` if absent."""

    @abc.abstractmethod
    def set(self, key: str, value: str) -> None:
        """Persist ``value`` (a JSON string) under ``key``."""

    @abc.abstractmethod
    def delete(self, key: str) -> None:
        """Remove ``key`` if present (no error if absent)."""

    def health(self) -> dict:
        """Return a small status dict. Default implementation is best-effort."""
        return {"backend": self.backend, "available": True, "writable": True}


class LocalFileStorageAdapter(StorageAdapter):
    """Stores each key as a JSON file under ``base_dir``."""

    backend = "local"

    def __init__(self, base_dir: Optional[str] = None):
        base = base_dir or os.getenv("USBAY_SIM_STORAGE_DIR") or os.path.join(
            "tmp", "usbay_sim_storage"
        )
        self.base_dir = Path(base)
        self._lock = threading.Lock()
        self.base_dir.mkdir(parents=True, exist_ok=True)

    def _path(self, key: str) -> Path:
        return self.base_dir / ("%s.json" % _validate_key(key))

    def get(self, key: str) -> Optional[str]:
        path = self._path(key)
        try:
            if not path.is_file():
                return None
            return path.read_text(encoding="utf-8")
        except OSError as exc:
            raise StorageError("local read failed") from exc

    def set(self, key: str, value: str) -> None:
        _validate_value(value)
        path = self._path(key)
        tmp = path.with_suffix(".json.tmp")
        try:
            with self._lock:
                tmp.write_text(value, encoding="utf-8")
                os.replace(tmp, path)
        except OSError as exc:
            raise StorageError("local write failed") from exc

    def delete(self, key: str) -> None:
        path = self._path(key)
        try:
            if path.is_file():
                path.unlink()
        except OSError as exc:
            raise StorageError("local delete failed") from exc

    def health(self) -> dict:
        writable = os.access(self.base_dir, os.W_OK)
        return {
            "backend": self.backend,
            "available": True,
            "writable": bool(writable),
            "location": str(self.base_dir),
        }


class SqliteStorageAdapter(StorageAdapter):
    """Stores keys in a single ``kv`` table inside a SQLite database."""

    backend = "sqlite"

    def __init__(self, db_path: Optional[str] = None):
        path = db_path or os.getenv("USBAY_SIM_STORAGE_SQLITE") or os.path.join(
            "tmp", "usbay_sim_storage", "simulator.db"
        )
        self.db_path = path
        self._lock = threading.Lock()
        if path != ":memory:":
            parent = os.path.dirname(path)
            if parent:
                os.makedirs(parent, exist_ok=True)
        # ``check_same_thread=False`` with an explicit lock so a single
        # connection can be reused safely across request threads.
        self._conn = sqlite3.connect(path, check_same_thread=False)
        self._init_schema()

    def _init_schema(self) -> None:
        with self._lock:
            self._conn.execute(
                "CREATE TABLE IF NOT EXISTS kv ("
                "  key TEXT PRIMARY KEY,"
                "  value TEXT NOT NULL,"
                "  updated_at REAL NOT NULL"
                ")"
            )
            self._conn.commit()

    def get(self, key: str) -> Optional[str]:
        _validate_key(key)
        try:
            with self._lock:
                cur = self._conn.execute(
                    "SELECT value FROM kv WHERE key = ?", (key,)
                )
                row = cur.fetchone()
        except sqlite3.Error as exc:
            raise StorageError("sqlite read failed") from exc
        return row[0] if row else None

    def set(self, key: str, value: str) -> None:
        _validate_key(key)
        _validate_value(value)
        try:
            with self._lock:
                self._conn.execute(
                    "INSERT INTO kv (key, value, updated_at) VALUES (?, ?, ?) "
                    "ON CONFLICT(key) DO UPDATE SET value = excluded.value, "
                    "updated_at = excluded.updated_at",
                    (key, value, time.time()),
                )
                self._conn.commit()
        except sqlite3.Error as exc:
            raise StorageError("sqlite write failed") from exc

    def delete(self, key: str) -> None:
        _validate_key(key)
        try:
            with self._lock:
                self._conn.execute("DELETE FROM kv WHERE key = ?", (key,))
                self._conn.commit()
        except sqlite3.Error as exc:
            raise StorageError("sqlite delete failed") from exc

    def health(self) -> dict:
        try:
            with self._lock:
                self._conn.execute("SELECT 1")
            available = True
        except sqlite3.Error:
            available = False
        return {
            "backend": self.backend,
            "available": available,
            "writable": available,
            "location": self.db_path,
        }


class PostgresStorageAdapter(StorageAdapter):
    """Reserved for a future deployment.

    PostgreSQL is intentionally NOT enabled in the training build. Without an
    explicit DSN this adapter fails closed: construction raises
    :class:`StorageUnavailable`, and every operation also fails closed.
    """

    backend = "postgres"

    def __init__(self, dsn: Optional[str] = None):
        self.dsn = dsn or os.getenv("USBAY_SIM_STORAGE_POSTGRES_DSN")
        if not self.dsn:
            raise StorageUnavailable(
                "postgres backend is reserved for a future release and is not "
                "configured — failing closed"
            )
        # Even when a DSN is supplied, the training build ships without a
        # Postgres driver wired in. We fail closed rather than pretend.
        raise StorageUnavailable(
            "postgres backend is not enabled in the training build — "
            "failing closed"
        )

    def get(self, key: str) -> Optional[str]:  # pragma: no cover - unreachable
        raise StorageUnavailable("postgres backend not enabled")

    def set(self, key: str, value: str) -> None:  # pragma: no cover
        raise StorageUnavailable("postgres backend not enabled")

    def delete(self, key: str) -> None:  # pragma: no cover
        raise StorageUnavailable("postgres backend not enabled")

    def health(self) -> dict:  # pragma: no cover - unreachable
        return {"backend": self.backend, "available": False, "writable": False}


def get_storage_adapter(backend: Optional[str] = None, **kwargs) -> StorageAdapter:
    """Return a storage adapter for ``backend``.

    ``backend`` defaults to the ``USBAY_SIM_STORAGE_BACKEND`` environment
    variable, then to ``local``. Unknown backends fail closed.
    """
    name = (backend or os.getenv("USBAY_SIM_STORAGE_BACKEND") or "local").lower()
    if name not in _VALID_BACKENDS:
        raise StorageUnavailable("unknown storage backend: %r" % name)
    if name == "local":
        return LocalFileStorageAdapter(base_dir=kwargs.get("base_dir"))
    if name == "sqlite":
        return SqliteStorageAdapter(db_path=kwargs.get("db_path"))
    # postgres — fail closed (raises StorageUnavailable)
    return PostgresStorageAdapter(dsn=kwargs.get("dsn"))
