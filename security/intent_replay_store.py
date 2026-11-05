"""Open-only, insert-only first-use state. Not an authority or signed audit ledger.

Provisioning is explicit. Missing/corrupt/locked state never self-initializes.
No expiry cleanup, release, repair, retry or recovery is implemented.
"""
from __future__ import annotations

import os
import sqlite3
import threading
from contextlib import contextmanager
from pathlib import Path

VERSION = "usbay.intent_governance.replay.v1"
DDL = "CREATE TABLE consumed (kind TEXT NOT NULL, reference TEXT NOT NULL, evidence TEXT NOT NULL, PRIMARY KEY(kind, reference))"


class IntentStoreError(RuntimeError):
    pass


class _ReservationGate:
    def __init__(self):
        self.lock = threading.Lock()
        self.users = 0


_RESERVATION_GATES_LOCK = threading.Lock()
_RESERVATION_GATES = {}


def _reset_reservation_gates_after_fork():
    """Drop process-local admission state; SQLite still fences other processes."""
    global _RESERVATION_GATES_LOCK, _RESERVATION_GATES
    _RESERVATION_GATES_LOCK = threading.Lock()
    _RESERVATION_GATES = {}


if hasattr(os, "register_at_fork"):
    os.register_at_fork(after_in_child=_reset_reservation_gates_after_fork)


@contextmanager
def _reservation_slot(path):
    """Reject local contention before opening SQLite; never wait or retry SQL."""
    uri = path.absolute().as_uri()
    with _RESERVATION_GATES_LOCK:
        gate = _RESERVATION_GATES.get(uri)
        if gate is None:
            gate = _ReservationGate()
            _RESERVATION_GATES[uri] = gate
        gate.users += 1
    acquired = False
    try:
        acquired = gate.lock.acquire(blocking=False)
        if not acquired:
            raise IntentStoreError("INTENT_STORE_UNAVAILABLE")
        yield uri
    finally:
        if acquired:
            gate.lock.release()
        with _RESERVATION_GATES_LOCK:
            gate.users -= 1
            if gate.users == 0:
                del _RESERVATION_GATES[uri]


class IntentReplayStore:
    def __init__(self, path: str | Path):
        self.path = Path(path)

    @classmethod
    def provision(cls, path: str | Path) -> "IntentReplayStore":
        """Explicit empty task-owned state; never invoked by consume()."""
        target = Path(path)
        fd = os.open(target, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        os.close(fd)
        connection = sqlite3.connect(target)
        try:
            connection.execute("PRAGMA synchronous=FULL")
            with connection:
                connection.execute(DDL)
                connection.execute("CREATE TABLE contract (version TEXT NOT NULL)")
                connection.execute("INSERT INTO contract VALUES (?)", (VERSION,))
        finally:
            connection.close()
        return cls(target)

    def reserve(self, *, intent_reference: str, nonce_reference: str, evidence: str) -> bool:
        try:
            with _reservation_slot(self.path) as target_uri:
                # URI mode=rw prevents automatic replacement of a missing database.
                connection = sqlite3.connect(target_uri + "?mode=rw", uri=True,
                                             timeout=0, isolation_level=None)
                try:
                    connection.execute("PRAGMA synchronous=FULL")
                    connection.execute("BEGIN IMMEDIATE")
                    if connection.execute("PRAGMA quick_check").fetchall() != [("ok",)]:
                        raise IntentStoreError("INTENT_STORE_UNAVAILABLE")
                    if connection.execute("SELECT version FROM contract").fetchall() != [(VERSION,)]:
                        raise IntentStoreError("INTENT_STORE_UNAVAILABLE")
                    schema = connection.execute("SELECT sql FROM sqlite_master WHERE name='consumed'").fetchone()
                    if schema != (DDL,):
                        raise IntentStoreError("INTENT_STORE_UNAVAILABLE")
                    # Check both identities before inserting either. No partially reserved success.
                    found = connection.execute(
                        "SELECT 1 FROM consumed WHERE (kind='intent' AND reference=?) OR (kind='nonce' AND reference=?)",
                        (intent_reference, nonce_reference),
                    ).fetchone()
                    if found:
                        connection.rollback()
                        return False
                    connection.executemany("INSERT INTO consumed VALUES (?,?,?)",
                                           [("intent", intent_reference, evidence), ("nonce", nonce_reference, evidence)])
                    connection.commit()
                    return True
                finally:
                    connection.close()
        except (sqlite3.Error, OSError, ValueError) as exc:
            raise IntentStoreError("INTENT_STORE_UNAVAILABLE") from exc

