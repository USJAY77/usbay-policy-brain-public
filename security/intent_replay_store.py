"""Open-only, insert-only first-use state. Not an authority or signed audit ledger.

Provisioning is explicit. Missing/corrupt/locked state never self-initializes.
No expiry cleanup, release, repair, retry or recovery is implemented.
"""
from __future__ import annotations

import os
import sqlite3
from pathlib import Path

VERSION = "usbay.intent_governance.replay.v1"
DDL = "CREATE TABLE consumed (kind TEXT NOT NULL, reference TEXT NOT NULL, evidence TEXT NOT NULL, PRIMARY KEY(kind, reference))"


class IntentStoreError(RuntimeError):
    pass


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
            # URI mode=rw prevents automatic replacement of a missing database.
            connection = sqlite3.connect(self.path.absolute().as_uri() + "?mode=rw", uri=True,
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
