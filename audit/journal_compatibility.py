"""Read-only compatibility with the local audit write journal.

The caller holds the ledger lock. This does not provision, complete or repair
history, and does not establish freshness against coherent filesystem rollback.
Journal-managed writes require their original paired writer, not a legacy append.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import sqlite3
import stat


class AuditCompatibilityError(RuntimeError):
    pass


def _metadata(path: Path):
    try:
        return path.lstat()
    except FileNotFoundError:
        return None


def _identity(metadata):
    return (metadata.st_dev, metadata.st_ino, metadata.st_mode, metadata.st_nlink,
            metadata.st_uid, metadata.st_gid, metadata.st_size,
            metadata.st_mtime_ns, metadata.st_ctime_ns)


def _fingerprint(path: Path) -> str:
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
            raise AuditCompatibilityError("ledger_integrity_invalid")
        digest = hashlib.sha256()
        while chunk := os.read(descriptor, 65536):
            digest.update(chunk)
        after = os.fstat(descriptor)
        if _identity(before) != _identity(after) or _identity(after) != _identity(path.lstat()):
            raise AuditCompatibilityError("ledger_integrity_invalid")
        return digest.hexdigest()
    finally:
        os.close(descriptor)


def _unique_fields(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise AuditCompatibilityError("ledger_integrity_invalid")
        result[key] = value
    return result


def check_read_state(ledger: Path | str) -> bool:
    """Raise on uncertainty; return whether a verified journal is present.

    An absent journal permits legacy verification, not authorization. The legacy
    marker always wins, including a dangling symlink or an unreadable marker.
    No SQLite database/schema or missing history is initialized by this reader.
    """
    ledger = Path(ledger)
    try:
        if _metadata(ledger.with_suffix(ledger.suffix + ".uncertain")) is not None:
            raise AuditCompatibilityError("ledger_write_uncertain")
        journal = Path(str(ledger) + ".writes.sqlite3")
        metadata = _metadata(journal)
        # The existing journal producer uses SQLite's rollback-journal mode.
        # Sidecars imply a different or interrupted protocol; never recover it.
        if any(_metadata(Path(str(journal) + suffix)) is not None
               for suffix in ("-journal", "-wal", "-shm")):
            raise AuditCompatibilityError("ledger_write_uncertain")
        if metadata is None:
            return False
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
            raise AuditCompatibilityError("ledger_integrity_invalid")
        connection = sqlite3.connect(journal.absolute().as_uri() + "?mode=ro", uri=True, timeout=1)
        try:
            if connection.execute("SELECT type FROM sqlite_master WHERE name = 'writes'").fetchone() != ("table",):
                raise AuditCompatibilityError("ledger_integrity_invalid")
            columns = connection.execute("PRAGMA table_info(writes)").fetchall()
            if [(column[1], column[2].upper(), column[5]) for column in columns] != [
                    ("id", "INTEGER", 1), ("phase", "TEXT", 0), ("hashes", "TEXT", 0)]:
                raise AuditCompatibilityError("ledger_integrity_invalid")
            row = connection.execute("SELECT phase, hashes FROM writes ORDER BY id DESC LIMIT 1").fetchone()
        finally:
            connection.close()
        if _identity(metadata) != _identity(journal.lstat()):
            raise AuditCompatibilityError("ledger_integrity_invalid")
        if row is None or row[0] != "COMPLETE":
            raise AuditCompatibilityError("ledger_write_uncertain")
        expected = json.loads(row[1], object_pairs_hook=_unique_fields)
        allowed = {ledger.name}
        if ledger.name.endswith(".ledger.jsonl"):
            allowed.add(ledger.name[:-len(".ledger.jsonl")])
        if not isinstance(expected, dict) or ledger.name not in expected:
            raise AuditCompatibilityError("ledger_integrity_invalid")
        for name, digest in expected.items():
            if (name not in allowed or not isinstance(digest, str) or len(digest) != 64
                    or any(char not in "0123456789abcdef" for char in digest)
                    or _fingerprint(ledger.parent / name) != digest):
                raise AuditCompatibilityError("ledger_integrity_invalid")
        return True
    except AuditCompatibilityError:
        raise
    except Exception as exc:
        raise AuditCompatibilityError("ledger_integrity_invalid") from exc
