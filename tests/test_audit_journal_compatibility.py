"""Native stdlib tests of journal admission, not ledger signature validation."""
from __future__ import annotations

import fcntl
import hashlib
import json
import multiprocessing
import os
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest.mock import patch

from audit.journal_compatibility import AuditCompatibilityError, check_read_state


def _journal(ledger, phase="COMPLETE", hashes=None):
    journal = Path(str(ledger) + ".writes.sqlite3")
    if hashes is None:
        hashes = {ledger.name: hashlib.sha256(ledger.read_bytes()).hexdigest()}
    with sqlite3.connect(journal) as connection:
        connection.execute("CREATE TABLE IF NOT EXISTS writes (id INTEGER PRIMARY KEY, phase TEXT, hashes TEXT)")
        connection.execute("INSERT INTO writes (phase, hashes) VALUES (?, ?)",
                           (phase, json.dumps(hashes)))
    return journal


def _crash_after_pending(ledger):
    _journal(Path(ledger), "PENDING")
    os._exit(23)


def _locked_writer(ledger, ready, finish):
    ledger = Path(ledger)
    with Path(str(ledger) + ".lock").open("a+b") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        _journal(ledger, "PENDING")
        ready.send(True)
        if not finish.poll(5):
            os._exit(24)
        finish.recv()
        ledger.write_bytes(b"synthetic second snapshot")
        _journal(ledger)


class AuditJournalCompatibilityTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.ledger = self.root / "chain.json.ledger.jsonl"
        self.ledger.write_bytes(b"synthetic first snapshot")

    def test_legacy_absence_does_not_initialize_journal(self):
        self.assertFalse(check_read_state(self.ledger))
        self.assertEqual(sorted(p.name for p in self.root.iterdir()), [self.ledger.name])
        self.ledger.unlink()
        self.assertFalse(check_read_state(str(self.ledger)))
        self.assertEqual(list(self.root.iterdir()), [])

    def test_complete_pair_is_verified_without_rewriting(self):
        chain = self.root / "chain.json"
        chain.write_bytes(b"synthetic companion")
        _journal(self.ledger, hashes={p.name: hashlib.sha256(p.read_bytes()).hexdigest()
                                     for p in (chain, self.ledger)})
        before = {p.name: p.read_bytes() for p in self.root.iterdir()}
        self.assertTrue(check_read_state(self.ledger))
        self.assertTrue(check_read_state(str(self.ledger)))
        self.assertEqual(before, {p.name: p.read_bytes() for p in self.root.iterdir()})

    def test_legacy_marker_wins_over_complete_or_absent_journal(self):
        marker = self.ledger.with_suffix(self.ledger.suffix + ".uncertain")
        for managed in (False, True):
            if managed:
                _journal(self.ledger)
            for kind in ("file", "directory", "dangling_symlink"):
                with self.subTest(managed=managed, kind=kind):
                    if kind == "file":
                        marker.write_bytes(b"")
                    elif kind == "directory":
                        marker.mkdir()
                    else:
                        marker.symlink_to(self.root / "missing")
                    with self.assertRaisesRegex(AuditCompatibilityError, "ledger_write_uncertain"):
                        check_read_state(self.ledger)
                    self.assertTrue(os.path.lexists(marker))
                    marker.rmdir() if kind == "directory" else marker.unlink()

    def test_marker_inspection_failure_fails_closed(self):
        marker = self.ledger.with_suffix(self.ledger.suffix + ".uncertain")
        original = Path.lstat
        def denied(path, *args, **kwargs):
            if path == marker:
                raise PermissionError("synthetic private detail")
            return original(path, *args, **kwargs)
        with patch.object(Path, "lstat", denied):
            with self.assertRaisesRegex(AuditCompatibilityError, "^ledger_integrity_invalid$"):
                check_read_state(self.ledger)

    def test_empty_pending_and_unknown_phase_block(self):
        journal = Path(str(self.ledger) + ".writes.sqlite3")
        with sqlite3.connect(journal) as connection:
            connection.execute("CREATE TABLE writes (id INTEGER PRIMARY KEY, phase TEXT, hashes TEXT)")
        for phase in (None, "PENDING", "UNKNOWN"):
            with self.subTest(phase=phase):
                if phase is not None:
                    _journal(self.ledger, phase)
                with self.assertRaisesRegex(AuditCompatibilityError, "ledger_write_uncertain"):
                    check_read_state(self.ledger)

    def test_malformed_or_corrupt_journal_never_repairs(self):
        journal = Path(str(self.ledger) + ".writes.sqlite3")
        for raw in (b"", b"not sqlite"):
            with self.subTest(raw_size=len(raw)):
                journal.write_bytes(raw)
                with self.assertRaises(AuditCompatibilityError):
                    check_read_state(self.ledger)
                self.assertEqual(journal.read_bytes(), raw)
                journal.unlink()

    def test_invalid_hash_bindings_and_missing_required_files_block(self):
        journal = Path(str(self.ledger) + ".writes.sqlite3")
        for hashes in ({}, [], {"../escape": "a" * 64}, {self.ledger.name: "x" * 64},
                       {self.ledger.name: "0" * 64}, {"chain.json": "a" * 64},
                       {self.ledger.name: hashlib.sha256(self.ledger.read_bytes()).hexdigest(),
                        "chain.json": "a" * 64}):
            with self.subTest(hashes=hashes):
                _journal(self.ledger, hashes=hashes)
                with self.assertRaises(AuditCompatibilityError):
                    check_read_state(self.ledger)
                journal.unlink()
        _journal(self.ledger)
        self.ledger.unlink()
        with self.assertRaises(AuditCompatibilityError):
            check_read_state(self.ledger)

    def test_duplicate_hash_keys_are_rejected(self):
        journal = _journal(self.ledger)
        digest = hashlib.sha256(self.ledger.read_bytes()).hexdigest()
        raw = '{"%s":"%s","%s":"%s"}' % (self.ledger.name, digest, self.ledger.name, digest)
        with sqlite3.connect(journal) as connection:
            connection.execute("UPDATE writes SET hashes = ?", (raw,))
        with self.assertRaises(AuditCompatibilityError):
            check_read_state(self.ledger)

    def test_wrong_schema_and_view_are_rejected(self):
        journal = Path(str(self.ledger) + ".writes.sqlite3")
        for schema in ("CREATE TABLE writes (id TEXT, phase TEXT, hashes TEXT)",
                       "CREATE VIEW writes AS SELECT 1 AS id, 'COMPLETE' AS phase, '{}' AS hashes"):
            with self.subTest(schema=schema):
                with sqlite3.connect(journal) as connection:
                    connection.execute(schema)
                with self.assertRaises(AuditCompatibilityError):
                    check_read_state(self.ledger)
                journal.unlink()

    def test_journal_symlink_and_sidecars_block(self):
        journal = Path(str(self.ledger) + ".writes.sqlite3")
        journal.symlink_to(self.root / "missing")
        with self.assertRaises(AuditCompatibilityError):
            check_read_state(self.ledger)
        journal.unlink()
        _journal(self.ledger)
        for suffix in ("-journal", "-wal", "-shm"):
            with self.subTest(suffix=suffix):
                sidecar = Path(str(journal) + suffix)
                sidecar.write_bytes(b"")
                with self.assertRaisesRegex(AuditCompatibilityError, "ledger_write_uncertain"):
                    check_read_state(self.ledger)
                self.assertTrue(sidecar.exists())
                sidecar.unlink()

    def test_unreadable_sqlite_state_is_bounded(self):
        _journal(self.ledger)
        with patch("audit.journal_compatibility.sqlite3.connect", side_effect=sqlite3.OperationalError("private")):
            with self.assertRaisesRegex(AuditCompatibilityError, "^ledger_integrity_invalid$"):
                check_read_state(self.ledger)

    def test_native_crash_pending_survives_reopen(self):
        process = multiprocessing.get_context("fork").Process(target=_crash_after_pending, args=(str(self.ledger),))
        process.start()
        process.join(5)
        if process.is_alive():
            process.terminate()
            process.join(2)
        self.assertEqual(process.exitcode, 23)
        journal = Path(str(self.ledger) + ".writes.sqlite3")
        before = journal.read_bytes()
        for _ in range(2):
            with self.assertRaisesRegex(AuditCompatibilityError, "ledger_write_uncertain"):
                check_read_state(self.ledger)
        self.assertEqual(journal.read_bytes(), before)

    def test_independent_writer_lock_prevents_mixed_snapshot(self):
        context = multiprocessing.get_context("fork")
        ready, child_ready = context.Pipe(duplex=False)
        child_finish, finish = context.Pipe(duplex=False)
        process = context.Process(target=_locked_writer, args=(str(self.ledger), child_ready, child_finish))
        process.start()
        try:
            self.assertTrue(ready.poll(5))
            self.assertTrue(ready.recv())
            with Path(str(self.ledger) + ".lock").open("a+b") as lock:
                with self.assertRaises(BlockingIOError):
                    fcntl.flock(lock, fcntl.LOCK_SH | fcntl.LOCK_NB)
                finish.send(True)
                process.join(5)
                self.assertEqual(process.exitcode, 0)
                fcntl.flock(lock, fcntl.LOCK_SH)
                self.assertTrue(check_read_state(self.ledger))
                self.assertEqual(self.ledger.read_bytes(), b"synthetic second snapshot")
        finally:
            if process.is_alive():
                process.terminate()
            process.join(2)
            for endpoint in (ready, child_ready, child_finish, finish):
                endpoint.close()
