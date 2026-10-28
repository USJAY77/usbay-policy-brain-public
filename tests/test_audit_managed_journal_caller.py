"""Real audit-writer failure through the synthetic authorization consumer.

This regression deliberately asserts preservation across the existing
chain-save/ledger-append boundary. It must not hide a partial write by injecting
an AuditWriteError or by replacing either real storage operation.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import sqlite3

import pytest

from audit import hash_chain
from audit.audit_writer import AuditWriteError, write_audit_record
from audit.immutable_ledger import (
    LedgerIntegrityError,
    ledger_path_for,
    verified_ledger_records,
)
from gateway import authorization_request_consumer as consumer
from tests.test_audit_exporter import isolated_anchor_keys
from tests.test_gateway_authorization_request_consumer import (
    NOW,
    _authority_registry,
    _context,
    _request,
)


pytestmark = pytest.mark.governance


def _snapshot(paths):
    return {path.name: path.read_bytes() if path.exists() else None for path in paths}


def _reserved_rows(path):
    with sqlite3.connect(path.absolute().as_uri() + "?mode=ro", uri=True) as connection:
        return connection.execute(
            "SELECT replay_key, request_hash, reserved_at "
            "FROM gateway_authorization_replay ORDER BY replay_key"
        ).fetchall()


@pytest.mark.parametrize(
    "paired", [False, True], ids=["ledger-only", "paired-chain-ledger"]
)
def test_real_consumer_managed_journal_failure_preserves_evidence_and_burns_replay(
    tmp_path, monkeypatch, paired
):
    isolated_anchor_keys(tmp_path, monkeypatch)
    request = _request(request_id="audit-managed-journal-caller")
    registry = _authority_registry(tmp_path, request, _context(request), "authority")

    # Establish that the unchanged real authority/consumer fixtures can ALLOW.
    # A separate control replay store and audit path never dispatch an adapter.
    control = consumer.consume_gateway_authorization_request(
        request,
        authority_registry=registry,
        replay_store=consumer.GatewayAuthorizationReplayStore(tmp_path / "control.db"),
        audit_path=tmp_path / "control-chain.json",
        now=NOW,
    )
    assert control["decision"] == "ALLOW"
    assert control["execution_authorized"] is True
    assert control["audit"] is not None

    chain = tmp_path / "chain.json"
    write_audit_record(
        "AUDIT_COMPATIBILITY_SEED",
        {"decision": "BLOCK", "tenant_id": "t1", "policy_hash": request["policy_hash"]},
        audit_path=chain,
    )
    ledger = ledger_path_for(chain)
    journal = Path(str(ledger) + ".writes.sqlite3")
    bound = [ledger, chain] if paired else [ledger]
    hashes = {path.name: hashlib.sha256(path.read_bytes()).hexdigest() for path in bound}
    with sqlite3.connect(journal) as connection:
        connection.execute(
            "CREATE TABLE writes (id INTEGER PRIMARY KEY, phase TEXT NOT NULL, hashes TEXT NOT NULL)"
        )
        connection.execute(
            "INSERT INTO writes (phase, hashes) VALUES ('COMPLETE', ?)",
            (json.dumps(hashes, sort_keys=True),),
        )
    assert len(verified_ledger_records(ledger)) == 1
    assert hash_chain.verify_chain(chain)

    marker = ledger.with_suffix(ledger.suffix + ".uncertain")
    lock = ledger.with_suffix(ledger.suffix + ".lock")
    assert lock.is_file()
    evidence = [chain, ledger, journal, marker, lock]
    evidence.extend(Path(str(journal) + suffix) for suffix in ("-journal", "-wal", "-shm"))
    before = _snapshot(evidence)
    assert before[marker.name] is None  # A legacy marker would block earlier.

    calls = []
    ledger_errors = []
    adapter_calls = []
    real_writer = consumer.write_audit_record
    real_save = hash_chain.save_chain
    real_append = hash_chain.append_evidence_event

    # Transparent spies preserve the real writer, save order and journal guard.
    def observed_writer(*args, **kwargs):
        calls.append("auditwriter")
        try:
            return real_writer(*args, **kwargs)
        except AuditWriteError as error:
            cause = error.__cause__
            seen = set()
            while cause is not None and id(cause) not in seen:
                seen.add(id(cause))
                if isinstance(cause, LedgerIntegrityError):
                    ledger_errors.append(str(cause))
                    break
                cause = cause.__cause__
            raise

    def observed_save(*args, **kwargs):
        calls.append("json_chain_save")
        return real_save(*args, **kwargs)

    def observed_append(*args, **kwargs):
        calls.append("ledger_append")
        return real_append(*args, **kwargs)

    def adapter():
        adapter_calls.append(True)
        raise AssertionError("SYNTHETIC_ADAPTER_MUST_NOT_RUN")

    monkeypatch.setattr(consumer, "write_audit_record", observed_writer)
    monkeypatch.setattr(hash_chain, "save_chain", observed_save)
    monkeypatch.setattr(hash_chain, "append_evidence_event", observed_append)
    replay_path = tmp_path / "replay.db"

    def attempt():
        return consumer.execute_with_gateway_authorization(
            request,
            executor=adapter,
            authority_registry=registry,
            replay_store=consumer.GatewayAuthorizationReplayStore(replay_path),
            audit_path=chain,
            now=NOW,
        )

    first = attempt()
    after_first = _snapshot(evidence)
    assert calls[0] == "auditwriter"
    assert ledger_errors  # The real writer must expose the real ledger guard.
    assert ledger_errors[0] == "ledger_journal_write_unsupported"
    assert first["executed"] is False
    assert first["decision"]["decision"] == "BLOCK"
    assert first["decision"]["execution_authorized"] is False
    assert first["decision"]["reason_codes"] == ["AUDIT_WRITE_FAILED"]
    assert first["decision"]["audit"] is None
    assert adapter_calls == []
    reserved = _reserved_rows(replay_path)
    assert {(key, digest) for key, digest, _ in reserved} == {
        ("nonce:" + request["nonce_reference"], request["request_hash"]),
        ("request:" + request["request_id"], request["request_hash"]),
    }

    # Check burn/replay even if the first attempt already damaged the chain.
    retry = attempt()
    after_retry = _snapshot(evidence)
    assert retry["executed"] is False
    assert retry["decision"]["decision"] == "BLOCK"
    assert retry["decision"]["execution_authorized"] is False
    assert retry["decision"]["audit"] is None
    assert "REPLAY_DETECTED" in retry["decision"]["reason_codes"]
    assert set(retry["decision"]["reason_codes"]) <= {"REPLAY_DETECTED", "AUDIT_WRITE_FAILED"}
    assert _reserved_rows(replay_path) == reserved
    assert adapter_calls == []
    for result in (first, retry):
        rendered = json.dumps(result)
        assert str(tmp_path) not in rendered
        assert "ledger_journal_write_unsupported" not in rendered
        assert "ledger_integrity_invalid" not in rendered
        assert "Traceback" not in rendered

    # Compare actual bytes, but failure output lists only filenames, not data.
    changed_first = [name for name, value in before.items() if after_first[name] != value]
    changed_retry = [name for name, value in after_first.items() if after_retry[name] != value]
    assert not changed_first and not changed_retry, (
        f"Committed evidence changed: first={changed_first}, retry={changed_retry}; calls={calls}"
    )
