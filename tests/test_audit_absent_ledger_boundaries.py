"""Proposed boundary regressions; synthetic authority, real local audit storage."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import sqlite3

import pytest

from audit import hash_chain
from audit.audit_writer import write_audit_record
from audit.immutable_ledger import LedgerIntegrityError, ledger_path_for
from gateway import authorization_request_consumer as consumer
from tests.test_audit_exporter import isolated_anchor_keys
from tests.test_audit_managed_journal_caller import _reserved_rows, _snapshot
from tests.test_gateway_authorization_request_consumer import (
    NOW, _authority_registry, _context, _request,
)

pytestmark = pytest.mark.governance
STATES = ("marker", "sidecar", "pending", "complete-missing-ledger")


def _assert_preserved(paths, before):
    after = _snapshot(paths)
    changed = [name for name in before if after[name] != before[name]]
    # Never display bytes, keys, signatures or payloads in assertion messages.
    assert not changed, "Existing evidence changed: " + ",".join(changed)


@pytest.fixture
def absent_history(tmp_path, monkeypatch, request):
    isolated_anchor_keys(tmp_path, monkeypatch)
    chain = tmp_path / "chain.json"
    write_audit_record(
        "ABSENT_LEDGER_SEED",
        {"decision": "BLOCK", "tenant_id": "t1", "policy_hash": "synthetic-policy"},
        audit_path=chain,
    )
    ledger = ledger_path_for(chain)
    assert hash_chain.verify_chain(chain)
    digest = hashlib.sha256(ledger.read_bytes()).hexdigest()
    journal = Path(str(ledger) + ".writes.sqlite3")
    marker = ledger.with_suffix(ledger.suffix + ".uncertain")
    lock = ledger.with_suffix(ledger.suffix + ".lock")
    assert lock.is_file()  # Established by seed; no lock removal required.
    ledger.unlink()  # Synthetic fixture only; never a recovery instruction.
    state = request.param
    if state == "marker":
        marker.write_bytes(b"synthetic-uncertainty\n")
    elif state == "sidecar":
        Path(str(journal) + "-journal").write_bytes(b"synthetic-sidecar\n")
    elif state in ("pending", "complete-missing-ledger"):
        with sqlite3.connect(journal) as connection:
            connection.execute(
                "CREATE TABLE writes (id INTEGER PRIMARY KEY, phase TEXT NOT NULL, hashes TEXT NOT NULL)"
            )
            connection.execute(
                "INSERT INTO writes (phase, hashes) VALUES (?, ?)",
                ("PENDING" if state == "pending" else "COMPLETE",
                 json.dumps({ledger.name: digest}, sort_keys=True)),
            )
    else:
        raise AssertionError("Unsupported fixture state")
    paths = [chain, ledger, journal, marker, lock]
    paths.extend(Path(str(journal) + suffix) for suffix in ("-journal", "-wal", "-shm"))
    return chain, paths, _snapshot(paths)


@pytest.mark.parametrize("absent_history", STATES, indirect=True)
def test_absent_ledger_append_refuses_without_evidence_mutation(absent_history):
    chain, paths, before = absent_history
    with pytest.raises(LedgerIntegrityError) as caught:
        hash_chain.append_event("SYNTHETIC_APPEND", {"tenant_id": "t1"}, chain)
    assert str(caught.value) in {"ledger_write_uncertain", "ledger_integrity_invalid"}
    _assert_preserved(paths, before)


@pytest.mark.parametrize("absent_history", STATES, indirect=True)
def test_absent_ledger_consumer_blocks_and_burns_replay(absent_history, tmp_path):
    chain, paths, before = absent_history
    request = _request(request_id="absent-ledger-caller")
    registry = _authority_registry(tmp_path, request, _context(request), "authority")
    control = consumer.consume_gateway_authorization_request(
        request, authority_registry=registry,
        replay_store=consumer.GatewayAuthorizationReplayStore(tmp_path / "control.db"),
        audit_path=tmp_path / "control-chain.json", now=NOW,
    )
    assert control["decision"] == "ALLOW"
    assert control["execution_authorized"] is True
    assert control["audit"] is not None
    adapter_calls = []

    def adapter():
        adapter_calls.append(True)
        raise AssertionError("SYNTHETIC_ADAPTER_MUST_NOT_RUN")

    replay = tmp_path / "replay.db"

    def attempt():
        return consumer.execute_with_gateway_authorization(
            request, executor=adapter, authority_registry=registry,
            replay_store=consumer.GatewayAuthorizationReplayStore(replay),
            audit_path=chain, now=NOW,
        )

    first = attempt()
    assert first["executed"] is False
    assert first["decision"]["decision"] == "BLOCK"
    assert first["decision"]["execution_authorized"] is False
    assert first["decision"]["reason_codes"] == ["AUDIT_WRITE_FAILED"]
    assert first["decision"]["audit"] is None
    assert not adapter_calls
    _assert_preserved(paths, before)
    reserved = _reserved_rows(replay)
    assert {(key, digest) for key, digest, _ in reserved} == {
        ("nonce:" + request["nonce_reference"], request["request_hash"]),
        ("request:" + request["request_id"], request["request_hash"]),
    }
    retry = attempt()
    assert retry["executed"] is False
    assert retry["decision"]["decision"] == "BLOCK"
    assert retry["decision"]["execution_authorized"] is False
    assert retry["decision"]["audit"] is None
    assert "REPLAY_DETECTED" in retry["decision"]["reason_codes"]
    assert set(retry["decision"]["reason_codes"]) <= {"REPLAY_DETECTED", "AUDIT_WRITE_FAILED"}
    assert _reserved_rows(replay) == reserved
    assert not adapter_calls
    _assert_preserved(paths, before)
    for result in (first, retry):
        rendered = json.dumps(result)
        assert str(tmp_path) not in rendered
        assert "ledger_write_uncertain" not in rendered
        assert "ledger_integrity_invalid" not in rendered
        assert "Traceback" not in rendered


@pytest.mark.parametrize("absent_history", STATES, indirect=True)
def test_absent_ledger_reader_fails_closed_without_repair(absent_history):
    chain, paths, before = absent_history
    # Expected to expose the current ledger.exists() verification bypass.
    assert hash_chain.verify_chain(chain) is False
    _assert_preserved(paths, before)
