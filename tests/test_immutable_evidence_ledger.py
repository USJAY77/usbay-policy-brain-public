from __future__ import annotations

import json
import hashlib
from pathlib import Path
import sqlite3

import pytest

from audit.hash_chain import AuditHashChain
from audit.immutable_ledger import (
    LedgerIntegrityError,
    append_evidence_event,
    export_evidence_bundle,
    ledger_path_for,
    verify_ledger,
    verified_ledger_records,
)
from tests.provenance_helpers import install_runtime_authority
from tests.test_audit_exporter import isolated_anchor_keys


def _decision(**overrides):
    decision = {
        "node_id": "node-1",
        "tenant_id": "t1",
        "tenant_hash": __import__("hashlib").sha256(b"t1").hexdigest(),
        "policy_hash": "policy-hash-1",
        "consensus_result": "ALLOW",
        "nonce_hash": "nonce-hash-1",
        "request_hash": "request-hash-1",
        "consensus_evidence_bundle": {
            "node_ids": ["node-1", "node-2", "node-3"],
            "timestamps": {"node-1": 1, "node-2": 1, "node-3": 1},
            "policy_hash": "policy-hash-1",
            "tenant_id": "t1",
            "tenant_hash": __import__("hashlib").sha256(b"t1").hexdigest(),
            "consensus_result": "allow",
            "sha256_evidence_hash": "evidence-hash-1",
            "consensus_signature": "consensus-signature-1",
        },
    }
    decision.update(overrides)
    return decision


def _records(path):
    return [
        json.loads(line)
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


def _write_records(path, records):
    path.write_text(
        "\n".join(json.dumps(record, sort_keys=True, separators=(",", ":")) for record in records) + "\n",
        encoding="utf-8",
    )


def _complete_journal(path):
    journal = Path(str(path) + ".writes.sqlite3")
    with sqlite3.connect(journal) as connection:
        connection.execute("CREATE TABLE writes (id INTEGER PRIMARY KEY, phase TEXT, hashes TEXT)")
        connection.execute("INSERT INTO writes (phase, hashes) VALUES ('COMPLETE', ?)",
                           (json.dumps({path.name: hashlib.sha256(path.read_bytes()).hexdigest()}),))
    return journal


def test_verified_reader_keeps_signed_order_and_blocks_legacy_managed_write(tmp_path, monkeypatch):
    isolated_anchor_keys(tmp_path, monkeypatch)
    path = tmp_path / "evidence.jsonl"
    expected = [append_evidence_event(path, action=action, decision=_decision())
                for action in ("consensus_allow", "execution_allowed")]
    _complete_journal(path)
    before = path.read_bytes()
    assert verified_ledger_records(path) == expected
    assert verified_ledger_records(str(path)) == expected
    assert verify_ledger(path)
    with pytest.raises(LedgerIntegrityError, match="ledger_journal_write_unsupported"):
        append_evidence_event(path, action="no_legacy_append", decision=_decision())
    assert path.read_bytes() == before
    assert verified_ledger_records(path) == expected


@pytest.mark.parametrize("kind", ["file", "directory", "dangling_symlink"])
def test_legacy_uncertainty_blocks_even_with_complete_journal(tmp_path, monkeypatch, kind):
    isolated_anchor_keys(tmp_path, monkeypatch)
    path = tmp_path / "evidence.jsonl"
    append_evidence_event(path, action="consensus_allow", decision=_decision())
    _complete_journal(path)
    marker = path.with_suffix(path.suffix + ".uncertain")
    if kind == "file":
        marker.write_bytes(b"")
    elif kind == "directory":
        marker.mkdir()
    else:
        marker.symlink_to(tmp_path / "missing")
    before = path.read_bytes()
    assert not verify_ledger(path)
    with pytest.raises(LedgerIntegrityError, match="ledger_write_uncertain"):
        verified_ledger_records(path)
    with pytest.raises(LedgerIntegrityError):
        append_evidence_event(path, action="denied", decision=_decision())
    assert path.read_bytes() == before
    assert marker.exists() or marker.is_symlink()


@pytest.mark.parametrize("state", ["pending", "empty", "corrupt", "missing_ledger", "changed_ledger"])
def test_required_journal_state_never_becomes_empty_history(tmp_path, monkeypatch, state):
    isolated_anchor_keys(tmp_path, monkeypatch)
    path = tmp_path / "evidence.jsonl"
    append_evidence_event(path, action="consensus_allow", decision=_decision())
    journal = _complete_journal(path)
    if state == "corrupt":
        journal.write_bytes(b"not sqlite")
    elif state == "missing_ledger":
        path.unlink()
    elif state == "changed_ledger":
        path.write_bytes(b"")
    else:
        with sqlite3.connect(journal) as connection:
            connection.execute("DELETE FROM writes" if state == "empty" else
                               "UPDATE writes SET phase = 'PENDING'")
    before = journal.read_bytes()
    assert not verify_ledger(path)
    with pytest.raises(LedgerIntegrityError):
        verified_ledger_records(path)
    assert journal.read_bytes() == before


def test_unreadable_ledger_has_bounded_reader_error(tmp_path, monkeypatch):
    isolated_anchor_keys(tmp_path, monkeypatch)
    path = tmp_path / "evidence.jsonl"
    append_evidence_event(path, action="consensus_allow", decision=_decision())
    original = Path.read_text
    def denied(candidate, *args, **kwargs):
        if candidate == path:
            raise PermissionError("private synthetic diagnostic")
        return original(candidate, *args, **kwargs)
    monkeypatch.setattr(Path, "read_text", denied)
    assert not verify_ledger(path)
    with pytest.raises(LedgerIntegrityError, match="^ledger_integrity_invalid$"):
        verified_ledger_records(path)


@pytest.mark.parametrize("record", [None, [], "invalid"])
def test_malformed_record_is_bounded_and_preserved(tmp_path, record):
    path = tmp_path / "evidence.jsonl"
    path.write_text(json.dumps(record) + "\n")
    before = path.read_bytes()
    with pytest.raises(LedgerIntegrityError, match="ledger_integrity_invalid"):
        verified_ledger_records(path)
    assert path.read_bytes() == before


def test_gateway_lifecycle_readers_keep_committed_evidence_contract(tmp_path, monkeypatch):
    from audit.audit_writer import write_audit_record
    from security.gateway_lifecycle import committed_audit_event, writer_evidence
    isolated_anchor_keys(tmp_path, monkeypatch)
    chain = tmp_path / "consumer.json"
    result = write_audit_record("GATEWAY_AUTHORIZATION_REQUEST_DECISION",
                               {"decision": "ALLOW", "tenant_id": "t1"}, audit_path=chain)
    path = ledger_path_for(chain)
    _complete_journal(path)
    event = writer_evidence(chain, result)
    assert event == committed_audit_event(chain, audit_hash=event["current_event_hash"])
    journal = Path(str(path) + ".writes.sqlite3")
    with sqlite3.connect(journal) as connection:
        connection.execute("UPDATE writes SET phase = 'PENDING'")
    with pytest.raises(LedgerIntegrityError):
        writer_evidence(chain, result)


def test_immutable_ledger_chains_and_signs_events(tmp_path, monkeypatch) -> None:
    isolated_anchor_keys(tmp_path, monkeypatch)
    path = tmp_path / "evidence.jsonl"

    first = append_evidence_event(path, action="consensus_allow", decision=_decision())
    second = append_evidence_event(path, action="execution_allowed", decision=_decision())

    assert first["previous_event_hash"] == "GENESIS"
    assert second["previous_event_hash"] == first["current_event_hash"]
    assert first["signature"]
    assert second["signature"]
    assert verify_ledger(path)


def test_immutable_ledger_detects_chain_tampering(tmp_path, monkeypatch) -> None:
    isolated_anchor_keys(tmp_path, monkeypatch)
    path = tmp_path / "evidence.jsonl"
    append_evidence_event(path, action="consensus_allow", decision=_decision())

    records = _records(path)
    records[0]["decision"]["consensus_result"] = "DENY"
    _write_records(path, records)

    assert not verify_ledger(path)


def test_immutable_ledger_detects_previous_hash_mismatch(tmp_path, monkeypatch) -> None:
    isolated_anchor_keys(tmp_path, monkeypatch)
    path = tmp_path / "evidence.jsonl"
    append_evidence_event(path, action="consensus_allow", decision=_decision())
    append_evidence_event(path, action="execution_allowed", decision=_decision())

    records = _records(path)
    records[1]["previous_event_hash"] = "broken"
    _write_records(path, records)

    assert not verify_ledger(path)


def test_immutable_ledger_detects_signature_corruption(tmp_path, monkeypatch) -> None:
    isolated_anchor_keys(tmp_path, monkeypatch)
    path = tmp_path / "evidence.jsonl"
    append_evidence_event(path, action="consensus_allow", decision=_decision())

    records = _records(path)
    records[0]["signature"] = "invalid"
    _write_records(path, records)

    assert not verify_ledger(path)


def test_immutable_ledger_append_fails_closed_when_corrupt(tmp_path, monkeypatch) -> None:
    isolated_anchor_keys(tmp_path, monkeypatch)
    path = tmp_path / "evidence.jsonl"
    append_evidence_event(path, action="consensus_allow", decision=_decision())
    records = _records(path)
    records[0]["current_event_hash"] = "0" * 64
    _write_records(path, records)

    try:
        append_evidence_event(path, action="execution_allowed", decision=_decision())
    except LedgerIntegrityError as exc:
        assert "ledger_integrity_invalid" in str(exc)
    else:
        raise AssertionError("corrupt ledger must fail closed on append")


def test_replay_and_consensus_evidence_preserved_in_export_bundle(tmp_path, monkeypatch) -> None:
    authority = install_runtime_authority(monkeypatch, tmp_path)
    isolated_anchor_keys(tmp_path, monkeypatch)
    chain = AuditHashChain(tmp_path / "audit_chain.json")
    chain.append_event("consensus_allow", _decision(reason_code="replay_checked"))
    ledger_path = ledger_path_for(chain.path)

    bundle = export_evidence_bundle(ledger_path, tmp_path / "export", provenance_authority=authority)

    assert (tmp_path / "export" / "audit.jsonl").exists()
    assert (tmp_path / "export" / "ledger.sha256").exists()
    assert (tmp_path / "export" / "signatures.json").exists()
    assert (tmp_path / "export" / "consensus_evidence.json").exists()
    assert bundle["ledger.sha256"] == (tmp_path / "export" / "ledger.sha256").read_text(encoding="utf-8").strip()
    assert "nonce-hash-1" in bundle["audit.jsonl"]
    assert "evidence-hash-1" in json.dumps(bundle["consensus_evidence.json"], sort_keys=True)
    assert "raw_nonce" not in bundle["audit.jsonl"]
    assert "private_key" not in bundle["audit.jsonl"]


def test_immutable_ledger_rejects_raw_nonce_and_secret_material(tmp_path, monkeypatch) -> None:
    isolated_anchor_keys(tmp_path, monkeypatch)
    path = tmp_path / "evidence.jsonl"

    try:
        append_evidence_event(path, action="consensus_allow", decision=_decision(raw_nonce="do-not-log"))
    except LedgerIntegrityError as exc:
        assert "forbidden_evidence_field" in str(exc)
    else:
        raise AssertionError("raw nonce evidence must be rejected")
