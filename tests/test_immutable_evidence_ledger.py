from __future__ import annotations

import json

from audit.hash_chain import AuditHashChain
from audit.immutable_ledger import (
    LedgerIntegrityError,
    append_evidence_event,
    export_evidence_bundle,
    ledger_path_for,
    verify_ledger,
)
from tests.provenance_helpers import install_valid_test_provenance
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
    provenance_context = install_valid_test_provenance(monkeypatch, tmp_path)
    isolated_anchor_keys(tmp_path, monkeypatch)
    chain = AuditHashChain(tmp_path / "audit_chain.json")
    chain.append_event("consensus_allow", _decision(reason_code="replay_checked"))
    ledger_path = ledger_path_for(chain.path)

    bundle = export_evidence_bundle(ledger_path, tmp_path / "export", provenance_context=provenance_context)

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
