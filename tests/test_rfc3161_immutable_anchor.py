from __future__ import annotations

import base64
import json
from datetime import datetime, timezone

import pytest

from audit.anchor import MockTSAClient
from audit.immutable_ledger import append_evidence_event, export_evidence_bundle
from audit.rfc3161_anchor import (
    component_hashes,
    create_timestamp_proof,
    message_imprint,
    verify_timestamp_proof,
)
from tests.provenance_helpers import install_runtime_authority
from tests.test_audit_exporter import isolated_anchor_keys


def _decision():
    return {
        "node_id": "node-1",
        "tenant_id": "t1",
        "tenant_hash": __import__("hashlib").sha256(b"t1").hexdigest(),
        "policy_hash": "policy-hash-1",
        "consensus_result": "ALLOW",
        "nonce_hash": "nonce-hash-1",
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


def _proof(message_hash="ab" * 32, previous="GENESIS"):
    return create_timestamp_proof(message_hash, previous_timestamp_hash=previous, tsa_client=MockTSAClient())


def test_export_bundle_includes_verified_detached_rfc3161_timestamp(tmp_path, monkeypatch) -> None:
    authority = install_runtime_authority(monkeypatch, tmp_path)
    isolated_anchor_keys(tmp_path, monkeypatch)
    ledger = tmp_path / "evidence.jsonl"
    append_evidence_event(ledger, action="consensus_allow", decision=_decision())

    bundle = export_evidence_bundle(ledger, tmp_path / "export", provenance_authority=authority)

    assert (tmp_path / "export" / "rfc3161_timestamp.tsr").exists()
    assert (tmp_path / "export" / "timestamp_verification.json").exists()
    assert (tmp_path / "export" / "tsa_certificate_chain.pem").exists()
    assert (tmp_path / "export" / "tsa_policy_oid.txt").exists()
    assert bundle["timestamp_verification.json"]["valid"] is True
    assert bundle["rfc3161_timestamp.tsr"].strip()
    token_text = (tmp_path / "export" / "rfc3161_timestamp.tsr").read_text(encoding="utf-8")
    assert "nonce-hash-1" not in token_text
    assert "consensus-signature-1" not in token_text
    assert bundle["tsa_policy_oid.txt"] == "1.3.6.1.4.1.57264.1.1"


def test_external_tsa_unavailable_fails_closed(tmp_path, monkeypatch) -> None:
    authority = install_runtime_authority(monkeypatch, tmp_path)
    isolated_anchor_keys(tmp_path, monkeypatch)
    monkeypatch.setenv("TSA_MODE", "external")
    monkeypatch.delenv("TSA_URL", raising=False)
    monkeypatch.delenv("USBAY_TSA_URL", raising=False)
    monkeypatch.setenv("TSA_POLICY_OID", "1.3.6.1.4.1.57264.1.1")
    ledger = tmp_path / "evidence.jsonl"
    append_evidence_event(ledger, action="consensus_allow", decision=_decision())

    with pytest.raises(Exception) as exc:
        export_evidence_bundle(ledger, tmp_path / "export", provenance_authority=authority)

    assert "missing TSA URL" in str(exc.value)


def test_message_imprint_is_over_component_hashes_only() -> None:
    components = component_hashes(
        audit_jsonl='{"nonce_hash":"nonce-hash-1"}\n',
        ledger_sha256="cd" * 32,
        signatures={"event-1": {"signature": "sig"}},
        consensus_evidence={"event-1": {"sha256_evidence_hash": "evidence"}},
    )
    imprint = message_imprint(components)
    proof = _proof(imprint)
    verification = verify_timestamp_proof(proof, imprint)

    assert verification["valid"] is True
    assert "nonce-hash-1" not in proof["token"]
    assert "sig" not in proof["token"]


def test_invalid_tsa_signature_fails_closed() -> None:
    proof = _proof()
    token = json.loads(base64.b64decode(proof["token"]).decode("utf-8"))
    token["signature"] = "bad-signature"
    proof["token"] = base64.b64encode(json.dumps(token, sort_keys=True).encode("utf-8")).decode("ascii")

    verification = verify_timestamp_proof(proof, "ab" * 32)

    assert verification["valid"] is False
    assert "tsa_signature_invalid" in verification["errors"]


def test_malformed_token_rejected() -> None:
    proof = _proof()
    proof["token"] = "not-base64"

    verification = verify_timestamp_proof(proof, "ab" * 32)

    assert verification["valid"] is False
    assert "timestamp_token_malformed" in verification["errors"]


def test_timestamp_corruption_fails_closed() -> None:
    proof = _proof()
    proof["timestamp_hash"] = "0" * 64

    verification = verify_timestamp_proof(proof, "ab" * 32)

    assert verification["valid"] is False
    assert "timestamp_hash_mismatch" in verification["errors"]


def test_replayed_timestamp_token_fails_closed() -> None:
    proof = _proof()
    seen = set()
    first = verify_timestamp_proof(proof, "ab" * 32, seen_token_hashes=seen)
    seen.add(__import__("hashlib").sha256(proof["token"].encode("utf-8")).hexdigest())
    second = verify_timestamp_proof(proof, "ab" * 32, seen_token_hashes=seen)

    assert first["valid"] is True
    assert second["valid"] is False
    assert second["timestamp_replay_detected"] is True


def test_message_imprint_mismatch_fails_closed() -> None:
    proof = _proof("ab" * 32)

    verification = verify_timestamp_proof(proof, "cd" * 32)

    assert verification["valid"] is False
    assert "message_imprint_mismatch" in verification["errors"]


def test_expired_tsa_certificate_fails_closed() -> None:
    proof = _proof()
    proof["tsa_cert_not_after"] = "2020-01-01T00:00:00Z"

    verification = verify_timestamp_proof(
        proof,
        "ab" * 32,
        now=datetime(2026, 1, 1, tzinfo=timezone.utc),
    )

    assert verification["valid"] is False
    assert "tsa_certificate_expired" in verification["errors"]


def test_wrong_policy_oid_rejected(monkeypatch) -> None:
    monkeypatch.setenv("TSA_POLICY_OID", "1.2.3.4.5")
    proof = _proof()

    verification = verify_timestamp_proof(proof, "ab" * 32)

    assert verification["valid"] is False
    assert "tsa_policy_oid_mismatch" in verification["errors"]


def test_production_mode_rejects_mock_tsa(monkeypatch) -> None:
    monkeypatch.setenv("TSA_MODE", "external")
    proof = _proof()

    verification = verify_timestamp_proof(proof, "ab" * 32)

    assert verification["valid"] is False
    assert "mock_tsa_rejected_in_production" in verification["errors"]


def test_no_secret_leakage_in_timestamp_export(tmp_path, monkeypatch) -> None:
    authority = install_runtime_authority(monkeypatch, tmp_path)
    isolated_anchor_keys(tmp_path, monkeypatch)
    ledger = tmp_path / "evidence.jsonl"
    append_evidence_event(ledger, action="consensus_allow", decision=_decision())

    export_evidence_bundle(ledger, tmp_path / "export", provenance_authority=authority)
    export_text = "\n".join(path.read_text(encoding="utf-8") for path in (tmp_path / "export").iterdir())

    assert "raw audit" not in export_text
    assert "approval" not in export_text
    assert "private_key" not in export_text
    assert "secret" not in export_text
    assert "nonce-hash-1" not in (tmp_path / "export" / "rfc3161_timestamp.tsr").read_text(encoding="utf-8")


def test_append_only_timestamp_continuity() -> None:
    first = _proof("ab" * 32)
    first_result = verify_timestamp_proof(first, "ab" * 32)
    second = _proof("cd" * 32, previous=first_result["timestamp_hash"])
    second_result = verify_timestamp_proof(
        second,
        "cd" * 32,
        previous_timestamp_hash=first_result["timestamp_hash"],
    )
    broken = verify_timestamp_proof(second, "cd" * 32, previous_timestamp_hash="wrong")

    assert first_result["valid"] is True
    assert second_result["valid"] is True
    assert broken["valid"] is False
    assert "timestamp_continuity_invalid" in broken["errors"]
