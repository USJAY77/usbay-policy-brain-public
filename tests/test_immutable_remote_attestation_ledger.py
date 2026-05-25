from __future__ import annotations

import json
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from governance.deployment_runtime_health import deployment_runtime_health
from governance.immutable_remote_attestation_ledger import (
    LEDGER_APPEND_BLOCKED,
    LEDGER_APPEND_SUCCEEDED,
    LEDGER_HASH_CHAIN_BROKEN,
    LEDGER_HASH_CHAIN_VERIFIED,
    LEDGER_POLICY_MISMATCH,
    LEDGER_REMOTE_UNAVAILABLE,
    append_ledger_entry,
    build_attestation_ledger_evidence,
    create_ledger_entry,
    ledger_summary,
    verify_ledger,
)
from governance.runtime_attestation_authority import create_signed_runtime_attestation


ROOT = Path(__file__).resolve().parents[1]


def _keypair() -> tuple[str, str]:
    private_key = Ed25519PrivateKey.generate()
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("utf-8")
    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("utf-8")
    return private_pem, public_pem


def _runtime_snapshot() -> dict:
    return {
        "status": "OK",
        "mode": "NORMAL",
        "policy_signature_valid": True,
        "policy_version": "policy-v1",
        "policy_hash": "a" * 64,
        "replay_protection_active": True,
        "runtime_parity": {"runtime_parity_status": "VERIFIED"},
    }


def _deployment_health() -> dict:
    return deployment_runtime_health(
        root=ROOT,
        runtime_snapshot=_runtime_snapshot(),
        audit_chain_entries=[],
    )


def _attestation() -> dict:
    private_key, public_key = _keypair()
    return create_signed_runtime_attestation(
        root=ROOT,
        deployment_health=_deployment_health(),
        runtime_snapshot=_runtime_snapshot(),
        audit_chain_entries=[],
        audit_chain_valid=True,
        private_key_pem=private_key,
        public_key_pem=public_key,
        deployment_timestamp_utc="2026-05-20T00:00:00Z",
    )


def _evidence(**overrides) -> dict:
    deployment = _deployment_health()
    evidence = build_attestation_ledger_evidence(
        runtime_attestation=_attestation(),
        deployment_health=deployment,
        startup_verification=deployment,
        post_merge_branch_hygiene={
            "audit_hash": "b" * 64,
            "reason_codes": ["BRANCH_DELETED_AFTER_MERGE_VERIFIED"],
        },
        cleanup_denial_event={
            "audit_hash": "c" * 64,
            "reason_codes": ["PROTECTED_BRANCH_CLEANUP_DENIED"],
        },
        policy_version="policy-v1",
        policy_hash="a" * 64,
        audit_chain_hash="d" * 64,
    )
    evidence.update(overrides)
    return evidence


def test_append_only_ledger_records_runtime_and_deployment_bindings(tmp_path: Path) -> None:
    ledger_path = tmp_path / "attestation-ledger.jsonl"

    entry = append_ledger_entry(
        ledger_path,
        evidence=_evidence(),
        timestamp_utc="2026-05-20T00:00:00Z",
        expected_policy_hash="a" * 64,
    )
    verification = verify_ledger(ledger_path)

    assert LEDGER_APPEND_SUCCEEDED in entry["reason_codes"]
    assert LEDGER_REMOTE_UNAVAILABLE in entry["reason_codes"]
    assert entry["evidence"]["runtime_attestation_hash"]
    assert entry["evidence"]["deployment_health_hash"]
    assert entry["evidence"]["post_merge_branch_hygiene_hash"]
    assert entry["evidence"]["cleanup_denial_event_hash"]
    assert verification.valid is True
    assert LEDGER_HASH_CHAIN_VERIFIED in verification.reason_codes


def test_second_append_links_to_previous_hash(tmp_path: Path) -> None:
    ledger_path = tmp_path / "attestation-ledger.jsonl"
    first = append_ledger_entry(ledger_path, evidence=_evidence(), timestamp_utc="2026-05-20T00:00:00Z")
    second = append_ledger_entry(ledger_path, evidence=_evidence(audit_chain_hash="e" * 64), timestamp_utc="2026-05-20T00:01:00Z")

    assert second["sequence"] == 2
    assert second["previous_hash"] == first["entry_hash"]
    assert verify_ledger(ledger_path).head_hash == second["entry_hash"]


def test_tampered_ledger_fails_closed(tmp_path: Path) -> None:
    ledger_path = tmp_path / "attestation-ledger.jsonl"
    append_ledger_entry(ledger_path, evidence=_evidence(), timestamp_utc="2026-05-20T00:00:00Z")
    text = ledger_path.read_text(encoding="utf-8")
    ledger_path.write_text(text.replace("READY", "BLOCKED"), encoding="utf-8")

    verification = verify_ledger(ledger_path)

    assert verification.valid is False
    assert LEDGER_HASH_CHAIN_BROKEN in verification.reason_codes


def test_policy_mismatch_blocks_append() -> None:
    entry = create_ledger_entry(
        evidence=_evidence(policy_hash="b" * 64),
        previous_hash="0" * 64,
        sequence=1,
        timestamp_utc="2026-05-20T00:00:00Z",
        expected_policy_hash="a" * 64,
    )

    assert LEDGER_POLICY_MISMATCH in entry["reason_codes"]
    assert LEDGER_APPEND_BLOCKED in entry["reason_codes"]


def test_remote_required_blocks_when_remote_unavailable() -> None:
    entry = create_ledger_entry(
        evidence=_evidence(),
        previous_hash="0" * 64,
        sequence=1,
        timestamp_utc="2026-05-20T00:00:00Z",
        require_remote_anchor=True,
    )

    assert LEDGER_REMOTE_UNAVAILABLE in entry["reason_codes"]
    assert LEDGER_APPEND_BLOCKED in entry["reason_codes"]


def test_unsafe_evidence_is_rejected() -> None:
    try:
        build_attestation_ledger_evidence(
            runtime_attestation={"attestation_status": "SIGNED", "private_key": "do-not-log"},
            deployment_health=_deployment_health(),
            startup_verification=_deployment_health(),
            policy_version="policy-v1",
            policy_hash="a" * 64,
            audit_chain_hash="d" * 64,
        )
    except Exception as exc:
        assert str(exc) == LEDGER_APPEND_BLOCKED
    else:
        raise AssertionError("unsafe ledger evidence was accepted")


def test_ledger_summary_is_hash_only(tmp_path: Path) -> None:
    ledger_path = tmp_path / "attestation-ledger.jsonl"
    append_ledger_entry(ledger_path, evidence=_evidence(), timestamp_utc="2026-05-20T00:00:00Z")

    encoded = json.dumps(ledger_summary(ledger_path), sort_keys=True)

    assert "PRIVATE " + "KEY" not in encoded
    assert "approval_" + "contents" not in encoded
    assert "raw_" + "payload" not in encoded
    assert "token" not in encoded.lower()
