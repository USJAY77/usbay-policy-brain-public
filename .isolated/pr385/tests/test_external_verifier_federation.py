from __future__ import annotations

import json
from pathlib import Path

from governance.deployment_runtime_health import sha256_text
from governance.external_verifier_federation import (
    TRUSTED_ANCHOR_UNAVAILABLE,
    TRUSTED_ANCHOR_VERIFIED,
    TSA_TIMESTAMP_INVALID,
    TSA_TIMESTAMP_VERIFIED,
    VERIFIER_CONTRADICTION_DETECTED,
    VERIFIER_NODE_UNAVAILABLE,
    VERIFIER_QUORUM_FAILED,
    VERIFIER_QUORUM_REACHED,
    VerifierNode,
    local_verifier_from_ledger,
    verifier_from_cache,
    verify_federation_quorum,
    verify_trusted_anchor,
    verify_tsa_timestamp,
)
from governance.immutable_remote_attestation_ledger import append_ledger_entry
from tests.test_immutable_remote_attestation_ledger import _evidence


def _ledger(tmp_path: Path) -> tuple[Path, str]:
    ledger_path = tmp_path / "attestation-ledger.jsonl"
    entry = append_ledger_entry(ledger_path, evidence=_evidence(), timestamp_utc="2026-05-20T00:00:00Z")
    return ledger_path, entry["entry_hash"]


def _anchor(head_hash: str) -> dict:
    return {
        "ledger_head_hash": head_hash,
        "anchor_hash": sha256_text(f"anchor:{head_hash}"),
        "anchor_type": "LOCAL_TRUSTED_ANCHOR_STUB",
    }


def _timestamp(head_hash: str) -> dict:
    return {
        "message_imprint_hash": head_hash,
        "timestamp_token_hash": sha256_text(f"timestamp:{head_hash}"),
        "tsa_policy_id": "1.3.6.1.4.1.57264.1.1",
        "tsa_gen_time_utc": "2026-05-20T00:00:00Z",
    }


def test_two_of_three_quorum_reaches_with_local_remote_and_offline_cache(tmp_path: Path) -> None:
    ledger_path, head = _ledger(tmp_path)
    local = local_verifier_from_ledger("local-verifier", ledger_path)
    remote = VerifierNode("remote-verifier", "REMOTE", True, head, True)
    offline = verifier_from_cache({
        "verifier_id": "offline-cache",
        "verifier_type": "OFFLINE_CACHE",
        "available": False,
        "ledger_head_hash": "",
        "ledger_valid": False,
        "reason_codes": ["VERIFIER_NODE_UNAVAILABLE"],
    })

    result = verify_federation_quorum(
        verifiers=[local, remote, offline],
        expected_ledger_head_hash=head,
        trusted_anchor=_anchor(head),
        timestamp_record=_timestamp(head),
    )

    assert result["federation_status"] == "VERIFIED"
    assert result["matching_verifier_count"] == 2
    assert VERIFIER_QUORUM_REACHED in result["reason_codes"]
    assert VERIFIER_NODE_UNAVAILABLE in result["reason_codes"]
    assert TRUSTED_ANCHOR_VERIFIED in result["reason_codes"]
    assert TSA_TIMESTAMP_VERIFIED in result["reason_codes"]


def test_contradictory_verifier_blocks_even_with_two_matching(tmp_path: Path) -> None:
    _ledger_path, head = _ledger(tmp_path)
    nodes = [
        VerifierNode("local", "LOCAL", True, head, True),
        VerifierNode("remote-a", "REMOTE", True, head, True),
        VerifierNode("remote-b", "REMOTE", True, "b" * 64, True),
    ]

    result = verify_federation_quorum(
        verifiers=nodes,
        expected_ledger_head_hash=head,
        trusted_anchor=_anchor(head),
        timestamp_record=_timestamp(head),
    )

    assert result["federation_status"] == "BLOCKED"
    assert VERIFIER_CONTRADICTION_DETECTED in result["reason_codes"]
    assert VERIFIER_QUORUM_FAILED in result["reason_codes"]


def test_quorum_fails_on_single_available_match(tmp_path: Path) -> None:
    _ledger_path, head = _ledger(tmp_path)
    nodes = [
        VerifierNode("local", "LOCAL", True, head, True),
        VerifierNode("remote-a", "REMOTE", False, "", False),
        VerifierNode("remote-b", "OFFLINE_CACHE", False, "", False),
    ]

    result = verify_federation_quorum(
        verifiers=nodes,
        expected_ledger_head_hash=head,
        trusted_anchor=_anchor(head),
        timestamp_record=_timestamp(head),
    )

    assert result["federation_status"] == "BLOCKED"
    assert VERIFIER_QUORUM_FAILED in result["reason_codes"]
    assert VERIFIER_NODE_UNAVAILABLE in result["reason_codes"]


def test_trusted_anchor_must_match_ledger_head(tmp_path: Path) -> None:
    _ledger_path, head = _ledger(tmp_path)

    valid = verify_trusted_anchor(ledger_head_hash=head, anchor_record=_anchor(head))
    invalid = verify_trusted_anchor(ledger_head_hash=head, anchor_record=_anchor("b" * 64))

    assert valid["valid"] is True
    assert TRUSTED_ANCHOR_VERIFIED in valid["reason_codes"]
    assert invalid["valid"] is False
    assert TRUSTED_ANCHOR_UNAVAILABLE in invalid["reason_codes"]


def test_tsa_timestamp_must_match_message_imprint(tmp_path: Path) -> None:
    _ledger_path, head = _ledger(tmp_path)

    valid = verify_tsa_timestamp(evidence_hash=head, timestamp_record=_timestamp(head))
    invalid = verify_tsa_timestamp(evidence_hash=head, timestamp_record=_timestamp("b" * 64))

    assert valid["valid"] is True
    assert TSA_TIMESTAMP_VERIFIED in valid["reason_codes"]
    assert invalid["valid"] is False
    assert TSA_TIMESTAMP_INVALID in invalid["reason_codes"]


def test_federation_output_is_hash_only_and_redacted(tmp_path: Path) -> None:
    ledger_path, head = _ledger(tmp_path)
    local = local_verifier_from_ledger("local-verifier", ledger_path)
    result = verify_federation_quorum(
        verifiers=[
            local,
            VerifierNode("remote-verifier", "REMOTE", True, head, True),
            VerifierNode("offline-cache", "OFFLINE_CACHE", False, "", False),
        ],
        expected_ledger_head_hash=head,
        trusted_anchor=_anchor(head),
        timestamp_record=_timestamp(head),
    )
    encoded = json.dumps(result, sort_keys=True)

    assert result["federation_hash"]
    assert "PRIVATE " + "KEY" not in encoded
    assert "approval_" + "contents" not in encoded
    assert "raw_" + "payload" not in encoded
    assert "bearer " not in encoded.lower()
    assert "access_token" not in encoded.lower()
