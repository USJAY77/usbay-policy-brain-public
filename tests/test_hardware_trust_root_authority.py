from __future__ import annotations

import json
from pathlib import Path

from governance.deployment_runtime_health import sha256_text
from governance.external_verifier_federation import VerifierNode, local_verifier_from_ledger, verify_federation_quorum
from governance.hardware_trust_root_authority import (
    HARDWARE_TRUST_ROOT_BLOCKED,
    HARDWARE_TRUST_ROOT_DEGRADED,
    HARDWARE_TRUST_ROOT_MISMATCH,
    HARDWARE_TRUST_ROOT_MISSING,
    HARDWARE_TRUST_ROOT_UNSUPPORTED,
    HARDWARE_TRUST_ROOT_VERIFIED,
    SOFTWARE_FALLBACK,
    create_trust_root_evidence,
    verify_hardware_trust_root,
)
from governance.immutable_remote_attestation_ledger import append_ledger_entry
from tests.test_immutable_remote_attestation_ledger import _attestation, _evidence


def _context(tmp_path: Path) -> dict:
    ledger_path = tmp_path / "attestation-ledger.jsonl"
    ledger_entry = append_ledger_entry(ledger_path, evidence=_evidence(), timestamp_utc="2026-05-20T00:00:00Z")
    head = ledger_entry["entry_hash"]
    trusted_anchor = {
        "ledger_head_hash": head,
        "anchor_hash": sha256_text(f"anchor:{head}"),
    }
    timestamp = {
        "message_imprint_hash": head,
        "timestamp_token_hash": sha256_text(f"timestamp:{head}"),
        "tsa_policy_id": "1.3.6.1.4.1.57264.1.1",
        "tsa_gen_time_utc": "2026-05-20T00:00:00Z",
    }
    federation = verify_federation_quorum(
        verifiers=[
            local_verifier_from_ledger("local", ledger_path),
            VerifierNode("remote", "REMOTE", True, head, True),
            VerifierNode("offline", "OFFLINE_CACHE", False, "", False),
        ],
        expected_ledger_head_hash=head,
        trusted_anchor=trusted_anchor,
        timestamp_record=timestamp,
    )
    return {
        "federation": federation,
        "runtime_attestation": _attestation(),
        "ledger_hash": head,
        "trusted_anchor": federation["trusted_anchor"],
        "tsa_timestamp": federation["tsa_timestamp"],
        "policy_hash": "a" * 64,
        "policy_version": "policy-v1",
    }


def _verify_with_type(tmp_path: Path, trust_root_type: str) -> dict:
    ctx = _context(tmp_path)
    evidence = create_trust_root_evidence(
        trust_root_type=trust_root_type,
        trust_root_hash=sha256_text(f"{trust_root_type}:root"),
        verifier_federation_result=ctx["federation"],
        runtime_attestation_result=ctx["runtime_attestation"],
        immutable_ledger_hash=ctx["ledger_hash"],
        trusted_anchor_result=ctx["trusted_anchor"],
        tsa_timestamp_result=ctx["tsa_timestamp"],
        policy_hash=ctx["policy_hash"],
        policy_version=ctx["policy_version"],
    )
    return verify_hardware_trust_root(
        trust_root_evidence=evidence,
        verifier_federation_result=ctx["federation"],
        runtime_attestation_result=ctx["runtime_attestation"],
        immutable_ledger_hash=ctx["ledger_hash"],
        trusted_anchor_result=ctx["trusted_anchor"],
        tsa_timestamp_result=ctx["tsa_timestamp"],
        policy_hash=ctx["policy_hash"],
        policy_version=ctx["policy_version"],
        hardware_required=True,
    )


def test_tpm_hardware_trust_root_verifies(tmp_path: Path) -> None:
    result = _verify_with_type(tmp_path, "TPM")

    assert result["trust_root_status"] == "VERIFIED"
    assert HARDWARE_TRUST_ROOT_VERIFIED in result["reason_codes"]
    assert result["merge_authority_granted"] is False


def test_hsm_hardware_trust_root_verifies(tmp_path: Path) -> None:
    result = _verify_with_type(tmp_path, "HSM")

    assert result["trust_root_status"] == "VERIFIED"
    assert HARDWARE_TRUST_ROOT_VERIFIED in result["reason_codes"]


def test_secure_enclave_hardware_trust_root_verifies(tmp_path: Path) -> None:
    result = _verify_with_type(tmp_path, "SECURE_ENCLAVE")

    assert result["trust_root_status"] == "VERIFIED"
    assert HARDWARE_TRUST_ROOT_VERIFIED in result["reason_codes"]


def test_software_fallback_is_degraded_not_full_trust(tmp_path: Path) -> None:
    ctx = _context(tmp_path)
    evidence = create_trust_root_evidence(
        trust_root_type=SOFTWARE_FALLBACK,
        trust_root_hash=sha256_text("software:fallback"),
        verifier_federation_result=ctx["federation"],
        runtime_attestation_result=ctx["runtime_attestation"],
        immutable_ledger_hash=ctx["ledger_hash"],
        trusted_anchor_result=ctx["trusted_anchor"],
        tsa_timestamp_result=ctx["tsa_timestamp"],
        policy_hash=ctx["policy_hash"],
        policy_version=ctx["policy_version"],
    )

    result = verify_hardware_trust_root(
        trust_root_evidence=evidence,
        verifier_federation_result=ctx["federation"],
        runtime_attestation_result=ctx["runtime_attestation"],
        immutable_ledger_hash=ctx["ledger_hash"],
        trusted_anchor_result=ctx["trusted_anchor"],
        tsa_timestamp_result=ctx["tsa_timestamp"],
        policy_hash=ctx["policy_hash"],
        policy_version=ctx["policy_version"],
    )

    assert result["trust_root_status"] == "DEGRADED"
    assert HARDWARE_TRUST_ROOT_DEGRADED in result["reason_codes"]
    assert HARDWARE_TRUST_ROOT_VERIFIED not in result["reason_codes"]
    assert result["fail_closed"] is True


def test_hardware_required_blocks_missing_or_software_fallback(tmp_path: Path) -> None:
    ctx = _context(tmp_path)

    missing = verify_hardware_trust_root(
        trust_root_evidence=None,
        verifier_federation_result=ctx["federation"],
        runtime_attestation_result=ctx["runtime_attestation"],
        immutable_ledger_hash=ctx["ledger_hash"],
        trusted_anchor_result=ctx["trusted_anchor"],
        tsa_timestamp_result=ctx["tsa_timestamp"],
        policy_hash=ctx["policy_hash"],
        policy_version=ctx["policy_version"],
        hardware_required=True,
    )

    assert missing["trust_root_status"] == "BLOCKED"
    assert HARDWARE_TRUST_ROOT_MISSING in missing["reason_codes"]
    assert HARDWARE_TRUST_ROOT_BLOCKED in missing["reason_codes"]


def test_unsupported_and_mismatched_roots_block(tmp_path: Path) -> None:
    ctx = _context(tmp_path)
    unsupported = create_trust_root_evidence(
        trust_root_type="USB_DONGLE",
        trust_root_hash=sha256_text("unsupported"),
        verifier_federation_result=ctx["federation"],
        runtime_attestation_result=ctx["runtime_attestation"],
        immutable_ledger_hash=ctx["ledger_hash"],
        trusted_anchor_result=ctx["trusted_anchor"],
        tsa_timestamp_result=ctx["tsa_timestamp"],
        policy_hash=ctx["policy_hash"],
        policy_version=ctx["policy_version"],
    )
    mismatched = dict(unsupported)
    mismatched["trust_root_type"] = "TPM"
    mismatched["binding_hash"] = "b" * 64

    unsupported_result = verify_hardware_trust_root(
        trust_root_evidence=unsupported,
        verifier_federation_result=ctx["federation"],
        runtime_attestation_result=ctx["runtime_attestation"],
        immutable_ledger_hash=ctx["ledger_hash"],
        trusted_anchor_result=ctx["trusted_anchor"],
        tsa_timestamp_result=ctx["tsa_timestamp"],
        policy_hash=ctx["policy_hash"],
        policy_version=ctx["policy_version"],
    )
    mismatch_result = verify_hardware_trust_root(
        trust_root_evidence=mismatched,
        verifier_federation_result=ctx["federation"],
        runtime_attestation_result=ctx["runtime_attestation"],
        immutable_ledger_hash=ctx["ledger_hash"],
        trusted_anchor_result=ctx["trusted_anchor"],
        tsa_timestamp_result=ctx["tsa_timestamp"],
        policy_hash=ctx["policy_hash"],
        policy_version=ctx["policy_version"],
    )

    assert HARDWARE_TRUST_ROOT_UNSUPPORTED in unsupported_result["reason_codes"]
    assert HARDWARE_TRUST_ROOT_BLOCKED in unsupported_result["reason_codes"]
    assert HARDWARE_TRUST_ROOT_MISMATCH in mismatch_result["reason_codes"]
    assert HARDWARE_TRUST_ROOT_BLOCKED in mismatch_result["reason_codes"]


def test_hardware_trust_root_output_is_hash_only(tmp_path: Path) -> None:
    result = _verify_with_type(tmp_path, "TPM")
    encoded = json.dumps(result, sort_keys=True)

    assert result["hardware_trust_root_authority_hash"]
    assert "PRIVATE " + "KEY" not in encoded
    assert "serial_number" not in encoded
    assert "device_identifier" not in encoded
    assert "approval_" + "contents" not in encoded
    assert "raw_" + "payload" not in encoded
    assert "bearer " not in encoded.lower()
    assert "access_token" not in encoded.lower()
