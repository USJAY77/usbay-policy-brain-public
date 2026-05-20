from __future__ import annotations

import json
from pathlib import Path

from governance.deployment_runtime_health import sha256_text
from governance.hardware_trust_consensus import (
    HARDWARE_CONSENSUS_DEGRADED,
    HARDWARE_CONSENSUS_FAILED,
    HARDWARE_CONSENSUS_REACHED,
    HARDWARE_ROOT_CONTRADICTION_DETECTED,
    HARDWARE_ROOT_POLICY_MISMATCH,
    HARDWARE_ROOT_QUORUM_MISSING,
    evaluate_hardware_trust_consensus,
)
from governance.hardware_trust_root_authority import (
    SOFTWARE_FALLBACK,
    create_trust_root_evidence,
    verify_hardware_trust_root,
)
from tests.test_hardware_trust_root_authority import _context


def _root_result(ctx: dict, root_type: str, *, policy_hash: str | None = None) -> dict:
    effective_policy_hash = policy_hash or ctx["policy_hash"]
    evidence = create_trust_root_evidence(
        trust_root_type=root_type,
        trust_root_hash=sha256_text(f"{root_type}:root"),
        verifier_federation_result=ctx["federation"],
        runtime_attestation_result=ctx["runtime_attestation"],
        immutable_ledger_hash=ctx["ledger_hash"],
        trusted_anchor_result=ctx["trusted_anchor"],
        tsa_timestamp_result=ctx["tsa_timestamp"],
        policy_hash=effective_policy_hash,
        policy_version=ctx["policy_version"],
    )
    return verify_hardware_trust_root(
        trust_root_evidence=evidence,
        verifier_federation_result=ctx["federation"],
        runtime_attestation_result=ctx["runtime_attestation"],
        immutable_ledger_hash=ctx["ledger_hash"],
        trusted_anchor_result=ctx["trusted_anchor"],
        tsa_timestamp_result=ctx["tsa_timestamp"],
        policy_hash=effective_policy_hash,
        policy_version=ctx["policy_version"],
        hardware_required=root_type != SOFTWARE_FALLBACK,
    )


def _consensus(ctx: dict, roots: list[dict], *, hardware_required: bool = True, policy_hash: str | None = None) -> dict:
    return evaluate_hardware_trust_consensus(
        hardware_root_results=roots,
        runtime_attestation_result=ctx["runtime_attestation"],
        verifier_federation_result=ctx["federation"],
        immutable_ledger_hash=ctx["ledger_hash"],
        trusted_anchor_result=ctx["trusted_anchor"],
        tsa_timestamp_result=ctx["tsa_timestamp"],
        policy_hash=policy_hash or ctx["policy_hash"],
        policy_version=ctx["policy_version"],
        hardware_required=hardware_required,
    )


def test_hardware_consensus_reaches_with_tpm_hsm_and_secure_enclave(tmp_path: Path) -> None:
    ctx = _context(tmp_path)
    roots = [_root_result(ctx, root_type) for root_type in ("TPM", "HSM", "SECURE_ENCLAVE")]

    result = _consensus(ctx, roots)

    assert result["consensus_status"] == "REACHED"
    assert result["verified_hardware_root_count"] == 3
    assert HARDWARE_CONSENSUS_REACHED in result["reason_codes"]
    assert result["merge_authority_granted"] is False


def test_hardware_consensus_blocks_missing_required_root(tmp_path: Path) -> None:
    ctx = _context(tmp_path)
    roots = [_root_result(ctx, root_type) for root_type in ("TPM", "HSM")]

    result = _consensus(ctx, roots)

    assert result["consensus_status"] == "BLOCKED"
    assert HARDWARE_ROOT_QUORUM_MISSING in result["reason_codes"]
    assert HARDWARE_CONSENSUS_FAILED in result["reason_codes"]


def test_hardware_consensus_blocks_contradictory_root_binding(tmp_path: Path) -> None:
    ctx = _context(tmp_path)
    roots = [_root_result(ctx, root_type) for root_type in ("TPM", "HSM", "SECURE_ENCLAVE")]
    roots[2] = dict(roots[2])
    roots[2]["binding_hash"] = "b" * 64

    result = _consensus(ctx, roots)

    assert result["consensus_status"] == "BLOCKED"
    assert HARDWARE_ROOT_CONTRADICTION_DETECTED in result["reason_codes"]
    assert HARDWARE_CONSENSUS_FAILED in result["reason_codes"]


def test_hardware_consensus_blocks_policy_mismatch(tmp_path: Path) -> None:
    ctx = _context(tmp_path)
    roots = [_root_result(ctx, root_type) for root_type in ("TPM", "HSM")]
    roots.append(_root_result(ctx, "SECURE_ENCLAVE", policy_hash="b" * 64))

    result = _consensus(ctx, roots)

    assert result["consensus_status"] == "BLOCKED"
    assert HARDWARE_ROOT_POLICY_MISMATCH in result["reason_codes"]
    assert HARDWARE_CONSENSUS_FAILED in result["reason_codes"]


def test_software_fallback_keeps_consensus_degraded_and_blocks_when_required(tmp_path: Path) -> None:
    ctx = _context(tmp_path)
    roots = [_root_result(ctx, root_type) for root_type in ("TPM", "HSM", "SECURE_ENCLAVE")]
    roots.append(_root_result(ctx, SOFTWARE_FALLBACK))

    degraded = _consensus(ctx, roots, hardware_required=False)
    blocked = _consensus(ctx, roots, hardware_required=True)

    assert degraded["consensus_status"] == "DEGRADED"
    assert HARDWARE_CONSENSUS_DEGRADED in degraded["reason_codes"]
    assert blocked["consensus_status"] == "BLOCKED"
    assert HARDWARE_CONSENSUS_DEGRADED in blocked["reason_codes"]
    assert HARDWARE_CONSENSUS_FAILED in blocked["reason_codes"]


def test_hardware_consensus_output_is_hash_only(tmp_path: Path) -> None:
    ctx = _context(tmp_path)
    roots = [_root_result(ctx, root_type) for root_type in ("TPM", "HSM", "SECURE_ENCLAVE")]

    result = _consensus(ctx, roots)
    encoded = json.dumps(result, sort_keys=True)

    assert result["hardware_consensus_hash"]
    assert "PRIVATE " + "KEY" not in encoded
    assert "serial_number" not in encoded
    assert "device_identifier" not in encoded
    assert "approval_" + "contents" not in encoded
    assert "raw_" + "payload" not in encoded
    assert "bearer " not in encoded.lower()
    assert "access_token" not in encoded.lower()
