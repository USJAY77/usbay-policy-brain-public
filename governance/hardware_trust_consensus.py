from __future__ import annotations

from typing import Any

from governance.deployment_runtime_health import canonical_json, sha256_text
from governance.hardware_trust_root_authority import (
    HARDWARE_TRUST_ROOT_DEGRADED,
    HARDWARE_TRUST_ROOT_VERIFIED,
    SOFTWARE_FALLBACK,
    SUPPORTED_HARDWARE_ROOTS,
)


SCHEMA_VERSION = "usbay.hardware_trust_consensus.v1"
HARDWARE_CONSENSUS_REACHED = "HARDWARE_CONSENSUS_REACHED"
HARDWARE_CONSENSUS_FAILED = "HARDWARE_CONSENSUS_FAILED"
HARDWARE_CONSENSUS_DEGRADED = "HARDWARE_CONSENSUS_DEGRADED"
HARDWARE_ROOT_CONTRADICTION_DETECTED = "HARDWARE_ROOT_CONTRADICTION_DETECTED"
HARDWARE_ROOT_QUORUM_MISSING = "HARDWARE_ROOT_QUORUM_MISSING"
HARDWARE_ROOT_POLICY_MISMATCH = "HARDWARE_ROOT_POLICY_MISMATCH"
REQUIRED_REASON_CODES = (
    HARDWARE_CONSENSUS_REACHED,
    HARDWARE_CONSENSUS_FAILED,
    HARDWARE_CONSENSUS_DEGRADED,
    HARDWARE_ROOT_CONTRADICTION_DETECTED,
    HARDWARE_ROOT_QUORUM_MISSING,
    HARDWARE_ROOT_POLICY_MISMATCH,
)
FORBIDDEN_DIAGNOSTIC_TERMS = (
    "PRIVATE " + "KEY",
    "approval_" + "contents",
    "raw_" + "payload",
    "serial_number",
    "device_identifier",
    "credential",
    "secret",
    "bearer ",
    "access_token",
)


class HardwareTrustConsensusError(RuntimeError):
    pass


def evaluate_hardware_trust_consensus(
    *,
    hardware_root_results: list[dict[str, Any]],
    runtime_attestation_result: dict[str, Any],
    verifier_federation_result: dict[str, Any],
    immutable_ledger_hash: str,
    trusted_anchor_result: dict[str, Any],
    tsa_timestamp_result: dict[str, Any],
    policy_hash: str,
    policy_version: str,
    required_hardware_roots: tuple[str, ...] = SUPPORTED_HARDWARE_ROOTS,
    hardware_required: bool = True,
) -> dict[str, Any]:
    _assert_safe({
        "hardware_root_results": hardware_root_results,
        "runtime_attestation_result": runtime_attestation_result,
        "verifier_federation_result": verifier_federation_result,
        "trusted_anchor_result": trusted_anchor_result,
        "tsa_timestamp_result": tsa_timestamp_result,
    })
    reason_codes: list[str] = []
    required = tuple(required_hardware_roots)
    root_by_type = {
        str(result.get("trust_root_type", "")): result
        for result in hardware_root_results
        if isinstance(result, dict) and result.get("trust_root_type")
    }
    verified_hardware = [
        result for result in hardware_root_results
        if result.get("trust_root_type") in SUPPORTED_HARDWARE_ROOTS
        and result.get("trust_root_status") == "VERIFIED"
        and HARDWARE_TRUST_ROOT_VERIFIED in result.get("reason_codes", [])
    ]
    degraded = [
        result for result in hardware_root_results
        if result.get("trust_root_type") == SOFTWARE_FALLBACK
        or HARDWARE_TRUST_ROOT_DEGRADED in result.get("reason_codes", [])
    ]
    missing = [root for root in required if root not in root_by_type]
    if missing and hardware_required:
        reason_codes.append(HARDWARE_ROOT_QUORUM_MISSING)
    if degraded:
        reason_codes.append(HARDWARE_CONSENSUS_DEGRADED)
        if hardware_required:
            reason_codes.append(HARDWARE_CONSENSUS_FAILED)

    expected_binding = _binding_hash(
        runtime_attestation_result=runtime_attestation_result,
        verifier_federation_result=verifier_federation_result,
        immutable_ledger_hash=immutable_ledger_hash,
        trusted_anchor_result=trusted_anchor_result,
        tsa_timestamp_result=tsa_timestamp_result,
        policy_hash=policy_hash,
        policy_version=policy_version,
    )
    binding_hashes = {
        str(result.get("binding_hash", ""))
        for result in verified_hardware
        if result.get("binding_hash")
    }
    if any(str(result.get("policy_hash", "")) != policy_hash for result in hardware_root_results):
        reason_codes.append(HARDWARE_ROOT_POLICY_MISMATCH)
    if binding_hashes and (binding_hashes != {expected_binding}):
        reason_codes.append(HARDWARE_ROOT_CONTRADICTION_DETECTED)
    if len(verified_hardware) < len(required):
        reason_codes.append(HARDWARE_ROOT_QUORUM_MISSING)

    if not reason_codes:
        reason_codes.append(HARDWARE_CONSENSUS_REACHED)
    elif HARDWARE_CONSENSUS_FAILED not in reason_codes and any(
        code in reason_codes
        for code in (
            HARDWARE_ROOT_CONTRADICTION_DETECTED,
            HARDWARE_ROOT_QUORUM_MISSING,
            HARDWARE_ROOT_POLICY_MISMATCH,
        )
    ):
        reason_codes.append(HARDWARE_CONSENSUS_FAILED)

    reached = reason_codes == [HARDWARE_CONSENSUS_REACHED]
    status = "REACHED" if reached else "DEGRADED" if reason_codes == [HARDWARE_CONSENSUS_DEGRADED] else "BLOCKED"
    payload = {
        "schema_version": SCHEMA_VERSION,
        "consensus_status": status,
        "required_hardware_roots": required,
        "verified_hardware_root_count": len(verified_hardware),
        "software_fallback_present": bool(degraded),
        "hardware_required": hardware_required,
        "binding_hash": expected_binding,
        "hardware_root_results_hash": sha256_text(canonical_json([
            {
                "trust_root_type": result.get("trust_root_type"),
                "trust_root_status": result.get("trust_root_status"),
                "trust_root_hash": result.get("trust_root_hash"),
                "binding_hash": result.get("binding_hash"),
                "policy_hash": result.get("policy_hash"),
                "reason_codes": result.get("reason_codes", []),
            }
            for result in hardware_root_results
        ])),
        "runtime_attestation_hash": str(
            runtime_attestation_result.get("verification", {}).get("attestation_hash")
            or runtime_attestation_result.get("attestation_hash", "")
        ),
        "verifier_federation_hash": str(verifier_federation_result.get("federation_hash", "")),
        "immutable_ledger_hash": str(immutable_ledger_hash),
        "trusted_anchor_hash": str(trusted_anchor_result.get("anchor_verification_hash", "")),
        "tsa_timestamp_hash": str(tsa_timestamp_result.get("timestamp_verification_hash", "")),
        "policy_hash": str(policy_hash),
        "policy_version_hash": sha256_text(str(policy_version)),
        "reason_codes": tuple(dict.fromkeys(reason_codes)),
        "fail_closed": not reached,
        "merge_authority_granted": False,
    }
    payload["hardware_consensus_hash"] = sha256_text(canonical_json(payload))
    _assert_safe(payload)
    return payload


def _binding_hash(
    *,
    runtime_attestation_result: dict[str, Any],
    verifier_federation_result: dict[str, Any],
    immutable_ledger_hash: str,
    trusted_anchor_result: dict[str, Any],
    tsa_timestamp_result: dict[str, Any],
    policy_hash: str,
    policy_version: str,
) -> str:
    return sha256_text(canonical_json({
        "runtime_attestation_hash": str(
            runtime_attestation_result.get("verification", {}).get("attestation_hash")
            or runtime_attestation_result.get("attestation_hash", "")
        ),
        "verifier_federation_hash": str(verifier_federation_result.get("federation_hash", "")),
        "immutable_ledger_hash": str(immutable_ledger_hash),
        "trusted_anchor_hash": str(trusted_anchor_result.get("anchor_verification_hash", "")),
        "tsa_timestamp_hash": str(tsa_timestamp_result.get("timestamp_verification_hash", "")),
        "policy_hash": str(policy_hash),
        "policy_version_hash": sha256_text(str(policy_version)),
    }))


def _assert_safe(value: Any) -> None:
    text = canonical_json(value)
    if any(term.lower() in text.lower() for term in FORBIDDEN_DIAGNOSTIC_TERMS):
        raise HardwareTrustConsensusError(HARDWARE_CONSENSUS_FAILED)
