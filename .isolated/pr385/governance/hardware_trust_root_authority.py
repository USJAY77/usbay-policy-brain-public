from __future__ import annotations

from typing import Any

from governance.deployment_runtime_health import canonical_json, sha256_text


SCHEMA_VERSION = "usbay.hardware_trust_root_authority.v1"
SUPPORTED_HARDWARE_ROOTS = ("TPM", "HSM", "SECURE_ENCLAVE")
SOFTWARE_FALLBACK = "SOFTWARE_FALLBACK"
HARDWARE_TRUST_ROOT_VERIFIED = "HARDWARE_TRUST_ROOT_VERIFIED"
HARDWARE_TRUST_ROOT_MISSING = "HARDWARE_TRUST_ROOT_MISSING"
HARDWARE_TRUST_ROOT_UNSUPPORTED = "HARDWARE_TRUST_ROOT_UNSUPPORTED"
HARDWARE_TRUST_ROOT_MISMATCH = "HARDWARE_TRUST_ROOT_MISMATCH"
HARDWARE_TRUST_ROOT_DEGRADED = "HARDWARE_TRUST_ROOT_DEGRADED"
HARDWARE_TRUST_ROOT_BLOCKED = "HARDWARE_TRUST_ROOT_BLOCKED"
REQUIRED_REASON_CODES = (
    HARDWARE_TRUST_ROOT_VERIFIED,
    HARDWARE_TRUST_ROOT_MISSING,
    HARDWARE_TRUST_ROOT_UNSUPPORTED,
    HARDWARE_TRUST_ROOT_MISMATCH,
    HARDWARE_TRUST_ROOT_DEGRADED,
    HARDWARE_TRUST_ROOT_BLOCKED,
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


class HardwareTrustRootError(RuntimeError):
    pass


def verify_hardware_trust_root(
    *,
    trust_root_evidence: dict[str, Any] | None,
    verifier_federation_result: dict[str, Any],
    runtime_attestation_result: dict[str, Any],
    immutable_ledger_hash: str,
    trusted_anchor_result: dict[str, Any],
    tsa_timestamp_result: dict[str, Any],
    policy_hash: str,
    policy_version: str,
    hardware_required: bool = False,
) -> dict[str, Any]:
    _assert_safe({
        "verifier_federation_result": verifier_federation_result,
        "runtime_attestation_result": runtime_attestation_result,
        "trusted_anchor_result": trusted_anchor_result,
        "tsa_timestamp_result": tsa_timestamp_result,
    })
    reason_codes: list[str] = []
    root_type = ""
    trust_root_hash = ""
    evidence_hash = ""
    if not trust_root_evidence:
        reason_codes.append(HARDWARE_TRUST_ROOT_MISSING)
        if hardware_required:
            reason_codes.append(HARDWARE_TRUST_ROOT_BLOCKED)
    else:
        _assert_safe(trust_root_evidence)
        root_type = str(trust_root_evidence.get("trust_root_type", ""))
        trust_root_hash = str(trust_root_evidence.get("trust_root_hash", ""))
        evidence_hash = sha256_text(canonical_json(trust_root_evidence))
        if root_type == SOFTWARE_FALLBACK:
            reason_codes.append(HARDWARE_TRUST_ROOT_DEGRADED)
            if hardware_required:
                reason_codes.append(HARDWARE_TRUST_ROOT_BLOCKED)
        elif root_type not in SUPPORTED_HARDWARE_ROOTS:
            reason_codes.append(HARDWARE_TRUST_ROOT_UNSUPPORTED)
            reason_codes.append(HARDWARE_TRUST_ROOT_BLOCKED)
        elif not _is_sha256(trust_root_hash):
            reason_codes.append(HARDWARE_TRUST_ROOT_MISMATCH)
            reason_codes.append(HARDWARE_TRUST_ROOT_BLOCKED)
        else:
            expected_binding_hash = _binding_hash(
                verifier_federation_result=verifier_federation_result,
                runtime_attestation_result=runtime_attestation_result,
                immutable_ledger_hash=immutable_ledger_hash,
                trusted_anchor_result=trusted_anchor_result,
                tsa_timestamp_result=tsa_timestamp_result,
                policy_hash=policy_hash,
                policy_version=policy_version,
            )
            if trust_root_evidence.get("binding_hash") != expected_binding_hash:
                reason_codes.append(HARDWARE_TRUST_ROOT_MISMATCH)
                reason_codes.append(HARDWARE_TRUST_ROOT_BLOCKED)
            else:
                reason_codes.append(HARDWARE_TRUST_ROOT_VERIFIED)

    if not reason_codes:
        reason_codes.append(HARDWARE_TRUST_ROOT_BLOCKED)
    verified = reason_codes == [HARDWARE_TRUST_ROOT_VERIFIED]
    degraded = HARDWARE_TRUST_ROOT_DEGRADED in reason_codes and HARDWARE_TRUST_ROOT_BLOCKED not in reason_codes
    payload = {
        "schema_version": SCHEMA_VERSION,
        "trust_root_status": "VERIFIED" if verified else "DEGRADED" if degraded else "BLOCKED",
        "trust_root_type": root_type or "NONE",
        "trust_root_evidence_hash": evidence_hash,
        "trust_root_hash": trust_root_hash,
        "binding_hash": _binding_hash(
            verifier_federation_result=verifier_federation_result,
            runtime_attestation_result=runtime_attestation_result,
            immutable_ledger_hash=immutable_ledger_hash,
            trusted_anchor_result=trusted_anchor_result,
            tsa_timestamp_result=tsa_timestamp_result,
            policy_hash=policy_hash,
            policy_version=policy_version,
        ),
        "verifier_federation_hash": str(verifier_federation_result.get("federation_hash", "")),
        "runtime_attestation_hash": str(
            runtime_attestation_result.get("verification", {}).get("attestation_hash")
            or runtime_attestation_result.get("attestation_hash", "")
        ),
        "immutable_ledger_hash": immutable_ledger_hash,
        "trusted_anchor_hash": str(trusted_anchor_result.get("anchor_verification_hash", "")),
        "tsa_timestamp_hash": str(tsa_timestamp_result.get("timestamp_verification_hash", "")),
        "policy_hash": str(policy_hash),
        "policy_version_hash": sha256_text(str(policy_version)),
        "reason_codes": tuple(dict.fromkeys(reason_codes)),
        "fail_closed": not verified,
        "merge_authority_granted": False,
    }
    payload["hardware_trust_root_authority_hash"] = sha256_text(canonical_json(payload))
    _assert_safe(payload)
    return payload


def create_trust_root_evidence(
    *,
    trust_root_type: str,
    trust_root_hash: str,
    verifier_federation_result: dict[str, Any],
    runtime_attestation_result: dict[str, Any],
    immutable_ledger_hash: str,
    trusted_anchor_result: dict[str, Any],
    tsa_timestamp_result: dict[str, Any],
    policy_hash: str,
    policy_version: str,
) -> dict[str, Any]:
    evidence = {
        "trust_root_type": trust_root_type,
        "trust_root_hash": trust_root_hash,
        "binding_hash": _binding_hash(
            verifier_federation_result=verifier_federation_result,
            runtime_attestation_result=runtime_attestation_result,
            immutable_ledger_hash=immutable_ledger_hash,
            trusted_anchor_result=trusted_anchor_result,
            tsa_timestamp_result=tsa_timestamp_result,
            policy_hash=policy_hash,
            policy_version=policy_version,
        ),
    }
    _assert_safe(evidence)
    return evidence


def _binding_hash(
    *,
    verifier_federation_result: dict[str, Any],
    runtime_attestation_result: dict[str, Any],
    immutable_ledger_hash: str,
    trusted_anchor_result: dict[str, Any],
    tsa_timestamp_result: dict[str, Any],
    policy_hash: str,
    policy_version: str,
) -> str:
    binding = {
        "verifier_federation_hash": str(verifier_federation_result.get("federation_hash", "")),
        "runtime_attestation_hash": str(
            runtime_attestation_result.get("verification", {}).get("attestation_hash")
            or runtime_attestation_result.get("attestation_hash", "")
        ),
        "immutable_ledger_hash": str(immutable_ledger_hash),
        "trusted_anchor_hash": str(trusted_anchor_result.get("anchor_verification_hash", "")),
        "tsa_timestamp_hash": str(tsa_timestamp_result.get("timestamp_verification_hash", "")),
        "policy_hash": str(policy_hash),
        "policy_version_hash": sha256_text(str(policy_version)),
    }
    return sha256_text(canonical_json(binding))


def _is_sha256(value: Any) -> bool:
    return isinstance(value, str) and len(value) == 64 and all(ch in "0123456789abcdef" for ch in value)


def _assert_safe(value: Any) -> None:
    text = canonical_json(value)
    if any(term.lower() in text.lower() for term in FORBIDDEN_DIAGNOSTIC_TERMS):
        raise HardwareTrustRootError(HARDWARE_TRUST_ROOT_BLOCKED)
