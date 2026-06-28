"""Final fail-closed publication evidence seal."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

from publication.models import EvidenceSealResult, hash_payload, is_sha256_ref


EVIDENCE_SEAL_POLICY_VERSION = "USBAY-PUBGOV-035"
APPROVED_REASON = "EVIDENCE_SEAL_APPROVED"
BLOCKED_REASON = "EVIDENCE_SEAL_BLOCKED"
REQUIRED_SEAL_ORDER = (
    "policy_bundle_hash",
    "evidence_chain_hash",
    "publication_lock_hash",
    "release_hash",
    "consistency_hash",
    "finalization_hash",
    "timestamp_hash",
)


def validate_evidence_seal(
    *,
    seal_inputs: Mapping[str, str] | None,
    ordered_hash_names: Sequence[str] | None,
    expected_hashes: Mapping[str, str] | None = None,
    policy_version: str,
    publication_contract_version: str,
    expected_policy_version: str,
    expected_publication_contract_version: str,
) -> EvidenceSealResult:
    """Approve only when the complete publication evidence package is sealed."""

    if seal_inputs is None or ordered_hash_names is None:
        return _blocked("MISSING_SEAL")

    ordered_names = tuple(ordered_hash_names)
    if ordered_names != REQUIRED_SEAL_ORDER:
        return _blocked("UNORDERED_EVIDENCE")
    if len(set(ordered_names)) != len(ordered_names):
        return _blocked("DUPLICATED_HASH")
    if set(seal_inputs) != set(REQUIRED_SEAL_ORDER):
        return _blocked("PUBLICATION_CONTRACT_MISMATCH")
    if policy_version != expected_policy_version:
        return _blocked("POLICY_MISMATCH")
    if publication_contract_version != expected_publication_contract_version:
        return _blocked("PUBLICATION_CONTRACT_MISMATCH")

    values = [seal_inputs.get(name, "") for name in REQUIRED_SEAL_ORDER]
    if any(not is_sha256_ref(value) for value in values):
        return _blocked("MISSING_HASHES")
    if len(set(values)) != len(values):
        return _blocked("DUPLICATED_HASH")

    if expected_hashes is not None:
        for name in REQUIRED_SEAL_ORDER:
            expected = expected_hashes.get(name)
            if expected and seal_inputs[name] != expected:
                return _blocked("MISMATCHED_HASHES")

    evidence_seal_hash = hash_payload(
        {
            "policy_version": EVIDENCE_SEAL_POLICY_VERSION,
            "publication_contract_version": publication_contract_version,
            "runtime_policy_version": policy_version,
            "ordered_hash_names": ordered_names,
            "seal_inputs": {name: seal_inputs[name] for name in REQUIRED_SEAL_ORDER},
            "raw_payload_stored": False,
        }
    )
    return EvidenceSealResult(
        approved=True,
        evidence_seal_hash=evidence_seal_hash,
        policy_bundle_hash=seal_inputs["policy_bundle_hash"],
        evidence_chain_hash=seal_inputs["evidence_chain_hash"],
        publication_lock_hash=seal_inputs["publication_lock_hash"],
        release_hash=seal_inputs["release_hash"],
        consistency_hash=seal_inputs["consistency_hash"],
        finalization_hash=seal_inputs["finalization_hash"],
        timestamp_hash=seal_inputs["timestamp_hash"],
        reason=APPROVED_REASON,
    )


def _blocked(reason: str) -> EvidenceSealResult:
    return EvidenceSealResult(
        approved=False,
        evidence_seal_hash=hash_payload({"policy_version": EVIDENCE_SEAL_POLICY_VERSION, "reason": reason}),
        policy_bundle_hash="",
        evidence_chain_hash="",
        publication_lock_hash="",
        release_hash="",
        consistency_hash="",
        finalization_hash="",
        timestamp_hash="",
        reason=reason or BLOCKED_REASON,
    )
