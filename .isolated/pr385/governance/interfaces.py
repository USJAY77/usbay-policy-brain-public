from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class GovernanceValidationResult:
    """Typed validation result shared across governance domains."""

    valid: bool
    failures: tuple[str, ...] = ()
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        payload = {"valid": self.valid, "failures": list(self.failures)}
        payload.update(self.metadata)
        return payload


@dataclass(frozen=True)
class EvidenceManifest:
    """Evidence manifest interface for append-only CI evidence chains."""

    schema: str
    workflow_version: str
    generated_at: str
    chain_head: str
    records: tuple[dict[str, Any], ...]


@dataclass(frozen=True)
class ChronologyConsensusRecord:
    """Single chronology consensus target record interface."""

    target: dict[str, Any]
    consensus_result: str
    consensus_hash: str
    authority_results: tuple[dict[str, Any], ...]


@dataclass(frozen=True)
class ChronologyConsensus:
    """Chronology consensus bundle interface."""

    schema: str
    authority_ids: tuple[str, ...]
    quorum_required: int
    max_authority_skew_seconds: int
    chain_head: str
    targets: tuple[ChronologyConsensusRecord, ...]


@dataclass(frozen=True)
class TimestampVerificationResult:
    """Timestamp verification result interface."""

    valid: bool
    message_imprint: str
    timestamp_hash: str
    failures: tuple[str, ...] = ()


@dataclass(frozen=True)
class TrustPolicyValidationResult:
    """Trust-policy validation result interface."""

    valid: bool
    failures: tuple[str, ...]
    policy_hash: str
    policy_version: str | None
    policy_signer_id: str | None
    policy_signer_fingerprint: str | None

    def to_dict(self) -> dict[str, Any]:
        return {
            "valid": self.valid,
            "failures": list(self.failures),
            "policy_hash": self.policy_hash,
            "policy_version": self.policy_version,
            "policy_signer_id": self.policy_signer_id,
            "policy_signer_fingerprint": self.policy_signer_fingerprint,
        }

