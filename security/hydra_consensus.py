from __future__ import annotations

from dataclasses import dataclass
import hashlib
import hmac
import json
import os
import time
from typing import Any


REQUIRED_VOTES = 2
REQUIRED_NODES = 3
ALLOW = "allow"
DENY = "deny"
VALID_DECISIONS = {ALLOW, DENY}
DEFAULT_NODE_SECRET = "usbay-local-hydra-dev-secret"
DEFAULT_TIMEOUT_SECONDS = 1.0
DEFAULT_ATTESTATION_FRESHNESS_SECONDS = 30
EXPECTED_NODE_ROLES = {
    "node-1": "primary",
    "node-2": "secondary",
    "node-3": "offline_backup",
}
OFFLINE_REASONS = {"node_unavailable", "missing_node", "node_failure", "invalid_node_signature"}
STATE_REQUIRED_FIELDS = (
    "policy_hash",
    "nonce_hash",
    "replay_registry_hash",
    "nonce_state",
    "attestation_timestamp",
    "attestation_hash",
    "attestation_node_id",
    "attestation_provider_mode",
)


@dataclass(frozen=True)
class HydraNodeDecision:
    node_id: str
    request_hash: str
    policy_version: str
    decision: str
    reason: str
    timestamp: float
    node_role: str = ""
    policy_hash: str = ""
    nonce_hash: str = ""
    replay_registry_hash: str = ""
    nonce_state: str = ""
    attestation_timestamp: float = 0.0
    attestation_hash: str = ""
    attestation_node_id: str = ""
    attestation_provider_mode: str = ""
    hardware_backed: bool = False
    signature: str | None = None

    def to_dict(self) -> dict:
        return {
            "node_id": self.node_id,
            "node_role": self.node_role,
            "request_hash": self.request_hash,
            "policy_version": self.policy_version,
            "policy_hash": self.policy_hash,
            "nonce_hash": self.nonce_hash,
            "replay_registry_hash": self.replay_registry_hash,
            "nonce_state": self.nonce_state,
            "attestation_timestamp": self.attestation_timestamp,
            "attestation_hash": self.attestation_hash,
            "attestation_node_id": self.attestation_node_id,
            "attestation_provider_mode": self.attestation_provider_mode,
            "hardware_backed": self.hardware_backed,
            "decision": self.decision,
            "reason": self.reason,
            "timestamp": self.timestamp,
            "signature": self.signature,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "HydraNodeDecision":
        return cls(
            node_id=str(data.get("node_id", "")),
            request_hash=str(data.get("request_hash", "")),
            policy_version=str(data.get("policy_version", "")),
            decision=str(data.get("decision", "")),
            reason=str(data.get("reason", "")),
            timestamp=float(data.get("timestamp", 0.0)),
            node_role=str(data.get("node_role", "")),
            policy_hash=str(data.get("policy_hash", "")),
            nonce_hash=str(data.get("nonce_hash", "")),
            replay_registry_hash=str(data.get("replay_registry_hash", "")),
            nonce_state=str(data.get("nonce_state", "")),
            attestation_timestamp=float(data.get("attestation_timestamp", 0.0)),
            attestation_hash=str(data.get("attestation_hash", "")),
            attestation_node_id=str(data.get("attestation_node_id", "")),
            attestation_provider_mode=str(data.get("attestation_provider_mode", "")),
            hardware_backed=bool(data.get("hardware_backed", False)),
            signature=data.get("signature"),
        )


@dataclass(frozen=True)
class HydraConsensusResult:
    final_decision: str
    consensus_reached: bool
    votes_allow: int
    votes_deny: int
    required_votes: int
    node_decisions: list[HydraNodeDecision]
    reason: str
    evidence_bundle: dict[str, Any] | None = None


def node_secret() -> str:
    return os.getenv("USBAY_HYDRA_NODE_SECRET", DEFAULT_NODE_SECRET)


def _signature_payload(decision: HydraNodeDecision) -> str:
    payload = {
        "decision": decision.decision,
        "attestation_hash": decision.attestation_hash,
        "attestation_node_id": decision.attestation_node_id,
        "attestation_provider_mode": decision.attestation_provider_mode,
        "attestation_timestamp": decision.attestation_timestamp,
        "hardware_backed": decision.hardware_backed,
        "node_role": decision.node_role,
        "node_id": decision.node_id,
        "nonce_hash": decision.nonce_hash,
        "nonce_state": decision.nonce_state,
        "policy_hash": decision.policy_hash,
        "policy_version": decision.policy_version,
        "reason": decision.reason,
        "replay_registry_hash": decision.replay_registry_hash,
        "request_hash": decision.request_hash,
        "timestamp": decision.timestamp,
    }
    return json.dumps(payload, sort_keys=True, separators=(",", ":"))


def sign_node_decision(decision: HydraNodeDecision, secret: str | None = None) -> HydraNodeDecision:
    signing_secret = secret or node_secret()
    signature = hmac.new(
        signing_secret.encode("utf-8"),
        _signature_payload(decision).encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
    return HydraNodeDecision(
        node_id=decision.node_id,
        request_hash=decision.request_hash,
        policy_version=decision.policy_version,
        decision=decision.decision,
        reason=decision.reason,
        timestamp=decision.timestamp,
        node_role=decision.node_role,
        policy_hash=decision.policy_hash,
        nonce_hash=decision.nonce_hash,
        replay_registry_hash=decision.replay_registry_hash,
        nonce_state=decision.nonce_state,
        attestation_timestamp=decision.attestation_timestamp,
        attestation_hash=decision.attestation_hash,
        attestation_node_id=decision.attestation_node_id,
        attestation_provider_mode=decision.attestation_provider_mode,
        hardware_backed=decision.hardware_backed,
        signature=signature,
    )


def verify_node_decision_signature(
    decision: HydraNodeDecision,
    secret: str | None = None,
) -> bool:
    if not decision.signature:
        return False

    expected = sign_node_decision(decision, secret).signature
    return hmac.compare_digest(decision.signature, expected)


def deny_decision(
    node_id: str,
    request_hash: str,
    policy_version: str,
    reason: str,
) -> HydraNodeDecision:
    return sign_node_decision(
        HydraNodeDecision(
            node_id=node_id,
            request_hash=request_hash,
            policy_version=policy_version,
            decision=DENY,
            reason=reason,
            timestamp=time.time(),
            node_role=EXPECTED_NODE_ROLES.get(node_id, ""),
        )
    )


def replay_registry_hash(policy_hash: str, nonce_hash: str) -> str:
    return hashlib.sha256(f"{policy_hash}:{nonce_hash}:unused".encode("utf-8")).hexdigest()


def consensus_secret() -> str:
    return os.getenv("USBAY_HYDRA_CONSENSUS_SECRET", node_secret())


def consensus_evidence_hash(evidence: dict[str, Any]) -> str:
    unsigned = {
        key: value
        for key, value in evidence.items()
        if key not in {"sha256_evidence_hash", "consensus_signature"}
    }
    body = json.dumps(unsigned, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(body.encode("utf-8")).hexdigest()


def sign_consensus_evidence(evidence: dict[str, Any]) -> str:
    return hmac.new(
        consensus_secret().encode("utf-8"),
        evidence["sha256_evidence_hash"].encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()


def build_consensus_evidence(
    *,
    result: str,
    reason: str,
    decisions: list[HydraNodeDecision],
    votes_allow: int,
    votes_deny: int,
) -> dict[str, Any]:
    policy_hashes = sorted({decision.policy_hash for decision in decisions if decision.policy_hash})
    evidence = {
        "node_ids": [decision.node_id for decision in decisions],
        "timestamps": {decision.node_id: decision.timestamp for decision in decisions},
        "policy_hash": policy_hashes[0] if len(policy_hashes) == 1 else None,
        "consensus_result": result,
        "reason": reason,
        "votes_allow": votes_allow,
        "votes_deny": votes_deny,
        "nodes": [
            {
                "node_id": decision.node_id,
                "node_role": decision.node_role,
                "decision": decision.decision,
                "reason": decision.reason,
                "timestamp": decision.timestamp,
                "policy_hash": decision.policy_hash,
                "nonce_hash": decision.nonce_hash,
                "replay_registry_hash": decision.replay_registry_hash,
                "nonce_state": decision.nonce_state,
                "attestation_timestamp": decision.attestation_timestamp,
                "attestation_hash": decision.attestation_hash,
                "attestation_node_id": decision.attestation_node_id,
                "attestation_provider_mode": decision.attestation_provider_mode,
                "hardware_backed": decision.hardware_backed,
            }
            for decision in decisions
        ],
    }
    evidence["attestation_evidence"] = [
        {
            "logical_node_id": decision.node_id,
            "node_id": decision.attestation_node_id,
            "node_role": decision.node_role,
            "provider_mode": decision.attestation_provider_mode,
            "hardware_backed": decision.hardware_backed,
            "attestation_hash": decision.attestation_hash,
            "attestation_timestamp": decision.attestation_timestamp,
        }
        for decision in decisions
        if decision.attestation_hash and decision.attestation_node_id
    ]
    evidence["attestation_evidence_hash"] = hashlib.sha256(
        json.dumps(evidence["attestation_evidence"], sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    evidence["sha256_evidence_hash"] = consensus_evidence_hash(evidence)
    evidence["consensus_signature"] = sign_consensus_evidence(evidence)
    return evidence


def _fail_closed(
    decisions: list[HydraNodeDecision],
    votes_allow: int = 0,
    votes_deny: int = 0,
    reason: str = "consensus_not_reached",
) -> HydraConsensusResult:
    evidence = build_consensus_evidence(
        result=DENY,
        reason=reason,
        decisions=decisions,
        votes_allow=votes_allow,
        votes_deny=votes_deny,
    )
    return HydraConsensusResult(
        final_decision=DENY,
        consensus_reached=False,
        votes_allow=votes_allow,
        votes_deny=votes_deny,
        required_votes=REQUIRED_VOTES,
        node_decisions=decisions,
        reason=reason,
        evidence_bundle=evidence,
    )


def _invalid_reason(decision: HydraNodeDecision) -> str | None:
    if not isinstance(decision, HydraNodeDecision):
        return "invalid_node_decision"
    if not decision.node_id:
        return "empty_node_id"
    if not decision.request_hash:
        return "empty_request_hash"
    if not decision.policy_version:
        return "empty_policy_version"
    if decision.decision not in VALID_DECISIONS:
        return "invalid_decision"
    if decision.node_role and EXPECTED_NODE_ROLES.get(decision.node_id) != decision.node_role:
        return "node_role_mismatch"
    return None


def _active_decisions(decisions: list[HydraNodeDecision]) -> list[HydraNodeDecision]:
    return [
        decision
        for decision in decisions
        if not (decision.decision == DENY and decision.reason in OFFLINE_REASONS)
    ]


def _stale(decision: HydraNodeDecision, now: float, freshness_seconds: int) -> bool:
    if decision.timestamp <= 0 or abs(now - decision.timestamp) > freshness_seconds:
        return True
    if decision.attestation_timestamp <= 0 or abs(now - decision.attestation_timestamp) > freshness_seconds:
        return True
    return False


def evaluate_consensus(
    decisions: list[HydraNodeDecision],
    *,
    expected_policy_hash: str | None = None,
    expected_nonce_hash: str | None = None,
    expected_replay_registry_hash: str | None = None,
    freshness_seconds: int | None = None,
) -> HydraConsensusResult:
    if len(decisions) < REQUIRED_NODES:
        return _fail_closed(decisions, reason="fewer_than_3_decisions")

    for decision in decisions:
        invalid_reason = _invalid_reason(decision)
        if invalid_reason is not None:
            return _fail_closed(decisions, reason=invalid_reason)

    request_hashes = {decision.request_hash for decision in decisions}
    if len(request_hashes) != 1:
        return _fail_closed(decisions, reason="request_hash_mismatch")

    policy_versions = {decision.policy_version for decision in decisions}
    if len(policy_versions) != 1:
        return _fail_closed(decisions, reason="policy_version_mismatch")

    active = _active_decisions(decisions)
    if len(active) < REQUIRED_VOTES:
        return _fail_closed(decisions, reason="quorum_unavailable")

    freshness = int(freshness_seconds or os.getenv(
        "USBAY_HYDRA_ATTESTATION_FRESHNESS_SECONDS",
        str(DEFAULT_ATTESTATION_FRESHNESS_SECONDS),
    ))
    now = time.time()
    if any(_stale(decision, now, freshness) for decision in active):
        return _fail_closed(decisions, reason="node_stale")

    for decision in active:
        if any(not getattr(decision, field) for field in STATE_REQUIRED_FIELDS):
            return _fail_closed(decisions, reason="node_stale")

    policy_hashes = {decision.policy_hash for decision in active}
    if len(policy_hashes) != 1 or (expected_policy_hash and expected_policy_hash not in policy_hashes):
        return _fail_closed(decisions, reason="policy_hash_mismatch")

    nonce_hashes = {decision.nonce_hash for decision in active}
    nonce_states = {decision.nonce_state for decision in active}
    if len(nonce_hashes) != 1 or nonce_states != {"unused"}:
        return _fail_closed(decisions, reason="nonce_state_mismatch")
    if expected_nonce_hash and expected_nonce_hash not in nonce_hashes:
        return _fail_closed(decisions, reason="nonce_state_mismatch")

    replay_hashes = {decision.replay_registry_hash for decision in active}
    if len(replay_hashes) != 1:
        return _fail_closed(decisions, reason="replay_registry_divergence")
    if expected_replay_registry_hash and expected_replay_registry_hash not in replay_hashes:
        return _fail_closed(decisions, reason="replay_registry_divergence")

    votes_allow = sum(1 for decision in decisions if decision.decision == ALLOW)
    votes_deny = sum(1 for decision in decisions if decision.decision == DENY)

    active_votes = {decision.decision for decision in active}
    if DENY in active_votes and ALLOW in active_votes:
        return _fail_closed(
            decisions,
            votes_allow=votes_allow,
            votes_deny=votes_deny,
            reason="node_disagreement",
        )

    if votes_allow >= REQUIRED_VOTES:
        evidence = build_consensus_evidence(
            result=ALLOW,
            reason="allow_consensus_reached",
            decisions=decisions,
            votes_allow=votes_allow,
            votes_deny=votes_deny,
        )
        return HydraConsensusResult(
            final_decision=ALLOW,
            consensus_reached=True,
            votes_allow=votes_allow,
            votes_deny=votes_deny,
            required_votes=REQUIRED_VOTES,
            node_decisions=decisions,
            reason="allow_consensus_reached",
            evidence_bundle=evidence,
        )

    if votes_deny >= REQUIRED_VOTES:
        evidence = build_consensus_evidence(
            result=DENY,
            reason="deny_consensus_reached",
            decisions=decisions,
            votes_allow=votes_allow,
            votes_deny=votes_deny,
        )
        return HydraConsensusResult(
            final_decision=DENY,
            consensus_reached=True,
            votes_allow=votes_allow,
            votes_deny=votes_deny,
            required_votes=REQUIRED_VOTES,
            node_decisions=decisions,
            reason="deny_consensus_reached",
            evidence_bundle=evidence,
        )

    return _fail_closed(
        decisions,
        votes_allow=votes_allow,
        votes_deny=votes_deny,
        reason="consensus_not_reached",
    )


def decide_consensus(votes) -> str:
    """Public dict-based consensus API for manual checks.

    This compatibility layer intentionally returns uppercase decisions while
    the internal Hydra engine keeps its lowercase model contract.
    """
    try:
        if not isinstance(votes, list):
            return "DENY"

        valid_decisions = []
        for vote in votes:
            if not isinstance(vote, dict):
                return "DENY"
            if vote.get("valid") is not True:
                continue
            decision = vote.get("decision")
            if decision not in {"ALLOW", "DENY"}:
                return "DENY"
            valid_decisions.append(decision)

        if len(valid_decisions) < REQUIRED_VOTES:
            return "DENY"

        if valid_decisions.count("ALLOW") >= REQUIRED_VOTES:
            return "ALLOW"

        return "DENY"
    except Exception:
        return "DENY"
