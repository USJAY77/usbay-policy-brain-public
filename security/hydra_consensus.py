from __future__ import annotations

from dataclasses import dataclass
import hashlib
import hmac
import json
import os
import time


REQUIRED_VOTES = 2
REQUIRED_NODES = 3
ALLOW = "allow"
DENY = "deny"
VALID_DECISIONS = {ALLOW, DENY}
DEFAULT_NODE_SECRET = "usbay-local-hydra-dev-secret"
DEFAULT_TIMEOUT_SECONDS = 1.0


@dataclass(frozen=True)
class HydraNodeDecision:
    node_id: str
    request_hash: str
    policy_version: str
    decision: str
    reason: str
    timestamp: float
    signature: str | None = None

    def to_dict(self) -> dict:
        return {
            "node_id": self.node_id,
            "request_hash": self.request_hash,
            "policy_version": self.policy_version,
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


def node_secret() -> str:
    return os.getenv("USBAY_HYDRA_NODE_SECRET", DEFAULT_NODE_SECRET)


def _signature_payload(decision: HydraNodeDecision) -> str:
    payload = {
        "decision": decision.decision,
        "node_id": decision.node_id,
        "policy_version": decision.policy_version,
        "reason": decision.reason,
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
        )
    )


def _fail_closed(
    decisions: list[HydraNodeDecision],
    votes_allow: int = 0,
    votes_deny: int = 0,
    reason: str = "consensus_not_reached",
) -> HydraConsensusResult:
    return HydraConsensusResult(
        final_decision=DENY,
        consensus_reached=False,
        votes_allow=votes_allow,
        votes_deny=votes_deny,
        required_votes=REQUIRED_VOTES,
        node_decisions=decisions,
        reason=reason,
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
    return None


def evaluate_consensus(decisions: list[HydraNodeDecision]) -> HydraConsensusResult:
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

    votes_allow = sum(1 for decision in decisions if decision.decision == ALLOW)
    votes_deny = sum(1 for decision in decisions if decision.decision == DENY)

    if votes_allow >= REQUIRED_VOTES:
        return HydraConsensusResult(
            final_decision=ALLOW,
            consensus_reached=True,
            votes_allow=votes_allow,
            votes_deny=votes_deny,
            required_votes=REQUIRED_VOTES,
            node_decisions=decisions,
            reason="allow_consensus_reached",
        )

    if votes_deny >= REQUIRED_VOTES:
        return HydraConsensusResult(
            final_decision=DENY,
            consensus_reached=True,
            votes_allow=votes_allow,
            votes_deny=votes_deny,
            required_votes=REQUIRED_VOTES,
            node_decisions=decisions,
            reason="deny_consensus_reached",
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
