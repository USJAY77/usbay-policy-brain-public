from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable


BLOCK = "DENY"
ALLOW = "ALLOW"
HIGH_RISK_LEVELS = {"HIGH", "CRITICAL"}


def _risk_level(policy_result: dict[str, Any]) -> str:
    return str(policy_result.get("risk") or policy_result.get("risk_level") or "").upper()


def _has_signature(policy_result: dict[str, Any]) -> bool:
    signature = policy_result.get("signature")
    return isinstance(signature, str) and bool(signature.strip())


class LocalReviewLayer:
    """Local-only policy review layer.

    This layer performs deterministic checks and never calls external AI APIs or
    executes user-provided commands.
    """

    def analyze(self, policy_result: dict[str, Any]) -> dict[str, Any]:
        if not isinstance(policy_result, dict):
            return {
                "clearance": False,
                "decision": BLOCK,
                "reason": "invalid_policy_result",
            }

        if not _has_signature(policy_result):
            return {
                "clearance": False,
                "decision": BLOCK,
                "reason": "missing_signature",
            }

        if policy_result.get("fail_closed_reason"):
            return {
                "clearance": False,
                "decision": BLOCK,
                "reason": "fail_closed_reason_present",
            }

        risk = _risk_level(policy_result)
        if risk in HIGH_RISK_LEVELS:
            return {
                "clearance": False,
                "decision": BLOCK,
                "reason": f"{risk.lower()}_risk",
            }

        return {
            "clearance": True,
            "decision": ALLOW,
            "reason": "local_review_clear",
        }


@dataclass(frozen=True)
class ConsensusVote:
    node_id: str
    decision: str
    reason: str


class HydraNode:
    def __init__(
        self,
        node_id: str,
        evaluator: Callable[[dict[str, Any]], ConsensusVote] | None = None,
    ) -> None:
        self.node_id = node_id
        self._evaluator = evaluator

    def vote(self, policy_result: dict[str, Any]) -> ConsensusVote:
        if self._evaluator is not None:
            return self._evaluator(policy_result)

        if not isinstance(policy_result, dict):
            return ConsensusVote(self.node_id, BLOCK, "invalid_policy_result")
        if not _has_signature(policy_result):
            return ConsensusVote(self.node_id, BLOCK, "missing_signature")
        if policy_result.get("fail_closed_reason"):
            return ConsensusVote(self.node_id, BLOCK, "fail_closed_reason_present")
        risk = _risk_level(policy_result)
        if risk in HIGH_RISK_LEVELS:
            return ConsensusVote(self.node_id, BLOCK, f"{risk.lower()}_risk")

        requested_decision = str(policy_result.get("decision", ALLOW)).upper()
        if requested_decision != ALLOW:
            return ConsensusVote(self.node_id, BLOCK, "policy_not_allow")
        return ConsensusVote(self.node_id, ALLOW, "node_allow")


class HydraConsensus:
    def __init__(self, nodes: list[HydraNode] | None = None, required_allow_votes: int = 2) -> None:
        self.nodes = nodes or [
            HydraNode("hydra-node-1"),
            HydraNode("hydra-node-2"),
            HydraNode("hydra-node-3"),
        ]
        if len(self.nodes) != 3:
            raise ValueError("Hydra requires exactly 3 nodes")
        self.required_allow_votes = required_allow_votes

    def evaluate(self, policy_result: dict[str, Any]) -> dict[str, Any]:
        votes: list[ConsensusVote] = []
        for node in self.nodes:
            try:
                vote = node.vote(policy_result)
            except Exception:
                vote = ConsensusVote(node.node_id, BLOCK, "node_failure")
            if vote.decision != ALLOW:
                vote = ConsensusVote(vote.node_id, BLOCK, vote.reason)
            votes.append(vote)

        allow_votes = sum(1 for vote in votes if vote.decision == ALLOW)
        decision = ALLOW if allow_votes >= self.required_allow_votes else BLOCK
        return {
            "decision": decision,
            "allow_votes": allow_votes,
            "required_allow_votes": self.required_allow_votes,
            "votes": [
                {
                    "node_id": vote.node_id,
                    "decision": vote.decision,
                    "reason": vote.reason,
                }
                for vote in votes
            ],
        }
