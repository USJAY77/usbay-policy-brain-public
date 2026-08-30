from __future__ import annotations

from typing import Any


class OpenClawGateway:
    """Fail-closed gateway for enclosed execution preparation.

    The gateway does not execute commands. It only returns whether an enclosed
    execution would be allowed by the provided governance evidence.
    """

    def authorize(
        self,
        *,
        request: dict[str, Any],
        hydra_consensus: dict[str, Any],
        local_review: dict[str, Any],
    ) -> dict[str, Any]:
        if not isinstance(request, dict):
            return self._blocked("invalid_request")
        if not request.get("governance_token"):
            return self._blocked("missing_governance_token")
        if hydra_consensus.get("decision") != "ALLOW":
            return self._blocked("hydra_consensus_denied")
        if local_review.get("clearance") is not True:
            return self._blocked("local_review_denied")

        return {
            "status": "READY",
            "execution_allowed": True,
            "reason": "governance_clearance_complete",
        }

    @staticmethod
    def _blocked(reason: str) -> dict[str, Any]:
        return {
            "status": "BLOCKED",
            "execution_allowed": False,
            "reason": reason,
        }
