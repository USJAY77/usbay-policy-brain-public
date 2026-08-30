from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any

from terminal.command_governance import DEFAULT_POLICY_HASH, TERMINAL_GOVERNANCE_VERSION, sha256_json


CORRECTION_PROPOSAL_VERSION = "pb259-human-approved-correction-proposal-v1"


@dataclass(frozen=True)
class CorrectionProposal:
    proposal_id: str
    reason: str
    files_affected: list[str]
    risk_level: str
    approval_required: bool
    policy_hash: str
    decision: str

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["contract_version"] = CORRECTION_PROPOSAL_VERSION
        payload["automatic_file_modification_allowed"] = False
        payload["git_add_allowed"] = False
        payload["git_commit_allowed"] = False
        payload["git_push_allowed"] = False
        payload["git_merge_allowed"] = False
        payload["delete_allowed"] = False
        payload["install_allowed"] = False
        payload["network_allowed"] = False
        return payload


def propose_correction(
    *,
    reason: str,
    files_affected: list[str],
    risk_level: str = "MEDIUM",
    policy_hash: str = DEFAULT_POLICY_HASH,
) -> dict[str, Any]:
    normalized_files = sorted(str(path) for path in files_affected)
    proposal_id = sha256_json({"reason": reason, "files_affected": normalized_files, "policy_hash": policy_hash})[:24]
    risk = risk_level if risk_level in {"LOW", "MEDIUM", "HIGH", "CRITICAL"} else "HIGH"
    decision = "BLOCKED" if risk == "CRITICAL" else "HUMAN_APPROVAL_REQUIRED"
    proposal = CorrectionProposal(
        proposal_id=proposal_id,
        reason=reason,
        files_affected=normalized_files,
        risk_level=risk,
        approval_required=True,
        policy_hash=policy_hash,
        decision=decision,
    )
    return proposal.to_dict()


def correction_proposal_flow_json() -> dict[str, Any]:
    return {
        "contract_version": TERMINAL_GOVERNANCE_VERSION,
        "generate_patch_proposals_only": True,
        "automatic_file_modification_allowed": False,
        "git_add_allowed": False,
        "git_commit_allowed": False,
        "git_push_allowed": False,
        "git_merge_allowed": False,
        "delete_allowed": False,
        "install_allowed": False,
        "network_allowed": False,
        "required_fields": [
            "proposal_id",
            "reason",
            "files_affected",
            "risk_level",
            "approval_required",
            "policy_hash",
            "decision",
        ],
    }
