from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from enum import Enum
from typing import Any


PILOT_APPROVAL_GATE_VERSION = "pb227-pilot-approval-gate-v1"
APPROVED_WORKFLOW = ("GitHub", "USBAY Gateway", "Human Approval", "Codex")
REQUIRED_APPROVAL_FIELDS = (
    "customer_id",
    "pilot_scope",
    "approved_actor",
    "policy_hash",
    "connector_state",
    "deployment_attestation_id",
    "approval_status",
    "expires_at",
)


class PilotApprovalStatus(str, Enum):
    BLOCKED = "BLOCKED"
    PENDING_HUMAN_APPROVAL = "PENDING_HUMAN_APPROVAL"
    APPROVED = "APPROVED"
    EXPIRED = "EXPIRED"


@dataclass(frozen=True)
class PilotApprovalContract:
    customer_id: str
    pilot_scope: str
    approved_actor: str
    policy_hash: str
    connector_state: str
    deployment_attestation_id: str
    approval_status: PilotApprovalStatus = PilotApprovalStatus.BLOCKED
    expires_at: str = "1970-01-01T00:00:00Z"

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["approval_status"] = self.approval_status.value
        payload["workflow"] = list(APPROVED_WORKFLOW)
        payload["contract_version"] = PILOT_APPROVAL_GATE_VERSION
        payload["live_execution_allowed"] = False
        return payload


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _parse_utc(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def _is_sha256(value: str) -> bool:
    return isinstance(value, str) and len(value) == 64 and all(ch in "0123456789abcdef" for ch in value)


def validate_pilot_approval_contract(payload: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(payload, dict):
        return {"decision": "FAIL_CLOSED", "status": "BLOCKED", "gaps": ["MALFORMED_APPROVAL_CONTRACT"]}
    gaps: list[str] = []
    for field in REQUIRED_APPROVAL_FIELDS:
        if field not in payload or not isinstance(payload.get(field), str) or not payload.get(field):
            gaps.append(f"MISSING_{field.upper()}")
    if "policy_hash" in payload and not _is_sha256(str(payload.get("policy_hash"))):
        gaps.append("MALFORMED_POLICY_HASH")
    if payload.get("pilot_scope") != "GitHub -> USBAY Gateway -> Human Approval -> Codex":
        gaps.append("PILOT_SCOPE_NOT_APPROVED")
    if payload.get("connector_state") not in {"DRY_RUN", "PILOT_APPROVED"}:
        gaps.append("CONNECTOR_STATE_NOT_READY")
    if payload.get("approval_status") != PilotApprovalStatus.APPROVED.value:
        gaps.append("HUMAN_APPROVAL_REQUIRED")
    try:
        if _parse_utc(str(payload.get("expires_at"))) <= _utc_now():
            gaps.append("APPROVAL_EXPIRED")
    except Exception:
        gaps.append("MALFORMED_EXPIRES_AT")
    return {
        "decision": "VERIFIED" if not gaps else "FAIL_CLOSED",
        "status": "READY_FOR_REVIEW" if not gaps else "BLOCKED",
        "gaps": sorted(set(gaps)),
        "contract_version": PILOT_APPROVAL_GATE_VERSION,
        "live_execution_allowed": False,
    }


def default_pilot_approval_contract_json() -> dict[str, Any]:
    return PilotApprovalContract(
        customer_id="pilot-customer-redacted",
        pilot_scope="GitHub -> USBAY Gateway -> Human Approval -> Codex",
        approved_actor="human-approval-required",
        policy_hash="88d1aaa62bbe011c9f51d7f159a7526a2fe283b94314e8c9b9cce73b199f04d1",
        connector_state="DRY_RUN",
        deployment_attestation_id="deployment-attestation-required",
        approval_status=PilotApprovalStatus.BLOCKED,
    ).to_dict()
