from __future__ import annotations

from dataclasses import asdict, dataclass
from enum import Enum
from typing import Any


DEPLOYMENT_ATTESTATION_VERSION = "pb219-deployment-attestation-contract-v1"
REQUIRED_ATTESTATION_FIELDS = (
    "deployment_id",
    "actor",
    "commit_sha",
    "policy_hash",
    "signature_id",
    "environment",
    "created_at",
    "status",
)


class DeploymentAttestationStatus(str, Enum):
    BLOCKED = "BLOCKED"
    READY_FOR_REVIEW = "READY_FOR_REVIEW"


@dataclass(frozen=True)
class DeploymentAttestation:
    deployment_id: str
    actor: str
    commit_sha: str
    policy_hash: str
    signature_id: str
    environment: str
    created_at: str
    status: DeploymentAttestationStatus = DeploymentAttestationStatus.BLOCKED

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["status"] = self.status.value
        payload["contract_version"] = DEPLOYMENT_ATTESTATION_VERSION
        return payload


def _is_sha256(value: str) -> bool:
    return isinstance(value, str) and len(value) == 64 and all(ch in "0123456789abcdef" for ch in value)


def validate_deployment_attestation(payload: dict[str, Any], *, all_checks_passed: bool = False) -> dict[str, Any]:
    if not isinstance(payload, dict):
        return {"decision": "FAIL_CLOSED", "status": "BLOCKED", "gaps": ["MALFORMED_ATTESTATION"]}
    gaps: list[str] = []
    for field in REQUIRED_ATTESTATION_FIELDS:
        if field not in payload or not isinstance(payload.get(field), str) or not payload.get(field):
            gaps.append(f"MISSING_{field.upper()}")
    if "policy_hash" in payload and not _is_sha256(str(payload.get("policy_hash"))):
        gaps.append("MALFORMED_POLICY_HASH")
    if str(payload.get("status", "BLOCKED")) != "BLOCKED" and not all_checks_passed:
        gaps.append("ATTESTATION_STATUS_MUST_DEFAULT_BLOCKED")

    status = "READY_FOR_REVIEW" if all_checks_passed and not gaps else "BLOCKED"
    return {
        "decision": "VERIFIED" if not gaps else "FAIL_CLOSED",
        "status": status,
        "gaps": sorted(set(gaps)),
        "contract_version": DEPLOYMENT_ATTESTATION_VERSION,
        "deployment_allowed": False,
    }


def deployment_attestation_schema() -> dict[str, Any]:
    return {
        "contract_version": DEPLOYMENT_ATTESTATION_VERSION,
        "type": "object",
        "required": list(REQUIRED_ATTESTATION_FIELDS),
        "properties": {
            "deployment_id": {"type": "string"},
            "actor": {"type": "string"},
            "commit_sha": {"type": "string"},
            "policy_hash": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
            "signature_id": {"type": "string"},
            "environment": {"type": "string"},
            "created_at": {"type": "string", "format": "date-time"},
            "status": {"type": "string", "enum": [status.value for status in DeploymentAttestationStatus]},
        },
        "default_status": "BLOCKED",
        "deployment_allowed": False,
    }
