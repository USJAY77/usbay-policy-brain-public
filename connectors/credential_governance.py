from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from enum import Enum
from typing import Any

from connectors.connector_contracts import CONNECTOR_NAMES, GovernedConnectorState


CREDENTIAL_GOVERNANCE_VERSION = "pb220-connector-credential-governance-v1"
SENSITIVE_MARKERS = ("secret", "token", "password", "private_key", "authorization", "api_key")


class CredentialApprovalState(str, Enum):
    UNAPPROVED = "UNAPPROVED"
    APPROVED = "APPROVED"
    EXPIRED = "EXPIRED"
    BLOCKED = "BLOCKED"


@dataclass(frozen=True)
class ConnectorCredentialReference:
    connector: str
    credential_reference: str
    approval_state: CredentialApprovalState = CredentialApprovalState.UNAPPROVED
    expires_at: str = "1970-01-01T00:00:00Z"
    connector_state: GovernedConnectorState = GovernedConnectorState.DISABLED

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["approval_state"] = self.approval_state.value
        payload["connector_state"] = self.connector_state.value
        return payload


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _parse_utc(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def _contains_sensitive_marker(value: str) -> bool:
    normalized = value.lower()
    return any(marker in normalized for marker in SENSITIVE_MARKERS)


def default_credential_governance_contract() -> dict[str, Any]:
    return {
        "contract_version": CREDENTIAL_GOVERNANCE_VERSION,
        "secrets_in_repo_allowed": False,
        "secrets_in_logs_allowed": False,
        "default_connector_state": GovernedConnectorState.DISABLED.value,
        "production_activation_allowed": False,
        "connectors": {
            name: ConnectorCredentialReference(connector=name, credential_reference=f"vault://disabled/{name.lower()}").to_dict()
            for name in CONNECTOR_NAMES
        },
    }


def validate_credential_reference(
    reference: ConnectorCredentialReference,
    *,
    now: datetime | None = None,
) -> dict[str, Any]:
    gaps: list[str] = []
    if reference.connector not in CONNECTOR_NAMES:
        gaps.append("UNKNOWN_CONNECTOR")
    if not reference.credential_reference or not reference.credential_reference.startswith("vault://"):
        gaps.append("CREDENTIAL_REFERENCE_MALFORMED")
    if _contains_sensitive_marker(reference.credential_reference):
        gaps.append("CREDENTIAL_REFERENCE_CONTAINS_SENSITIVE_MARKER")
    if reference.connector_state != GovernedConnectorState.DISABLED:
        gaps.append("CONNECTOR_NOT_DISABLED")
    if reference.approval_state != CredentialApprovalState.APPROVED:
        gaps.append("CREDENTIAL_UNAPPROVED")
    try:
        expires_at = _parse_utc(reference.expires_at)
        if expires_at <= (now or _utc_now()):
            gaps.append("CREDENTIAL_EXPIRED")
    except Exception:
        gaps.append("CREDENTIAL_REFERENCE_MALFORMED")
    return {
        "decision": "VERIFIED" if not gaps else "FAIL_CLOSED",
        "gaps": sorted(set(gaps)),
        "connector": reference.connector,
        "connector_state": reference.connector_state.value,
        "credential_governance_version": CREDENTIAL_GOVERNANCE_VERSION,
        "live_activation_allowed": False,
    }
