from __future__ import annotations

from datetime import datetime, timedelta, timezone

from connectors.connector_contracts import CONNECTOR_NAMES, GovernedConnectorState
from connectors.credential_governance import (
    ConnectorCredentialReference,
    CredentialApprovalState,
    default_credential_governance_contract,
    validate_credential_reference,
)


def _future() -> str:
    return (datetime.now(timezone.utc) + timedelta(days=1)).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def test_credential_governance_contract_defaults_all_connectors_disabled() -> None:
    contract = default_credential_governance_contract()
    assert contract["secrets_in_repo_allowed"] is False
    assert contract["secrets_in_logs_allowed"] is False
    assert set(contract["connectors"]) == set(CONNECTOR_NAMES)
    assert all(item["connector_state"] == "DISABLED" for item in contract["connectors"].values())


def test_missing_or_unapproved_credential_reference_fails_closed() -> None:
    reference = ConnectorCredentialReference(connector="LinkedIn", credential_reference="")
    result = validate_credential_reference(reference)
    assert result["decision"] == "FAIL_CLOSED"
    assert "CREDENTIAL_REFERENCE_MALFORMED" in result["gaps"]
    assert "CREDENTIAL_UNAPPROVED" in result["gaps"]


def test_expired_credential_reference_fails_closed() -> None:
    reference = ConnectorCredentialReference(
        connector="Notion",
        credential_reference="vault://disabled/notion",
        approval_state=CredentialApprovalState.APPROVED,
        expires_at="2026-01-01T00:00:00Z",
    )
    result = validate_credential_reference(reference)
    assert result["decision"] == "FAIL_CLOSED"
    assert "CREDENTIAL_EXPIRED" in result["gaps"]


def test_sensitive_marker_in_reference_fails_closed() -> None:
    reference = ConnectorCredentialReference(
        connector="GitHub",
        credential_reference="vault://disabled/github-token",
        approval_state=CredentialApprovalState.APPROVED,
        expires_at=_future(),
    )
    result = validate_credential_reference(reference)
    assert result["decision"] == "FAIL_CLOSED"
    assert "CREDENTIAL_REFERENCE_CONTAINS_SENSITIVE_MARKER" in result["gaps"]


def test_approved_fresh_reference_still_does_not_enable_live_activation() -> None:
    reference = ConnectorCredentialReference(
        connector="Codex",
        credential_reference="vault://disabled/codex",
        approval_state=CredentialApprovalState.APPROVED,
        expires_at=_future(),
        connector_state=GovernedConnectorState.DISABLED,
    )
    result = validate_credential_reference(reference)
    assert result["decision"] == "VERIFIED"
    assert result["live_activation_allowed"] is False
