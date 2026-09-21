from __future__ import annotations

import time
from collections.abc import Callable
from typing import Any


EVIDENCE_EXPORT_AUDIENCE = "usbay:evidence-export"
EVIDENCE_READ_SCOPE = "evidence:read"


class EvidenceExportAuthorizationError(RuntimeError):
    pass


class EvidenceExportIdentityAuthorityUnavailable(EvidenceExportAuthorizationError):
    pass


class EvidenceExportCredentialDenied(EvidenceExportAuthorizationError):
    pass


EvidenceExportIdentityVerifier = Callable[..., dict[str, Any]]


def unavailable_evidence_export_identity_verifier(
    credential: str,
    *,
    required_audience: str,
    required_scope: str,
) -> dict[str, Any]:
    del credential, required_audience, required_scope
    raise EvidenceExportIdentityAuthorityUnavailable("identity_authority_unavailable")


def validate_evidence_export_principal(
    principal: Any,
    *,
    now_epoch: int | None = None,
) -> dict[str, Any]:
    if not isinstance(principal, dict):
        raise EvidenceExportCredentialDenied("credential_denied")

    subject_id = principal.get("subject_id")
    tenant_id = principal.get("tenant_id")
    audience = principal.get("audience")
    scopes = principal.get("scopes")
    expires_at_epoch = principal.get("expires_at_epoch")
    rotation_state = principal.get("rotation_state")

    if not isinstance(subject_id, str) or not subject_id:
        raise EvidenceExportCredentialDenied("credential_denied")
    if not isinstance(tenant_id, str) or not tenant_id:
        raise EvidenceExportCredentialDenied("credential_denied")
    if audience != EVIDENCE_EXPORT_AUDIENCE:
        raise EvidenceExportCredentialDenied("credential_denied")
    if not isinstance(scopes, (list, tuple, set)) or EVIDENCE_READ_SCOPE not in set(scopes):
        raise EvidenceExportCredentialDenied("credential_denied")
    if principal.get("revoked") is not False:
        raise EvidenceExportCredentialDenied("credential_denied")
    if rotation_state != "ROTATION_CURRENT":
        raise EvidenceExportCredentialDenied("credential_denied")
    if (
        not isinstance(expires_at_epoch, int)
        or isinstance(expires_at_epoch, bool)
        or expires_at_epoch <= int(now_epoch if now_epoch is not None else time.time())
    ):
        raise EvidenceExportCredentialDenied("credential_denied")

    return {
        "subject_id": subject_id,
        "tenant_id": tenant_id,
        "audience": audience,
        "scopes": tuple(sorted(set(scopes))),
        "expires_at_epoch": expires_at_epoch,
        "rotation_state": rotation_state,
        "credential_id": str(principal.get("credential_id", "")),
    }