"""Shared test helper: issue a properly signed approval into a registry."""

from __future__ import annotations

import uuid

from governance.approval_issuance import (
    build_issuance_payload,
    generate_issuer_keypair,
    sign_issuance,
)
from governance.authority_registry import authorization_binding_hash

DEFAULT_ISSUER = "issuer-human-1"
DEFAULT_TENANT = "tenant-alpha"


def register_test_issuer(
    registry,
    *,
    issuer_id: str = DEFAULT_ISSUER,
    authorized_actors=("human-actor-1",),
    authorized_providers=("higgsfield",),
    tenant_reference: str | None = DEFAULT_TENANT,
) -> str:
    """Register an issuer with a fresh keypair; returns the private PEM."""
    private_pem, public_pem = generate_issuer_keypair()
    registry.register_issuer(
        issuer_id=issuer_id,
        public_key_pem=public_pem,
        authorized_actors=authorized_actors,
        authorized_providers=authorized_providers,
        tenant_reference=tenant_reference,
    )
    return private_pem


def signed_issuance(
    *,
    private_pem: str,
    authorization,
    actor_id: str,
    issuer_id: str = DEFAULT_ISSUER,
    tenant_reference: str = DEFAULT_TENANT,
    execution_id: str | None = None,
    nonce: str | None = None,
    **payload_overrides,
) -> tuple[dict, str]:
    payload = build_issuance_payload(
        issuer_id=issuer_id,
        actor_id=actor_id,
        authorization_id=authorization.authorization_id,
        binding_hash=authorization_binding_hash(authorization, actor_id),
        tenant_reference=tenant_reference,
        nonce=nonce or uuid.uuid4().hex,
        execution_id=execution_id,
    )
    payload.update(payload_overrides)
    return payload, sign_issuance(private_pem, payload)


def issue_approval(
    registry,
    *,
    private_pem: str,
    authorization,
    actor_id: str,
    issuer_id: str = DEFAULT_ISSUER,
    tenant_reference: str = DEFAULT_TENANT,
    execution_id: str | None = None,
    valid_for_seconds: int = 3600,
) -> str:
    payload, signature = signed_issuance(
        private_pem=private_pem,
        authorization=authorization,
        actor_id=actor_id,
        issuer_id=issuer_id,
        tenant_reference=tenant_reference,
        execution_id=execution_id,
    )
    return registry.register_approval(
        authorization=authorization,
        actor_id=actor_id,
        issuance_payload=payload,
        issuance_signature=signature,
        valid_for_seconds=valid_for_seconds,
        execution_id=execution_id,
    )
