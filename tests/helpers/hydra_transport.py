"""Synthetic human issuer; never used by application execution."""
import time
from datetime import datetime, timezone
from governance.approval_issuance import generate_issuer_keypair
from governance.authority_registry import sign_issuer_registration
from governance.durable_authority_registries import DurableAuthorityRegistry, HUMAN_APPROVAL
from security.hydra_transport_authority import CONTRACT
from security.tenant_context import tenant_hash

TENANT = "test-tenant"
ENVIRONMENT = "sha256:" + "2" * 64
POLICY = "sha256:" + "3" * 64
POLICY_HASH = "sha256:" + "4" * 64
ISSUER = "sha256:" + "5" * 64
NOW = 1_700_000_010.0


def configure_transport_authority(tmp_path, monkeypatch, *, tenant=TENANT,
                                  policy_hash=POLICY_HASH, now=NOW,
                                  node_ids=("node1", "node-3")):
    monkeypatch.setattr(time, "time", lambda: now)
    private, public = generate_issuer_keypair()
    registry = DurableAuthorityRegistry(tmp_path / "authority.jsonl")
    record = {
        "authority_reference": ISSUER,
        "tenant_reference": "sha256:" + tenant_hash(tenant),
        "environment_reference": ENVIRONMENT, "policy_reference": POLICY,
        "policy_hash": policy_hash,
        "issued_at": datetime.fromtimestamp(now - 30, timezone.utc).isoformat(),
        "expires_at": datetime.fromtimestamp(now + 90, timezone.utc).isoformat(),
        "current_status": "APPROVED",
        "provenance_evidence_reference": "sha256:" + "6" * 64,
        "issuer_role": "governance_owner", "transport_contract": CONTRACT,
        "issuer_public_key_pem": public,
        "allowed_node_ids": list(node_ids),
        "allowed_endpoint_hashes": [],
    }
    from security.hydra_live_client import hydra_endpoint_url_hash
    record["allowed_endpoint_hashes"] = [hydra_endpoint_url_hash("https://hydra.example.test/" + p)
                                         for p in ("vote", "evaluate")]
    registry.create_authority(HUMAN_APPROVAL, record)
    monkeypatch.setenv("USBAY_GATEWAY_AUTHORITY_REGISTRY", str(registry.registry_path))
    monkeypatch.setenv("USBAY_HYDRA_ENVIRONMENT_REFERENCE", ENVIRONMENT)
    monkeypatch.setenv("USBAY_HYDRA_TRANSPORT_REPLAY_DB", str(tmp_path / "replay.db"))

    def signed(context, *, nonce="nonce-1"):
        context = dict(context)
        mandate = dict(context["hydra_remote_transport_authorization"])
        for field in ("evidence_verified", "trust_material_available", "revoked", "replayed"):
            mandate.pop(field, None)
        mandate.update(contract_version=CONTRACT, issuer_reference=ISSUER,
                       tenant_reference="sha256:" + tenant_hash(tenant),
                       environment_reference=ENVIRONMENT, policy_reference=POLICY,
                       policy_hash=policy_hash, nonce=nonce)
        mandate["signature"] = sign_issuer_registration(private, mandate)
        context.update(tenant_id=tenant, policy_hash=policy_hash,
                       hydra_remote_transport_authorization=mandate)
        return context

    return signed, registry, record
