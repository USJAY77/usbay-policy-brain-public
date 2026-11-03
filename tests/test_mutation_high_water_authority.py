"""Synthetic-only tests for bounded high-water/recovery authority contracts."""
from copy import deepcopy

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from governance.mutation_high_water_authority import (
    AUTHORITY_DOMAIN, fingerprint, verify_high_water_writer_grant,
    verify_recovery_epoch_grant,
)
from governance.tenant_enrollment_contracts import (
    FLAGS, POLICY_DOMAIN, PURPOSE, SCOPE_FIELDS, TRUST_DOMAIN, canonical, digest,
)
from security.enrollment_policy_currentness import EnrollmentTrust, ScopedPublicKey
from tests.helpers.tenant_enrollment import NOW


def _fixture(action="WRITE_MUTATION_HIGH_WATER"):
    tenant = "synthetic-enrollment-tenant"
    registry = digest({"registry": "synthetic-only"})
    specs = {
        "proposal": ("synthetic-high-water-actor", ("mutation_high_water_proposal",)),
        "review-a": ("USBAY-AUDIT", ("mutation_high_water_review:USBAY-AUDIT",)),
        "review-b": ("USBAY-GLOBAL23", ("mutation_high_water_review:USBAY-GLOBAL23",)),
        "grant": ("synthetic-high-water-issuer", ("mutation_high_water_grant",)),
    }
    private = {k: Ed25519PrivateKey.generate() for k in specs}
    keys = [
        ScopedPublicKey(
            issuer, key_id,
            private[key_id].public_key().public_bytes(Encoding.Raw, PublicFormat.Raw),
            roles, tenant, registry,
            "2026-01-01T00:00:00Z", "2026-01-03T00:00:00Z",
            digest({"synthetic-high-water-key": key_id}),
        )
        for key_id, (issuer, roles) in specs.items()
    ]
    trust = EnrollmentTrust(tuple(keys), max_age_seconds=60)
    resource_type = (
        "MUTATION_HIGH_WATER_LEDGER"
        if action == "WRITE_MUTATION_HIGH_WATER"
        else "MUTATION_CURRENTNESS_EPOCH"
    )
    common = dict(
        trust_domain=TRUST_DOMAIN,
        policy_domain=POLICY_DOMAIN,
        tenant_id=tenant,
        environment="non-production",
        purpose=PURPOSE,
        registry_instance_reference=registry,
        authority_domain=AUTHORITY_DOMAIN,
        algorithm="Ed25519",
        valid_from="2026-01-02T11:00:00Z",
        valid_until="2026-01-02T13:00:00Z",
        issued_at="2026-01-02T11:59:59Z",
        authority_flags=dict.fromkeys(FLAGS, False),
    )
    scope_hash = digest({"scope": tenant})
    position_hash = (
        digest({"position": 2})
        if action == "WRITE_MUTATION_HIGH_WATER"
        else digest({"recovered": 8})
    )
    update_ref = (
        digest({"update": "u2"})
        if action == "WRITE_MUTATION_HIGH_WATER"
        else digest({"recovery_operation_id": "synthetic-recovery-operation"})
    )
    base = dict(
        actor_id="synthetic-high-water-actor",
        allowed_action=action,
        resource_type=resource_type,
        resource_id=digest({"resource": resource_type}),
        ledger_reference=digest({"ledger": tenant}),
        storage_boundary_reference=digest({"storage": "independent-test"}),
        allowed_scope_hash=scope_hash,
        allowed_scope_domain="USBAY_MUTATION_CURRENTNESS",
        redelegation_allowed=False,
        parent_authority_id="synthetic-owner-authority",
        parent_authority_hash=digest({"owner-authority": "bounded"}),
    )
    proposal = dict(
        common,
        schema_version="usbay.mutation_high_water_authority.proposal.v1",
        issuer_id=specs["proposal"][0],
        issuer_key_id="proposal",
        **base,
        proposal_id="synthetic-high-water-proposal",
        proposal_nonce="synthetic-high-water-proposal-nonce",
        proposed_position_hash=position_hash,
        update_id_reference=update_ref,
        proposal_fingerprint="",
    )
    proposal["proposal_fingerprint"] = fingerprint(proposal, "proposal")
    proposal = {"payload": proposal, "signature": private["proposal"].sign(canonical(proposal)).hex()}
    reviews = []
    for key_id in ("review-a", "review-b"):
        reviewer = specs[key_id][0]
        payload = dict(
            common,
            schema_version="usbay.mutation_high_water_authority.review.v1",
            issuer_id=reviewer,
            issuer_key_id=key_id,
            proposal_hash=digest(proposal["payload"]),
            reviewer_id=reviewer,
            reviewer_role=reviewer,
            decision="APPROVE",
            decision_nonce="nonce-" + key_id,
            decision_fingerprint="",
        )
        payload["decision_fingerprint"] = fingerprint(payload, "review")
        reviews.append({"payload": payload, "signature": private[key_id].sign(canonical(payload)).hex()})
    if action == "WRITE_MUTATION_HIGH_WATER":
        payload = dict(
            common,
            schema_version="usbay.mutation_high_water_authority.writer_grant.v1",
            issuer_id=specs["grant"][0],
            issuer_key_id="grant",
            **base,
            grant_id="synthetic-writer-grant",
            grant_nonce="synthetic-writer-nonce",
            signer_identity_reference=digest({"signer": "preprovisioned"}),
            signer_key_id="preprovisioned-test-key",
            signer_key_fingerprint=digest({"key": "preprovisioned"}),
            expected_source_epoch=1,
            expected_source_version=1,
            expected_projection_hash=digest({"projection": 1}),
            proposed_position_hash=position_hash,
            update_id_reference=update_ref,
            max_updates=1,
            proposal_hash=digest(proposal["payload"]),
            reviewer_a_decision_hash=digest(reviews[0]["payload"]),
            reviewer_b_decision_hash=digest(reviews[1]["payload"]),
            grant_fingerprint="",
        )
        kind = "writer_grant"
    else:
        payload = dict(
            common,
            schema_version="usbay.mutation_high_water_authority.recovery_grant.v1",
            issuer_id=specs["grant"][0],
            issuer_key_id="grant",
            **base,
            grant_id="synthetic-recovery-grant",
            grant_nonce="synthetic-recovery-nonce",
            previous_epoch=1,
            next_epoch=2,
            previous_source_version=7,
            previous_projection_hash=digest({"projection": 7}),
            previous_high_water_event_hash=digest({"event": 7}),
            recovery_evidence_reference=digest({"recovery": "evidence"}),
            reason_code="RESTORE_FROM_VERIFIED_HIGH_WATER",
            proposed_recovery_state_hash=digest({"recovered": 8}),
            recovery_operation_id="synthetic-recovery-operation",
            max_uses=1,
            proposal_hash=digest(proposal["payload"]),
            reviewer_a_decision_hash=digest(reviews[0]["payload"]),
            reviewer_b_decision_hash=digest(reviews[1]["payload"]),
            grant_fingerprint="",
        )
        kind = "recovery_grant"
    payload["grant_fingerprint"] = fingerprint(payload, kind)
    grant = {"payload": payload, "signature": private["grant"].sign(canonical(payload)).hex()}
    return trust, proposal, reviews, grant, scope_hash, position_hash, update_ref


def test_writer_grant_exact_binding_allows():
    trust, proposal, reviews, grant, scope_hash, position_hash, update_ref = _fixture()
    g = grant["payload"]
    result = verify_high_water_writer_grant(
        proposal, reviews, grant, trust=trust, now=NOW,
        expected_scope_hash=scope_hash,
        expected_position_hash=position_hash,
        expected_update_id_reference=update_ref,
        expected_signer_identity_reference=g["signer_identity_reference"],
        expected_signer_key_id=g["signer_key_id"],
        expected_signer_key_fingerprint=g["signer_key_fingerprint"],
        expected_parent_authority_id=g["parent_authority_id"],
        expected_parent_authority_hash=g["parent_authority_hash"],
    )
    assert result["decision"] == "ALLOW"
    assert result["max_updates"] == 1
    assert result["redelegation_allowed"] is False


def test_writer_grant_signer_substitution_denied():
    trust, proposal, reviews, grant, scope_hash, position_hash, update_ref = _fixture()
    result = verify_high_water_writer_grant(
        proposal, reviews, grant, trust=trust, now=NOW,
        expected_scope_hash=scope_hash,
        expected_position_hash=position_hash,
        expected_update_id_reference=update_ref,
        expected_signer_identity_reference=digest({"signer": "other"}),
        expected_signer_key_id=grant["payload"]["signer_key_id"],
        expected_signer_key_fingerprint=grant["payload"]["signer_key_fingerprint"],
    )
    assert result["decision"] == "DENY"
    assert result["reason"] == "HIGH_WATER_SIGNER_MISMATCH"


def test_writer_grant_redelegation_never_allowed():
    trust, proposal, reviews, grant, scope_hash, position_hash, update_ref = _fixture()
    grant = deepcopy(grant)
    grant["payload"]["redelegation_allowed"] = True
    grant["payload"]["grant_fingerprint"] = fingerprint(grant["payload"], "writer_grant")
    # signature is now stale; either signature or scope check must deny.
    result = verify_high_water_writer_grant(
        proposal, reviews, grant, trust=trust, now=NOW,
        expected_scope_hash=scope_hash,
        expected_position_hash=position_hash,
        expected_update_id_reference=update_ref,
        expected_signer_identity_reference=grant["payload"]["signer_identity_reference"],
        expected_signer_key_id=grant["payload"]["signer_key_id"],
        expected_signer_key_fingerprint=grant["payload"]["signer_key_fingerprint"],
    )
    assert result["decision"] == "DENY"


def test_writer_requires_both_reviewers():
    trust, proposal, reviews, grant, scope_hash, position_hash, update_ref = _fixture()
    g = grant["payload"]
    result = verify_high_water_writer_grant(
        proposal, reviews[:1], grant, trust=trust, now=NOW,
        expected_scope_hash=scope_hash,
        expected_position_hash=position_hash,
        expected_update_id_reference=update_ref,
        expected_signer_identity_reference=g["signer_identity_reference"],
        expected_signer_key_id=g["signer_key_id"],
        expected_signer_key_fingerprint=g["signer_key_fingerprint"],
        expected_parent_authority_id=g["parent_authority_id"],
        expected_parent_authority_hash=g["parent_authority_hash"],
    )
    assert result["decision"] == "DENY"
    assert result["reason"] == "REVIEW_THRESHOLD_NOT_MET"


def test_recovery_epoch_exact_increment_allows():
    trust, proposal, reviews, grant, scope_hash, _, _ = _fixture(
        "ADVANCE_MUTATION_RECOVERY_EPOCH")
    g = grant["payload"]
    result = verify_recovery_epoch_grant(
        proposal, reviews, grant, trust=trust, now=NOW,
        expected_scope_hash=scope_hash,
        current_epoch=1,
        current_source_version=7,
        current_projection_hash=g["previous_projection_hash"],
        expected_high_water_event_hash=g["previous_high_water_event_hash"],
        expected_recovery_state_hash=g["proposed_recovery_state_hash"],
        expected_parent_authority_id=g["parent_authority_id"],
        expected_parent_authority_hash=g["parent_authority_hash"],
    )
    assert result["decision"] == "ALLOW"
    assert result["next_epoch"] == 2
    assert result["max_uses"] == 1


def test_recovery_epoch_skip_denied():
    trust, proposal, reviews, grant, scope_hash, _, _ = _fixture(
        "ADVANCE_MUTATION_RECOVERY_EPOCH")
    g = grant["payload"]
    result = verify_recovery_epoch_grant(
        proposal, reviews, grant, trust=trust, now=NOW,
        expected_scope_hash=scope_hash,
        current_epoch=2,
        current_source_version=7,
        current_projection_hash=g["previous_projection_hash"],
        expected_high_water_event_hash=g["previous_high_water_event_hash"],
        expected_recovery_state_hash=g["proposed_recovery_state_hash"],
        expected_parent_authority_id=g["parent_authority_id"],
        expected_parent_authority_hash=g["parent_authority_hash"],
    )
    assert result["decision"] == "DENY"
    assert result["reason"] == "RECOVERY_EPOCH_INVALID"


def test_writer_parent_authority_substitution_denied():
    trust, proposal, reviews, grant, scope_hash, position_hash, update_ref = _fixture()
    g = grant["payload"]
    result = verify_high_water_writer_grant(
        proposal, reviews, grant, trust=trust, now=NOW,
        expected_scope_hash=scope_hash,
        expected_position_hash=position_hash,
        expected_update_id_reference=update_ref,
        expected_signer_identity_reference=g["signer_identity_reference"],
        expected_signer_key_id=g["signer_key_id"],
        expected_signer_key_fingerprint=g["signer_key_fingerprint"],
        expected_parent_authority_id="other-parent",
        expected_parent_authority_hash=g["parent_authority_hash"],
    )
    assert result["decision"] == "DENY"
    assert result["reason"] == "HIGH_WATER_PARENT_AUTHORITY_MISMATCH"


def test_writer_reviewed_proposal_position_mismatch_denied():
    trust, proposal, reviews, grant, scope_hash, position_hash, update_ref = _fixture()
    grant = deepcopy(grant)
    grant["payload"]["proposed_position_hash"] = digest({"position": "different"})
    result = verify_high_water_writer_grant(
        proposal, reviews, grant, trust=trust, now=NOW,
        expected_scope_hash=scope_hash,
        expected_position_hash=grant["payload"]["proposed_position_hash"],
        expected_update_id_reference=update_ref,
        expected_signer_identity_reference=grant["payload"]["signer_identity_reference"],
        expected_signer_key_id=grant["payload"]["signer_key_id"],
        expected_signer_key_fingerprint=grant["payload"]["signer_key_fingerprint"],
        expected_parent_authority_id=grant["payload"]["parent_authority_id"],
        expected_parent_authority_hash=grant["payload"]["parent_authority_hash"],
    )
    assert result["decision"] == "DENY"
