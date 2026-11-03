"""Synthetic-only tests for additive all-version policy revocation effect authority."""
from copy import deepcopy

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from governance.mutation_policy_revocation_effect import (
    EFFECT, EFFECT_DOMAIN, fingerprint, verify_policy_revocation_effect,
)
from governance.tenant_enrollment_contracts import (
    FLAGS, POLICY_DOMAIN, PURPOSE, SCOPE_FIELDS, TRUST_DOMAIN, canonical, digest,
)
from security.enrollment_policy_currentness import EnrollmentTrust, ScopedPublicKey
from tests.helpers.mutation_authority import synthetic_mutation
from tests.helpers.tenant_enrollment import NOW


def _effect_fixture():
    m = synthetic_mutation()
    mg = m.grant["payload"]
    specs = {
        "effect-parent": (
            "synthetic-effect-parent",
            ("policy_revocation_effect_parent",),
        ),
        "effect-proposal": (
            mg["actor_id"],
            ("policy_revocation_effect_request",),
        ),
        "effect-review-a": (
            "USBAY-AUDIT",
            ("policy_revocation_effect_review:USBAY-AUDIT",),
        ),
        "effect-review-b": (
            "USBAY-GLOBAL23",
            ("policy_revocation_effect_review:USBAY-GLOBAL23",),
        ),
        "effect-grant": (
            "synthetic-effect-issuer",
            ("policy_revocation_effect_issuer",),
        ),
    }
    private = {name: Ed25519PrivateKey.generate() for name in specs}
    keys = list(m.trust._keys.values())
    for key_id, (issuer, roles) in specs.items():
        keys.append(ScopedPublicKey(
            issuer,
            key_id,
            private[key_id].public_key().public_bytes(
                Encoding.Raw, PublicFormat.Raw),
            roles,
            mg["tenant_id"],
            mg["registry_instance_reference"],
            "2026-01-01T00:00:00Z",
            "2026-01-03T00:00:00Z",
            digest({"synthetic-effect-key": key_id}),
        ))
    trust = EnrollmentTrust(tuple(keys), max_age_seconds=60)
    m.trust = trust
    m.enrollment.trust = trust

    def common(kind, key_id):
        return {
            "schema_version":
                "usbay.policy_revocation_effect." + kind + ".v1",
            **{k: mg[k] for k in SCOPE_FIELDS},
            "effect_authority_domain": EFFECT_DOMAIN,
            "issuer_id": specs[key_id][0],
            "issuer_key_id": key_id,
            "algorithm": "Ed25519",
            "valid_from": "2026-01-02T11:00:00Z",
            "valid_until": "2026-01-02T13:00:00Z",
            "issued_at": "2026-01-02T11:59:59Z",
            "authority_flags": dict.fromkeys(FLAGS, False),
        }

    root_hash = digest(m.root_authority["payload"])
    issuer_hash = digest(m.issuer_grant["payload"])
    base = {
        "actor_id": mg["actor_id"],
        "allowed_action": "REVOKE_POLICY_OBJECT",
        "resource_type": "POLICY_OBJECT",
        "resource_id": mg["resource_id"],
        "object_id": mg["object_id"],
        "object_version_hash": mg["object_version_hash"],
        "policy_id": mg["policy_id"],
        "expected_current_head": mg["expected_current_head"],
        "revocation_effect_scope": EFFECT,
        "parent_effect_authority_id": "upstream-effect-root",
        "parent_effect_authority_hash":
            digest({"upstream-effect-root": "synthetic"}),
        "mutation_grant_id": mg["grant_id"],
        "mutation_grant_hash": digest(mg),
        "issuer_authority_hash": issuer_hash,
        "root_authority_hash": root_hash,
        "redelegation_allowed": False,
    }

    parent = {
        **common("parent", "effect-parent"),
        **base,
        "effect_authority_id": "synthetic-policy-revocation-effect-parent",
        "subject_issuer_id": "synthetic-effect-parent",
        "effect_fingerprint": "",
    }
    parent["effect_fingerprint"] = fingerprint(parent, "parent")
    parent_env = {
        "payload": parent,
        "signature": private["effect-parent"].sign(canonical(parent)).hex(),
    }

    parent_ref = {
        "parent_effect_authority_id": parent["effect_authority_id"],
        "parent_effect_authority_hash": digest(parent),
    }
    proposal = {
        **common("proposal", "effect-proposal"),
        **base,
        **parent_ref,
        "proposal_id": "synthetic-effect-proposal",
        "proposal_nonce": "synthetic-effect-proposal-nonce",
        "proposal_fingerprint": "",
    }
    proposal["proposal_fingerprint"] = fingerprint(proposal, "proposal")
    proposal_env = {
        "payload": proposal,
        "signature": private["effect-proposal"].sign(
            canonical(proposal)).hex(),
    }

    reviews = []
    for key_id in ("effect-review-a", "effect-review-b"):
        reviewer = specs[key_id][0]
        payload = {
            **common("review", key_id),
            "proposal_hash": digest(proposal),
            "reviewer_id": reviewer,
            "reviewer_role": reviewer,
            "decision": "APPROVE",
            "decision_nonce": "synthetic-" + key_id,
            "decision_fingerprint": "",
        }
        payload["decision_fingerprint"] = fingerprint(payload, "review")
        reviews.append({
            "payload": payload,
            "signature": private[key_id].sign(canonical(payload)).hex(),
        })

    by_id = {r["payload"]["reviewer_id"]: r for r in reviews}
    grant = {
        **common("grant", "effect-grant"),
        **base,
        **parent_ref,
        "grant_id": "synthetic-effect-grant",
        "grant_nonce": "synthetic-effect-grant-nonce",
        "proposal_hash": digest(proposal),
        "reviewer_a_decision_hash":
            digest(by_id["USBAY-AUDIT"]["payload"]),
        "reviewer_b_decision_hash":
            digest(by_id["USBAY-GLOBAL23"]["payload"]),
        "review_threshold": 2,
        "review_required": 2,
        "grant_fingerprint": "",
    }
    grant["grant_fingerprint"] = fingerprint(grant, "grant")
    grant_env = {
        "payload": grant,
        "signature": private["effect-grant"].sign(canonical(grant)).hex(),
    }

    material = {
        "parent_artifact": m.parent,
        "parent_source": m.parent_source,
        "currentness": m.currentness(),
        "target_object": m.enrollment.inputs["policy"],
        "root_authority": m.root_authority,
        "issuer_grant": m.issuer_grant,
        "review_policy": m.review_policy,
        "root_source": m.root_source,
    }
    expected_state = {
        "tenant_id": mg["tenant_id"],
        "object_id": mg["object_id"],
        "object_version_hash": mg["object_version_hash"],
        "expected_current_head": mg["expected_current_head"],
        "policy_id": mg["policy_id"],
        "policy_version": m.enrollment.inputs["policy"]["payload"][
            "policy_version"],
        "policy_hash": mg["object_version_hash"],
        "revocation_effect_scope": EFFECT,
        "expected_revocation_state": "NOT_REVOKED",
    }
    return (
        m, trust, private, parent_env, proposal_env, reviews, grant_env,
        material, expected_state,
    )


def _verify(fixture):
    (
        m, trust, _, parent, proposal, reviews, grant,
        material, expected_state,
    ) = fixture
    return verify_policy_revocation_effect(
        mutation_proposal=m.proposal,
        mutation_reviews=m.reviews,
        mutation_grant=m.grant,
        mutation_material=material,
        effect_parent=parent,
        effect_proposal=proposal,
        effect_reviews=reviews,
        effect_grant=grant,
        trust=trust,
        now=NOW,
        expected_state=expected_state,
    )


def test_exact_all_version_effect_extension_allows():
    result = _verify(_effect_fixture())
    assert result["decision"] == "ALLOW"
    assert result["effect_scope"] == EFFECT
    assert result["redelegation_allowed"] is False


def test_missing_effect_extension_cannot_be_inferred_from_v1():
    fixture = list(_effect_fixture())
    fixture[6] = None
    try:
        result = _verify(tuple(fixture))
    except Exception:
        result = {"decision": "DENY"}
    assert result["decision"] == "DENY"


def test_effect_scope_substitution_denied():
    fixture = list(_effect_fixture())
    grant = deepcopy(fixture[6])
    grant["payload"]["revocation_effect_scope"] = "EXACT_VERSION_ONLY"
    fixture[6] = grant
    result = _verify(tuple(fixture))
    assert result["decision"] == "DENY"


def test_effect_parent_reference_substitution_denied():
    fixture = list(_effect_fixture())
    proposal = deepcopy(fixture[4])
    proposal["payload"]["parent_effect_authority_hash"] = digest({
        "other": "parent"})
    fixture[4] = proposal
    result = _verify(tuple(fixture))
    assert result["decision"] == "DENY"


def test_effect_requires_both_distinct_reviewers():
    fixture = list(_effect_fixture())
    fixture[5] = fixture[5][:1]
    result = _verify(tuple(fixture))
    assert result["decision"] == "DENY"
    assert result["reason"] == "REVIEW_THRESHOLD_NOT_MET"


def test_effect_mutation_grant_hash_mismatch_denied():
    fixture = list(_effect_fixture())
    grant = deepcopy(fixture[6])
    grant["payload"]["mutation_grant_hash"] = digest({"other": "grant"})
    fixture[6] = grant
    result = _verify(tuple(fixture))
    assert result["decision"] == "DENY"


def test_effect_cross_tenant_substitution_denied():
    fixture = list(_effect_fixture())
    grant = deepcopy(fixture[6])
    grant["payload"]["tenant_id"] = "other-tenant"
    fixture[6] = grant
    result = _verify(tuple(fixture))
    assert result["decision"] == "DENY"
