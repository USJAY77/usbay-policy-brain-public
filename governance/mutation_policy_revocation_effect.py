"""Bounded non-production all-version policy-revocation effect authority.

This is an additive capability. Existing mutation-authority v1 grants are not
modified and remain insufficient for REVOKE_POLICY_OBJECT all-version effects.
The extension can only be evaluated together with an already verified mutation
authority chain and creates no writer, signer, storage, production authority,
or exact-version fallback.
"""
from __future__ import annotations

from dataclasses import dataclass
from copy import deepcopy
import re

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from governance.mutation_authority import (
    REVIEWERS, verify_mutation_authority_grant,
)
from governance.tenant_enrollment_contracts import (
    FLAGS, POLICY_DOMAIN, PURPOSE, SCOPE_FIELDS, TRUST_DOMAIN, EnrollmentDenied,
    canonical, decision, digest, instant, parse_json, require,
)
from security.enrollment_policy_currentness import EnrollmentTrust

EFFECT_DOMAIN = "USBAY_POLICY_REVOCATION_EFFECT_AUTHORITY"
ACTION = "REVOKE_POLICY_OBJECT"
RESOURCE = "POLICY_OBJECT"
EFFECT = "ALL_VERSIONS_OF_OBJECT"

COMMON = {
    "schema_version", *SCOPE_FIELDS, "effect_authority_domain", "issuer_id",
    "issuer_key_id", "algorithm", "valid_from", "valid_until", "issued_at",
    "authority_flags",
}
BINDINGS = {
    "actor_id", "allowed_action", "resource_type", "resource_id", "object_id",
    "object_version_hash", "policy_id", "expected_current_head",
    "revocation_effect_scope", "parent_effect_authority_id",
    "parent_effect_authority_hash", "mutation_grant_id", "mutation_grant_hash",
    "issuer_authority_hash", "root_authority_hash", "redelegation_allowed",
}
FIELDS = {
    "parent": BINDINGS | {
        "effect_authority_id", "subject_issuer_id", "effect_fingerprint",
    },
    "proposal": BINDINGS | {
        "proposal_id", "proposal_nonce", "proposal_fingerprint",
    },
    "review": {
        "proposal_hash", "reviewer_id", "reviewer_role", "decision",
        "decision_nonce", "decision_fingerprint",
    },
    "grant": BINDINGS | {
        "grant_id", "grant_nonce", "proposal_hash",
        "reviewer_a_decision_hash", "reviewer_b_decision_hash",
        "review_threshold", "review_required", "grant_fingerprint",
    },
}
FP = {
    "parent": "effect_fingerprint",
    "proposal": "proposal_fingerprint",
    "review": "decision_fingerprint",
    "grant": "grant_fingerprint",
}


def fingerprint(payload, kind):
    return digest({k: v for k, v in payload.items() if k != FP[kind]})


@dataclass(frozen=True)
class _Contract:
    encoded: bytes
    kind = ""

    @property
    def payload(self):
        return parse_json(self.encoded)

    @classmethod
    def from_payload(cls, p):
        require(type(p) is dict and set(p) == COMMON | FIELDS[cls.kind],
                "POLICY_REVOCATION_EFFECT_INVALID")
        canonical(p)
        require(
            p["schema_version"]
            == "usbay.policy_revocation_effect." + cls.kind + ".v1",
            "POLICY_REVOCATION_EFFECT_INVALID")
        require(
            p["trust_domain"] == TRUST_DOMAIN
            and p["policy_domain"] == POLICY_DOMAIN
            and p["environment"] == "non-production"
            and p["purpose"] == PURPOSE
            and p["effect_authority_domain"] == EFFECT_DOMAIN,
            "POLICY_REVOCATION_EFFECT_INVALID")
        require(
            type(p["tenant_id"]) is str
            and re.fullmatch(r"[a-z0-9][a-z0-9_-]{0,63}", p["tenant_id"]),
            "TENANT_MISMATCH")
        require(
            type(p["authority_flags"]) is dict
            and set(p["authority_flags"]) == set(FLAGS)
            and all(v is False for v in p["authority_flags"].values()),
            "AUTHORITY_SCOPE_BROADENING")
        require(
            p["algorithm"] == "Ed25519"
            and instant(p["valid_from"]) < instant(p["valid_until"])
            and instant(p["issued_at"]) < instant(p["valid_until"]),
            "POLICY_REVOCATION_EFFECT_INVALID")

        special = {
            "authority_flags", "redelegation_allowed",
            "review_threshold", "review_required",
        }
        for key, value in p.items():
            if key in special:
                continue
            require(type(value) is str and 0 < len(value) <= 256
                    and "*" not in value,
                    "POLICY_REVOCATION_EFFECT_INVALID")
            if (key.endswith(("_hash", "_fingerprint"))
                    or key in ("resource_id", "object_id",
                               "expected_current_head")):
                require(re.fullmatch(r"sha256:[0-9a-f]{64}", value) is not None,
                        "POLICY_REVOCATION_EFFECT_INVALID")

        if cls.kind == "review":
            require(
                p["reviewer_id"] in REVIEWERS
                and p["reviewer_role"] == REVIEWERS[p["reviewer_id"]]
                and p["issuer_id"] == p["reviewer_id"]
                and p["decision"] in ("APPROVE", "REJECT"),
                "REVIEW_DECISION_INVALID")
        else:
            require(
                p["allowed_action"] == ACTION
                and p["resource_type"] == RESOURCE
                and p["resource_id"] == p["object_id"],
                "ACTION_NOT_AUTHORIZED")
            require(p["revocation_effect_scope"] == EFFECT,
                    "REVOCATION_SCOPE_MISMATCH")
            require(p["redelegation_allowed"] is False,
                    "PROHIBITED_REDELEGATION")

        if cls.kind == "parent":
            require(
                p["issuer_id"] == p["subject_issuer_id"],
                "PARENT_AUTHORITY_INVALID")
        if cls.kind == "proposal":
            require(p["issuer_id"] == p["actor_id"], "ACTOR_MISMATCH")
        if cls.kind == "grant":
            require(
                type(p["review_threshold"]) is int
                and type(p["review_required"]) is int
                and p["review_threshold"] == p["review_required"] == 2,
                "REVIEW_THRESHOLD_NOT_MET")

        require(p[FP[cls.kind]] == fingerprint(p, cls.kind),
                "POLICY_REVOCATION_EFFECT_INVALID")
        return cls(canonical(p))


class PolicyRevocationEffectParentV1(_Contract):
    kind = "parent"


class PolicyRevocationEffectProposalV1(_Contract):
    kind = "proposal"


class PolicyRevocationEffectReviewV1(_Contract):
    kind = "review"


class PolicyRevocationEffectGrantV1(_Contract):
    kind = "grant"


def _signed(trust, envelope, model, role, now):
    require(
        isinstance(trust, EnrollmentTrust)
        and type(envelope) is dict
        and set(envelope) == {"payload", "signature"},
        "POLICY_REVOCATION_EFFECT_INVALID")
    p = model.from_payload(envelope["payload"]).payload
    key = trust._keys.get(p["issuer_key_id"])
    require(
        key is not None and key.issuer_id == p["issuer_id"]
        and role in key.roles
        and tuple(p[k] for k in SCOPE_FIELDS)
            == (key.trust_domain, key.policy_domain, key.tenant_id,
                key.environment, key.purpose,
                key.registry_instance_reference),
        "POLICY_REVOCATION_EFFECT_INVALID")
    require(
        instant(key.valid_from) <= now < instant(key.expires_at)
        and instant(p["valid_from"]) <= now < instant(p["valid_until"]),
        "POLICY_REVOCATION_EFFECT_EXPIRED")
    try:
        Ed25519PublicKey.from_public_bytes(key.public_key).verify(
            bytes.fromhex(envelope["signature"]), canonical(p))
    except Exception:
        raise EnrollmentDenied("POLICY_REVOCATION_EFFECT_INVALID") from None
    return p, key


def verify_policy_revocation_effect(
        *, mutation_proposal, mutation_reviews, mutation_grant,
        mutation_material, effect_parent, effect_proposal,
        effect_reviews, effect_grant, trust, now, expected_state):
    """Verify additive all-version effect authority over a valid mutation chain."""
    try:
        mutation = verify_mutation_authority_grant(
            mutation_proposal, mutation_reviews, mutation_grant,
            trust=trust, now=now, **mutation_material)
        require(mutation["decision"] == "ALLOW",
                mutation.get("reason", "MUTATION_AUTHORITY_MISSING"))

        mg = mutation_grant["payload"]
        parent, _ = _signed(
            trust, effect_parent, PolicyRevocationEffectParentV1,
            "policy_revocation_effect_parent", now)
        proposal, _ = _signed(
            trust, effect_proposal, PolicyRevocationEffectProposalV1,
            "policy_revocation_effect_request", now)
        require(type(effect_reviews) is list and len(effect_reviews) == 2,
                "REVIEW_THRESHOLD_NOT_MET")
        reviews = []
        for envelope in effect_reviews:
            reviewer = envelope.get("payload", {}).get("reviewer_id")
            item, key = _signed(
                trust, envelope, PolicyRevocationEffectReviewV1,
                "policy_revocation_effect_review:" + str(reviewer), now)
            reviews.append((item, key))
        grant, _ = _signed(
            trust, effect_grant, PolicyRevocationEffectGrantV1,
            "policy_revocation_effect_issuer", now)

        require(
            {r["reviewer_id"] for r, _ in reviews} == set(REVIEWERS)
            and len({k.public_key for _, k in reviews}) == 2,
            "REVIEW_THRESHOLD_NOT_MET")
        by_id = {r["reviewer_id"]: r for r, _ in reviews}
        require(all(r["decision"] == "APPROVE" for r, _ in reviews),
                "REVIEW_DECISION_INVALID")
        require(all(r["proposal_hash"] == digest(proposal)
                    for r, _ in reviews),
                "REVIEW_PROPOSAL_MISMATCH")
        require(
            grant["proposal_hash"] == digest(proposal)
            and grant["reviewer_a_decision_hash"]
                == digest(by_id["USBAY-AUDIT"])
            and grant["reviewer_b_decision_hash"]
                == digest(by_id["USBAY-GLOBAL23"]),
            "REVIEW_DECISION_INVALID")

        for field in BINDINGS:
            require(grant[field] == proposal[field],
                    "AUTHORITY_SCOPE_BROADENING")
            require(grant[field] == parent[field],
                    "AUTHORITY_SCOPE_BROADENING")

        require(
            grant["parent_effect_authority_id"]
                == parent["effect_authority_id"]
            and grant["parent_effect_authority_hash"] == digest(parent),
            "PARENT_AUTHORITY_INVALID")

        require(
            grant["mutation_grant_id"] == mg["grant_id"]
            and grant["mutation_grant_hash"] == digest(mg),
            "MUTATION_AUTHORITY_INVALID")
        require(
            grant["issuer_authority_hash"]
                == mutation_material["issuer_grant"]["payload"].get(
                    "issuer_grant_hash",
                    digest(mutation_material["issuer_grant"]["payload"]))
                or grant["issuer_authority_hash"]
                == digest(mutation_material["issuer_grant"]["payload"]),
            "MUTATION_AUTHORITY_INVALID")
        require(
            grant["root_authority_hash"]
                == digest(mutation_material["root_authority"]["payload"]),
            "MUTATION_AUTHORITY_INVALID")

        require(
            grant["actor_id"] == mg["actor_id"]
            and grant["allowed_action"] == mg["allowed_action"] == ACTION
            and grant["resource_type"] == mg["resource_type"] == RESOURCE
            and grant["resource_id"] == mg["resource_id"]
            and grant["object_id"] == mg["object_id"]
            and grant["object_version_hash"] == mg["object_version_hash"]
            and grant["policy_id"] == mg["policy_id"]
            and grant["expected_current_head"]
                == mg["expected_current_head"],
            "AUTHORITY_SCOPE_BROADENING")
        require(all(grant[k] == mg[k] for k in SCOPE_FIELDS),
                "TENANT_MISMATCH")
        require(
            expected_state["revocation_effect_scope"] == EFFECT
            and grant["revocation_effect_scope"] == EFFECT,
            "REVOCATION_SCOPE_MISMATCH")
        require(
            expected_state["object_id"] == grant["object_id"]
            and expected_state["object_version_hash"]
                == grant["object_version_hash"]
            and expected_state["expected_current_head"]
                == grant["expected_current_head"]
            and expected_state["policy_id"] == grant["policy_id"],
            "EXPECTED_STATE_MISMATCH")

        return decision(
            "POLICY_REVOCATION_EFFECT_VERIFIED",
            allowed=True,
            effect_scope=EFFECT,
            effect_grant_id=grant["grant_id"],
            effect_grant_hash=digest(grant),
            parent_effect_authority_hash=digest(parent),
            redelegation_allowed=False,
        )
    except Exception as error:
        return decision(
            str(error) if type(error) is EnrollmentDenied
            else "POLICY_REVOCATION_EFFECT_INVALID")
