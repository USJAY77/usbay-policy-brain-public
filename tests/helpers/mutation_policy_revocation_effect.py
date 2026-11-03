"""TEST ONLY builder for additive policy-revocation effect authority."""
from copy import deepcopy
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from governance.mutation_policy_revocation_effect import EFFECT, EFFECT_DOMAIN, fingerprint
from governance.tenant_enrollment_contracts import FLAGS, SCOPE_FIELDS, canonical, digest
from security.enrollment_policy_currentness import EnrollmentTrust, ScopedPublicKey


def build_effect_for_mutation(m):
    mg=m.grant["payload"]
    specs={
        "effect-parent":("synthetic-effect-parent",("policy_revocation_effect_parent",)),
        "effect-proposal":(mg["actor_id"],("policy_revocation_effect_request",)),
        "effect-review-a":("USBAY-AUDIT",("policy_revocation_effect_review:USBAY-AUDIT",)),
        "effect-review-b":("USBAY-GLOBAL23",("policy_revocation_effect_review:USBAY-GLOBAL23",)),
        "effect-grant":("synthetic-effect-issuer",("policy_revocation_effect_issuer",)),
    }
    private={k:Ed25519PrivateKey.generate() for k in specs}
    keys=list(m.trust._keys.values())
    for key_id,(issuer,roles) in specs.items():
        keys.append(ScopedPublicKey(
            issuer,key_id,
            private[key_id].public_key().public_bytes(Encoding.Raw,PublicFormat.Raw),
            roles,mg["tenant_id"],mg["registry_instance_reference"],
            "2026-01-01T00:00:00Z","2026-01-03T00:00:00Z",
            digest({"synthetic-effect-key":key_id}),
        ))
    m.trust=EnrollmentTrust(tuple(keys),max_age_seconds=60)
    m.enrollment.trust=m.trust
    def common(kind,key_id):
        return dict(
            schema_version="usbay.policy_revocation_effect."+kind+".v1",
            **{k:mg[k] for k in SCOPE_FIELDS},
            effect_authority_domain=EFFECT_DOMAIN,
            issuer_id=specs[key_id][0],issuer_key_id=key_id,algorithm="Ed25519",
            valid_from="2026-01-02T11:00:00Z",valid_until="2026-01-02T13:00:00Z",
            issued_at="2026-01-02T11:59:59Z",authority_flags=dict.fromkeys(FLAGS,False),
        )
    base=dict(
        actor_id=mg["actor_id"],allowed_action="REVOKE_POLICY_OBJECT",resource_type="POLICY_OBJECT",
        resource_id=mg["resource_id"],object_id=mg["object_id"],object_version_hash=mg["object_version_hash"],
        policy_id=mg["policy_id"],expected_current_head=mg["expected_current_head"],
        revocation_effect_scope=EFFECT,parent_effect_authority_id="upstream-effect-root",
        parent_effect_authority_hash=digest({"upstream-effect-root":"synthetic"}),
        mutation_grant_id=mg["grant_id"],mutation_grant_hash=digest(mg),
        issuer_authority_hash=digest(m.issuer_grant["payload"]),
        root_authority_hash=digest(m.root_authority["payload"]),redelegation_allowed=False,
    )
    parent=dict(common("parent","effect-parent"),**base,
        effect_authority_id="synthetic-policy-revocation-effect-parent",
        subject_issuer_id="synthetic-effect-parent",effect_fingerprint="")
    parent["effect_fingerprint"]=fingerprint(parent,"parent")
    parent_env=dict(payload=parent,signature=private["effect-parent"].sign(canonical(parent)).hex())
    pref=dict(parent_effect_authority_id=parent["effect_authority_id"],parent_effect_authority_hash=digest(parent))
    proposal=dict(common("proposal","effect-proposal"),**base,**pref,
        proposal_id="synthetic-effect-proposal",proposal_nonce="synthetic-effect-proposal-nonce",
        proposal_fingerprint="")
    proposal["proposal_fingerprint"]=fingerprint(proposal,"proposal")
    proposal_env=dict(payload=proposal,signature=private["effect-proposal"].sign(canonical(proposal)).hex())
    reviews=[]
    for key_id in ("effect-review-a","effect-review-b"):
        reviewer=specs[key_id][0]
        p=dict(common("review",key_id),proposal_hash=digest(proposal),reviewer_id=reviewer,
            reviewer_role=reviewer,decision="APPROVE",decision_nonce="synthetic-"+key_id,
            decision_fingerprint="")
        p["decision_fingerprint"]=fingerprint(p,"review")
        reviews.append(dict(payload=p,signature=private[key_id].sign(canonical(p)).hex()))
    by_id={r["payload"]["reviewer_id"]:r for r in reviews}
    grant=dict(common("grant","effect-grant"),**base,**pref,
        grant_id="synthetic-effect-grant",grant_nonce="synthetic-effect-grant-nonce",
        proposal_hash=digest(proposal),
        reviewer_a_decision_hash=digest(by_id["USBAY-AUDIT"]["payload"]),
        reviewer_b_decision_hash=digest(by_id["USBAY-GLOBAL23"]["payload"]),
        review_threshold=2,review_required=2,grant_fingerprint="")
    grant["grant_fingerprint"]=fingerprint(grant,"grant")
    grant_env=dict(payload=grant,signature=private["effect-grant"].sign(canonical(grant)).hex())
    return dict(parent=parent_env,proposal=proposal_env,reviews=reviews,grant=grant_env)
