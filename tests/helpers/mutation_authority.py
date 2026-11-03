"""Synthetic signatures only: reviewer labels are NOT human reviews/approvals.
No real root, parent authority, mutation grant or reviewer identity is provisioned.
"""
from copy import deepcopy
from dataclasses import dataclass

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from governance.mutation_authority import AUTHORITY_DOMAIN, fingerprint
from governance.tenant_enrollment_contracts import FLAGS, SCOPE_FIELDS, canonical, digest, object_id, EnrollmentPolicy
from security.enrollment_policy_currentness import EnrollmentTrust, ScopedPublicKey
from tests.helpers.tenant_enrollment import NOW, synthetic_enrollment


@dataclass
class SyntheticMutation:
    enrollment: object
    trust: EnrollmentTrust
    private: dict
    proposal: dict
    reviews: list
    grant: dict
    parent: dict
    parent_source: object = None
    root_authority: object = None
    issuer_grant: object = None
    review_policy: object = None
    root_source: object = None

    def sign(self, p):
        return dict(payload=deepcopy(p), signature=self.private[p["issuer_key_id"]].sign(canonical(p)).hex())

    def seal(self, p, kind):
        p = deepcopy(p)
        key = {"proposal": "proposal_fingerprint", "review": "decision_fingerprint", "grant": "grant_fingerprint", "parent_scope": "parent_fingerprint"}[kind]
        p[key] = fingerprint(p, kind)
        return self.sign(p)

    def refresh(self):
        self.parent = self.seal(self.parent["payload"], "parent_scope")
        parent_hash = digest(self.parent["payload"])
        p = deepcopy(self.proposal["payload"])
        p.update(parent_authority_hash=parent_hash, parent_authority_id=self.parent["payload"]["authority_id"])
        self.proposal = self.seal(p, "proposal")
        ph = digest(self.proposal["payload"])
        self.reviews = [self.seal(dict(r["payload"], proposal_hash=ph), "review") for r in self.reviews]
        by_id = {r["payload"]["reviewer_id"]: r for r in self.reviews}
        g = deepcopy(self.grant["payload"])
        g.update(parent_authority_id=self.parent["payload"]["authority_id"], parent_authority_hash=parent_hash,
                 issuer_authority_reference=parent_hash, proposal_hash=ph,
                 reviewer_a_decision_hash=digest(by_id["USBAY-AUDIT"]["payload"]),
                 reviewer_b_decision_hash=digest(by_id["USBAY-GLOBAL23"]["payload"]))
        self.grant = self.seal(g, "grant")

    def currentness(self):
        f = self.enrollment
        result = {k: f.inputs[k] for k in ("policy", "adoption", "h", "w", "revocations")}
        result.update(expected=f.head, challenge=f.inputs["request"]["payload"]["nonce"],
                      request_digest=digest(f.inputs["request"]["payload"]))
        return result

    def rebind_enrollment(self, enrollment):
        self.enrollment = enrollment
        policy = enrollment.inputs["policy"]["payload"]
        for envelope in (self.parent, self.proposal, self.grant):
            envelope["payload"].update(object_id=object_id(EnrollmentPolicy, policy),
                resource_id=object_id(EnrollmentPolicy, policy), object_version_hash=digest(policy),
                expected_current_head=enrollment.head["head_hash"])
        self.parent["payload"]["revocation_reference"] = policy["revocation_reference"]
        self.refresh()
        # Explicit synthetic setup update, not a request-driven trust operation.
        if self.parent_source is not None:
            self.parent_source.install_test_record(self)

    def verify(self, **overrides):
        from governance.mutation_authority import verify_mutation_authority_grant
        args = dict(trust=self.trust, parent_artifact=self.parent, currentness=self.currentness(),
                    parent_source=self.parent_source, root_authority=self.root_authority, issuer_grant=self.issuer_grant,
                    review_policy=self.review_policy, root_source=self.root_source, target_object=self.enrollment.inputs["policy"], now=NOW)
        args.update(overrides)
        return verify_mutation_authority_grant(self.proposal, self.reviews, self.grant, **args)


class SyntheticParentAuthoritySource:
    """Test-owned authoritative fixture, not a live registry or producer.

    The requested hash cannot select/overwrite this independently installed
    record. Real Ed25519 proofs use an independent ephemeral source key. This is
    explicit simulated parent authority, not an assertion that live authority or
    real reviewer identities exist. No production implementation uses this class.
    """
    def __init__(self, fixture):
        self.private = fixture.private["test-parent-currentness"]
        self.status = "ACTIVE"
        self.sequence = 1
        self.challenges = []
        self.install_test_record(fixture)

    def install_test_record(self, fixture):
        p = fixture.parent["payload"]
        self.record = deepcopy(p)
        self.head = fixture.enrollment.head["head_hash"]
        self.revocation = fixture.enrollment.inputs["revocations"]["payload"]["revocation_reference"]

    def read_parent_authority(self, *, request_binding, challenge):
        from governance.mutation_authority import COMMON
        self.challenges.append(challenge)
        p = {k: deepcopy(self.record[k]) for k in COMMON}
        p.update(schema_version="usbay.mutation_authority.parent_status.v1",
            issuer_id="synthetic-parent-source", issuer_key_id="test-parent-currentness",
            parent_authority_id=self.record["authority_id"], parent_authority_hash=digest(self.record),
            subject_issuer_id=self.record["subject_issuer_id"], issuance_scope=AUTHORITY_DOMAIN,
            parent_status=self.status, state_sequence=self.sequence, state_epoch=1,
            expected_current_head=self.head, revocation_reference=self.revocation,
            challenge=challenge, request_binding=request_binding,
            issued_at="2026-01-02T12:00:00Z", valid_from="2026-01-02T12:00:00Z")
        p["status_fingerprint"] = fingerprint(p, "parent_status")
        return dict(payload=p, signature=self.private.sign(canonical(p)).hex())


def synthetic_mutation():
    f = synthetic_enrollment()
    specs = {
        "test-proposer": ("synthetic-actor", "request"),
        "test-issuer": ("synthetic-mutation-issuer", "mutation_issuer"),
        "test-review-a": ("USBAY-AUDIT", "mutation_review:USBAY-AUDIT"),
        "test-review-b": ("USBAY-GLOBAL23", "mutation_review:USBAY-GLOBAL23"),
        "test-parent-assertion": ("synthetic-parent-signer", "mutation_parent_assertion"),
        "test-parent-currentness": ("synthetic-parent-source", "mutation_parent_currentness"),
    }
    private = {name: Ed25519PrivateKey.generate() for name in specs}
    keys = list(f.trust._keys.values())
    base = f.inputs["policy"]["payload"]
    for name, (issuer, role) in specs.items():
        keys.append(ScopedPublicKey(issuer, name, private[name].public_key().public_bytes(Encoding.Raw, PublicFormat.Raw),
            (role,), base["tenant_id"], base["registry_instance_reference"], "2026-01-01T00:00:00Z",
            "2026-01-03T00:00:00Z", digest({"synthetic-signature-binding-only": name})))
    trust = EnrollmentTrust(tuple(keys), max_age_seconds=60)

    def common(kind, key):
        return dict(schema_version="usbay.mutation_authority." + kind + ".v1", **{k: base[k] for k in SCOPE_FIELDS},
            authority_domain=AUTHORITY_DOMAIN, issuer_id=specs[key][0], issuer_key_id=key, algorithm="Ed25519",
            valid_from="2026-01-02T11:00:00Z", valid_until="2026-01-02T13:00:00Z", issued_at="2026-01-02T11:59:59Z",
            authority_flags=dict.fromkeys(FLAGS, False))

    binding = dict(actor_id="synthetic-actor", allowed_action="REVOKE_POLICY_OBJECT", resource_type="POLICY_OBJECT",
        object_id=object_id(EnrollmentPolicy, base), object_version_hash=digest(base), policy_id=base["policy_id"],
        target_grant_id=None, adoption_id=None, expected_current_head=f.head["head_hash"], redelegation_allowed=False,
        parent_authority_id="synthetic-parent", parent_authority_hash=digest({"unproven-root": 0}))
    binding["resource_id"] = binding["object_id"]
    parent = dict(common("parent_scope", "test-parent-assertion"), **binding,
        authority_id="synthetic-parent", subject_issuer_id="synthetic-mutation-issuer", issuance_scope=AUTHORITY_DOMAIN,
        revocation_reference=base["revocation_reference"], parent_fingerprint="placeholder")
    parent["parent_authority_id"] = "unproven-root-parent"
    p = dict(common("proposal", "test-proposer"), **binding, proposal_id="synthetic-proposal", proposal_nonce="synthetic-proposal-nonce", proposal_fingerprint="placeholder")
    reviews = [dict(common("review", key), proposal_hash=digest({}), reviewer_id=specs[key][0], reviewer_role=specs[key][0],
                    decision="APPROVE", decision_nonce="synthetic-" + key, decision_fingerprint="placeholder")
               for key in ("test-review-a", "test-review-b")]
    grant = dict(common("grant", "test-issuer"), **binding, grant_id="synthetic-mutation-grant", proposal_hash=digest({}),
        reviewer_a_decision_hash=digest({}), reviewer_b_decision_hash=digest({}), review_threshold=2, review_required=2,
        issuer_authority_reference=digest({}), grant_nonce="synthetic-grant-nonce", grant_fingerprint="placeholder")
    result = SyntheticMutation(f, trust, private, dict(payload=p), [dict(payload=d) for d in reviews], dict(payload=grant), dict(payload=parent))
    result.refresh()
    result.parent_source = SyntheticParentAuthoritySource(result)
    from tests.helpers.mutation_issuer_authority import attach_synthetic_issuance
    attach_synthetic_issuance(result)
    return result
