"""Dormant root/issuer contracts; no roots, signers, registry or writer provisioned.

Trust and the read-only current-authority source are privileged composition
inputs. Artifact parsing, signatures, reviewer labels and workspace ownership
alone confer no authority. ALLOW is contract verification, never consumption or
permission to execute a mutation. A future writer must atomically recheck and
consume the one-time issuance in its protected store before any effect.
"""
from dataclasses import dataclass
import re
import secrets

from governance.mutation_authority import (
    ACTION_RESOURCES, AUTHORITY_DOMAIN, COMMON, REVIEWERS, ParentAuthorityScopeV1,
    _reviewed_contracts, _signed, _verification_deadline, _envelope_deadline, _deadline_text, check_child_subset_parent,
)
from governance.tenant_enrollment_contracts import (
    FLAGS, POLICY_DOMAIN, PURPOSE, SCOPE_FIELDS, TRUST_DOMAIN, EnrollmentDenied,
    canonical, decision, digest, instant, key_id, parse_json, require,
)
from security.enrollment_policy_currentness import verify_currentness

ROLE_LABELS = ("USBAY_OWNER_ROOT", "USBAY-AUDIT", "USBAY-GLOBAL23")
# These are empty defaults, not mutable registries or implicit bootstrap inputs.
ROOT_AUTHORITIES = ()
MUTATION_ISSUER_AUTHORITIES = ()
MUTATION_AUTHORITY_GRANTS = ()
LIVE_REVIEWER_DECISIONS = ()
HASH = r"sha256:[0-9a-f]{64}"
OBJECT_FIELDS = {"resource_type", "resource_id", "object_id", "object_version_hash",
                 "policy_id", "target_grant_id", "adoption_id"}
SCOPES = {"allowed_actor_scope", "allowed_purpose_scope", "allowed_actions",
          "allowed_resource_types", "allowed_resource_scope", "allowed_object_scope",
          "allowed_policy_scope", "allowed_grant_scope", "allowed_adoption_scope"}
FIELDS = {
    "root": SCOPES | {"root_authority_id", "root_identity_reference", "lineage_reference",
        "governance_role", "capability", "allowed_issuer_scope", "redelegation_allowed",
        "review_policy_reference", "root_fingerprint"},
    "issuer": SCOPES | {"issuer_grant_id", "authority_issuer_id", "subject_key_id",
        "issuer_identity_reference", "parent_authority_id", "parent_authority_hash",
        "capability", "redelegation_allowed", "review_policy_reference", "issuance_nonce",
        "max_child_grants", "issuer_grant_fingerprint"},
    "review_policy": {"review_policy_id", "required_reviewers", "threshold", "required",
        "distinct_reviewers", "proposal_binding", "review_policy_fingerprint"},
    "status": {"root_authority_id", "root_authority_hash", "issuer_grant_id", "issuer_grant_hash",
        "subject_issuer_id", "root_status", "issuer_status", "issuance_state", "state_sequence",
        "state_epoch", "expected_current_head", "revocation_reference", "challenge",
        "request_binding", "status_fingerprint"},
}
FP = {"root": "root_fingerprint", "issuer": "issuer_grant_fingerprint",
      "review_policy": "review_policy_fingerprint", "status": "status_fingerprint"}


def authority_fingerprint(p, kind):
    return digest({k: v for k, v in p.items() if k != FP[kind]})


def _text(v):
    return type(v) is str and 0 < len(v) <= 256 and "*" not in v


def _hash(v):
    return type(v) is str and re.fullmatch(HASH, v) is not None


@dataclass(frozen=True)
class _IssuanceContract:
    encoded: bytes
    kind = ""

    @property
    def payload(self):
        return parse_json(self.encoded)

    @classmethod
    def from_payload(cls, p):
        require(type(p) is dict and set(p) == COMMON | FIELDS[cls.kind], "ISSUER_AUTHORITY_INVALID")
        canonical(p)
        require(p["schema_version"] == "usbay.mutation_issuance." + cls.kind + ".v1", "ISSUER_AUTHORITY_INVALID")
        require(p["authority_domain"] == AUTHORITY_DOMAIN, "ISSUER_DOMAIN_MISMATCH")
        require(p["trust_domain"] == TRUST_DOMAIN and p["policy_domain"] == POLICY_DOMAIN
                and p["environment"] == "non-production" and p["purpose"] == PURPOSE, "ISSUER_PURPOSE_SCOPE_MISMATCH")
        require(type(p["tenant_id"]) is str and re.fullmatch(r"[a-z0-9][a-z0-9_-]{0,63}", p["tenant_id"])
                is not None, "ISSUER_TENANT_SCOPE_MISMATCH")
        require(type(p["authority_flags"]) is dict and set(p["authority_flags"]) == set(FLAGS)
                and all(v is False for v in p["authority_flags"].values()), "AUTHORITY_SCOPE_BROADENING")
        structured = SCOPES | {"allowed_issuer_scope", "authority_flags", "redelegation_allowed",
            "max_child_grants", "required_reviewers", "threshold", "required", "distinct_reviewers",
            "state_sequence", "state_epoch"}
        for field, value in p.items():
            if field in structured:
                continue
            require(_text(value), "ISSUER_AUTHORITY_INVALID")
            if field.endswith(("_hash", "_fingerprint", "_reference")) or field in ("expected_current_head", "request_binding"):
                require(_hash(value), "ISSUER_AUTHORITY_INVALID")
        require(p["algorithm"] == "Ed25519", "ISSUER_AUTHORITY_INVALID")
        require(instant(p["valid_from"]) < instant(p["valid_until"])
                and instant(p["issued_at"]) < instant(p["valid_until"]), "ISSUER_AUTHORITY_INVALID")
        if cls.kind in ("root", "issuer"):
            require(p["redelegation_allowed"] is False, "PROHIBITED_REDELEGATION")
            for field in SCOPES - {"allowed_object_scope"}:
                v = p[field]
                require(type(v) is list and len(v) <= 64 and all(_text(x) for x in v)
                        and len(v) == len(set(v)), "ISSUER_AUTHORITY_INVALID")
                require(bool(v) or field in ("allowed_grant_scope", "allowed_adoption_scope"), "ISSUER_AUTHORITY_INVALID")
            require(set(p["allowed_actions"]) <= set(ACTION_RESOURCES), "ISSUER_ACTION_SCOPE_MISMATCH")
            require(set(p["allowed_resource_types"]) == {ACTION_RESOURCES[x] for x in p["allowed_actions"]},
                    "ISSUER_RESOURCE_SCOPE_MISMATCH")
            require(p["allowed_purpose_scope"] == [PURPOSE], "ISSUER_PURPOSE_SCOPE_MISMATCH")
            require(all(_hash(x) for x in p["allowed_resource_scope"]), "ISSUER_RESOURCE_SCOPE_MISMATCH")
            objects = p["allowed_object_scope"]
            require(type(objects) is list and 0 < len(objects) <= 64 and len({canonical(x) for x in objects}) == len(objects),
                    "ISSUER_OBJECT_SCOPE_MISMATCH")
            for obj in objects:
                require(type(obj) is dict and set(obj) == OBJECT_FIELDS, "ISSUER_OBJECT_SCOPE_MISMATCH")
                require(obj["resource_type"] in p["allowed_resource_types"] and obj["resource_id"] in p["allowed_resource_scope"]
                        and obj["object_id"] == obj["resource_id"] and _hash(obj["object_version_hash"]), "ISSUER_OBJECT_SCOPE_MISMATCH")
                for field, scope in (("policy_id", "allowed_policy_scope"), ("target_grant_id", "allowed_grant_scope"),
                                     ("adoption_id", "allowed_adoption_scope")):
                    require(obj[field] in p[scope] if obj[field] is not None else field != "policy_id", "ISSUER_OBJECT_SCOPE_MISMATCH")
            if cls.kind == "root":
                require(p["capability"] == "AUTHORIZE_BOUNDED_MUTATION_ISSUER"
                        and p["governance_role"] == "USBAY_OWNER_ROOT", "ROOT_AUTHORITY_INVALID")
                require(type(p["allowed_issuer_scope"]) is list and bool(p["allowed_issuer_scope"])
                        and all(_text(x) for x in p["allowed_issuer_scope"])
                        and len(set(p["allowed_issuer_scope"])) == len(p["allowed_issuer_scope"]), "ROOT_AUTHORITY_INVALID")
            else:
                require(p["capability"] == "ISSUE_BOUNDED_MUTATION_GRANT" and type(p["max_child_grants"]) is int
                        and p["max_child_grants"] == 1, "ISSUER_AUTHORITY_INVALID")
        elif cls.kind == "review_policy":
            require(type(p["required_reviewers"]) is list and p["required_reviewers"] == list(REVIEWERS)
                    and type(p["threshold"]) is int and type(p["required"]) is int
                    and p["threshold"] == p["required"] == 2 and p["distinct_reviewers"] is True
                    and p["proposal_binding"] == "EXACT_PROPOSAL_VERSION_HASH", "REVIEW_POLICY_NOT_SATISFIED")
        else:
            require(p["root_status"] in ("ACTIVE", "REVOKED") and p["issuer_status"] in ("ACTIVE", "REVOKED")
                    and p["issuance_state"] in ("AVAILABLE", "CONSUMED")
                    and all(type(p[k]) is int and p[k] >= 1 for k in ("state_sequence", "state_epoch"))
                    and re.fullmatch(r"[0-9a-f]{64}", p["challenge"]) is not None, "ROOT_AUTHORITY_INVALID")
        require(p[FP[cls.kind]] == authority_fingerprint(p, cls.kind), "ISSUER_AUTHORITY_INVALID")
        return cls(canonical(p))


class RootMutationAuthorityV1(_IssuanceContract):
    kind = "root"


class MutationAuthorityIssuerGrantV1(_IssuanceContract):
    kind = "issuer"


class MutationReviewPolicyV1(_IssuanceContract):
    kind = "review_policy"


class IssuerAuthorityStatusV1(_IssuanceContract):
    kind = "status"


def identity_reference(key):
    """Pinned governance identity evidence, not a caller account/role claim."""
    return digest({"principal": key.issuer_id, "key_id": key.key_id, "public_key": key.public_key.hex(),
                   "tenant_id": key.tenant_id, "registry_instance_reference": key.registry_instance_reference,
                   "provenance_reference": key.provenance_reference})


def _subset(issuer, root):
    require(all(issuer[k] == root[k] for k in SCOPE_FIELDS), "ISSUER_TENANT_SCOPE_MISMATCH")
    reasons = {"allowed_actor_scope": "ISSUER_ACTOR_SCOPE_MISMATCH", "allowed_purpose_scope": "ISSUER_PURPOSE_SCOPE_MISMATCH",
        "allowed_actions": "ISSUER_ACTION_SCOPE_MISMATCH", "allowed_resource_types": "ISSUER_RESOURCE_SCOPE_MISMATCH",
        "allowed_resource_scope": "ISSUER_RESOURCE_SCOPE_MISMATCH", "allowed_object_scope": "ISSUER_OBJECT_SCOPE_MISMATCH"}
    for field in ("allowed_actor_scope", "allowed_purpose_scope", "allowed_actions", "allowed_resource_types",
                  "allowed_resource_scope", "allowed_object_scope", "allowed_policy_scope", "allowed_grant_scope",
                  "allowed_adoption_scope"):
        require({canonical(x) for x in issuer[field]} <= {canonical(x) for x in root[field]},
                reasons.get(field, "ISSUER_OBJECT_SCOPE_MISMATCH"))
    require(instant(issuer["valid_from"]) >= instant(root["valid_from"])
            and instant(issuer["valid_until"]) <= instant(root["valid_until"]), "AUTHORITY_SCOPE_BROADENING")


def _child_scope(child, issuer):
    require(all(child[k] == issuer[k] for k in SCOPE_FIELDS), "ISSUER_TENANT_SCOPE_MISMATCH")
    for field, scope, reason in (("actor_id", "allowed_actor_scope", "ISSUER_ACTOR_SCOPE_MISMATCH"),
        ("purpose", "allowed_purpose_scope", "ISSUER_PURPOSE_SCOPE_MISMATCH"),
        ("allowed_action", "allowed_actions", "ISSUER_ACTION_SCOPE_MISMATCH"),
        ("resource_type", "allowed_resource_types", "ISSUER_RESOURCE_SCOPE_MISMATCH"),
        ("resource_id", "allowed_resource_scope", "ISSUER_RESOURCE_SCOPE_MISMATCH")):
        require(child[field] in issuer[scope], reason)
    require({k: child[k] for k in OBJECT_FIELDS} in issuer["allowed_object_scope"], "ISSUER_OBJECT_SCOPE_MISMATCH")
    require(child["redelegation_allowed"] is False and issuer["redelegation_allowed"] is False, "PROHIBITED_REDELEGATION")
    require(instant(child["valid_from"]) >= instant(issuer["valid_from"])
            and instant(child["valid_until"]) <= instant(issuer["valid_until"]), "AUTHORITY_SCOPE_BROADENING")


def verify_mutation_authority_issuer(root_authority=None, issuer_grant=None, review_policy=None, *,
        proposal=None, reviewer_decisions=None, grant=None, parent_artifact=None,
        trust=None, root_source=None, currentness=None, now=None):
    """Read-only complete issuance-chain verification; no signer/consumer/writer.

    Fresh independent status must select its own authoritative root and issuer
    records, authenticate lineage and report durable one-time consumption. The
    future writer must recheck/consume transactionally; ALLOW is not a receipt.
    """
    try:
        if root_authority is None:
            return decision("MUTATION_AUTHORITY_MISSING", authority_reason="ROOT_AUTHORITY_MISSING")
        require(issuer_grant is not None, "ISSUER_AUTHORITY_MISSING")
        if now is None or root_source is None:
            return decision("MUTATION_AUTHORITY_MISSING", authority_reason="ROOT_AUTHORITY_MISSING")
        try:
            root, root_key = _signed(trust, root_authority, RootMutationAuthorityV1, "mutation_root_authority", now)
        except Exception:
            raise EnrollmentDenied("ROOT_AUTHORITY_INVALID") from None
        require(root["root_identity_reference"] == identity_reference(root_key), "ROOT_AUTHORITY_INVALID")
        try:
            issuer, issuer_key = _signed(trust, issuer_grant, MutationAuthorityIssuerGrantV1,
                                        "mutation_issuer_issuance", now, signer_field="authority_issuer_id")
        except EnrollmentDenied as error:
            raise EnrollmentDenied("ISSUER_AUTHORITY_EXPIRED" if str(error) == "MUTATION_AUTHORITY_EXPIRED" else str(error)) from None
        require(issuer_key.public_key == root_key.public_key and issuer["authority_issuer_id"] == root["issuer_id"]
                and issuer["parent_authority_id"] == root["root_authority_id"]
                and issuer["parent_authority_hash"] == digest(root), "ROOT_AUTHORITY_INVALID")
        subject = trust._keys.get(issuer["subject_key_id"])
        require(subject is not None and subject.issuer_id == issuer["issuer_id"]
                and issuer["issuer_identity_reference"] == identity_reference(subject)
                and issuer["issuer_id"] in root["allowed_issuer_scope"], "ISSUER_AUTHORITY_INVALID")
        _subset(issuer, root)
        require(review_policy is not None, "REVIEW_POLICY_NOT_SATISFIED")
        policy, policy_key = _signed(trust, review_policy, MutationReviewPolicyV1, "mutation_review_policy", now)
        require(policy_key.public_key == root_key.public_key and all(policy[k] == root[k] for k in SCOPE_FIELDS)
                and root["review_policy_reference"] == issuer["review_policy_reference"] == digest(policy), "REVIEW_POLICY_NOT_SATISFIED")
        p, g, reviews = _reviewed_contracts(proposal, reviewer_decisions, grant, trust, now)
        parent, _ = _signed(trust, parent_artifact, ParentAuthorityScopeV1, "mutation_parent_assertion", now)
        check_child_subset_parent(g, parent)
        require(g["issuer_id"] == issuer["issuer_id"] and g["issuer_key_id"] == issuer["subject_key_id"]
                and parent["subject_issuer_id"] == issuer["issuer_id"]
                and parent["parent_authority_id"] == issuer["issuer_grant_id"]
                and parent["parent_authority_hash"] == digest(issuer), "ISSUER_AUTHORITY_INVALID")
        _child_scope(parent, issuer)
        _child_scope(g, issuer)
        current_policy, _, revocations = verify_currentness(trust, **currentness, now=now)
        require(all(current_policy[k] == g[k] for k in SCOPE_FIELDS) and current_policy["policy_id"] == g["policy_id"],
                "ISSUER_TENANT_SCOPE_MISMATCH")
        require(currentness["expected"]["head_hash"] == g["expected_current_head"]
                and parent["revocation_reference"] == revocations["revocation_reference"], "EXPECTED_HEAD_MISMATCH")
        # Existing scoped key revocations remain intact; new object-status kinds
        # are not smuggled into enrollment v3 revocation schemas.
        def not_revoked(payload, principal, reason):
            keyed = dict(payload, issuer_id=principal)
            for entry in revocations["revocations"]:
                require(entry["target_scope"] == {k: g[k] for k in SCOPE_FIELDS}, "ISSUER_TENANT_SCOPE_MISMATCH")
                require(not (entry["kind"] == "KEY_REVOCATION" and entry["target_id"] == key_id(keyed)
                    and instant(entry["effective_at"]) <= now), reason)
        for item, principal, reason in ((root, root["issuer_id"], "ROOT_AUTHORITY_REVOKED"),
            (issuer, issuer["authority_issuer_id"], "ROOT_AUTHORITY_REVOKED"),
            (policy, policy["issuer_id"], "ROOT_AUTHORITY_REVOKED"),
            (g, g["issuer_id"], "ISSUER_AUTHORITY_REVOKED"),
            (p, p["issuer_id"], "MUTATION_AUTHORITY_REVOKED"),
            (parent, parent["issuer_id"], "PARENT_AUTHORITY_REVOKED"),
            *((d, d["issuer_id"], "MUTATION_AUTHORITY_REVOKED") for d, _ in reviews)):
            not_revoked(item, principal, reason)
        review_hashes = {d["reviewer_id"]: digest(d) for d, _ in reviews}
        binding_facts = dict(authority_domain=AUTHORITY_DOMAIN, root_hash=digest(root), issuer_hash=digest(issuer),
            issuer_grant_id=issuer["issuer_grant_id"], issuance_nonce=issuer["issuance_nonce"],
            proposal_hash=digest(p), review_hashes=review_hashes, child_hash=digest(g),
            parent_hash=digest(parent), review_policy_hash=digest(policy), head=g["expected_current_head"],
            scope={k: g[k] for k in SCOPE_FIELDS})
        binding, challenge = digest(binding_facts), secrets.token_hex(32)
        try:
            response = root_source.read_issuer_authority(request_binding=binding, challenge=challenge)
            status, status_key = _signed(trust, response, IssuerAuthorityStatusV1, "mutation_root_currentness", now)
        except Exception:
            raise EnrollmentDenied("ROOT_AUTHORITY_INVALID") from None
        require(status_key.public_key != root_key.public_key and status_key.issuer_id != root_key.issuer_id,
                "ROOT_AUTHORITY_INVALID")
        require(all(status[k] == g[k] for k in (*SCOPE_FIELDS, "authority_domain"))
                and status["root_authority_id"] == root["root_authority_id"] and status["root_authority_hash"] == digest(root)
                and status["issuer_grant_id"] == issuer["issuer_grant_id"] and status["issuer_grant_hash"] == digest(issuer)
                and status["subject_issuer_id"] == issuer["issuer_id"] and status["challenge"] == challenge
                and status["request_binding"] == binding and status["expected_current_head"] == g["expected_current_head"]
                and status["revocation_reference"] == revocations["revocation_reference"], "ROOT_AUTHORITY_INVALID")
        require(instant(status["valid_until"]) <= min(instant(root["valid_until"]), instant(issuer["valid_until"]),
                instant(status_key.expires_at)), "ROOT_AUTHORITY_INVALID")
        not_revoked(status, status["issuer_id"], "ROOT_AUTHORITY_REVOKED")
        require(status["root_status"] == "ACTIVE", "ROOT_AUTHORITY_REVOKED")
        require(status["issuer_status"] == "ACTIVE", "ISSUER_AUTHORITY_REVOKED")
        require(status["issuance_state"] == "AVAILABLE", "ISSUANCE_REPLAY")
        # Bounded hashes only: no raw proposal, identity, addresses or review text.
        deadlines = [_verification_deadline(trust, root, root_key),
            _verification_deadline(trust, issuer, issuer_key),
            _verification_deadline(trust, policy, policy_key),
            _verification_deadline(trust, parent, trust._keys[parent["issuer_key_id"]]),
            _verification_deadline(trust, status, status_key),
            _envelope_deadline(trust, proposal), _envelope_deadline(trust, grant),
            *(_envelope_deadline(trust, envelope) for envelope in reviewer_decisions),
            *(_envelope_deadline(trust, currentness[name]) for name in ("policy","adoption","h","w","revocations"))]
        verification_valid_until = _deadline_text(min(deadlines))
        evidence = dict(issuer_identity_reference=issuer["issuer_identity_reference"], parent_authority_hash=digest(root),
            proposal_hash=digest(p), review_hashes=review_hashes, child_grant_hash=digest(g),
            issuer_grant_hash=digest(issuer), parent_scope_artifact_hash=digest(parent), child_scope_hash=digest({k:g[k] for k in OBJECT_FIELDS}),
            parent_scope_hash=digest({k:issuer[k] for k in SCOPES}), attenuation="CHILD_SUBSET_PARENT",
            valid_until=g["valid_until"], revocation_reference=status["revocation_reference"],
            replay_state="AVAILABLE_NOT_CONSUMED", issuance_binding=binding, status_hash=digest(status),
            verification_valid_until=verification_valid_until)
        return decision("MUTATION_ISSUER_AUTHORITY_VERIFIED", allowed=True,
                        assurance="SYNTHETIC_OR_CONFIGURED_CONTRACT_VERIFICATION_ONLY", issuance_evidence=evidence,
                        verification_valid_until=verification_valid_until)
    except Exception as error:
        return decision(str(error) if type(error) is EnrollmentDenied else "ISSUER_AUTHORITY_INVALID")
