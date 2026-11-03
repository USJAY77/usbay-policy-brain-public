"""Dormant mutation-authority contracts, never a writer or an authority issuer.

Default parent authority is absent. A configured read-only authority source must
provide a separately authenticated, fresh, challenge-bound attestation of an
existing exact parent record and its issuance scope. A parent assertion, role,
hash or caller boolean alone cannot establish that fact. No producer, signer,
root loader, registry creation, consumption or live integration exists here.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
import re
import secrets

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from governance.tenant_enrollment_contracts import (
    FLAGS, POLICY_DOMAIN, PURPOSE, SCOPE_FIELDS, TRUST_DOMAIN, EnrollmentDenied,
    canonical, decision, digest, instant, parse_json, require, utc_now,
)
from security.enrollment_policy_currentness import EnrollmentTrust, verify_currentness

AUTHORITY_DOMAIN = "USBAY_ENROLLMENT_GOVERNANCE_MUTATION"
ACTION_RESOURCES = {
    "FINALIZE_POLICY_ADOPTION": "POLICY_ADOPTION",
    "REVOKE_POLICY_OBJECT": "POLICY_OBJECT",
    "REVOKE_GRANT_OBJECT": "ENROLLMENT_GRANT",
    "REVOKE_ADOPTION": "ADOPTION_RECORD",
}
REVIEWERS = {"USBAY-AUDIT": "USBAY-AUDIT", "USBAY-GLOBAL23": "USBAY-GLOBAL23"}
COMMON = {"schema_version", *SCOPE_FIELDS, "authority_domain", "issuer_id", "issuer_key_id",
          "algorithm", "valid_from", "valid_until", "issued_at", "authority_flags"}
BINDINGS = {"actor_id", "allowed_action", "resource_type", "resource_id", "object_id", "object_version_hash",
            "policy_id", "target_grant_id", "adoption_id", "expected_current_head", "redelegation_allowed",
            "parent_authority_id", "parent_authority_hash"}
FIELDS = {
    "proposal": BINDINGS | {"proposal_id", "proposal_nonce", "proposal_fingerprint"},
    "review": {"proposal_hash", "reviewer_id", "reviewer_role", "decision", "decision_nonce", "decision_fingerprint"},
    "grant": BINDINGS | {"grant_id", "proposal_hash", "reviewer_a_decision_hash", "reviewer_b_decision_hash",
                         "review_threshold", "review_required", "issuer_authority_reference", "grant_nonce", "grant_fingerprint"},
    # Representation of a future parent artifact, NOT a trusted parent context.
    "parent_scope": BINDINGS | {"authority_id", "subject_issuer_id", "issuance_scope", "revocation_reference", "parent_fingerprint"},
    "parent_status": {"parent_authority_id", "parent_authority_hash", "subject_issuer_id", "issuance_scope",
                      "parent_status", "state_sequence", "state_epoch", "expected_current_head", "revocation_reference",
                      "challenge", "request_binding", "status_fingerprint"},
}
FINGERPRINTS = {"proposal": "proposal_fingerprint", "review": "decision_fingerprint",
                "grant": "grant_fingerprint", "parent_scope": "parent_fingerprint", "parent_status": "status_fingerprint"}


def fingerprint(payload: dict, kind: str) -> str:
    """No self-reference: signatures cover the complete payload INCLUDING this."""
    return digest({k: v for k, v in payload.items() if k != FINGERPRINTS[kind]})


@dataclass(frozen=True)
class _Contract:
    encoded: bytes
    kind = ""

    @property
    def payload(self):
        return parse_json(self.encoded)

    @classmethod
    def from_payload(cls, p):
        require(type(p) is dict and set(p) == COMMON | FIELDS[cls.kind], "MUTATION_AUTHORITY_INVALID")
        canonical(p)
        require(p["schema_version"] == "usbay.mutation_authority." + cls.kind + ".v1", "MUTATION_AUTHORITY_INVALID")
        require(p["purpose"] == PURPOSE, "PURPOSE_MISMATCH")
        require(p["trust_domain"] == TRUST_DOMAIN and p["policy_domain"] == POLICY_DOMAIN
                and p["authority_domain"] == AUTHORITY_DOMAIN and p["environment"] == "non-production"
                and p["purpose"] == PURPOSE, "MUTATION_AUTHORITY_INVALID")
        require(type(p["tenant_id"]) is str and bool(re.fullmatch(r"[a-z0-9][a-z0-9_-]{0,63}", p["tenant_id"])), "TENANT_MISMATCH")
        require(type(p["authority_flags"]) is dict and set(p["authority_flags"]) == set(FLAGS)
                and all(v is False for v in p["authority_flags"].values()), "AUTHORITY_SCOPE_BROADENING")
        optional = {"policy_id", "target_grant_id", "adoption_id"}
        special = optional | {"authority_flags", "redelegation_allowed", "review_threshold", "review_required", "state_sequence", "state_epoch"}
        for k, v in p.items():
            if k in special:
                continue
            require(type(v) is str and 0 < len(v) <= 256 and "*" not in v, "MUTATION_AUTHORITY_INVALID")
            if k.endswith(("_hash", "_fingerprint", "_reference")) or k in ("object_id", "resource_id", "expected_current_head", "request_binding"):
                require(bool(re.fullmatch(r"sha256:[0-9a-f]{64}", v)), "MUTATION_AUTHORITY_INVALID")
        for k in optional & set(p):
            require(p[k] is None or (type(p[k]) is str and 0 < len(p[k]) <= 128 and "*" not in p[k]), "MUTATION_AUTHORITY_INVALID")
        require(p["algorithm"] == "Ed25519", "MUTATION_AUTHORITY_INVALID")
        require(instant(p["valid_from"]) < instant(p["valid_until"])
                and instant(p["issued_at"]) < instant(p["valid_until"]), "MUTATION_AUTHORITY_INVALID")
        if cls.kind == "review":
            require(p["reviewer_id"] in REVIEWERS and p["reviewer_role"] == REVIEWERS[p["reviewer_id"]], "REVIEW_DECISION_INVALID")
            require(p["issuer_id"] == p["reviewer_id"] and p["decision"] in ("APPROVE", "REJECT"), "REVIEW_DECISION_INVALID")
        elif cls.kind == "parent_status":
            require(p["parent_status"] in ("ACTIVE", "REVOKED") and p["issuance_scope"] == AUTHORITY_DOMAIN, "PARENT_AUTHORITY_INVALID")
            require(all(type(p[k]) is int and p[k] >= 1 for k in ("state_sequence", "state_epoch")), "PARENT_AUTHORITY_INVALID")
            require(bool(re.fullmatch(r"[0-9a-f]{64}", p["challenge"])), "PARENT_AUTHORITY_INVALID")
        else:
            require(p["allowed_action"] in ACTION_RESOURCES, "ACTION_NOT_AUTHORIZED")
            require(p["resource_type"] == ACTION_RESOURCES[p["allowed_action"]]
                    and p["resource_id"] == p["object_id"], "RESOURCE_NOT_AUTHORIZED")
            require(p["redelegation_allowed"] is False, "PROHIBITED_REDELEGATION")
            required_selectors = {"policy_id"}
            if p["allowed_action"] == "REVOKE_GRANT_OBJECT":
                required_selectors.add("target_grant_id")
            if p["allowed_action"] in ("FINALIZE_POLICY_ADOPTION", "REVOKE_ADOPTION"):
                required_selectors.add("adoption_id")
            require(all((p[k] is not None) == (k in required_selectors) for k in optional), "RESOURCE_NOT_AUTHORIZED")
        if cls.kind == "proposal":
            require(p["issuer_id"] == p["actor_id"], "ACTOR_MISMATCH")
        if cls.kind == "grant":
            require(type(p["review_threshold"]) is int and type(p["review_required"]) is int
                    and p["review_threshold"] == p["review_required"] == 2, "REVIEW_THRESHOLD_NOT_MET")
        if cls.kind == "parent_scope":
            require(p["issuance_scope"] == AUTHORITY_DOMAIN and p["authority_id"] != p["parent_authority_id"], "PARENT_AUTHORITY_INVALID")
        require(p[FINGERPRINTS[cls.kind]] == fingerprint(p, cls.kind), "MUTATION_AUTHORITY_INVALID")
        return cls(canonical(p))


class MutationAuthorityProposalV1(_Contract):
    kind = "proposal"


class ReviewerDecisionV1(_Contract):
    kind = "review"


class MutationAuthorityGrantV1(_Contract):
    kind = "grant"


class ParentAuthorityScopeV1(_Contract):
    """Untrusted representation only. Parsing/signature validity grants nothing."""
    kind = "parent_scope"


class ParentAuthorityStatusV1(_Contract):
    """Read-only authority evidence, not a root, issuer or mutation command.

    The source must derive status from its authoritative current record, NOT
    endorse arbitrary request-selected parent hashes. A live source and its
    explicitly governed verification-key binding are not provisioned here.
    """
    kind = "parent_status"


def _verification_deadline(trust, payload, key):
    """Earliest instant at which this verified evidence/key can no longer support ALLOW."""
    end = payload.get("valid_until", payload.get("expires_at"))
    require(end is not None and "issued_at" in payload, "MUTATION_AUTHORITY_INVALID")
    return min(instant(end), instant(key.expires_at),
               instant(payload["issued_at"]) + timedelta(seconds=trust.max_age_seconds))


def _envelope_deadline(trust, envelope):
    require(type(envelope) is dict and type(envelope.get("payload")) is dict, "MUTATION_AUTHORITY_INVALID")
    payload = envelope["payload"]
    key = trust._keys.get(payload.get("issuer_key_id"))
    require(key is not None, "MUTATION_AUTHORITY_MISSING")
    return _verification_deadline(trust, payload, key)


def _deadline_text(value):
    return value.strftime("%Y-%m-%dT%H:%M:%SZ")


def _signed(trust, envelope, model, role, now, *, signer_field="issuer_id"):
    require(type(trust) is EnrollmentTrust and type(envelope) is dict
            and set(envelope) == {"payload", "signature"}, "MUTATION_AUTHORITY_INVALID")
    p = model.from_payload(envelope["payload"]).payload
    key = trust._keys.get(p["issuer_key_id"])
    require(key is not None and trust.max_age_seconds > 0, "MUTATION_AUTHORITY_MISSING")
    require(key.issuer_id == p[signer_field] and role in key.roles
            and tuple(p[k] for k in SCOPE_FIELDS) == (key.trust_domain, key.policy_domain, key.tenant_id,
                key.environment, key.purpose, key.registry_instance_reference), "MUTATION_AUTHORITY_INVALID")
    require(type(key.provenance_reference) is str and bool(re.fullmatch(r"sha256:[0-9a-f]{64}", key.provenance_reference)), "MUTATION_AUTHORITY_INVALID")
    require(instant(key.valid_from) <= now < instant(key.expires_at), "MUTATION_AUTHORITY_EXPIRED")
    require(instant(p["valid_from"]) <= now < instant(p["valid_until"]), "MUTATION_AUTHORITY_EXPIRED")
    require(0 <= (now - instant(p["issued_at"])).total_seconds() <= trust.max_age_seconds, "MUTATION_AUTHORITY_INVALID")
    require(type(envelope["signature"]) is str and len(envelope["signature"]) == 128, "MUTATION_AUTHORITY_INVALID")
    try:
        Ed25519PublicKey.from_public_bytes(key.public_key).verify(bytes.fromhex(envelope["signature"]), canonical(p))
    except Exception:
        raise EnrollmentDenied("MUTATION_AUTHORITY_INVALID") from None
    return p, key


def check_child_subset_parent(child: dict, parent: dict) -> None:
    """Exact singleton scope comparison, NOT independent parent authentication.
    Consumers must never use this structural helper as authority verification.
    """
    c = MutationAuthorityGrantV1.from_payload(child).payload
    p = ParentAuthorityScopeV1.from_payload(parent).payload
    reasons = {"tenant_id": "TENANT_MISMATCH", "actor_id": "ACTOR_MISMATCH", "purpose": "PURPOSE_MISMATCH",
               "allowed_action": "ACTION_NOT_AUTHORIZED", "resource_type": "RESOURCE_NOT_AUTHORIZED",
               "resource_id": "RESOURCE_NOT_AUTHORIZED", "object_id": "OBJECT_ID_MISMATCH",
               "object_version_hash": "OBJECT_VERSION_MISMATCH", "expected_current_head": "EXPECTED_HEAD_MISMATCH"}
    for field in ("authority_domain", *SCOPE_FIELDS, "actor_id", "allowed_action", "resource_type", "resource_id",
                  "object_id", "object_version_hash", "policy_id", "target_grant_id", "adoption_id", "expected_current_head"):
        require(c[field] == p[field], reasons.get(field, "AUTHORITY_SCOPE_BROADENING"))
    require(instant(c["valid_from"]) >= instant(p["valid_from"])
            and instant(c["valid_until"]) <= instant(p["valid_until"]), "AUTHORITY_SCOPE_BROADENING")
    require(c["issuer_id"] == p["subject_issuer_id"] and c["parent_authority_id"] == p["authority_id"]
            and c["parent_authority_hash"] == digest(p)
            and c["issuer_authority_reference"] == digest(p), "PARENT_AUTHORITY_INVALID")


def _reviewed_contracts(proposal, reviewer_decisions, grant, trust, now):
    """Authenticate exact proposal/review/child bindings; grants no authority."""
    p, _ = _signed(trust, proposal, MutationAuthorityProposalV1, "request", now)
    g, _ = _signed(trust, grant, MutationAuthorityGrantV1, "mutation_issuer", now)
    require(type(reviewer_decisions) is list and len(reviewer_decisions) == 2, "REVIEW_THRESHOLD_NOT_MET")
    reviewers = []
    for envelope in reviewer_decisions:
        require(type(envelope) is dict and type(envelope.get("payload")) is dict, "REVIEW_DECISION_INVALID")
        reviewer = envelope["payload"].get("reviewer_id")
        d, key = _signed(trust, envelope, ReviewerDecisionV1, "mutation_review:" + str(reviewer), now)
        reviewers.append((d, key))
    require(len({d["reviewer_id"] for d, _ in reviewers}) == 2
            and len({key.public_key for _, key in reviewers}) == 2, "REVIEWER_DUPLICATE")
    require({d["reviewer_id"] for d, _ in reviewers} == set(REVIEWERS), "REVIEW_THRESHOLD_NOT_MET")
    by_id = {d["reviewer_id"]: d for d, _ in reviewers}
    for d, _ in reviewers:
        require(d["decision"] == "APPROVE", "REVIEW_DECISION_INVALID")
        require(d["proposal_hash"] == digest(p), "REVIEW_PROPOSAL_MISMATCH")
        require(all(d[k] == p[k] for k in (*SCOPE_FIELDS, "authority_domain")), "REVIEW_DECISION_INVALID")
        require(instant(d["valid_until"]) <= instant(p["valid_until"]), "REVIEW_DECISION_INVALID")
    require(g["proposal_hash"] == digest(p), "REVIEW_PROPOSAL_MISMATCH")
    require(g["reviewer_a_decision_hash"] == digest(by_id["USBAY-AUDIT"])
            and g["reviewer_b_decision_hash"] == digest(by_id["USBAY-GLOBAL23"]), "REVIEW_DECISION_INVALID")
    require(all(g[k] == p[k] for k in (*BINDINGS, *SCOPE_FIELDS, "authority_domain")), "MUTATION_AUTHORITY_INVALID")
    require(instant(g["valid_from"]) >= instant(p["valid_from"])
            and instant(g["valid_until"]) <= instant(p["valid_until"]), "AUTHORITY_SCOPE_BROADENING")
    return p, g, reviewers


def verify_mutation_authority_grant(proposal=None, reviewer_decisions=None, grant=None, *, trust=None,
                                    parent_artifact=None, parent_source=None, currentness=None, target_object=None,
                                    root_authority=None, issuer_grant=None, review_policy=None, root_source=None,
                                    now: datetime | None = None) -> dict:
    """Read-only contract verification. parent_source is a privileged composition
    dependency, never part of caller JSON or a caller-supplied 'verified' context.
    Its response still requires the full independently pinned proof verification.
    Missing source/trust/parent evidence always denies; verification consumes no
    grant and ALLOW authorizes no writer/provider/execution side effect.
    """
    try:
        require(proposal is not None and grant is not None, "MUTATION_AUTHORITY_MISSING")
        require(now is not None, "MUTATION_AUTHORITY_MISSING")
        p, g, reviewers = _reviewed_contracts(proposal, reviewer_decisions, grant, trust, now)
        require(parent_artifact is not None, "MUTATION_AUTHORITY_MISSING")
        try:
            parent, parent_key = _signed(trust, parent_artifact, ParentAuthorityScopeV1, "mutation_parent_assertion", now)
        except EnrollmentDenied as invalid_parent:
            if str(invalid_parent) == "MUTATION_AUTHORITY_EXPIRED":
                raise
            raise EnrollmentDenied("PARENT_AUTHORITY_INVALID") from None
        check_child_subset_parent(g, parent)
        require(type(currentness) is dict, "MUTATION_AUTHORITY_MISSING")
        policy, _, revocations = verify_currentness(trust, **currentness, now=now)
        require(all(policy[k] == g[k] for k in SCOPE_FIELDS) and policy["policy_id"] == g["policy_id"]
                and currentness["expected"]["head_hash"] == g["expected_current_head"], "EXPECTED_HEAD_MISMATCH")
        require(parent["revocation_reference"] == revocations["revocation_reference"], "PARENT_AUTHORITY_INVALID")
        from governance.tenant_enrollment_contracts import (
            EnrollmentPolicy, EnrollmentGrant, PolicyAdoption, object_id, key_id,
        )
        target_model, target_role = {
            "REVOKE_POLICY_OBJECT": (EnrollmentPolicy, "policy"),
            "REVOKE_GRANT_OBJECT": (EnrollmentGrant, "enrollment"),
            "REVOKE_ADOPTION": (PolicyAdoption, "adoption"),
            "FINALIZE_POLICY_ADOPTION": (PolicyAdoption, "adoption"),
        }[g["allowed_action"]]
        target = trust.verify(target_object, target_model, target_role, now)
        require(all(target[k] == g[k] for k in SCOPE_FIELDS), "TENANT_MISMATCH")
        require(object_id(target_model, target) == g["object_id"], "OBJECT_ID_MISMATCH")
        require(digest(target) == g["object_version_hash"], "OBJECT_VERSION_MISMATCH")
        require(target["policy_id"] == g["policy_id"], "RESOURCE_NOT_AUTHORIZED")
        if g["allowed_action"] == "REVOKE_GRANT_OBJECT":
            require(target["grant_id"] == g["target_grant_id"], "RESOURCE_NOT_AUTHORIZED")
        if g["allowed_action"] in ("REVOKE_ADOPTION", "FINALIZE_POLICY_ADOPTION"):
            require(g["adoption_id"] == object_id(target_model, target), "RESOURCE_NOT_AUTHORIZED")
        for payload, model in ((p, MutationAuthorityProposalV1), (g, MutationAuthorityGrantV1),
                               (parent, ParentAuthorityScopeV1), *((d, ReviewerDecisionV1) for d, _ in reviewers)):
            # Existing v3 supports scoped KEY_REVOCATION. Its grant object-ID
            # schema is an ENROLLMENT grant, not this new mutation grant; never
            # silently reinterpret the two contracts or add a new revocation kind.
            for entry in revocations["revocations"]:
                require(entry["target_scope"] == {k: payload[k] for k in SCOPE_FIELDS}, "TENANT_MISMATCH")
                require(not (entry["kind"] == "KEY_REVOCATION" and entry["target_id"] == key_id(payload)
                             and instant(entry["effective_at"]) <= now),
                        "PARENT_AUTHORITY_REVOKED" if model is ParentAuthorityScopeV1 else "MUTATION_AUTHORITY_REVOKED")
        if parent_source is None:
            return decision("MUTATION_AUTHORITY_MISSING", assurance="PARENT_ISSUANCE_AUTHORITY_NOT_ESTABLISHED",
                            contract_bindings_valid=True)
        # No producer or live transport is implemented. The separately composed
        # reader must attest its existing record; a boolean/unsigned response is
        # rejected. A fresh random challenge prevents captured status proof reuse.
        challenge = secrets.token_hex(32)
        binding = digest({"authority_domain": AUTHORITY_DOMAIN, "parent_id": parent["authority_id"],
                          "parent_hash": digest(parent), "grant_hash": digest(g),
                          "head": g["expected_current_head"], "scope": {k: g[k] for k in SCOPE_FIELDS}})
        try:
            response = parent_source.read_parent_authority(request_binding=binding, challenge=challenge)
            status, status_key = _signed(trust, response, ParentAuthorityStatusV1, "mutation_parent_currentness", now)
        except Exception:
            raise EnrollmentDenied("PARENT_AUTHORITY_INVALID") from None
        require(status_key.public_key != parent_key.public_key and status["issuer_id"] != parent["issuer_id"], "PARENT_AUTHORITY_INVALID")
        require(all(status[k] == g[k] for k in (*SCOPE_FIELDS, "authority_domain"))
                and status["parent_authority_id"] == parent["authority_id"]
                and status["parent_authority_hash"] == digest(parent)
                and status["subject_issuer_id"] == g["issuer_id"]
                and status["challenge"] == challenge and status["request_binding"] == binding
                and status["expected_current_head"] == g["expected_current_head"]
                and status["revocation_reference"] == revocations["revocation_reference"], "PARENT_AUTHORITY_INVALID")
        require(instant(status["valid_until"]) <= instant(parent["valid_until"])
                and instant(status["valid_until"]) <= instant(status_key.expires_at), "PARENT_AUTHORITY_INVALID")
        for entry in revocations["revocations"]:
            require(not (entry["kind"] == "KEY_REVOCATION" and entry["target_id"] == key_id(status)
                         and instant(entry["effective_at"]) <= now), "PARENT_AUTHORITY_REVOKED")
        require(status["parent_status"] == "ACTIVE", "PARENT_AUTHORITY_REVOKED")
        # Mandatory independent root -> issuer issuance proof. No legacy parent
        # assertion/status or successful review can substitute for this chain.
        from governance.mutation_issuer_authority import verify_mutation_authority_issuer
        issuance = verify_mutation_authority_issuer(root_authority, issuer_grant, review_policy,
            proposal=proposal, reviewer_decisions=reviewer_decisions, grant=grant,
            parent_artifact=parent_artifact, trust=trust, root_source=root_source,
            currentness=currentness, now=now)
        if issuance["decision"] != "ALLOW":
            return issuance
        deadlines = [instant(issuance["verification_valid_until"]),
            _verification_deadline(trust, parent, parent_key),
            _verification_deadline(trust, status, status_key),
            _envelope_deadline(trust, proposal), _envelope_deadline(trust, grant),
            *(_envelope_deadline(trust, envelope) for envelope in reviewer_decisions),
            *(_envelope_deadline(trust, currentness[name]) for name in ("policy","adoption","h","w","revocations")),
            _envelope_deadline(trust, target_object)]
        verification_valid_until = _deadline_text(min(deadlines))
        return decision("MUTATION_AUTHORITY_VERIFIED", allowed=True,
                        assurance="CONTRACT_VERIFICATION_ONLY", grant_fingerprint=g["grant_fingerprint"],
                        issuance_evidence=issuance["issuance_evidence"],
                        verification_valid_until=verification_valid_until)
    except Exception as error:
        return decision(str(error) if type(error) is EnrollmentDenied else "MUTATION_AUTHORITY_INVALID")
