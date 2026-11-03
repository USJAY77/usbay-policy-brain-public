"""Dormant admission gates. Reverify raw signed inputs inside the storage fence.

There is no trusted-context deserializer, live root loader, endpoint or signer.
The caller cannot replace any gate with a boolean or an earlier ALLOW result.
"""
from __future__ import annotations

from governance.tenant_enrollment_contracts import (
    EnrollmentGrant, EnrollmentRequest, HeadAdvance, PolicyAdoption, EnrollmentPolicy,
    EnrollmentDenied, decision, digest, instant, require, scope, check_revocation,
)
from security.enrollment_policy_currentness import EnrollmentTrust, verify_currentness
from security.enrollment_policy_witness import target_head, verify_successor


def verify_enrollment(trust: EnrollmentTrust, inputs: dict, *, expected: dict, now) -> dict:
    require(type(trust) is EnrollmentTrust and type(inputs) is dict, "TRUST_CONTEXT_INVALID")
    require(set(inputs) == {"grant", "request", "policy", "adoption", "h", "w", "revocations"}, "INPUTS_INVALID")
    grant = trust.verify(inputs["grant"], EnrollmentGrant, "enrollment", now)
    request = trust.verify(inputs["request"], EnrollmentRequest, "request", now)
    require(scope(grant) == scope(request) and grant["registrar_actor"] == request["actor"]
            == request["issuer_id"] and grant["request_id"] == request["request_id"], "REQUEST_BINDING_INVALID")
    require(request["method"] == "INTERNAL" and request["path"] == "tenant-enrollment"
            and request["grant_hash"] == digest(grant), "REQUEST_BINDING_INVALID")
    # Fresh request nonce is signed by the independently trusted registrar.
    # Witness evidence must bind this exact request, not a requester-selected hash.
    p, adoption, revocations = verify_currentness(trust, policy=inputs["policy"],
        adoption=inputs["adoption"], h=inputs["h"], w=inputs["w"], revocations=inputs["revocations"],
        expected=expected, challenge=request["nonce"], request_digest=digest(request), now=now)
    require(scope(p) == scope(grant) and request["actor"] in p["registrar_constraints"], "POLICY_SCOPE_INVALID")
    for key in ("policy_id", "policy_version", "policy_hash"):
        expected_value = digest(p) if key == "policy_hash" else p[key]
        require(grant[key] == request[key] == expected_value, "GRANT_POLICY_INVALID")
    require(grant["currentness_reference"] == p["currentness_reference"]
            and grant["revocation_reference"] == revocations["revocation_reference"], "GRANT_POLICY_INVALID")
    require(now < instant(grant["enrollment_valid_until"]), "EXPIRED")
    check_revocation(revocations, grant, EnrollmentGrant, now)
    check_revocation(revocations, request, EnrollmentRequest, now)
    return {"grant": grant, "request": request, "policy": p, "adoption": adoption,
            "revocations": revocations}


def evaluate_enrollment(trust: EnrollmentTrust | None = None, inputs=None, *, expected=None, now=None) -> dict:
    """Read-only precheck, never a registration receipt or reusable authority."""
    try:
        require(trust is not None and inputs is not None and now is not None, "AUTHORITY_MISSING")
        verify_enrollment(trust, inputs, expected=expected, now=now)
        return decision("VERIFIED_NOT_COMMITTED", verification_valid=True)
    except Exception as error:
        return decision(str(error) if type(error) is EnrollmentDenied else "VERIFICATION_UNAVAILABLE")


def verify_adoption(trust, inputs, *, previous, now):
    """A/B/policy signatures alone cannot establish a current policy head.
    This function only permits a pending local proposal against a verified prior
    snapshot. Publication/finalization requires matching independent receipts.
    """
    require(type(inputs) is dict and set(inputs) == {"policy", "adoption", "advance", "prior"}, "INPUTS_INVALID")
    prior = inputs["prior"]
    verify_currentness(trust, **prior, expected=previous, now=now)
    p = trust.verify(inputs["policy"], EnrollmentPolicy, "policy", now)
    a = trust.verify(inputs["adoption"], PolicyAdoption, "adoption", now)
    b = trust.verify(inputs["advance"], HeadAdvance, "advance", now)
    require(scope(p) == scope(a) == scope(b), "POLICY_SCOPE_INVALID")
    require(a["policy_hash"] == b["policy_hash"] == digest(p)
            and all(a[k] == b[k] == p[k] for k in ("policy_id", "policy_version")), "ADOPTION_POLICY_INVALID")
    require(p["adoption_authority_reference"] in a["approval_references"], "ADOPTION_AUTHORITY_INVALID")
    require(b["adoption_core_hash"] == digest(a) and b["head_hash"] == target_head(b), "HEAD_TARGET_INVALID")
    require(a["adopter_actor"] == a["issuer_id"] and b["advance_actor"] == b["issuer_id"], "ACTOR_INVALID")
    for key in ("previous_head_hash", "sequence", "generation", "epoch", "lineage_hash"):
        require(a[key] == b[key], "ADOPTION_HEAD_INVALID")
    require(p["parent_policy_reference"] == previous["policy_hash"], "LINEAGE_INVALID")
    require(p["lineage_hash"] == b["lineage_hash"] and p["revocation_reference"] == prior["revocations"]["payload"]["revocation_reference"]
            and p["currentness_reference"] == prior["policy"]["payload"]["currentness_reference"], "LINEAGE_INVALID")
    require(set(p["registrar_constraints"]) <= set(prior["policy"]["payload"]["registrar_constraints"]), "POLICY_WIDENING_DENIED")
    for payload, model in ((p, EnrollmentPolicy), (a, PolicyAdoption), (b, HeadAdvance)):
        check_revocation(prior["revocations"]["payload"], payload, model, now)
    verify_successor(previous, b)
    return p, a, b
