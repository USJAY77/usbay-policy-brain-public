from copy import deepcopy
from datetime import timedelta

import pytest

from governance.tenant_enrollment_verification import evaluate_enrollment
from governance.tenant_enrollment_contracts import digest
from tests.helpers.tenant_enrollment import synthetic_enrollment, NOW


@pytest.mark.parametrize("part", ["policy", "adoption", "h", "w", "revocations"])
def test_expired_policy_adoption_trust_evidence_denies(part):
    f = synthetic_enrollment()
    p = deepcopy(f.inputs[part]["payload"])
    p["expires_at"] = "2026-01-02T12:00:00Z"
    f.inputs[part] = f.sign(p)
    assert evaluate_enrollment(f.trust, f.inputs, expected=f.head, now=NOW).get("verification_valid") is not True


@pytest.mark.parametrize("part", ["policy", "adoption", "grant", "request", "h", "w"])
def test_revoked_object_denies_even_with_valid_signatures(part):
    role = {"grant": "enrollment", "h": "H", "w": "W"}.get(part, part)
    f = synthetic_enrollment(revoked_signers=(role,))
    result = evaluate_enrollment(f.trust, f.inputs, expected=f.head, now=NOW)
    assert result["reason"] == "KEY_REVOKED"


def test_old_signed_currentness_is_not_latest_proof():
    f = synthetic_enrollment()
    f.head["sequence"] += 1
    assert evaluate_enrollment(f.trust, f.inputs, expected=f.head, now=NOW).get("verification_valid") is not True


def test_freshness_cannot_be_extended_by_payload():
    f = synthetic_enrollment()
    result = evaluate_enrollment(f.trust, f.inputs, expected=f.head, now=NOW + timedelta(seconds=61))
    assert result["decision"] == "DENY" and result.get("verification_valid") is not True


@pytest.mark.parametrize("object_name,kind", [
    ("policy", "POLICY_OBJECT_REVOCATION"), ("adoption", "ADOPTION_REVOCATION"),
    ("grant", "GRANT_OBJECT_REVOCATION"),
])
def test_direct_object_revocation_is_non_circular_and_separate_from_valid_keys(object_name, kind):
    from governance.tenant_enrollment_contracts import EnrollmentPolicy, EnrollmentGrant, PolicyAdoption, object_id
    from tests.helpers.tenant_enrollment import object_revocation
    models = {"policy": EnrollmentPolicy, "grant": EnrollmentGrant, "adoption": PolicyAdoption}
    initial = synthetic_enrollment()
    assert evaluate_enrollment(initial.trust, initial.inputs, expected=initial.head, now=NOW).get("verification_valid") is True
    target = object_id(models[object_name], initial.inputs[object_name]["payload"])
    entry = object_revocation(models[object_name], initial.inputs[object_name]["payload"])
    revoked = synthetic_enrollment(private_keys=initial.private, revocations=[entry])
    payload = revoked.inputs[object_name]["payload"]
    assert object_id(models[object_name], payload) == target
    assert digest(payload) != digest(initial.inputs[object_name]["payload"])
    role = {"grant": "enrollment"}.get(object_name, object_name)
    revoked.trust.verify(revoked.inputs[object_name], models[object_name], role, NOW)
    from governance.tenant_enrollment_contracts import CurrentHeadWitness
    from security.enrollment_policy_witness import verify_witness_pair
    for name, role_name in (("h", "H"), ("w", "W")):
        revoked.trust.verify(revoked.inputs[name], CurrentHeadWitness, role_name, NOW)
    request = revoked.inputs["request"]["payload"]
    policy = revoked.inputs["policy"]["payload"]
    assert revoked.inputs["grant"]["payload"]["policy_hash"] == request["policy_hash"] == digest(policy)
    verify_witness_pair(revoked.inputs["h"]["payload"], revoked.inputs["w"]["payload"], policy=policy,
                        adoption_hash=digest(revoked.inputs["adoption"]["payload"]), expected=revoked.head,
                        challenge=request["nonce"], request_digest=digest(request))
    result = evaluate_enrollment(revoked.trust, revoked.inputs, expected=revoked.head, now=NOW)
    assert result["reason"] == kind and result["decision"] == "DENY"
    # Different object ID does not revoke the original exact object.
    other = dict(entry, target_id=digest({"different-object": object_name}))
    unaffected = synthetic_enrollment(private_keys=initial.private, revocations=[other])
    assert evaluate_enrollment(unaffected.trust, unaffected.inputs, expected=unaffected.head, now=NOW).get("verification_valid") is True


def test_older_signed_policy_and_head_rejected_after_newer_signed_head(record_property):
    from governance.tenant_enrollment_contracts import EnrollmentDenied
    from security.enrollment_policy_currentness import verify_currentness
    old = synthetic_enrollment()
    newer = synthetic_enrollment(private_keys=old.private, sequence=2, previous=old.head)
    # Both complete chains independently pass their real signature/currentness
    # checks against the corresponding authoritative synthetic head.
    for f in (old, newer):
        assert evaluate_enrollment(f.trust, f.inputs, expected=f.head, now=NOW).get("verification_valid") is True
    previous = {name: old.inputs[name] for name in ("policy", "adoption", "h", "w", "revocations")}
    with pytest.raises(EnrollmentDenied, match="^STOPPED_UNVERIFIED_POLICY_HEAD$"):
        verify_currentness(old.trust, **previous, expected=newer.head,
                           challenge=old.inputs["request"]["payload"]["nonce"],
                           request_digest=digest(old.inputs["request"]["payload"]), now=NOW)
    record_property("boundary", "SYNTHETIC_PROTOCOL_ANTI_ROLLBACK_NOT_OPERATIONAL_INDEPENDENCE")


@pytest.mark.parametrize("kind,field,value,reason", [
    ("policy", "tenant_id", "foreign-tenant", "REVOCATION_TARGET_SCOPE_INVALID"),
    ("policy", "policy_domain", "foreign-domain", "REVOCATION_TARGET_SCOPE_INVALID"),
    ("grant", "tenant_id", "foreign-tenant", "REVOCATION_TARGET_SCOPE_INVALID"),
    ("grant", "policy_domain", "foreign-domain", "REVOCATION_TARGET_SCOPE_INVALID"),
])
def test_same_object_id_with_substituted_revocation_scope_is_invalid(kind, field, value, reason):
    from governance.tenant_enrollment_contracts import EnrollmentPolicy, EnrollmentGrant
    from tests.helpers.tenant_enrollment import object_revocation
    base = synthetic_enrollment()
    model = EnrollmentPolicy if kind == "policy" else EnrollmentGrant
    entry = object_revocation(model, base.inputs[kind]["payload"])
    entry["target_scope"][field] = value
    f = synthetic_enrollment(private_keys=base.private, revocations=[entry])
    result = evaluate_enrollment(f.trust, f.inputs, expected=f.head, now=NOW)
    assert result["reason"] == reason and result["decision"] == "DENY"


@pytest.mark.parametrize("kind,reason", [("policy", "POLICY_OBJECT_REVOCATION"), ("grant", "GRANT_OBJECT_REVOCATION")])
def test_object_revocation_effective_time_is_enforced_at_equality(kind, reason):
    from governance.tenant_enrollment_contracts import EnrollmentPolicy, EnrollmentGrant
    from tests.helpers.tenant_enrollment import object_revocation
    base = synthetic_enrollment()
    model = EnrollmentPolicy if kind == "policy" else EnrollmentGrant
    entry = object_revocation(model, base.inputs[kind]["payload"], effective_at="2026-01-02T12:00:01Z")
    f = synthetic_enrollment(private_keys=base.private, revocations=[entry])
    assert evaluate_enrollment(f.trust, f.inputs, expected=f.head, now=NOW).get("verification_valid") is True
    result = evaluate_enrollment(f.trust, f.inputs, expected=f.head, now=NOW + timedelta(seconds=1))
    assert result["reason"] == reason and result["decision"] == "DENY"


@pytest.mark.parametrize("coverage", [None, "", "*", "EXACT_VERSION_HASH"])
def test_missing_or_unsupported_revocation_coverage_never_becomes_wildcard(coverage):
    from governance.tenant_enrollment_contracts import EnrollmentPolicy
    from tests.helpers.tenant_enrollment import object_revocation
    base = synthetic_enrollment()
    entry = object_revocation(EnrollmentPolicy, base.inputs["policy"]["payload"])
    if coverage is None:
        del entry["coverage"]
    else:
        entry["coverage"] = coverage
    f = synthetic_enrollment(private_keys=base.private, revocations=[entry])
    result = evaluate_enrollment(f.trust, f.inputs, expected=f.head, now=NOW)
    assert result["decision"] == "DENY" and result.get("verification_valid") is not True
