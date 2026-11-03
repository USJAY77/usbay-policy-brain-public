from copy import deepcopy
from dataclasses import replace

import pytest

from governance.tenant_enrollment_contracts import FLAGS, digest
from governance.tenant_enrollment_verification import evaluate_enrollment
from security.enrollment_policy_currentness import EnrollmentTrust
from tests.helpers.tenant_enrollment import synthetic_enrollment, NOW


def check(f):
    return evaluate_enrollment(f.trust, f.inputs, expected=f.head, now=NOW)


def test_positive_precheck_is_not_registration_or_execution_authority():
    result = check(synthetic_enrollment())
    assert result["decision"] == "DENY" and result["verification_valid"] is True
    assert result["reason"] == "VERIFIED_NOT_COMMITTED"
    assert result["authority_flags"] == dict.fromkeys(FLAGS, False)


@pytest.mark.parametrize("missing", ["trust", "grant", "head", "policy", "adoption", "request", "h", "w", "revocations"])
def test_missing_governance_input_denies(missing):
    f = synthetic_enrollment()
    if missing == "trust":
        f.trust = EnrollmentTrust()
    elif missing == "head":
        f.head = {}
    else:
        f.inputs.pop(missing)
    assert check(f)["decision"] == "DENY"
    assert check(f).get("verification_valid") is not True


@pytest.mark.parametrize("field,value", [
    ("trust_domain", "ai_act_live_policy_engine"), ("policy_domain", "mail"),
    ("tenant_id", "foreign-tenant"), ("environment", "production"), ("purpose", "send_exact"),
    ("action", "SEND_EMAIL"), ("policy_id", "substituted"), ("policy_version", "old"),
    ("policy_hash", "sha256:" + "f" * 64), ("tenant_id", "*"), ("delegation_allowed", True),
    ("registrar_actor", "administrator"), ("issuer_id", "unknown"), ("issuer_key_id", "unknown"),
    ("expires_at", "2026-01-02T12:00:00Z"), ("enrollment_valid_until", "2026-01-02T12:00:00Z"),
])
def test_otherwise_signed_grant_substitution_denies(field, value):
    f = synthetic_enrollment()
    payload = deepcopy(f.inputs["grant"]["payload"])
    payload[field] = value
    # Unknown key cannot sign: retain original issuer key solely for this negative.
    envelope = f.sign(payload) if payload["issuer_key_id"] in f.private else dict(payload=payload, signature=f.inputs["grant"]["signature"])
    f.inputs["grant"] = envelope
    assert check(f).get("verification_valid") is not True


@pytest.mark.parametrize("domain", ["ai_act_live_policy_engine", "mail", "deployment", "runtime_artifact_producer", "Hydra", "other-tenant"])
def test_cross_domain_trust_cannot_substitute(domain):
    f = synthetic_enrollment()
    keys = tuple(replace(key, trust_domain=domain) for key in f.trust._keys.values())
    f.trust = EnrollmentTrust(keys, max_age_seconds=60)
    assert check(f).get("verification_valid") is not True


def test_caller_constructed_context_cannot_replace_signed_inputs():
    f = synthetic_enrollment()
    f.inputs = {"trusted": True, "decision": "ALLOW", "policy_hash": digest({})}
    assert check(f)["decision"] == "DENY"
    assert evaluate_enrollment()["decision"] == "DENY"


def test_environment_does_not_create_roots_or_default_signer(monkeypatch):
    monkeypatch.setenv("USBAY_ENROLLMENT_TRUST_ROOT", "caller-key")
    monkeypatch.setenv("USBAY_ENROLLMENT_ALLOW", "true")
    trust = EnrollmentTrust()
    assert dict(trust._keys) == {}
    assert not hasattr(trust, "register_issuer")
    assert not hasattr(trust, "sign")
    assert evaluate_enrollment(trust)["decision"] == "DENY"


@pytest.mark.parametrize("field,value", [
    ("policy_id", "different-policy"), ("policy_version", "different-version"),
    ("policy_hash", "sha256:" + "e" * 64),
])
def test_policy_join_isolated_after_valid_signed_request_and_currentness(field, value, monkeypatch):
    """Real currentness succeeds; only the final grant-policy join must fail."""
    import governance.tenant_enrollment_verification as verifier
    from governance.tenant_enrollment_contracts import EnrollmentDenied

    f = synthetic_enrollment()
    grant = deepcopy(f.inputs["grant"]["payload"])
    grant[field] = value
    f.inputs["grant"] = f.sign(grant)
    request = deepcopy(f.inputs["request"]["payload"])
    request[field] = value
    request["grant_hash"] = digest(grant)
    f.inputs["request"] = f.sign(request)
    for name in ("h", "w"):
        witness = deepcopy(f.inputs[name]["payload"])
        witness["request_digest"] = digest(request)
        f.inputs[name] = f.sign(witness)
    original = verifier.verify_currentness
    observed = []

    def observe_real_currentness(*args, **kwargs):
        result = original(*args, **kwargs)
        observed.append("CURRENTNESS_SUCCEEDED")
        return result

    monkeypatch.setattr(verifier, "verify_currentness", observe_real_currentness)
    with pytest.raises(EnrollmentDenied, match="^GRANT_POLICY_INVALID$"):
        verifier.verify_enrollment(f.trust, f.inputs, expected=f.head, now=NOW)
    assert observed == ["CURRENTNESS_SUCCEEDED"]


def test_policy_domain_is_a_closed_schema_boundary_not_a_later_join(record_property):
    """Evidence limitation: cannot claim the later join was reached."""
    from governance.tenant_enrollment_contracts import EnrollmentDenied, EnrollmentPolicy
    f = synthetic_enrollment()
    p = deepcopy(f.inputs["policy"]["payload"])
    p["policy_domain"] = "other-policy-domain"
    signed = f.sign(p)
    with pytest.raises(EnrollmentDenied, match="^DOMAIN_INVALID$"):
        f.trust.verify(signed, EnrollmentPolicy, "policy", NOW)
    record_property("boundary", "CLOSED_SCHEMA_ONLY_NOT_LATER_DOMAIN_JOIN")
