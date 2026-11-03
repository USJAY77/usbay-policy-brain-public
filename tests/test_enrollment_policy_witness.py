from copy import deepcopy

import pytest

from governance.tenant_enrollment_contracts import EnrollmentDenied
from governance.tenant_enrollment_verification import evaluate_enrollment
from security.enrollment_policy_witness import verify_successor
from tests.helpers.tenant_enrollment import synthetic_enrollment


@pytest.mark.parametrize("field,value", [
    ("sequence", 0), ("sequence", 2), ("epoch", 2), ("generation", 2),
    ("head_hash", "sha256:" + "a" * 64), ("lineage_hash", "sha256:" + "b" * 64),
    ("tenant_id", "foreign"), ("challenge", "old-challenge"), ("role", "H"),
    ("request_digest", "sha256:" + "c" * 64),
])
def test_signed_fork_rollback_scope_or_challenge_mismatch_denies(field, value):
    from tests.helpers.tenant_enrollment import NOW
    f = synthetic_enrollment()
    p = deepcopy(f.inputs["w"]["payload"])
    p[field] = value
    f.inputs["w"] = f.sign(p)
    result = evaluate_enrollment(f.trust, f.inputs, expected=f.head, now=NOW)
    assert result.get("verification_valid") is not True


def test_cas_requires_exact_parent_and_never_infers_genesis():
    f = synthetic_enrollment()
    b = f.next_adoption()["advance"]["payload"]
    verify_successor(f.head, b)
    for previous in ({}, dict(f.head, sequence=7), dict(f.head, epoch=8)):
        with pytest.raises(EnrollmentDenied):
            verify_successor(previous, b)


def test_no_recovery_or_live_witness_api():
    import security.enrollment_policy_witness as module
    for name in ("recover", "reset", "provision", "genesis", "connect", "choose_fork", "rollback"):
        assert not hasattr(module, name)


@pytest.mark.parametrize("case,expected_reason", [
    ("old_sequence", "STOPPED_UNVERIFIED_POLICY_HEAD"),
    ("duplicate_sequence", "STOPPED_UNVERIFIED_POLICY_HEAD"),
    ("skipped_sequence", "STOPPED_UNVERIFIED_POLICY_HEAD"),
    ("wrong_predecessor", "STOPPED_UNVERIFIED_POLICY_HEAD"),
    ("wrong_epoch", "STOPPED_UNVERIFIED_POLICY_HEAD"),
    ("wrong_lineage", "STOPPED_UNVERIFIED_POLICY_HEAD"),
    ("forked_successor", "HEAD_TARGET_INVALID"),
])
def test_isolated_signed_successor_protocol_boundary(case, expected_reason):
    from governance.tenant_enrollment_contracts import HeadAdvance, digest
    from security.enrollment_policy_witness import target_head
    from tests.helpers.tenant_enrollment import NOW
    f = synthetic_enrollment()
    previous = dict(f.head, sequence=3, head_hash=digest({"synthetic-head": 3}))
    b = f.next_adoption()["advance"]["payload"]
    b.update(previous_head_hash=previous["head_hash"], sequence=4)
    b["head_hash"] = target_head(b)
    # Positive control reaches the actual successor check with valid signature.
    verified = f.trust.verify(f.sign(b), HeadAdvance, "advance", NOW)
    verify_successor(previous, verified)
    changes = {"old_sequence": {"sequence": 2}, "duplicate_sequence": {"sequence": 3},
               "skipped_sequence": {"sequence": 5}, "wrong_predecessor": {"previous_head_hash": digest({"other": "parent"})},
               "wrong_epoch": {"epoch": 2}, "wrong_lineage": {"lineage_hash": digest({"other": "lineage"})},
               "forked_successor": {"head_hash": digest({"other": "target"})}}
    b.update(changes[case])
    if case != "forked_successor":
        b["head_hash"] = target_head(b)
    verified = f.trust.verify(f.sign(b), HeadAdvance, "advance", NOW)
    with pytest.raises(EnrollmentDenied, match="^" + expected_reason + "$"):
        verify_successor(previous, verified)


@pytest.mark.parametrize("field,value,reason", [
    ("tenant_id", "different-tenant", "WITNESS_SCOPE_INVALID"),
    ("policy_hash", "sha256:" + "a" * 64, "WITNESS_POLICY_INVALID"),
    ("adoption_record_hash", "sha256:" + "b" * 64, "STOPPED_UNVERIFIED_POLICY_HEAD"),
    ("sequence", 2, "STOPPED_UNVERIFIED_POLICY_HEAD"),
    ("epoch", 2, "STOPPED_UNVERIFIED_POLICY_HEAD"),
])
def test_isolated_witness_pair_fields_after_crypto_and_shape_checks(field, value, reason, record_property):
    from governance.tenant_enrollment_contracts import CurrentHeadWitness, canonical, digest
    from security.enrollment_policy_witness import verify_witness_pair
    from tests.helpers.tenant_enrollment import NOW
    f = synthetic_enrollment()
    h = f.inputs["h"]["payload"]
    w = deepcopy(f.inputs["w"]["payload"])
    policy = f.inputs["policy"]["payload"]
    kwargs = dict(policy=policy, adoption_hash=digest(f.inputs["adoption"]["payload"]),
                  expected=f.head, challenge=h["challenge"], request_digest=h["request_digest"])
    verify_witness_pair(h, w, **kwargs)
    w[field] = value
    signed = f.sign(w)
    # Direct protocol unit: a foreign-tenant signature is cryptographically real,
    # not trusted for that tenant. The connected trust boundary rejects it even
    # earlier; this test isolates only the lower-level protocol scope check.
    f.private["W"].public_key().verify(bytes.fromhex(signed["signature"]), canonical(w))
    CurrentHeadWitness.from_payload(w)
    if field != "tenant_id":
        f.trust.verify(signed, CurrentHeadWitness, "W", NOW)
    with pytest.raises(EnrollmentDenied, match="^" + reason + "$"):
        verify_witness_pair(h, w, **kwargs)
    record_property("boundary", "ISOLATED_WITNESS_PROTOCOL_NOT_LIVE_TRUST")


def test_witness_wrong_policy_domain_is_explicit_schema_boundary(record_property):
    from governance.tenant_enrollment_contracts import CurrentHeadWitness
    from tests.helpers.tenant_enrollment import NOW
    f = synthetic_enrollment()
    w = deepcopy(f.inputs["w"]["payload"])
    w["policy_domain"] = "foreign-domain"
    with pytest.raises(EnrollmentDenied, match="^DOMAIN_INVALID$"):
        f.trust.verify(f.sign(w), CurrentHeadWitness, "W", NOW)
    record_property("boundary", "CLOSED_SCHEMA_ONLY_NOT_LATER_DOMAIN_JOIN")


def test_passive_recovery_cannot_select_fork_or_mutate_head():
    import security.enrollment_policy_witness as witness
    from governance.authority_registry import EnrollmentAuthorityView
    forbidden = ("choose_fork", "select_canonical_fork", "rollback", "replace_trust_anchor",
                 "continue_uncertain_advance", "release_replay", "recover", "reset", "finalize")
    for name in forbidden:
        assert not hasattr(witness, name)
        assert not hasattr(EnrollmentAuthorityView, name)
