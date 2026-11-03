"""Contract-layer tests only. No synthetic assertion is elevated to root authority."""
from copy import deepcopy
from datetime import timedelta

import pytest

from governance.mutation_authority import (
    MutationAuthorityProposalV1, ReviewerDecisionV1, MutationAuthorityGrantV1,
    ParentAuthorityScopeV1, check_child_subset_parent, verify_mutation_authority_grant,
)
from governance.tenant_enrollment_contracts import EnrollmentDenied, FLAGS, digest, parse_json
from tests.helpers.mutation_authority import synthetic_mutation
from tests.helpers.tenant_enrollment import NOW


def test_complete_two_of_two_with_explicit_synthetic_parent_evidence_allows_contract_only():
    f = synthetic_mutation()
    check_child_subset_parent(f.grant["payload"], f.parent["payload"])
    result = f.verify()
    assert result["decision"] == "ALLOW" and result["reason"] == "MUTATION_AUTHORITY_VERIFIED"
    assert result["assurance"] == "CONTRACT_VERIFICATION_ONLY"
    assert result["authority_flags"] == dict.fromkeys(FLAGS, False)
    # Explicit synthetic authority fixture; neither real human decisions nor a
    # live parent/root/store is created. ALLOW is read-only contract verification.


def test_signed_parent_assertion_without_authoritative_status_is_insufficient():
    f = synthetic_mutation()
    result = f.verify(parent_source=None)
    assert result["decision"] == "DENY" and result["reason"] == "MUTATION_AUTHORITY_MISSING"
    assert result["contract_bindings_valid"] is True


def test_parent_revocation_status_is_separate_from_key_revocation():
    f = synthetic_mutation()
    assert f.verify()["decision"] == "ALLOW"
    f.parent_source.status = "REVOKED"
    f.parent_source.sequence += 1
    result = f.verify()
    assert result["decision"] == "DENY" and result["reason"] == "PARENT_AUTHORITY_REVOKED"


@pytest.mark.parametrize("reply", [True, {"approved": True}, {"verified_parent": True}])
def test_caller_booleans_or_unsigned_source_results_cannot_supply_parent_authority(reply):
    class FakeSource:
        def read_parent_authority(self, **kwargs):
            return reply
    result = synthetic_mutation().verify(parent_source=FakeSource())
    assert result["decision"] == "DENY" and result["reason"] == "PARENT_AUTHORITY_INVALID"


def test_source_attests_installed_record_not_caller_selected_parent_hash():
    f = synthetic_mutation()
    f.parent["payload"]["authority_id"] = "caller-selected-parent"
    f.refresh()
    result = f.verify()
    assert result["decision"] == "DENY" and result["reason"] == "PARENT_AUTHORITY_INVALID"


def test_captured_parent_status_cannot_be_replayed_for_a_new_challenge():
    f = synthetic_mutation()
    source = f.parent_source
    class CapturingSource:
        def __init__(self):
            self.response = None
        def read_parent_authority(self, **kwargs):
            if self.response is None:
                self.response = source.read_parent_authority(**kwargs)
            return deepcopy(self.response)
    capture = CapturingSource()
    assert f.verify(parent_source=capture)["decision"] == "ALLOW"
    result = f.verify(parent_source=capture)
    assert result["decision"] == "DENY" and result["reason"] == "PARENT_AUTHORITY_INVALID"


def test_repeated_read_verification_is_not_mutation_or_grant_consumption():
    f = synthetic_mutation()
    before = deepcopy(f.parent_source.record)
    for _ in range(2):
        result = f.verify()
        assert result["decision"] == "ALLOW"
        assert result["authority_flags"] == dict.fromkeys(FLAGS, False)
    assert f.parent_source.record == before
    assert len(f.parent_source.challenges) == 2 and len(set(f.parent_source.challenges)) == 2


@pytest.mark.parametrize("field,value", [("parent_authority_hash", "sha256:" + "f" * 64),
    ("subject_issuer_id", "different-issuer"), ("expected_current_head", "sha256:" + "f" * 64),
    ("revocation_reference", "sha256:" + "f" * 64), ("issued_at", "2026-01-02T11:58:00Z")])
def test_even_signed_parent_status_must_match_exact_fresh_scope(field, value):
    from governance.mutation_authority import fingerprint
    f = synthetic_mutation()
    source = f.parent_source
    class SubstitutingSource:
        def read_parent_authority(self, **kwargs):
            p = source.read_parent_authority(**kwargs)["payload"]
            p[field] = value
            p["status_fingerprint"] = fingerprint(p, "parent_status")
            return f.sign(p)
    result = f.verify(parent_source=SubstitutingSource())
    assert result["decision"] == "DENY" and result["reason"] == "PARENT_AUTHORITY_INVALID"


def test_parent_issuer_cannot_self_attest_authoritative_status_using_same_key():
    from dataclasses import replace
    from security.enrollment_policy_currentness import EnrollmentTrust
    f = synthetic_mutation()
    issuer_key = f.trust._keys["test-parent-assertion"].public_key
    keys = tuple(replace(k, public_key=issuer_key) if k.key_id == "test-parent-currentness" else k for k in f.trust._keys.values())
    f.trust = EnrollmentTrust(keys, max_age_seconds=60)
    f.parent_source.private = f.private["test-parent-assertion"]
    result = f.verify()
    assert result["decision"] == "DENY" and result["reason"] == "PARENT_AUTHORITY_INVALID"


def test_empty_defaults_and_missing_parent_fail_closed():
    assert verify_mutation_authority_grant()["decision"] == "DENY"
    f = synthetic_mutation()
    assert f.verify(parent_artifact=None)["reason"] == "MUTATION_AUTHORITY_MISSING"


@pytest.mark.parametrize("parent", [{}, {"valid": True}, {"approved": True, "parent_hash": "caller"}])
def test_caller_parent_context_never_becomes_authority(parent):
    result = synthetic_mutation().verify(parent_artifact=parent)
    assert result["decision"] == "DENY" and result["reason"] == "PARENT_AUTHORITY_INVALID"


@pytest.mark.parametrize("index", [0, 1])
def test_either_single_reviewer_cannot_meet_threshold(index):
    f = synthetic_mutation()
    f.reviews = [f.reviews[index]]
    assert f.verify()["reason"] == "REVIEW_THRESHOLD_NOT_MET"


def test_duplicate_reviewer_cannot_meet_two_of_two():
    f = synthetic_mutation()
    f.reviews = [f.reviews[0], deepcopy(f.reviews[0])]
    assert f.verify()["reason"] == "REVIEWER_DUPLICATE"


def test_two_labels_using_one_key_do_not_establish_independence():
    from dataclasses import replace
    from security.enrollment_policy_currentness import EnrollmentTrust
    f = synthetic_mutation()
    key = f.trust._keys["test-review-a"]
    f.private["test-review-b"] = f.private["test-review-a"]
    keys = tuple(replace(k, public_key=key.public_key) if k.key_id == "test-review-b" else k for k in f.trust._keys.values())
    f.trust = EnrollmentTrust(keys, max_age_seconds=60)
    f.reviews[1] = f.seal(f.reviews[1]["payload"], "review")
    assert f.verify()["reason"] == "REVIEWER_DUPLICATE"


@pytest.mark.parametrize("value", [True, 1, 3])
def test_review_threshold_cannot_be_coerced_or_reduced(value):
    f = synthetic_mutation()
    g = dict(f.grant["payload"], review_threshold=value)
    with pytest.raises(EnrollmentDenied, match="^REVIEW_THRESHOLD_NOT_MET$"):
        MutationAuthorityGrantV1.from_payload(g)


@pytest.mark.parametrize("index", [0, 1])
def test_signed_rejection_and_proposal_mismatch_deny(index):
    f = synthetic_mutation()
    d = deepcopy(f.reviews[index]["payload"])
    d["decision"] = "REJECT"
    f.reviews[index] = f.seal(d, "review")
    assert f.verify()["reason"] == "REVIEW_DECISION_INVALID"
    d["decision"] = "APPROVE"
    d["proposal_hash"] = digest({"other-proposal": 1})
    f.reviews[index] = f.seal(d, "review")
    assert f.verify()["reason"] == "REVIEW_PROPOSAL_MISMATCH"


@pytest.mark.parametrize("index", [0, 1])
def test_expired_review_at_equality_denies(index):
    f = synthetic_mutation()
    d = dict(f.reviews[index]["payload"], valid_until="2026-01-02T12:00:00Z")
    f.reviews[index] = f.seal(d, "review")
    assert f.verify()["decision"] == "DENY"
    assert f.verify()["reason"] == "MUTATION_AUTHORITY_EXPIRED"


@pytest.mark.parametrize("field", ["proposal_hash", "reviewer_a_decision_hash", "reviewer_b_decision_hash"])
def test_grant_exact_proposal_and_review_hashes(field):
    f = synthetic_mutation()
    f.grant = f.seal(dict(f.grant["payload"], **{field: digest({"substituted": field})}), "grant")
    assert f.verify()["reason"] in ("REVIEW_PROPOSAL_MISMATCH", "REVIEW_DECISION_INVALID")


@pytest.mark.parametrize("which,kind,model", [
    ("proposal", "proposal", MutationAuthorityProposalV1), ("grant", "grant", MutationAuthorityGrantV1),
    ("parent", "parent_scope", ParentAuthorityScopeV1),
])
def test_closed_protected_fields_and_each_byte_binding(which, kind, model):
    f = synthetic_mutation()
    envelope = getattr(f, which)
    model.from_payload(envelope["payload"])
    for field in envelope["payload"]:
        changed = deepcopy(envelope)
        changed["payload"][field] = "caller-substitution" if changed["payload"][field] is None else None
        with pytest.raises(EnrollmentDenied):
            model.from_payload(changed["payload"])
        missing = deepcopy(envelope["payload"])
        del missing[field]
        with pytest.raises(EnrollmentDenied):
            model.from_payload(missing)
    extra = dict(envelope["payload"], approved=True)
    with pytest.raises(EnrollmentDenied):
        model.from_payload(extra)


@pytest.mark.parametrize("field,value", [
    ("allowed_action", "ISSUE_ENROLLMENT_GRANT"), ("allowed_action", "REVOKE_SIGNING_KEY"),
    ("allowed_action", "MUTATING_RECOVERY"), ("allowed_action", "MAIL_EXECUTION"),
    ("tenant_id", "*"), ("resource_id", "*"), ("actor_id", ""), ("redelegation_allowed", True),
])
def test_prohibited_actions_empty_scope_wildcards_and_redelegation_reject(field, value):
    f = synthetic_mutation()
    p = dict(f.proposal["payload"], **{field: value})
    with pytest.raises(EnrollmentDenied):
        MutationAuthorityProposalV1.from_payload(p)


def test_duplicate_json_fields_reject():
    with pytest.raises(EnrollmentDenied):
        parse_json('{"approved":true,"approved":false}')


@pytest.mark.parametrize("which", ["proposal", "grant"])
def test_changed_protected_bytes_without_new_fingerprint_or_signature_deny(which):
    f = synthetic_mutation()
    changed = deepcopy(getattr(f, which))
    changed["payload"]["object_version_hash"] = digest({"changed": which})
    setattr(f, which, changed)
    assert f.verify()["reason"] == "MUTATION_AUTHORITY_INVALID"


@pytest.mark.parametrize("which,kind,field", [("proposal", "proposal", "proposal_id"), ("grant", "grant", "grant_nonce")])
def test_recomputed_unkeyed_fingerprint_cannot_replace_original_signature(which, kind, field):
    from governance.mutation_authority import fingerprint
    f = synthetic_mutation()
    changed = deepcopy(getattr(f, which))
    changed["payload"][field] += "-changed"
    changed["payload"]["proposal_fingerprint" if kind == "proposal" else "grant_fingerprint"] = fingerprint(changed["payload"], kind)
    setattr(f, which, changed)
    assert f.verify()["reason"] == "MUTATION_AUTHORITY_INVALID"


@pytest.mark.parametrize("field,value,reason", [
    ("tenant_id", "other-tenant", "TENANT_MISMATCH"), ("actor_id", "other-actor", "ACTOR_MISMATCH"),
    ("object_version_hash", "sha256:" + "f" * 64, "OBJECT_VERSION_MISMATCH"),
    ("expected_current_head", "sha256:" + "f" * 64, "EXPECTED_HEAD_MISMATCH"),
    ("valid_from", "2026-01-02T11:30:00Z", "AUTHORITY_SCOPE_BROADENING"),
    ("valid_until", "2026-01-02T12:30:00Z", "AUTHORITY_SCOPE_BROADENING"),
])
def test_structural_subset_denies_parent_mismatch_without_claiming_parent_authentication(field, value, reason):
    f = synthetic_mutation()
    f.parent["payload"][field] = value
    f.refresh()
    with pytest.raises(EnrollmentDenied, match="^" + reason + "$"):
        check_child_subset_parent(f.grant["payload"], f.parent["payload"])


def test_structural_subset_action_resource_and_object_are_exact_not_prefixes():
    f = synthetic_mutation()
    parent = f.parent["payload"]
    child = deepcopy(f.grant["payload"])
    child.update(allowed_action="REVOKE_GRANT_OBJECT", resource_type="ENROLLMENT_GRANT", target_grant_id="target-grant")
    f.grant = f.seal(child, "grant")
    with pytest.raises(EnrollmentDenied, match="^ACTION_NOT_AUTHORIZED$"):
        check_child_subset_parent(f.grant["payload"], parent)
    f = synthetic_mutation()
    p = f.parent["payload"]
    p.update(resource_id=digest({"other-resource": 1}), object_id=digest({"other-resource": 1}))
    f.refresh()
    with pytest.raises(EnrollmentDenied, match="^RESOURCE_NOT_AUTHORIZED$"):
        check_child_subset_parent(f.grant["payload"], f.parent["payload"])


def test_untrusted_parent_assertion_cannot_enable_replay_or_execution():
    f = synthetic_mutation()
    for _ in range(2):
        result = f.verify(parent_source=None)
        assert result["decision"] == "DENY" and result["retry_allowed"] is False
        assert result["authority_flags"] == dict.fromkeys(FLAGS, False)
    # This verifier performs no mutation or durable grant consumption. Actual
    # COMMAND_REPLAY belongs to a future separately authorized writer boundary.


def test_expired_parent_assertion_denies_at_equality():
    f = synthetic_mutation()
    f.parent["payload"]["valid_until"] = "2026-01-02T12:00:00Z"
    f.refresh()
    result = f.verify()
    assert result["decision"] == "DENY" and result["reason"] == "MUTATION_AUTHORITY_EXPIRED"


@pytest.mark.parametrize("which", ["parent", "reviewer_a", "grant"])
def test_existing_scoped_key_revocation_denies_without_inventing_parent_object_revocation(which):
    from governance.tenant_enrollment_contracts import key_id, SCOPE_FIELDS
    from tests.helpers.tenant_enrollment import synthetic_enrollment
    f = synthetic_mutation()
    p = f.parent["payload"] if which == "parent" else f.grant["payload"] if which == "grant" else f.reviews[0]["payload"]
    entry = dict(kind="KEY_REVOCATION", target_id=key_id(p), target_scope={k: p[k] for k in SCOPE_FIELDS},
                 coverage="EXACT_KEY_ID", effective_at="2026-01-02T12:00:00Z")
    enrollment = synthetic_enrollment(private_keys=f.enrollment.private, revocations=[entry])
    f.rebind_enrollment(enrollment)
    result = f.verify()
    assert result["decision"] == "DENY"
    assert result["reason"] == ("PARENT_AUTHORITY_REVOKED" if which == "parent" else "MUTATION_AUTHORITY_REVOKED")


def test_reviewer_closed_contract_checks_every_field():
    f = synthetic_mutation()
    original = f.reviews[0]["payload"]
    ReviewerDecisionV1.from_payload(original)
    for field in original:
        missing = dict(original)
        del missing[field]
        with pytest.raises(EnrollmentDenied):
            ReviewerDecisionV1.from_payload(missing)
    with pytest.raises(EnrollmentDenied):
        ReviewerDecisionV1.from_payload(dict(original, approved=True))


def test_target_version_cannot_be_substituted_by_a_fresh_valid_signature():
    f = synthetic_mutation()
    target = dict(f.enrollment.inputs["policy"]["payload"], policy_version="changed-version")
    signed = f.enrollment.sign(target)
    result = f.verify(target_object=signed)
    assert result["decision"] == "DENY" and result["reason"] == "OBJECT_VERSION_MISMATCH"


def test_other_object_cannot_be_substituted_by_a_valid_signature():
    f = synthetic_mutation()
    target = dict(f.enrollment.inputs["policy"]["payload"], policy_id="other-policy")
    result = f.verify(target_object=f.enrollment.sign(target))
    assert result["decision"] == "DENY" and result["reason"] == "OBJECT_ID_MISMATCH"


def test_no_writer_or_issuance_api_or_environment_bootstrap(monkeypatch):
    import governance.mutation_authority as module
    monkeypatch.setenv("USBAY_MUTATION_AUTHORITY_ALLOW", "true")
    monkeypatch.setenv("USBAY_MUTATION_PARENT_AUTHORITY", "caller-parent")
    result = module.verify_mutation_authority_grant()
    assert result["decision"] == "DENY"
    for name in ("issue", "sign", "register_parent", "bootstrap", "execute", "finalize", "publish", "recover"):
        assert not hasattr(module, name)


def test_parent_scope_purpose_mismatch_fails_closed_at_closed_schema():
    f = synthetic_mutation()
    f.parent["payload"]["purpose"] = "different-purpose"
    f.refresh()
    with pytest.raises(EnrollmentDenied, match="^PURPOSE_MISMATCH$"):
        check_child_subset_parent(f.grant["payload"], f.parent["payload"])


def test_redelegation_remains_prohibited_even_in_a_signed_parent_assertion():
    f = synthetic_mutation()
    f.parent["payload"]["redelegation_allowed"] = True
    f.refresh()
    result = f.verify()
    assert result["decision"] == "DENY"
    assert result["reason"] == "PARENT_AUTHORITY_INVALID"


def test_parent_cannot_bootstrap_itself_by_matching_ids():
    f = synthetic_mutation()
    f.parent["payload"]["parent_authority_id"] = f.parent["payload"]["authority_id"]
    f.refresh()
    assert f.verify()["reason"] == "PARENT_AUTHORITY_INVALID"
