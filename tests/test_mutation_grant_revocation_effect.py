"""Synthetic-only tests for EnrollmentGrant revocation effect authority."""
from copy import deepcopy
from governance.mutation_grant_revocation_effect import verify_grant_revocation_effect
from governance.tenant_enrollment_contracts import digest
from tests.helpers.mutation_commit import synthetic_commit
from tests.helpers.mutation_grant_revocation_effect import build_grant_effect_for_mutation
from tests.helpers.mutation_policy_revocation_effect import build_effect_for_mutation
from tests.helpers.tenant_enrollment import NOW

def _fixture(tmp_path):
    f=synthetic_commit(tmp_path,action="REVOKE_GRANT_OBJECT")
    effect=build_grant_effect_for_mutation(f.f)
    f.view.trust=f.f.trust
    material=dict(parent_artifact=f.f.parent,parent_source=f.f.parent_source,
        root_authority=f.f.root_authority,issuer_grant=f.f.issuer_grant,
        review_policy=f.f.review_policy,root_source=f.f.root_source,
        currentness=f.f.currentness(),target_object=f.f.commit_target)
    return f,effect,material

def _verify(f,effect,material):
    return verify_grant_revocation_effect(
        mutation_proposal=f.f.proposal,mutation_reviews=f.f.reviews,
        mutation_grant=f.f.grant,mutation_material=material,
        effect_parent=effect["parent"],effect_proposal=effect["proposal"],
        effect_reviews=effect["reviews"],effect_grant=effect["grant"],
        trust=f.f.trust,now=NOW,expected_state=f.state)

def test_exact_grant_all_version_effect_allows(tmp_path):
    f,e,m=_fixture(tmp_path)
    r=_verify(f,e,m)
    assert r["decision"]=="ALLOW"
    assert r["effect_scope"]=="ALL_VERSIONS_OF_OBJECT"

def test_policy_effect_cannot_substitute_for_grant_effect(tmp_path):
    f,_,m=_fixture(tmp_path)
    policy=build_effect_for_mutation(f.f)
    f.view.trust=f.f.trust
    r=verify_grant_revocation_effect(
        mutation_proposal=f.f.proposal,mutation_reviews=f.f.reviews,mutation_grant=f.f.grant,
        mutation_material=m,effect_parent=policy["parent"],effect_proposal=policy["proposal"],
        effect_reviews=policy["reviews"],effect_grant=policy["grant"],trust=f.f.trust,now=NOW,
        expected_state=f.state)
    assert r["decision"]=="DENY"

def test_grant_effect_scope_substitution_denied(tmp_path):
    f,e,m=_fixture(tmp_path)
    bad=deepcopy(e)
    bad["grant"]["payload"]["revocation_effect_scope"]="EXACT_VERSION_ONLY"
    r=_verify(f,bad,m)
    assert r["decision"]=="DENY"

def test_grant_effect_target_id_mismatch_denied(tmp_path):
    f,e,m=_fixture(tmp_path)
    bad=deepcopy(e)
    bad["grant"]["payload"]["target_grant_id"]="other-grant"
    r=_verify(f,bad,m)
    assert r["decision"]=="DENY"

def test_grant_effect_requires_two_reviewers(tmp_path):
    f,e,m=_fixture(tmp_path)
    bad=deepcopy(e);bad["reviews"]=bad["reviews"][:1]
    r=_verify(f,bad,m)
    assert r["decision"]=="DENY"
    assert r["reason"]=="REVIEW_THRESHOLD_NOT_MET"
