"""Synthetic-only tests for PolicyAdoption revocation effect authority."""
from copy import deepcopy
from governance.mutation_adoption_revocation_effect import verify_adoption_revocation_effect
from tests.helpers.mutation_commit import synthetic_commit
from tests.helpers.mutation_adoption_revocation_effect import build_adoption_effect_for_mutation
from tests.helpers.mutation_policy_revocation_effect import build_effect_for_mutation
from tests.helpers.mutation_grant_revocation_effect import build_grant_effect_for_mutation
from tests.helpers.tenant_enrollment import NOW

def _fixture(tmp_path):
    f=synthetic_commit(tmp_path,action="REVOKE_ADOPTION")
    effect=build_adoption_effect_for_mutation(f.f)
    f.view.trust=f.f.trust
    material=dict(parent_artifact=f.f.parent,parent_source=f.f.parent_source,
        root_authority=f.f.root_authority,issuer_grant=f.f.issuer_grant,
        review_policy=f.f.review_policy,root_source=f.f.root_source,
        currentness=f.f.currentness(),target_object=f.f.commit_target)
    return f,effect,material

def _verify(f,effect,material,state=None):
    return verify_adoption_revocation_effect(
        mutation_proposal=f.f.proposal,mutation_reviews=f.f.reviews,
        mutation_grant=f.f.grant,mutation_material=material,
        effect_parent=effect["parent"],effect_proposal=effect["proposal"],
        effect_reviews=effect["reviews"],effect_grant=effect["grant"],
        trust=f.f.trust,now=NOW,expected_state=f.state if state is None else state)

def test_exact_adoption_all_version_effect_allows(tmp_path):
    f,e,m=_fixture(tmp_path)
    r=_verify(f,e,m)
    assert r["decision"]=="ALLOW"
    assert r["effect_scope"]=="ALL_VERSIONS_OF_OBJECT"

def test_policy_effect_cannot_substitute_for_adoption_effect(tmp_path):
    f,_,m=_fixture(tmp_path)
    bad=build_effect_for_mutation(f.f)
    f.view.trust=f.f.trust
    r=verify_adoption_revocation_effect(
        mutation_proposal=f.f.proposal,mutation_reviews=f.f.reviews,mutation_grant=f.f.grant,
        mutation_material=m,effect_parent=bad["parent"],effect_proposal=bad["proposal"],
        effect_reviews=bad["reviews"],effect_grant=bad["grant"],trust=f.f.trust,now=NOW,
        expected_state=f.state)
    assert r["decision"]=="DENY"

def test_grant_effect_cannot_substitute_for_adoption_effect(tmp_path):
    f,_,m=_fixture(tmp_path)
    bad=build_grant_effect_for_mutation(f.f)
    f.view.trust=f.f.trust
    r=verify_adoption_revocation_effect(
        mutation_proposal=f.f.proposal,mutation_reviews=f.f.reviews,mutation_grant=f.f.grant,
        mutation_material=m,effect_parent=bad["parent"],effect_proposal=bad["proposal"],
        effect_reviews=bad["reviews"],effect_grant=bad["grant"],trust=f.f.trust,now=NOW,
        expected_state=f.state)
    assert r["decision"]=="DENY"

def test_adoption_effect_pending_state_denied(tmp_path):
    f,e,m=_fixture(tmp_path)
    state=deepcopy(f.state)
    state["expected_finalization_state"]="PENDING"
    r=_verify(f,e,m,state)
    assert r["decision"]=="DENY"
    assert r["reason"]=="ADOPTION_FINALIZATION_STATE_INVALID"

def test_adoption_effect_requires_two_reviewers(tmp_path):
    f,e,m=_fixture(tmp_path)
    bad=deepcopy(e);bad["reviews"]=bad["reviews"][:1]
    r=_verify(f,bad,m)
    assert r["decision"]=="DENY"
    assert r["reason"]=="REVIEW_THRESHOLD_NOT_MET"
