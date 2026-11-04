"""Synthetic-only tests for adoption finalization composition."""
from copy import deepcopy

from governance.mutation_adoption_finalization import verify_finalization_composition
from governance.tenant_enrollment_contracts import digest
from tests.helpers.mutation_adoption_finalization import build_finalization_artifacts
from tests.helpers.mutation_commit import synthetic_commit
from tests.helpers.tenant_enrollment import NOW


def _fixture(tmp_path):
    f=synthetic_commit(tmp_path,action="FINALIZE_POLICY_ADOPTION")
    artifacts,pending_event,pending_event_hash=build_finalization_artifacts(f)
    return f,artifacts,pending_event,pending_event_hash


def _verify(f,artifacts,pending_event,pending_event_hash):
    return verify_finalization_composition(
        f.view.trust,
        previous_currentness=f.f.currentness(),
        previous_head=f.f.enrollment.head,
        pending_event=pending_event,
        pending_event_hash=pending_event_hash,
        artifacts=artifacts,
        now=NOW,
    )


def test_finalization_composition_verifies(tmp_path):
    f,a,e,h=_fixture(tmp_path)
    r=_verify(f,a,e,h)
    assert r["decision"]=="ALLOW"
    assert r["reason"]=="ADOPTION_FINALIZATION_COMPOSITION_VERIFIED"
    assert r["authority_created"] is False
    assert r["witness_created"] is False


def test_finalization_composition_same_witness_key_denied(tmp_path):
    f,a,e,h=_fixture(tmp_path)
    bad=deepcopy(a)
    bad["w"]=deepcopy(bad["h"])
    bad["w"]["payload"]["role"]="W"
    r=_verify(f,bad,e,h)
    assert r["decision"]=="DENY"


def test_finalization_composition_stale_challenge_denied(tmp_path):
    f,a,e,h=_fixture(tmp_path)
    bad=deepcopy(a)
    bad["challenge"]="stale-finalization-challenge"
    r=_verify(f,bad,e,h)
    assert r["decision"]=="DENY"
    assert r["reason"]=="WITNESS_CHALLENGE_INVALID"


def test_finalization_composition_pending_event_mismatch_denied(tmp_path):
    f,a,e,h=_fixture(tmp_path)
    bad=deepcopy(e)
    bad["target_head"]=digest({"wrong":"head"})
    r=_verify(f,a,bad,h)
    assert r["decision"]=="DENY"
    assert r["reason"]=="FINALIZATION_PENDING_EVIDENCE_INVALID"


def test_finalization_composition_target_head_mismatch_denied(tmp_path):
    f,a,e,h=_fixture(tmp_path)
    bad=deepcopy(a)
    bad["expected"]["head_hash"]=digest({"wrong":"target-head"})
    r=_verify(f,bad,e,h)
    assert r["decision"]=="DENY"
