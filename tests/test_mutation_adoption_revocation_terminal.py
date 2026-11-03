"""Synthetic-only tests for PolicyAdoption revocation terminal proof."""
from copy import deepcopy
from governance.mutation_adoption_revocation_terminal import verify_adoption_revocation_terminal_transition
from governance.tenant_enrollment_contracts import PolicyAdoption,digest
from tests.helpers.tenant_enrollment import NOW,object_revocation,synthetic_enrollment

def _bundle(f):
    return dict(policy=f.inputs["policy"],adoption=f.inputs["adoption"],h=f.inputs["h"],w=f.inputs["w"],
        revocations=f.inputs["revocations"],expected=deepcopy(f.head),
        challenge=f.inputs["request"]["payload"]["nonce"],request_digest=digest(f.inputs["request"]["payload"]))

def _fixture():
    old=synthetic_enrollment()
    target=old.inputs["adoption"]
    entries=deepcopy(old.inputs["revocations"]["payload"]["revocations"])
    entries.append(object_revocation(PolicyAdoption,target["payload"]))
    new=synthetic_enrollment(private_keys=old.private,sequence=2,
        previous={"policy_hash":digest(old.inputs["policy"]["payload"]),"head_hash":old.head["head_hash"]},
        revocations=entries)
    return old,new,target

def _verify(old,new,target,state="FINALIZED"):
    return verify_adoption_revocation_terminal_transition(
        old.trust,target_adoption=target,previous_currentness=_bundle(old),
        revoked_currentness=_bundle(new),now=NOW,
        command_hash=digest({"command":"adoption-revoke"}),
        transaction_id="adoption-revoke-tx",
        effect_grant_hash=digest({"effect":"adoption"}),
        mutation_event_hash=digest({"event":"core"}),
        durable_position_hash=digest({"position":2}),
        finalization_state=state)

def test_adoption_terminal_transition_verifies():
    old,new,target=_fixture()
    r=_verify(old,new,target)
    assert r["decision"]=="ALLOW"
    assert r["terminal_proof"]["status"]=="ADOPTION_REVOKED_NON_PRODUCTION"
    assert r["terminal_proof"]["finalization_state"]=="FINALIZED"

def test_adoption_terminal_pending_denied():
    old,new,target=_fixture()
    r=_verify(old,new,target,"PENDING")
    assert r["decision"]=="DENY"
    assert r["reason"]=="ADOPTION_FINALIZATION_STATE_INVALID"

def test_adoption_terminal_rejects_removed_prior_revocation():
    old=synthetic_enrollment(revoked_signers=("request",))
    target=old.inputs["adoption"]
    entries=[object_revocation(PolicyAdoption,target["payload"])]
    new=synthetic_enrollment(private_keys=old.private,sequence=2,
        previous={"policy_hash":digest(old.inputs["policy"]["payload"]),"head_hash":old.head["head_hash"]},
        revocations=entries)
    r=_verify(old,new,target)
    assert r["decision"]=="DENY"
    assert r["reason"]=="REVOCATION_REMOVAL_DETECTED"

def test_adoption_terminal_rejects_sequence_skip():
    old,new,target=_fixture()
    payload=deepcopy(new.inputs["revocations"]["payload"])
    payload["sequence"]=3
    payload["revocation_reference"]=digest({k:v for k,v in payload.items() if k!="revocation_reference"})
    new.inputs["revocations"]=new.sign(payload)
    r=_verify(old,new,target)
    assert r["decision"]=="DENY"

def test_adoption_terminal_rejects_target_substitution():
    old,new,target=_fixture()
    other=synthetic_enrollment().inputs["adoption"]
    r=_verify(old,new,other)
    assert r["decision"]=="DENY"
