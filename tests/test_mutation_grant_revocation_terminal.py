"""Synthetic-only tests for EnrollmentGrant revocation terminal proof."""
from copy import deepcopy
from governance.mutation_grant_revocation_terminal import verify_grant_revocation_terminal_transition
from governance.tenant_enrollment_contracts import EnrollmentGrant,digest
from tests.helpers.tenant_enrollment import NOW,object_revocation,synthetic_enrollment

def _bundle(f):
    return dict(policy=f.inputs["policy"],adoption=f.inputs["adoption"],h=f.inputs["h"],w=f.inputs["w"],
        revocations=f.inputs["revocations"],expected=deepcopy(f.head),
        challenge=f.inputs["request"]["payload"]["nonce"],request_digest=digest(f.inputs["request"]["payload"]))

def _fixture():
    old=synthetic_enrollment()
    target=old.inputs["grant"]
    entries=deepcopy(old.inputs["revocations"]["payload"]["revocations"])
    entries.append(object_revocation(EnrollmentGrant,target["payload"]))
    new=synthetic_enrollment(private_keys=old.private,sequence=2,
        previous={"policy_hash":digest(old.inputs["policy"]["payload"]),"head_hash":old.head["head_hash"]},
        revocations=entries)
    return old,new,target

def _verify(old,new,target,state="UNCONSUMED"):
    return verify_grant_revocation_terminal_transition(old.trust,target_grant=target,
        previous_currentness=_bundle(old),revoked_currentness=_bundle(new),now=NOW,
        command_hash=digest({"command":"grant-revoke"}),transaction_id="grant-revoke-tx",
        effect_grant_hash=digest({"effect":"grant"}),mutation_event_hash=digest({"event":"core"}),
        durable_position_hash=digest({"position":2}),consumption_state=state)

def test_grant_terminal_transition_verifies_unconsumed():
    old,new,target=_fixture()
    r=_verify(old,new,target)
    assert r["decision"]=="ALLOW"
    assert r["terminal_proof"]["status"]=="GRANT_REVOKED_NON_PRODUCTION"
    assert r["terminal_proof"]["consumption_state"]=="UNCONSUMED"

def test_grant_terminal_transition_binds_consumed_state():
    old,new,target=_fixture()
    r=_verify(old,new,target,"CONSUMED")
    assert r["decision"]=="ALLOW"
    assert r["terminal_proof"]["consumption_state"]=="CONSUMED"

def test_grant_terminal_rejects_removed_prior_revocation():
    old=synthetic_enrollment(revoked_signers=("request",))
    target=old.inputs["grant"]
    entries=[object_revocation(EnrollmentGrant,target["payload"])]
    new=synthetic_enrollment(private_keys=old.private,sequence=2,
        previous={"policy_hash":digest(old.inputs["policy"]["payload"]),"head_hash":old.head["head_hash"]},
        revocations=entries)
    r=_verify(old,new,target)
    assert r["decision"]=="DENY"
    assert r["reason"]=="REVOCATION_REMOVAL_DETECTED"

def test_grant_terminal_rejects_sequence_skip():
    old,new,target=_fixture()
    bad=deepcopy(new.inputs["revocations"]["payload"]);bad["sequence"]=3
    bad["revocation_reference"]=digest({k:v for k,v in bad.items() if k!="revocation_reference"})
    new.inputs["revocations"]=new.sign(bad)
    r=_verify(old,new,target)
    assert r["decision"]=="DENY"

def test_grant_terminal_rejects_invalid_consumption_state():
    old,new,target=_fixture()
    r=_verify(old,new,target,"PARTIAL")
    assert r["decision"]=="DENY"
    assert r["reason"]=="GRANT_CONSUMPTION_STATE_INVALID"
