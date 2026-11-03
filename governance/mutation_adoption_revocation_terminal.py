"""Non-authorizing terminal proof for an all-version PolicyAdoption revocation."""
from __future__ import annotations
from copy import deepcopy

from governance.tenant_enrollment_contracts import (
    EnrollmentDenied, EnrollmentPolicy, PolicyAdoption, RevocationRecord,
    CurrentHeadWitness, SCOPE_FIELDS, check_revocation, decision, digest,
    object_id, require, scope,
)
from security.enrollment_policy_currentness import verify_currentness
from security.enrollment_policy_witness import verify_witness_pair

STATUS="ADOPTION_REVOKED_NON_PRODUCTION"
EFFECT="ALL_VERSIONS_OF_OBJECT"
KIND="ADOPTION_REVOCATION"

def _bundle_hash(bundle):
    return digest({
        "policy":bundle["policy"]["payload"],
        "adoption":bundle["adoption"]["payload"],
        "h":bundle["h"]["payload"],
        "w":bundle["w"]["payload"],
        "revocations":bundle["revocations"]["payload"],
        "expected":bundle["expected"],
        "challenge":bundle["challenge"],
        "request_digest":bundle["request_digest"],
    })

def verify_adoption_revocation_terminal_transition(
        trust,*,target_adoption,previous_currentness,revoked_currentness,now,
        command_hash,transaction_id,effect_grant_hash,mutation_event_hash,
        durable_position_hash,finalization_state):
    try:
        require(finalization_state=="FINALIZED","ADOPTION_FINALIZATION_STATE_INVALID")
        for value in (command_hash,effect_grant_hash,mutation_event_hash,durable_position_hash):
            require(type(value) is str and value.startswith("sha256:"),
                    "ADOPTION_REVOCATION_TERMINAL_PROOF_INVALID")
        require(type(transaction_id) is str and bool(transaction_id) and "*" not in transaction_id,
                "ADOPTION_REVOCATION_TERMINAL_PROOF_INVALID")

        old_policy,old_adoption,old_revocations=verify_currentness(
            trust,**previous_currentness,now=now)
        target=trust.verify(target_adoption,PolicyAdoption,"adoption",now)
        require(object_id(PolicyAdoption,target)==object_id(PolicyAdoption,old_adoption),
                "OBJECT_ID_MISMATCH")
        require(digest(target)==digest(old_adoption),"OBJECT_VERSION_MISMATCH")

        bundle=revoked_currentness
        require(type(bundle) is dict and set(bundle)=={
            "policy","adoption","h","w","revocations","expected","challenge","request_digest"},
            "ADOPTION_REVOCATION_TERMINAL_PROOF_INVALID")
        new_policy=trust.verify(bundle["policy"],EnrollmentPolicy,"policy",now)
        new_adoption=trust.verify(bundle["adoption"],PolicyAdoption,"adoption",now)
        new_revocations=trust.verify(bundle["revocations"],RevocationRecord,"revocation",now)
        hh=trust.verify(bundle["h"],CurrentHeadWitness,"H",now)
        ww=trust.verify(bundle["w"],CurrentHeadWitness,"W",now)

        require(scope(old_policy)==scope(new_policy)==scope(target)==scope(new_adoption)
                ==scope(new_revocations),"POLICY_SCOPE_INVALID")
        require(object_id(EnrollmentPolicy,new_policy)==object_id(EnrollmentPolicy,old_policy),
                "OBJECT_ID_MISMATCH")
        require(digest(new_policy)==digest(old_policy),"OBJECT_VERSION_MISMATCH")
        require(object_id(PolicyAdoption,new_adoption)==object_id(PolicyAdoption,target),
                "OBJECT_ID_MISMATCH")
        require(digest(new_adoption)==digest(target),"OBJECT_VERSION_MISMATCH")
        require(new_adoption["policy_id"]==new_policy["policy_id"]
                and new_adoption["policy_version"]==new_policy["policy_version"]
                and new_adoption["policy_hash"]==digest(new_policy),
                "ADOPTION_POLICY_INVALID")
        require(new_policy["adoption_authority_reference"] in new_adoption["approval_references"],
                "ADOPTION_AUTHORITY_INVALID")
        require(new_policy["lineage_hash"]==new_adoption["lineage_hash"]==hh["lineage_hash"],
                "LINEAGE_INVALID")

        require(new_revocations["sequence"]==old_revocations["sequence"]+1
                and new_revocations["generation"]==old_revocations["generation"]
                and new_revocations["epoch"]==old_revocations["epoch"],
                "REVOCATION_NOT_CURRENT")
        old_entries=deepcopy(old_revocations["revocations"])
        new_entries=deepcopy(new_revocations["revocations"])
        for entry in old_entries:
            require(entry in new_entries,"REVOCATION_REMOVAL_DETECTED")
        additions=[entry for entry in new_entries if entry not in old_entries]
        require(len(additions)==1,"ADOPTION_REVOCATION_TERMINAL_PROOF_INVALID")
        added=additions[0]
        require(added["kind"]==KIND
                and added["target_id"]==object_id(PolicyAdoption,target)
                and added["target_scope"]=={k:target[k] for k in SCOPE_FIELDS}
                and added["coverage"]==EFFECT,
                "REVOCATION_SCOPE_MISMATCH")

        require(hh["revocation_reference"]==new_revocations["revocation_reference"]
                and ww["revocation_reference"]==new_revocations["revocation_reference"],
                "REVOCATION_NOT_CURRENT")
        require(all(new_revocations[k]==hh[k] for k in ("sequence","generation","epoch"))
                and all(hh[k]==ww[k] for k in (
                    "head_hash","sequence","generation","epoch","revocation_reference")),
                "REVOCATION_NOT_CURRENT")
        require(trust._keys[hh["issuer_key_id"]].public_key
                != trust._keys[ww["issuer_key_id"]].public_key,
                "WITNESS_SEPARATION_INVALID")
        verify_witness_pair(
            hh,ww,policy=new_policy,adoption_hash=digest(new_adoption),
            expected=bundle["expected"],challenge=bundle["challenge"],
            request_digest=bundle["request_digest"])

        try:
            check_revocation(new_revocations,target,PolicyAdoption,now)
        except EnrollmentDenied as error:
            require(str(error)==KIND,"ADOPTION_REVOCATION_TERMINAL_PROOF_INVALID")
        else:
            raise EnrollmentDenied("REVOCATION_NOT_EFFECTIVE")

        proof={
            "schema_version":"usbay.adoption_revocation_terminal_proof.v1",
            "status":STATUS,
            "target_object_id":object_id(PolicyAdoption,target),
            "target_object_version_hash":digest(target),
            "adoption_id":object_id(PolicyAdoption,target),
            "policy_id":target["policy_id"],
            "finalization_state":finalization_state,
            "revocation_effect_scope":EFFECT,
            "previous_revocation_reference":old_revocations["revocation_reference"],
            "new_revocation_reference":new_revocations["revocation_reference"],
            "previous_revocation_hash":digest(old_revocations),
            "new_revocation_hash":digest(new_revocations),
            "previous_sequence":old_revocations["sequence"],
            "new_sequence":new_revocations["sequence"],
            "generation":new_revocations["generation"],
            "epoch":new_revocations["epoch"],
            "h_witness_hash":digest(hh),
            "w_witness_hash":digest(ww),
            "previous_currentness_hash":_bundle_hash(previous_currentness),
            "revoked_currentness_hash":_bundle_hash(bundle),
            "command_hash":command_hash,
            "transaction_id":transaction_id,
            "effect_grant_hash":effect_grant_hash,
            "mutation_event_hash":mutation_event_hash,
            "durable_position_hash":durable_position_hash,
        }
        return decision("ADOPTION_REVOCATION_TERMINAL_PROOF_VERIFIED",allowed=True,
            terminal_proof=proof,terminal_proof_hash=digest(proof),
            mutation_authority_created=False)
    except Exception as error:
        return decision(str(error) if type(error) is EnrollmentDenied
                        else "ADOPTION_REVOCATION_TERMINAL_PROOF_INVALID")
