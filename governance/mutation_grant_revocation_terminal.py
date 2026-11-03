"""Non-authorizing terminal proof for an all-version EnrollmentGrant revocation."""
from __future__ import annotations
from copy import deepcopy

from governance.tenant_enrollment_contracts import (
    EnrollmentDenied, EnrollmentGrant, SCOPE_FIELDS, check_revocation, decision,
    digest, object_id, require, scope,
)
from security.enrollment_policy_currentness import verify_currentness

STATUS="GRANT_REVOKED_NON_PRODUCTION"
EFFECT="ALL_VERSIONS_OF_OBJECT"
KIND="GRANT_OBJECT_REVOCATION"

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

def verify_grant_revocation_terminal_transition(
        trust,*,target_grant,previous_currentness,revoked_currentness,now,
        command_hash,transaction_id,effect_grant_hash,mutation_event_hash,
        durable_position_hash,consumption_state):
    """Verify transition integrity; creates no authority and performs no write."""
    try:
        require(consumption_state in ("CONSUMED","UNCONSUMED"),
                "GRANT_CONSUMPTION_STATE_INVALID")
        for value in (command_hash,effect_grant_hash,mutation_event_hash,durable_position_hash):
            require(type(value) is str and value.startswith("sha256:"),
                    "GRANT_REVOCATION_TERMINAL_PROOF_INVALID")
        require(type(transaction_id) is str and bool(transaction_id) and "*" not in transaction_id,
                "GRANT_REVOCATION_TERMINAL_PROOF_INVALID")

        old_policy,_,old_revocations=verify_currentness(
            trust,**previous_currentness,now=now)
        new_policy,_,new_revocations=verify_currentness(
            trust,**revoked_currentness,now=now)
        target=trust.verify(target_grant,EnrollmentGrant,"enrollment",now)

        require(scope(target)==scope(old_policy)==scope(new_policy),"POLICY_SCOPE_INVALID")
        require(target["policy_id"]==old_policy["policy_id"],"RESOURCE_NOT_AUTHORIZED")
        require(new_policy["policy_id"]==old_policy["policy_id"],"POLICY_SCOPE_INVALID")
        require(new_revocations["sequence"]==old_revocations["sequence"]+1
                and new_revocations["generation"]==old_revocations["generation"]
                and new_revocations["epoch"]==old_revocations["epoch"],
                "REVOCATION_NOT_CURRENT")

        old_entries=deepcopy(old_revocations["revocations"])
        new_entries=deepcopy(new_revocations["revocations"])
        for entry in old_entries:
            require(entry in new_entries,"REVOCATION_REMOVAL_DETECTED")
        additions=[entry for entry in new_entries if entry not in old_entries]
        require(len(additions)==1,"GRANT_REVOCATION_TERMINAL_PROOF_INVALID")
        added=additions[0]
        require(added["kind"]==KIND
                and added["target_id"]==object_id(EnrollmentGrant,target)
                and added["target_scope"]=={k:target[k] for k in SCOPE_FIELDS}
                and added["coverage"]==EFFECT,
                "REVOCATION_SCOPE_MISMATCH")
        try:
            check_revocation(new_revocations,target,EnrollmentGrant,now)
        except EnrollmentDenied as error:
            require(str(error)==KIND,"GRANT_REVOCATION_TERMINAL_PROOF_INVALID")
        else:
            raise EnrollmentDenied("REVOCATION_NOT_EFFECTIVE")

        proof={
            "schema_version":"usbay.grant_revocation_terminal_proof.v1",
            "status":STATUS,
            "target_object_id":object_id(EnrollmentGrant,target),
            "target_object_version_hash":digest(target),
            "target_grant_id":target["grant_id"],
            "revocation_effect_scope":EFFECT,
            "consumption_state":consumption_state,
            "previous_revocation_reference":old_revocations["revocation_reference"],
            "new_revocation_reference":new_revocations["revocation_reference"],
            "previous_revocation_hash":digest(old_revocations),
            "new_revocation_hash":digest(new_revocations),
            "previous_sequence":old_revocations["sequence"],
            "new_sequence":new_revocations["sequence"],
            "generation":new_revocations["generation"],
            "epoch":new_revocations["epoch"],
            "previous_currentness_hash":_bundle_hash(previous_currentness),
            "revoked_currentness_hash":_bundle_hash(revoked_currentness),
            "command_hash":command_hash,
            "transaction_id":transaction_id,
            "effect_grant_hash":effect_grant_hash,
            "mutation_event_hash":mutation_event_hash,
            "durable_position_hash":durable_position_hash,
        }
        return decision("GRANT_REVOCATION_TERMINAL_PROOF_VERIFIED",allowed=True,
            terminal_proof=proof,terminal_proof_hash=digest(proof),
            mutation_authority_created=False)
    except Exception as error:
        return decision(str(error) if type(error) is EnrollmentDenied
                        else "GRANT_REVOCATION_TERMINAL_PROOF_INVALID")
