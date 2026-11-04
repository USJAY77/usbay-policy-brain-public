"""Non-authorizing composition verifier for FINALIZE_POLICY_ADOPTION.

This module creates no witness, key, trust anchor, receipt or publication
authority. It only verifies already-signed successor policy/adoption/advance/H/W
artifacts against one durable ADOPTION_PENDING event and the verified prior head.
"""
from __future__ import annotations
from copy import deepcopy

from governance.tenant_enrollment_contracts import (
    CurrentHeadWitness, EnrollmentDenied, HeadAdvance, PolicyAdoption,
    EnrollmentPolicy, decision, digest, object_id, require,
)
from governance.tenant_enrollment_verification import verify_adoption
from security.enrollment_policy_witness import verify_witness_pair

SCHEMA="usbay.adoption_finalization.composition.v1"


def pending_record_reference(*, pending_event_hash, adoption_core_hash):
    return digest({
        "kind":"ADOPTION_PENDING",
        "event_hash":pending_event_hash,
        "adoption_core_hash":adoption_core_hash,
    })


def verify_finalization_composition(
        trust, *, previous_currentness, previous_head,
        pending_event, pending_event_hash, artifacts, now):
    try:
        require(type(pending_event) is dict
                and pending_event.get("kind")=="ADOPTION_PENDING",
                "FINALIZATION_PENDING_EVIDENCE_INVALID")
        require(type(pending_event_hash) is str
                and pending_event_hash.startswith("sha256:"),
                "FINALIZATION_PENDING_EVIDENCE_INVALID")
        require(type(artifacts) is dict and set(artifacts)=={
            "policy","adoption","advance","h","w","expected",
            "challenge","request_digest"},
            "FINALIZATION_EVIDENCE_INVALID")

        prior={
            key:deepcopy(value)
            for key,value in previous_currentness.items()
            if key!="expected"
        }
        p,a,b=verify_adoption(
            trust,
            {
                "policy":artifacts["policy"],
                "adoption":artifacts["adoption"],
                "advance":artifacts["advance"],
                "prior":prior,
            },
            previous=deepcopy(previous_head),
            now=now,
        )
        hh=trust.verify(artifacts["h"],CurrentHeadWitness,"H",now)
        ww=trust.verify(artifacts["w"],CurrentHeadWitness,"W",now)
        require(
            trust._keys[hh["issuer_key_id"]].public_key
            != trust._keys[ww["issuer_key_id"]].public_key,
            "WITNESS_SEPARATION_INVALID")
        require(
            pending_event["policy_hash"]==digest(p)
            and pending_event["adoption_core_hash"]==digest(a)
            and pending_event["head_advance_grant_hash"]==digest(b)
            and pending_event["target_head"]==b["head_hash"],
            "FINALIZATION_PENDING_EVIDENCE_INVALID")
        record_ref=pending_record_reference(
            pending_event_hash=pending_event_hash,
            adoption_core_hash=digest(a))
        require(
            hh["adoption_record_hash"]==record_ref
            and ww["adoption_record_hash"]==record_ref,
            "FINALIZATION_PENDING_EVIDENCE_INVALID")
        require(
            hh["head_advance_grant_hash"]==digest(b)
            and ww["head_advance_grant_hash"]==digest(b),
            "FINALIZATION_HEAD_ADVANCE_INVALID")
        verify_witness_pair(
            hh,ww,
            policy=p,
            adoption_hash=digest(a),
            expected=artifacts["expected"],
            challenge=artifacts["challenge"],
            request_digest=artifacts["request_digest"],
        )
        require(artifacts["expected"]["head_hash"]==b["head_hash"],
                "FINALIZATION_HEAD_ADVANCE_INVALID")
        require(artifacts["expected"]["previous_head_hash"]
                ==previous_head["head_hash"],
                "FINALIZATION_HEAD_ADVANCE_INVALID")
        require(artifacts["challenge"]==hh["challenge"]
                and artifacts["request_digest"]==hh["request_digest"],
                "WITNESS_CHALLENGE_INVALID")

        composition={
            "schema_version":SCHEMA,
            "policy_id":p["policy_id"],
            "policy_version":p["policy_version"],
            "policy_hash":digest(p),
            "adoption_id":object_id(PolicyAdoption,a),
            "adoption_version_hash":digest(a),
            "head_advance_hash":digest(b),
            "previous_head_hash":previous_head["head_hash"],
            "target_head":b["head_hash"],
            "pending_event_hash":pending_event_hash,
            "pending_record_reference":record_ref,
            "h_witness_hash":digest(hh),
            "w_witness_hash":digest(ww),
            "challenge_reference":digest({"challenge":artifacts["challenge"]}),
            "request_digest":artifacts["request_digest"],
            "revocation_reference":hh["revocation_reference"],
            "anchor_hash":hh["anchor_hash"],
        }
        return decision(
            "ADOPTION_FINALIZATION_COMPOSITION_VERIFIED",
            allowed=True,
            composition=composition,
            composition_hash=digest(composition),
            authority_created=False,
            witness_created=False,
        )
    except Exception as error:
        return decision(
            str(error) if type(error) is EnrollmentDenied
            else "FINALIZATION_EVIDENCE_INVALID")
