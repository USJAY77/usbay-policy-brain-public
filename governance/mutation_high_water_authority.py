"""Bounded non-production authority contracts for mutation high-water and recovery.

These contracts are separate from ordinary GovernanceMutationCommandV1 actions.
They create no keys, signers, registry records, storage, deployment authority,
or production authority. Live composition remains absent by default.
"""
from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass
import re

from governance.mutation_authority import REVIEWERS
from governance.tenant_enrollment_contracts import (
    FLAGS, POLICY_DOMAIN, PURPOSE, SCOPE_FIELDS, TRUST_DOMAIN, EnrollmentDenied,
    canonical, decision, digest, instant, parse_json, require,
)

AUTHORITY_DOMAIN = "USBAY_MUTATION_HIGH_WATER_GOVERNANCE"
ACTIONS = {
    "WRITE_MUTATION_HIGH_WATER": "MUTATION_HIGH_WATER_LEDGER",
    "ADVANCE_MUTATION_RECOVERY_EPOCH": "MUTATION_CURRENTNESS_EPOCH",
}
COMMON = {
    "schema_version", *SCOPE_FIELDS, "authority_domain", "issuer_id",
    "issuer_key_id", "algorithm", "valid_from", "valid_until", "issued_at",
    "authority_flags",
}
BASE = {
    "actor_id", "allowed_action", "resource_type", "resource_id",
    "ledger_reference", "storage_boundary_reference", "allowed_scope_hash",
    "allowed_scope_domain", "redelegation_allowed", "parent_authority_id",
    "parent_authority_hash",
}
FIELDS = {
    "proposal": BASE | {
        "proposal_id", "proposal_nonce", "proposed_position_hash",
        "update_id_reference", "proposal_fingerprint",
    },
    "review": {
        "proposal_hash", "reviewer_id", "reviewer_role", "decision",
        "decision_nonce", "decision_fingerprint",
    },
    "writer_grant": BASE | {
        "grant_id", "grant_nonce", "signer_identity_reference", "signer_key_id",
        "signer_key_fingerprint", "expected_source_epoch",
        "expected_source_version", "expected_projection_hash",
        "proposed_position_hash", "update_id_reference", "max_updates",
        "proposal_hash", "reviewer_a_decision_hash",
        "reviewer_b_decision_hash", "grant_fingerprint",
    },
    "recovery_grant": BASE | {
        "grant_id", "grant_nonce", "previous_epoch", "next_epoch",
        "previous_source_version", "previous_projection_hash",
        "previous_high_water_event_hash", "recovery_evidence_reference",
        "reason_code", "proposed_recovery_state_hash",
        "recovery_operation_id", "max_uses", "proposal_hash",
        "reviewer_a_decision_hash", "reviewer_b_decision_hash",
        "grant_fingerprint",
    },
}
FP = {
    "proposal": "proposal_fingerprint",
    "review": "decision_fingerprint",
    "writer_grant": "grant_fingerprint",
    "recovery_grant": "grant_fingerprint",
}


def fingerprint(payload, kind):
    return digest({k: v for k, v in payload.items() if k != FP[kind]})


def _hash(value):
    return type(value) is str and re.fullmatch(r"sha256:[0-9a-f]{64}", value) is not None


def _text(value):
    return type(value) is str and 0 < len(value) <= 256 and "*" not in value


@dataclass(frozen=True)
class _Contract:
    encoded: bytes
    kind = ""

    @property
    def payload(self):
        return parse_json(self.encoded)

    @classmethod
    def from_payload(cls, p):
        require(type(p) is dict and set(p) == COMMON | FIELDS[cls.kind],
                "HIGH_WATER_AUTHORITY_INVALID")
        canonical(p)
        require(p["schema_version"]
                == "usbay.mutation_high_water_authority." + cls.kind + ".v1",
                "HIGH_WATER_AUTHORITY_INVALID")
        require(p["trust_domain"] == TRUST_DOMAIN
                and p["policy_domain"] == POLICY_DOMAIN
                and p["environment"] == "non-production"
                and p["purpose"] == PURPOSE
                and p["authority_domain"] == AUTHORITY_DOMAIN,
                "HIGH_WATER_AUTHORITY_INVALID")
        require(type(p["authority_flags"]) is dict
                and set(p["authority_flags"]) == set(FLAGS)
                and all(v is False for v in p["authority_flags"].values()),
                "AUTHORITY_SCOPE_BROADENING")
        require(p["algorithm"] == "Ed25519"
                and instant(p["valid_from"]) < instant(p["valid_until"])
                and instant(p["issued_at"]) < instant(p["valid_until"]),
                "HIGH_WATER_AUTHORITY_INVALID")
        require(type(p["tenant_id"]) is str
                and re.fullmatch(r"[a-z0-9][a-z0-9_-]{0,63}", p["tenant_id"]),
                "TENANT_MISMATCH")

        if cls.kind == "review":
            require(p["reviewer_id"] in REVIEWERS
                    and p["reviewer_role"] == REVIEWERS[p["reviewer_id"]]
                    and p["issuer_id"] == p["reviewer_id"]
                    and p["decision"] in ("APPROVE", "REJECT"),
                    "REVIEW_DECISION_INVALID")
        else:
            require(p["allowed_action"] in ACTIONS
                    and p["resource_type"] == ACTIONS[p["allowed_action"]],
                    "ACTION_NOT_AUTHORIZED")
            require(p["redelegation_allowed"] is False,
                    "PROHIBITED_REDELEGATION")
            for field in ("resource_id", "ledger_reference",
                          "storage_boundary_reference", "allowed_scope_hash",
                          "parent_authority_hash"):
                require(_hash(p[field]), "HIGH_WATER_AUTHORITY_INVALID")
            require(_text(p["allowed_scope_domain"])
                    and _text(p["actor_id"])
                    and _text(p["parent_authority_id"]),
                    "HIGH_WATER_AUTHORITY_INVALID")

        if cls.kind == "proposal":
            require(p["issuer_id"] == p["actor_id"],
                    "ACTOR_MISMATCH")
            require(_hash(p["proposed_position_hash"])
                    and _hash(p["update_id_reference"]),
                    "HIGH_WATER_AUTHORITY_INVALID")
        elif cls.kind == "writer_grant":
            require(p["allowed_action"] == "WRITE_MUTATION_HIGH_WATER"
                    and p["max_updates"] == 1,
                    "ACTION_NOT_AUTHORIZED")
            require(type(p["expected_source_epoch"]) is int
                    and type(p["expected_source_version"]) is int
                    and p["expected_source_epoch"] >= 1
                    and p["expected_source_version"] >= 1,
                    "HIGH_WATER_AUTHORITY_INVALID")
            for field in (
                "signer_identity_reference", "signer_key_fingerprint",
                "expected_projection_hash", "proposed_position_hash",
                "update_id_reference", "proposal_hash",
                "reviewer_a_decision_hash", "reviewer_b_decision_hash",
            ):
                require(_hash(p[field]), "HIGH_WATER_AUTHORITY_INVALID")
            require(_text(p["signer_key_id"]),
                    "HIGH_WATER_AUTHORITY_INVALID")
        elif cls.kind == "recovery_grant":
            require(p["allowed_action"] == "ADVANCE_MUTATION_RECOVERY_EPOCH"
                    and p["max_uses"] == 1,
                    "ACTION_NOT_AUTHORIZED")
            require(type(p["previous_epoch"]) is int
                    and type(p["next_epoch"]) is int
                    and type(p["previous_source_version"]) is int
                    and p["previous_epoch"] >= 1
                    and p["next_epoch"] == p["previous_epoch"] + 1
                    and p["previous_source_version"] >= 1,
                    "RECOVERY_EPOCH_INVALID")
            for field in (
                "previous_projection_hash", "previous_high_water_event_hash",
                "recovery_evidence_reference", "proposed_recovery_state_hash",
                "proposal_hash", "reviewer_a_decision_hash",
                "reviewer_b_decision_hash",
            ):
                require(_hash(p[field]), "HIGH_WATER_AUTHORITY_INVALID")
            require(_text(p["reason_code"])
                    and _text(p["recovery_operation_id"]),
                    "HIGH_WATER_AUTHORITY_INVALID")

        require(p[FP[cls.kind]] == fingerprint(p, cls.kind),
                "HIGH_WATER_AUTHORITY_INVALID")
        return cls(canonical(p))


class MutationHighWaterAuthorityProposalV1(_Contract):
    kind = "proposal"


class MutationHighWaterReviewerDecisionV1(_Contract):
    kind = "review"


class MutationHighWaterWriterGrantV1(_Contract):
    kind = "writer_grant"


class MutationRecoveryEpochGrantV1(_Contract):
    kind = "recovery_grant"


def _signed(trust, envelope, model, role, now):
    require(type(envelope) is dict and set(envelope) == {"payload", "signature"},
            "HIGH_WATER_AUTHORITY_INVALID")
    p = model.from_payload(envelope["payload"]).payload
    key = trust._keys.get(p["issuer_key_id"])
    require(key is not None and key.issuer_id == p["issuer_id"]
            and role in key.roles
            and all(p[k] == getattr(key, k)
                    for k in ("tenant_id", "registry_instance_reference")),
            "HIGH_WATER_AUTHORITY_INVALID")
    require(instant(p["valid_from"]) <= now < instant(p["valid_until"])
            and now < instant(key.expires_at),
            "HIGH_WATER_AUTHORITY_EXPIRED")
    try:
        key.public_key.verify(bytes.fromhex(envelope["signature"]), canonical(p))
    except Exception:
        raise EnrollmentDenied("HIGH_WATER_AUTHORITY_INVALID") from None
    return p, key


def _reviewed(proposal, reviews, grant, trust, now, grant_model):
    p, _ = _signed(
        trust, proposal, MutationHighWaterAuthorityProposalV1,
        "mutation_high_water_proposal", now)
    require(type(reviews) is list and len(reviews) == 2,
            "REVIEW_THRESHOLD_NOT_MET")
    parsed = [
        _signed(
            trust, item, MutationHighWaterReviewerDecisionV1,
            "mutation_high_water_review:" + item["payload"]["reviewer_id"],
            now)[0]
        for item in reviews
    ]
    require({x["reviewer_id"] for x in parsed} == set(REVIEWERS)
            and all(x["decision"] == "APPROVE" for x in parsed)
            and all(x["proposal_hash"] == digest(p) for x in parsed),
            "REVIEW_THRESHOLD_NOT_MET")
    g, _ = _signed(
        trust, grant, grant_model, "mutation_high_water_grant", now)
    by_id = {x["reviewer_id"]: x for x in parsed}
    require(g["proposal_hash"] == digest(p)
            and g["reviewer_a_decision_hash"]
            == digest(by_id["USBAY-AUDIT"])
            and g["reviewer_b_decision_hash"]
            == digest(by_id["USBAY-GLOBAL23"]),
            "REVIEW_THRESHOLD_NOT_MET")
    for field in BASE:
        require(g[field] == p[field], "AUTHORITY_SCOPE_BROADENING")
    return p, parsed, g


def verify_high_water_writer_grant(proposal, reviews, grant, *,
                                   trust, now, expected_scope_hash,
                                   expected_position_hash,
                                   expected_update_id_reference,
                                   expected_signer_identity_reference,
                                   expected_signer_key_id,
                                   expected_signer_key_fingerprint):
    try:
        _, _, g = _reviewed(
            proposal, reviews, grant, trust, now,
            MutationHighWaterWriterGrantV1)
        require(g["allowed_scope_hash"] == expected_scope_hash,
                "TENANT_MISMATCH")
        require(g["proposed_position_hash"] == expected_position_hash
                and g["update_id_reference"] == expected_update_id_reference,
                "HIGH_WATER_POSITION_MISMATCH")
        require(g["signer_identity_reference"]
                == expected_signer_identity_reference
                and g["signer_key_id"] == expected_signer_key_id
                and g["signer_key_fingerprint"]
                == expected_signer_key_fingerprint,
                "HIGH_WATER_SIGNER_MISMATCH")
        return decision(
            "HIGH_WATER_WRITER_AUTHORITY_VERIFIED",
            allowed=True,
            authority_domain=AUTHORITY_DOMAIN,
            grant_id=g["grant_id"],
            grant_hash=digest(g),
            max_updates=1,
            redelegation_allowed=False,
        )
    except Exception as error:
        return decision(
            str(error) if type(error) is EnrollmentDenied
            else "HIGH_WATER_AUTHORITY_INVALID")


def verify_recovery_epoch_grant(proposal, reviews, grant, *,
                                trust, now, expected_scope_hash,
                                current_epoch, current_source_version,
                                current_projection_hash,
                                expected_high_water_event_hash,
                                expected_recovery_state_hash):
    try:
        _, _, g = _reviewed(
            proposal, reviews, grant, trust, now,
            MutationRecoveryEpochGrantV1)
        require(g["allowed_scope_hash"] == expected_scope_hash,
                "TENANT_MISMATCH")
        require(g["previous_epoch"] == current_epoch
                and g["next_epoch"] == current_epoch + 1
                and g["previous_source_version"] == current_source_version
                and g["previous_projection_hash"] == current_projection_hash
                and g["previous_high_water_event_hash"]
                == expected_high_water_event_hash
                and g["proposed_recovery_state_hash"]
                == expected_recovery_state_hash,
                "RECOVERY_EPOCH_INVALID")
        return decision(
            "RECOVERY_EPOCH_AUTHORITY_VERIFIED",
            allowed=True,
            authority_domain=AUTHORITY_DOMAIN,
            grant_id=g["grant_id"],
            grant_hash=digest(g),
            next_epoch=g["next_epoch"],
            max_uses=1,
            redelegation_allowed=False,
        )
    except Exception as error:
        return decision(
            str(error) if type(error) is EnrollmentDenied
            else "HIGH_WATER_AUTHORITY_INVALID")
