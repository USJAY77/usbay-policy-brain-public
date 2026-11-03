"""Dormant witness protocol verification; no client, signer or genesis path."""
from __future__ import annotations

from governance.tenant_enrollment_contracts import (
    CurrentHeadWitness, digest, require, scope,
)


def target_head(advance: dict) -> str:
    """Target excludes its own hash, signature and later publication receipts."""
    return digest({key: advance[key] for key in (
        "trust_domain", "policy_domain", "tenant_id", "environment", "purpose",
        "registry_instance_reference", "policy_id", "policy_version", "policy_hash",
        "previous_head_hash", "sequence", "generation", "epoch", "lineage_hash", "adoption_core_hash",
    )})


def verify_successor(previous: dict, advance: dict) -> None:
    """Exact parent CAS only. Never infer genesis or select a canonical fork."""
    require(type(previous) is dict and previous, "STOPPED_UNVERIFIED_POLICY_HEAD")
    require(scope(previous) == scope(advance), "WITNESS_SCOPE_INVALID")
    require(advance["previous_head_hash"] == previous["head_hash"]
            and advance["sequence"] == previous["sequence"] + 1
            and all(advance[k] == previous[k] for k in ("generation", "epoch", "lineage_hash")),
            "STOPPED_UNVERIFIED_POLICY_HEAD")
    require(advance["head_hash"] == target_head(advance), "HEAD_TARGET_INVALID")


def verify_witness_pair(h: dict, w: dict, *, policy: dict, adoption_hash: str,
                        expected: dict, challenge: str, request_digest: str) -> None:
    """Inputs must already have passed scoped signatures. Structural checks alone
    are NOT currentness or evidence of independent operational infrastructure.
    """
    CurrentHeadWitness.from_payload(h)
    CurrentHeadWitness.from_payload(w)
    require(h["role"] == "H" and w["role"] == "W", "WITNESS_ROLE_INVALID")
    require(h["issuer_id"] != w["issuer_id"] and h["issuer_key_id"] != w["issuer_key_id"], "WITNESS_SEPARATION_INVALID")
    for item in (h, w):
        require(scope(item) == scope(policy), "WITNESS_SCOPE_INVALID")
        require(item["challenge"] == challenge and item["request_digest"] == request_digest, "WITNESS_CHALLENGE_INVALID")
        require(item["policy_hash"] == digest(policy)
                and item["policy_id"] == policy["policy_id"]
                and item["policy_version"] == policy["policy_version"]
                and item["adoption_core_hash"] == adoption_hash, "WITNESS_POLICY_INVALID")
    # W's independently verified latest observation, not historical inclusion.
    keys = ("head_hash", "sequence", "generation", "epoch", "lineage_hash", "policy_hash",
            "policy_id", "policy_version", "adoption_core_hash", "adoption_record_hash",
            "head_advance_grant_hash", "previous_head_hash", "revocation_reference", "anchor_hash")
    require(all(h[k] == w[k] for k in keys), "STOPPED_UNVERIFIED_POLICY_HEAD")
    require(type(expected) is dict and expected and all(h[k] == expected[k] for k in keys),
            "STOPPED_UNVERIFIED_POLICY_HEAD")
