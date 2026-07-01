"""Deterministic Suricata policy manifest helpers."""

from __future__ import annotations

from typing import Any

from publication.models import hash_payload


def suricata_policy_manifest_payload(
    *,
    policy_id: str,
    policy_version: str,
    signature_hash: str,
    rule_count: int,
) -> dict[str, Any]:
    return {
        "policy_id": policy_id,
        "policy_version": policy_version,
        "signature_hash": signature_hash,
        "rule_count": rule_count,
    }


def suricata_policy_evidence_hash(
    *,
    policy_id: str,
    policy_version: str,
    signature_hash: str,
    rule_count: int,
) -> str:
    return hash_payload(
        suricata_policy_manifest_payload(
            policy_id=policy_id,
            policy_version=policy_version,
            signature_hash=signature_hash,
            rule_count=rule_count,
        )
    )


def suricata_registry_hash(records: tuple[dict[str, Any], ...]) -> str:
    return hash_payload({"suricata_policy_registry": records})
