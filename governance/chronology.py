from __future__ import annotations

from typing import Any

from governance.interfaces import ChronologyConsensus, ChronologyConsensusRecord, GovernanceValidationResult

CHRONOLOGY_CONSENSUS_SCHEMA = "usbay.governance_chronology_consensus.v1"


def validate_chronology_consensus_interface(payload: dict[str, Any]) -> GovernanceValidationResult:
    """Validate chronology consensus shape at the chronology boundary.

    Governance scope: consensus record structure, quorum fields, and authority
    result presence. Continuity and timestamp proof validation remain in the
    chronology verification engine.
    Fail-closed expectation: malformed records are deny conditions.
    Sensitive-data handling: chronology records contain public hashes only.
    """

    failures: list[str] = []
    if not isinstance(payload, dict):
        return GovernanceValidationResult(False, ("GOVERNANCE_CHRONOLOGY_CONSENSUS_INVALID",))
    if payload.get("schema") != CHRONOLOGY_CONSENSUS_SCHEMA:
        failures.append("GOVERNANCE_CHRONOLOGY_CONSENSUS_SCHEMA_INVALID")
    authority_ids = payload.get("authority_ids")
    if not isinstance(authority_ids, list) or not authority_ids:
        failures.append("GOVERNANCE_CHRONOLOGY_AUTHORITY_SET_INVALID")
    if not isinstance(payload.get("quorum_required"), int):
        failures.append("GOVERNANCE_CHRONOLOGY_QUORUM_INVALID")
    if not isinstance(payload.get("max_authority_skew_seconds"), int):
        failures.append("GOVERNANCE_CHRONOLOGY_SKEW_POLICY_INVALID")
    targets = payload.get("targets")
    if not isinstance(targets, list) or not targets:
        failures.append("GOVERNANCE_CHRONOLOGY_CONSENSUS_EMPTY")
        targets = []
    for index, target_record in enumerate(targets):
        if not isinstance(target_record, dict):
            failures.append(f"GOVERNANCE_CHRONOLOGY_TARGET_INVALID:{index}")
            continue
        if not isinstance(target_record.get("target"), dict):
            failures.append(f"GOVERNANCE_CHRONOLOGY_CONSENSUS_TARGET_INVALID:{index}")
        if target_record.get("consensus_result") not in {"ALLOW", "DENY"}:
            failures.append(f"GOVERNANCE_CHRONOLOGY_CONSENSUS_RESULT_INVALID:{index}")
        if not target_record.get("consensus_hash"):
            failures.append(f"GOVERNANCE_CHRONOLOGY_CONSENSUS_HASH_MISSING:{index}")
        if not isinstance(target_record.get("authority_results"), list):
            failures.append(f"GOVERNANCE_CHRONOLOGY_AUTHORITY_RESULTS_MISSING:{index}")
    if not payload.get("chain_head"):
        failures.append("GOVERNANCE_CHRONOLOGY_CHAIN_HEAD_MISSING")
    return GovernanceValidationResult(not failures, tuple(sorted(set(failures))))


def chronology_consensus_from_payload(payload: dict[str, Any]) -> ChronologyConsensus:
    result = validate_chronology_consensus_interface(payload)
    if not result.valid:
        raise ValueError(",".join(result.failures))
    records = tuple(
        ChronologyConsensusRecord(
            target=dict(record["target"]),
            consensus_result=str(record["consensus_result"]),
            consensus_hash=str(record["consensus_hash"]),
            authority_results=tuple(record["authority_results"]),
        )
        for record in payload["targets"]
    )
    return ChronologyConsensus(
        schema=str(payload["schema"]),
        authority_ids=tuple(str(authority) for authority in payload["authority_ids"]),
        quorum_required=int(payload["quorum_required"]),
        max_authority_skew_seconds=int(payload["max_authority_skew_seconds"]),
        chain_head=str(payload["chain_head"]),
        targets=records,
    )

