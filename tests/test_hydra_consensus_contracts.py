from __future__ import annotations

import pytest

from governance.hydra_consensus_contracts import (
    FAIL_CLOSED_REASON_CODES,
    build_hydra_consensus_record,
    build_hydra_node,
    validate_hydra_consensus_record,
    validate_hydra_node,
)


pytestmark = pytest.mark.governance


def node(node_id="PRIMARY_NODE", **overrides):
    payload = {
        "node_id": node_id,
        "node_identity": f"identity-{node_id}",
        "node_attestation": f"attestation-{node_id}",
        "node_lineage": f"lineage-{node_id}",
        "policy_version": "policy-v1",
        "audit_hash": "a" * 64,
        "evidence_hash": "e" * 64,
        "timestamp": "2026-06-18T00:00:00Z",
        "trusted": True,
    }
    payload.update(overrides)
    return build_hydra_node(**payload)


def consensus(**overrides):
    payload = {
        "consensus_id": "hydra-1",
        "nodes": [node("PRIMARY_NODE"), node("SECONDARY_NODE")],
        "policy_version": "policy-v1",
        "audit_hash": "a" * 64,
        "evidence_hash": "e" * 64,
        "lineage_hash": "l" * 64,
        "timestamp": "2026-06-18T00:00:00Z",
    }
    payload.update(overrides)
    return build_hydra_consensus_record(**payload)


def test_valid_hydra_consensus_contract():
    result = validate_hydra_consensus_record(consensus())

    assert result.valid is True
    assert result.status == "CONSENSUS_REACHED"


def test_single_node_consensus_blocks():
    result = validate_hydra_consensus_record(consensus(nodes=[node("PRIMARY_NODE")]))

    assert "QUORUM_NOT_REACHED" in result.reason_codes


def test_unknown_untrusted_and_missing_attestation_block():
    validation = validate_hydra_node(node("UNKNOWN_NODE", trusted=False, node_attestation=""))

    assert "UNKNOWN_NODE" in validation.reason_codes
    assert "UNTRUSTED_NODE" in validation.reason_codes
    assert "MISSING_ATTESTATION" in validation.reason_codes


def test_override_replay_and_bypass_block():
    record = consensus()
    record.update({"quorum_override": True, "consensus_replay": True, "consensus_bypass": True})

    result = validate_hydra_consensus_record(record)

    assert "CONSENSUS_OVERRIDE_FORBIDDEN" in result.reason_codes
    assert "CONSENSUS_REPLAY_DETECTED" in result.reason_codes
    assert "CONSENSUS_BYPASS_FORBIDDEN" in result.reason_codes


def test_fail_closed_reason_code_registry_contains_required_codes():
    assert "QUORUM_NOT_REACHED" in FAIL_CLOSED_REASON_CODES
    assert "CONSENSUS_BYPASS_FORBIDDEN" in FAIL_CLOSED_REASON_CODES
