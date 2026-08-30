from __future__ import annotations

import pytest

from governance.consensus_evidence import evaluate_consensus_evidence
from governance.hydra_consensus_contracts import build_hydra_consensus_record, build_hydra_node


pytestmark = pytest.mark.governance


def node(node_id, **overrides):
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


def record(**overrides):
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


def test_consensus_evidence_valid_when_hashes_match():
    result = evaluate_consensus_evidence(record())

    assert result["consensus_evidence_status"] == "VALID"
    assert result["connector_write_enabled"] is False


def test_consensus_evidence_blocks_missing_evidence_and_audit_mismatch():
    result = evaluate_consensus_evidence(record(evidence_hash="", audit_hash=""))

    assert "EVIDENCE_MISMATCH" in result["reason_codes"]
    assert "AUDIT_MISMATCH" in result["reason_codes"]


def test_consensus_evidence_blocks_node_evidence_mismatch_and_replay():
    bad = record(nodes=[node("PRIMARY_NODE", evidence_hash="x"), node("SECONDARY_NODE")])
    bad["consensus_replay"] = True

    result = evaluate_consensus_evidence(bad)

    assert "EVIDENCE_MISMATCH" in result["reason_codes"]
    assert "CONSENSUS_REPLAY_DETECTED" in result["reason_codes"]
