from __future__ import annotations

import pytest

from governance.consensus_lineage import evaluate_consensus_lineage
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


def test_consensus_lineage_valid_when_links_exist():
    result = evaluate_consensus_lineage(record())

    assert result["consensus_lineage_status"] == "VALID"
    assert result["auto_remediation"] is False


def test_consensus_lineage_blocks_missing_lineage():
    result = evaluate_consensus_lineage(record(lineage_hash="", nodes=[node("PRIMARY_NODE", node_lineage=""), node("SECONDARY_NODE")]))

    assert "MISSING_LINEAGE" in result["reason_codes"]


def test_consensus_lineage_blocks_bypass():
    payload = record()
    payload["consensus_bypass"] = True

    result = evaluate_consensus_lineage(payload)

    assert "CONSENSUS_BYPASS_FORBIDDEN" in result["reason_codes"]
