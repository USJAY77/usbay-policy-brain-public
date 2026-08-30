from __future__ import annotations

from datetime import datetime, timezone

import pytest

from governance.hydra_consensus_contracts import build_hydra_node
from governance.quorum_validation import evaluate_quorum


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


def test_quorum_ready_with_two_valid_nodes():
    result = evaluate_quorum(
        [node("PRIMARY_NODE"), node("SECONDARY_NODE")],
        policy_version="policy-v1",
        timestamp="2026-06-18T00:00:00Z",
        now=datetime(2026, 6, 18, tzinfo=timezone.utc),
    )

    assert result["quorum_status"] == "QUORUM_READY"
    assert result["quorum_override_enabled"] is False


def test_quorum_blocks_single_node():
    result = evaluate_quorum(
        [node("PRIMARY_NODE")],
        policy_version="policy-v1",
        timestamp="2026-06-18T00:00:00Z",
        now=datetime(2026, 6, 18, tzinfo=timezone.utc),
    )

    assert result["quorum_status"] == "BLOCKED"
    assert "QUORUM_NOT_REACHED" in result["reason_codes"]


def test_quorum_blocks_policy_mismatch_and_stale_timestamp():
    result = evaluate_quorum(
        [node("PRIMARY_NODE"), node("SECONDARY_NODE", policy_version="policy-v2")],
        policy_version="policy-v1",
        timestamp="2026-06-17T00:00:00Z",
        now=datetime(2026, 6, 18, tzinfo=timezone.utc),
    )

    assert "POLICY_MISMATCH" in result["reason_codes"]
    assert "STALE_TIMESTAMP" in result["reason_codes"]
