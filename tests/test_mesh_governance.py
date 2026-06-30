from __future__ import annotations

import pytest

from governance.mesh_governance import evaluate_mesh_governance


pytestmark = pytest.mark.governance


def mesh(**overrides):
    payload = {
        "mesh_node_identity": "node-1",
        "mesh_quorum": "MET",
        "mesh_lineage": "lineage-1",
        "mesh_audit_continuity": "CONTINUOUS",
    }
    payload.update(overrides)
    return payload


def test_valid_mesh_governance():
    result = evaluate_mesh_governance(mesh())

    assert result["mesh_status"] == "READY"
    assert result["cluster_write_enabled"] is False


def test_unknown_node_blocks():
    result = evaluate_mesh_governance(mesh(mesh_node_identity=""))

    assert "MESH_NODE_UNKNOWN" in result["reason_codes"]


def test_missing_quorum_blocks():
    result = evaluate_mesh_governance(mesh(mesh_quorum="MISSING"))

    assert "MESH_QUORUM_MISSING" in result["reason_codes"]


def test_broken_mesh_lineage_blocks():
    result = evaluate_mesh_governance(mesh(mesh_lineage="", lineage_hash=""))

    assert "MESH_LINEAGE_BREAK" in result["reason_codes"]


def test_missing_audit_continuity_blocks():
    result = evaluate_mesh_governance(mesh(mesh_audit_continuity="BROKEN"))

    assert "MESH_AUDIT_CONTINUITY_MISSING" in result["reason_codes"]
