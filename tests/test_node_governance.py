from __future__ import annotations

import pytest

from governance.node_governance import evaluate_node_governance


pytestmark = pytest.mark.governance


def node(**overrides):
    payload = {
        "node_identity": "node-1",
        "node_trust": "TRUSTED",
        "node_attestation": "attestation-hash",
        "node_lineage": "lineage-1",
        "node_policy_hash": "p" * 64,
        "node_audit_hash": "a" * 64,
    }
    payload.update(overrides)
    return payload


def test_valid_node_governance():
    result = evaluate_node_governance(node())

    assert result["node_governance_status"] == "READY"
    assert result["shell_control_enabled"] is False


def test_unknown_node_blocks():
    result = evaluate_node_governance(node(node_identity=""))

    assert result["node_governance_status"] == "BLOCKED"
    assert "NODE_UNKNOWN" in result["reason_codes"]


def test_untrusted_node_blocks():
    result = evaluate_node_governance(node(node_trust="UNTRUSTED"))

    assert "NODE_UNTRUSTED" in result["reason_codes"]


def test_missing_attestation_blocks():
    result = evaluate_node_governance(node(node_attestation=""))

    assert "NODE_ATTESTATION_MISSING" in result["reason_codes"]


def test_missing_lineage_blocks():
    result = evaluate_node_governance(node(node_lineage="", lineage_hash=""))

    assert "NODE_LINEAGE_MISSING" in result["reason_codes"]
