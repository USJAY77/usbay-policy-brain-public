from __future__ import annotations

import pytest

from governance.airgap_governance import evaluate_airgap_governance


pytestmark = pytest.mark.governance


def airgap(**overrides):
    payload = {
        "offline_mode": True,
        "mesh_mode": "OFFLINE_MESH",
        "synchronization_lineage": "sync-lineage",
        "lineage_hash": "l" * 64,
        "evidence_continuity": "CONTINUOUS",
    }
    payload.update(overrides)
    return payload


def test_valid_airgap_governance():
    result = evaluate_airgap_governance(airgap())

    assert result["airgap_status"] == "READY"
    assert result["deployment_enabled"] is False


def test_unknown_synchronization_blocks():
    result = evaluate_airgap_governance(airgap(synchronization_lineage=""))

    assert "AIRGAP_SYNCHRONIZATION_UNKNOWN" in result["reason_codes"]


def test_broken_lineage_blocks():
    result = evaluate_airgap_governance(airgap(lineage_hash=""))

    assert "AIRGAP_LINEAGE_BROKEN" in result["reason_codes"]


def test_missing_evidence_blocks():
    result = evaluate_airgap_governance(airgap(evidence_continuity="BROKEN"))

    assert "AIRGAP_EVIDENCE_CONTINUITY_MISSING" in result["reason_codes"]


def test_offline_mode_required():
    result = evaluate_airgap_governance(airgap(offline_mode=False))

    assert "AIRGAP_OFFLINE_MODE_NOT_CONFIRMED" in result["reason_codes"]
