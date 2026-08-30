from __future__ import annotations

import pytest

from governance.computer_use_lineage import evaluate_computer_use_lineage


pytestmark = pytest.mark.governance


def test_computer_use_lineage_valid_with_links_and_policy():
    result = evaluate_computer_use_lineage({"audit_hash": "a", "evidence_hash": "e", "lineage_hash": "l", "policy_binding": True})

    assert result["computer_use_lineage_status"] == "VALID"


def test_computer_use_lineage_blocks_missing_links_policy_and_bypass():
    result = evaluate_computer_use_lineage(
        {"audit_hash": "", "evidence_hash": "", "lineage_hash": "", "policy_binding": False, "governance_bypass": True}
    )

    assert "MISSING_AUDIT_LINKAGE" in result["reason_codes"]
    assert "MISSING_EVIDENCE_LINKAGE" in result["reason_codes"]
    assert "MISSING_LINEAGE" in result["reason_codes"]
    assert "MISSING_POLICY_BINDING" in result["reason_codes"]
    assert "COMPUTER_USE_GOVERNANCE_BYPASS" in result["reason_codes"]
