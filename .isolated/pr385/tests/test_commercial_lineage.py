from __future__ import annotations

import pytest

from governance.commercial_lineage import evaluate_commercial_lineage


pytestmark = pytest.mark.governance


def test_valid_commercial_lineage_passes():
    result = evaluate_commercial_lineage(
        {
            "policy_binding": True,
            "policy_version": "policy-v1",
            "audit_hash": "a" * 64,
            "evidence_hash": "e" * 64,
            "lineage_hash": "l" * 64,
        }
    )

    assert result["commercial_lineage_status"] == "VALID"
    assert result["reason_codes"] == []


def test_missing_commercial_lineage_blocks():
    result = evaluate_commercial_lineage({})

    assert result["commercial_lineage_status"] == "BLOCKED"
    assert result["reason_codes"] == [
        "MISSING_AUDIT_LINKAGE",
        "MISSING_EVIDENCE_LINKAGE",
        "MISSING_LINEAGE",
        "MISSING_POLICY_BINDING",
    ]
