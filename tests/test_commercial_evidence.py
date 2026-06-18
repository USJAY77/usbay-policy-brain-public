from __future__ import annotations

import pytest

from governance.commercial_evidence import evaluate_commercial_evidence


pytestmark = pytest.mark.governance


def test_valid_commercial_evidence_passes():
    result = evaluate_commercial_evidence({"audit_hash": "a" * 64, "evidence_hash": "e" * 64})

    assert result["commercial_evidence_status"] == "VALID"
    assert result["reason_codes"] == []


def test_missing_commercial_evidence_blocks():
    result = evaluate_commercial_evidence({})

    assert result["commercial_evidence_status"] == "BLOCKED"
    assert result["reason_codes"] == ["MISSING_AUDIT_LINKAGE", "MISSING_EVIDENCE_LINKAGE"]
