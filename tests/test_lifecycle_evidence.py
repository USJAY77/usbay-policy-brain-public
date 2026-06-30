from __future__ import annotations

import pytest

from governance.lifecycle_evidence import evaluate_lifecycle_evidence


pytestmark = pytest.mark.governance


def test_valid_lifecycle_evidence_passes():
    result = evaluate_lifecycle_evidence({"audit_hash": "a" * 64, "evidence_hash": "e" * 64})

    assert result["lifecycle_evidence_status"] == "VALID"
    assert result["reason_codes"] == []


def test_missing_lifecycle_evidence_blocks():
    result = evaluate_lifecycle_evidence({})

    assert result["lifecycle_evidence_status"] == "BLOCKED"
    assert result["reason_codes"] == ["MISSING_AUDIT_LINKAGE", "MISSING_EVIDENCE_LINKAGE"]
