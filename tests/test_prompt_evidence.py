from __future__ import annotations

import pytest

from governance.prompt_evidence import evaluate_prompt_evidence


pytestmark = pytest.mark.governance


def test_valid_prompt_evidence_passes():
    result = evaluate_prompt_evidence({"audit_hash": "a" * 64, "evidence_hash": "e" * 64})

    assert result["prompt_evidence_status"] == "VALID"
    assert result["reason_codes"] == []


def test_missing_prompt_evidence_blocks():
    result = evaluate_prompt_evidence({})

    assert result["prompt_evidence_status"] == "BLOCKED"
    assert result["reason_codes"] == ["MISSING_AUDIT_LINKAGE", "MISSING_EVIDENCE_LINKAGE"]
