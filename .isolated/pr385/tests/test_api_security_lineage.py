from __future__ import annotations

import pytest

from governance.api_security_lineage import evaluate_api_security_lineage


pytestmark = pytest.mark.governance


def test_api_security_lineage_valid_with_links():
    result = evaluate_api_security_lineage({"audit_hash": "a", "evidence_hash": "e", "lineage_hash": "l"})

    assert result["api_security_lineage_status"] == "VALID"
    assert result["auto_remediation"] is False


def test_api_security_lineage_blocks_missing_links_and_bypass():
    result = evaluate_api_security_lineage({"audit_hash": "", "evidence_hash": "", "lineage_hash": "", "governance_bypass": True})

    assert "MISSING_AUDIT_LINKAGE" in result["reason_codes"]
    assert "MISSING_EVIDENCE_LINKAGE" in result["reason_codes"]
    assert "MISSING_API_INVENTORY" in result["reason_codes"]
    assert "GOVERNANCE_BYPASS_ATTEMPT" in result["reason_codes"]
