from __future__ import annotations

import pytest

from governance.renewal_governance import evaluate_renewal_governance


pytestmark = pytest.mark.governance


def test_valid_renewal_governance_passes():
    assert evaluate_renewal_governance({"renewal_record": True, "renewal_status": "AUTHORIZED"})["renewal_status"] == "VALID"


def test_renewal_execution_blocks():
    result = evaluate_renewal_governance({"renewal_record": True, "renewal_status": "AUTHORIZED", "renewal_execution": True})

    assert result["renewal_status"] == "BLOCKED"
    assert result["reason_codes"] == ["RENEWAL_EXECUTION_FORBIDDEN"]
