from __future__ import annotations

import pytest

from governance.contract_governance import evaluate_contract_governance


pytestmark = pytest.mark.governance


def test_valid_contract_governance_passes():
    assert evaluate_contract_governance({"contract_record": True, "contract_status": "AUTHORIZED"})["contract_status"] == "VALID"


def test_contract_signing_blocks():
    result = evaluate_contract_governance({"contract_record": True, "contract_status": "AUTHORIZED", "contract_signing": True})

    assert result["contract_status"] == "BLOCKED"
    assert result["reason_codes"] == ["CONTRACT_SIGNING_FORBIDDEN"]
