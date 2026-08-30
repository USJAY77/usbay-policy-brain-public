from __future__ import annotations

import pytest

from governance.runtime_governance import evaluate_runtime_governance


pytestmark = pytest.mark.governance


def test_valid_runtime_governance_passes():
    assert evaluate_runtime_governance({"runtime_approval": True, "runtime_status": "AUTHORIZED"})["runtime_status"] == "VALID"


def test_runtime_modification_blocks():
    result = evaluate_runtime_governance({"runtime_approval": True, "runtime_status": "AUTHORIZED", "runtime_modification": True})

    assert result["runtime_status"] == "BLOCKED"
    assert result["reason_codes"] == ["LIFECYCLE_GOVERNANCE_BYPASS"]
