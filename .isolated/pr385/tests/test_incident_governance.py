from __future__ import annotations

import pytest

from governance.incident_governance import evaluate_incident_governance


pytestmark = pytest.mark.governance


def test_valid_incident_governance_passes():
    assert evaluate_incident_governance({"incident_record": True, "incident_status": "AUTHORIZED"})["incident_status"] == "VALID"


def test_auto_remediation_blocks():
    result = evaluate_incident_governance({"incident_record": True, "incident_status": "AUTHORIZED", "auto_remediation": True})

    assert result["incident_status"] == "BLOCKED"
    assert result["reason_codes"] == ["AUTO_REMEDIATION_FORBIDDEN"]
