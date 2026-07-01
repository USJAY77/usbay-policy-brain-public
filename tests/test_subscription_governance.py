from __future__ import annotations

import pytest

from governance.subscription_governance import evaluate_subscription_governance


pytestmark = pytest.mark.governance


def test_valid_subscription_governance_passes():
    assert evaluate_subscription_governance({"subscription_record": True, "subscription_status": "AUTHORIZED"})["subscription_status"] == "VALID"


def test_subscription_activation_blocks():
    result = evaluate_subscription_governance(
        {"subscription_record": True, "subscription_status": "AUTHORIZED", "subscription_activation": True}
    )

    assert result["subscription_status"] == "BLOCKED"
    assert result["reason_codes"] == ["SUBSCRIPTION_ACTIVATION_FORBIDDEN"]
