from __future__ import annotations

import pytest

from governance.prompt_policy_binding import evaluate_prompt_policy_binding


pytestmark = pytest.mark.governance


def test_valid_prompt_policy_binding_passes():
    result = evaluate_prompt_policy_binding({"policy_binding": True, "policy_version": "policy-v1"})

    assert result["prompt_policy_binding_status"] == "VALID"
    assert result["reason_codes"] == []


def test_missing_prompt_policy_binding_blocks():
    result = evaluate_prompt_policy_binding({"policy_binding": False, "policy_version": ""})

    assert result["prompt_policy_binding_status"] == "BLOCKED"
    assert result["reason_codes"] == ["MISSING_POLICY_BINDING"]
