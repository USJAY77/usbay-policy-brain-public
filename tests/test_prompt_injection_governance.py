from __future__ import annotations

import pytest

from governance.prompt_injection_governance import evaluate_prompt_injection_governance


pytestmark = pytest.mark.governance


def test_clean_prompt_injection_status_passes():
    assert evaluate_prompt_injection_governance({"injection_status": "CLEAN"})["prompt_injection_status"] == "VALID"


def test_unknown_prompt_injection_status_blocks():
    result = evaluate_prompt_injection_governance({"injection_status": "RISK"})

    assert result["prompt_injection_status"] == "BLOCKED"
    assert result["reason_codes"] == ["PROMPT_INJECTION_RISK"]
