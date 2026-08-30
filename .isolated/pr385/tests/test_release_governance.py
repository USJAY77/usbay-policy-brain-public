from __future__ import annotations

import pytest

from governance.release_governance import evaluate_release_governance


pytestmark = pytest.mark.governance


def test_valid_release_governance_passes():
    assert evaluate_release_governance({"release_approval": True, "release_status": "AUTHORIZED"})["release_status"] == "VALID"


def test_auto_release_blocks():
    result = evaluate_release_governance({"release_approval": True, "release_status": "AUTHORIZED", "auto_release": True})

    assert result["release_status"] == "BLOCKED"
    assert result["reason_codes"] == ["AUTO_RELEASE_FORBIDDEN"]
