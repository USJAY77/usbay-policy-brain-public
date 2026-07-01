from __future__ import annotations

import pytest

from governance.workspace_lifecycle import evaluate_workspace_lifecycle


pytestmark = pytest.mark.governance


def workspace(**overrides):
    payload = {
        "workspace_id": "ws-1",
        "workspace_state": "ACTIVE",
        "human_approval": True,
        "auto_onboarding": False,
        "auto_activation": False,
        "auto_archive": False,
    }
    payload.update(overrides)
    return payload


def test_valid_lifecycle_state():
    result = evaluate_workspace_lifecycle(workspace())

    assert result["workspace_lifecycle_status"] == "VALID"
    assert result["activation_enabled"] is False


def test_auto_onboarding_blocks():
    result = evaluate_workspace_lifecycle(workspace(auto_onboarding=True))

    assert "AUTO_ONBOARDING_FORBIDDEN" in result["reason_codes"]


def test_auto_activation_blocks():
    result = evaluate_workspace_lifecycle(workspace(auto_activation=True))

    assert "AUTO_ACTIVATION_FORBIDDEN" in result["reason_codes"]


def test_auto_archive_blocks():
    result = evaluate_workspace_lifecycle(workspace(auto_archive=True))

    assert "AUTO_ARCHIVE_FORBIDDEN" in result["reason_codes"]


def test_active_workspace_without_human_approval_blocks():
    result = evaluate_workspace_lifecycle(workspace(human_approval=False))

    assert "NO_HUMAN_APPROVAL" in result["reason_codes"]
