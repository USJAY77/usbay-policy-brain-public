from __future__ import annotations

import pytest

from governance.desktop_governance import evaluate_desktop_governance


pytestmark = pytest.mark.governance


def test_desktop_governance_valid_when_passive():
    result = evaluate_desktop_governance({"application_control": False, "file_modification": False, "shell_control": False})

    assert result["desktop_status"] == "VALID"
    assert result["application_launch_enabled"] is False


def test_desktop_governance_blocks_application_file_and_shell_control():
    result = evaluate_desktop_governance({"application_control": True, "file_modification": True, "shell_control": True})

    assert "APPLICATION_CONTROL_FORBIDDEN" in result["reason_codes"]
    assert "FILE_MODIFICATION_FORBIDDEN" in result["reason_codes"]
    assert "SHELL_CONTROL_FORBIDDEN" in result["reason_codes"]
