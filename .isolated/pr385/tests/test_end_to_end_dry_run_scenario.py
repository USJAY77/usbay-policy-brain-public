from pilot_operations.end_to_end_dry_run import build_end_to_end_dry_run_scenario


def test_end_to_end_dry_run_uses_full_existing_stack_without_execution():
    scenario = build_end_to_end_dry_run_scenario()

    assert scenario["decision"] == "VERIFIED"
    assert scenario["status"] == "READY_FOR_REVIEW"
    assert scenario["workflow"] == [
        "LinkedIn",
        "Notion",
        "Euria",
        "USBAY Control Plane",
        "GitHub",
        "Codex",
        "Mac",
        "Terminal",
    ]
    assert scenario["default_state"] == "READ_ONLY"
    assert scenario["runtime_mode"] == "DRY_RUN"
    assert scenario["production_activation_allowed"] is False
    assert scenario["connector_activation_allowed"] is False
    assert scenario["browser_automation_allowed"] is False
    assert scenario["desktop_execution_allowed"] is False
    assert scenario["terminal_write_commands_allowed"] is False
    assert scenario["external_api_calls_allowed"] is False


def test_every_dry_run_step_has_hash_only_audit_evidence():
    scenario = build_end_to_end_dry_run_scenario()

    assert len(scenario["steps"]) == 8
    for step in scenario["steps"]:
        assert step["decision"] == "VERIFIED"
        assert step["state"] in {"READ_ONLY", "DRY_RUN"}
        assert step["audit_evidence_hash"]
        assert step["execution_allowed"] is False
