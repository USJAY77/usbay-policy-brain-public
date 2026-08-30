from runtime.computer_use.providers.provider_factory import get_provider


def test_mock_provider_success_audited() -> None:
    provider = get_provider("mock", scenario="low_risk_read_screen")
    result = provider.analyze_screen({"observation_id": "obs-1", "screenshot_hash": "hash"})

    assert result.status == "ALLOW"
    assert result.audit["raw_screenshot_stored"] is False
    assert result.safe_audit_hash()


def test_unknown_provider_fail_closed() -> None:
    provider = get_provider("unknown")
    result = provider.analyze_screen({"observation_id": "obs-1"})

    assert result.status == "FAIL_CLOSED"


def test_provider_missing_observation_fail_closed() -> None:
    provider = get_provider("mock")
    result = provider.analyze_screen({})

    assert result.status == "FAIL_CLOSED"


def test_high_risk_provider_requires_human_review() -> None:
    provider = get_provider("mock", scenario="high_risk_click")
    result = provider.analyze_screen({"observation_id": "obs-1"})

    assert result.status == "HUMAN_REVIEW"
    assert result.requires_human_approval is True

