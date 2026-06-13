from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from runtime.computer_use.audit_recorder import ComputerUseAuditRecorder
from runtime.computer_use.providers.provider_factory import get_provider
from runtime.computer_use.screen_capture import ScreenCapture
from runtime.computer_use.vision_adapter import VisionAdapter


def _audit(tmp_path: Path) -> ComputerUseAuditRecorder:
    return ComputerUseAuditRecorder(tmp_path / "provider_audit.jsonl")


def _observation(scenario: str = "low_risk_read_screen") -> dict[str, Any]:
    metadata = ScreenCapture().capture_metadata(width=800, height=600)
    return {
        "action_id": f"action-{scenario}",
        "scenario": scenario,
        "screen_metadata": metadata.to_dict(),
    }


def _assert_normalized_schema(result: dict[str, Any]) -> None:
    assert set(result) == {
        "provider",
        "status",
        "screen_summary",
        "proposed_action",
        "requires_human_approval",
        "reason",
        "audit",
    }
    assert result["status"] in {"ALLOW", "BLOCK", "FAIL_CLOSED"}
    assert set(result["proposed_action"]) == {"type", "target", "risk"}
    assert result["proposed_action"]["type"] in {"read_screen", "click", "type", "scroll", "wait", "unknown"}
    assert result["proposed_action"]["risk"] in {"LOW", "MEDIUM", "HIGH", "CRITICAL"}
    assert result["audit"]["raw_screenshot_stored"] is False
    assert result["audit"]["provider_call_recorded"] is True
    assert result["audit"]["policy_checked"] is True
    assert len(result["audit"]["hash"]) == 64


def test_default_provider_is_mock_and_low_risk_read_screen_allows(tmp_path: Path) -> None:
    provider = get_provider(audit_recorder=_audit(tmp_path))

    result = provider.analyze_screen(_observation("low_risk_read_screen"))

    _assert_normalized_schema(result)
    assert provider.provider_name == "mock"
    assert result["provider"] == "mock"
    assert result["status"] == "ALLOW"
    assert result["proposed_action"]["type"] == "read_screen"
    assert result["requires_human_approval"] is False


def test_unknown_provider_fails_closed(tmp_path: Path) -> None:
    provider = get_provider("gemini", audit_recorder=_audit(tmp_path))

    result = provider.analyze_screen(_observation("low_risk_read_screen"))

    _assert_normalized_schema(result)
    assert result["status"] == "FAIL_CLOSED"
    assert result["reason"] == "PROVIDER_UNKNOWN"
    assert provider.health_check()["status"] == "FAIL_CLOSED"


def test_missing_provider_name_fails_closed(tmp_path: Path) -> None:
    provider = get_provider("", audit_recorder=_audit(tmp_path))

    result = provider.analyze_screen(_observation("low_risk_read_screen"))

    _assert_normalized_schema(result)
    assert result["status"] == "FAIL_CLOSED"
    assert result["reason"] == "PROVIDER_UNKNOWN"
    assert provider.health_check()["requested_provider"] == "missing"


def test_provider_exception_fails_closed(tmp_path: Path) -> None:
    provider = get_provider("mock", audit_recorder=_audit(tmp_path))

    result = provider.analyze_screen(_observation("provider_exception"))

    _assert_normalized_schema(result)
    assert result["status"] == "FAIL_CLOSED"
    assert result["reason"] == "PROVIDER_EXCEPTION"


def test_provider_timeout_fails_closed(tmp_path: Path) -> None:
    provider = get_provider("mock", audit_recorder=_audit(tmp_path), timeout_seconds=0.001)

    result = provider.analyze_screen(_observation("provider_timeout"))

    _assert_normalized_schema(result)
    assert result["status"] == "FAIL_CLOSED"
    assert result["reason"] == "PROVIDER_TIMEOUT"


def test_malformed_response_fails_closed(tmp_path: Path) -> None:
    provider = get_provider("mock", audit_recorder=_audit(tmp_path))

    result = provider.analyze_screen(_observation("malformed_response"))

    _assert_normalized_schema(result)
    assert result["status"] == "FAIL_CLOSED"
    assert result["reason"] == "PROVIDER_RESPONSE_MALFORMED"


def test_provider_proposes_unknown_action_blocks(tmp_path: Path) -> None:
    provider = get_provider("mock", audit_recorder=_audit(tmp_path))

    result = provider.analyze_screen(_observation("unknown_action"))

    _assert_normalized_schema(result)
    assert result["status"] == "BLOCK"
    assert result["proposed_action"]["type"] == "unknown"
    assert result["reason"] == "UNKNOWN_ACTION_BLOCKED"


def test_high_risk_click_requires_approval_boundary(tmp_path: Path) -> None:
    provider = get_provider("mock", audit_recorder=_audit(tmp_path))

    result = provider.analyze_screen(_observation("high_risk_click"))

    _assert_normalized_schema(result)
    assert result["status"] == "BLOCK"
    assert result["proposed_action"]["risk"] == "HIGH"
    assert result["requires_human_approval"] is True
    assert result["reason"] == "HUMAN_APPROVAL_REQUIRED"


def test_high_risk_without_approval_marker_fails_closed(tmp_path: Path) -> None:
    provider = get_provider("mock", audit_recorder=_audit(tmp_path))

    result = provider.analyze_screen(_observation("high_risk_click_missing_approval_marker"))

    _assert_normalized_schema(result)
    assert result["status"] == "FAIL_CLOSED"
    assert result["reason"] == "HIGH_RISK_ACTION_APPROVAL_MARKER_MISSING"


def test_secret_like_text_blocks(tmp_path: Path) -> None:
    provider = get_provider("mock", audit_recorder=_audit(tmp_path))

    result = provider.analyze_screen(_observation("secret_like_text"))

    _assert_normalized_schema(result)
    assert result["status"] == "BLOCK"
    assert result["proposed_action"]["type"] == "type"
    assert result["reason"] == "SECRET_LIKE_TEXT_BLOCKED"


def test_missing_policy_fails_closed(tmp_path: Path) -> None:
    provider = get_provider("mock", audit_recorder=_audit(tmp_path))

    result = provider.analyze_screen(_observation("missing_policy"))

    _assert_normalized_schema(result)
    assert result["status"] == "FAIL_CLOSED"
    assert result["reason"] == "COMPUTER_USE_POLICY_MISSING"


def test_observation_missing_required_fields_fails_closed(tmp_path: Path) -> None:
    provider = get_provider("mock", audit_recorder=_audit(tmp_path))

    result = provider.analyze_screen({"action_id": "missing-fields"})

    _assert_normalized_schema(result)
    assert result["status"] == "FAIL_CLOSED"
    assert result["reason"] == "OBSERVATION_REQUIRED_FIELDS_MISSING"


def test_audit_metadata_is_safe_and_does_not_store_raw_screen(tmp_path: Path) -> None:
    provider = get_provider("mock", audit_recorder=_audit(tmp_path))
    observation = _observation("low_risk_read_screen")
    observation["screen_text"] = "api_key=sk-should-not-be-written"

    result = provider.analyze_screen(observation)

    audit_lines = (tmp_path / "provider_audit.jsonl").read_text(encoding="utf-8").splitlines()
    event = json.loads(audit_lines[-1])
    assert result["status"] == "ALLOW"
    assert event["raw_screenshot_stored"] is False
    assert "api_key" not in json.dumps(event)
    assert "sk-should-not-be-written" not in json.dumps(event)
    assert event["observation_hash"]


def test_vision_adapter_uses_mock_provider_without_live_call_or_raw_persistence(tmp_path: Path) -> None:
    adapter = VisionAdapter.for_provider("mock", audit_recorder=_audit(tmp_path))

    observation = adapter.observe(ScreenCapture().capture_metadata(width=100, height=50))

    assert observation.provider == "mock"
    assert observation.summary == "metadata-only low risk screen observation"
    assert observation.raw_model_call_performed is False
    assert not list(tmp_path.glob("*.png"))
