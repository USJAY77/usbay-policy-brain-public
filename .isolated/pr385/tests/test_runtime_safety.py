from runtime.computer_use.runtime_safety import redact_screen_metadata, validate_safe_payload


def test_redaction_never_persists_raw_screenshot() -> None:
    redacted = redact_screen_metadata({"observation_id": "obs", "screenshot_hash": "abc", "raw_screenshot": "bytes"})

    assert redacted == {"observation_id": "obs", "has_screenshot": True, "raw_screenshot_stored": False}


def test_secret_like_payload_blocks() -> None:
    valid, reason = validate_safe_payload({"text": "API_TOKEN=abc"})

    assert valid is False
    assert reason == "secret_like_payload"


def test_raw_screenshot_payload_blocks() -> None:
    valid, reason = validate_safe_payload({"raw_screenshot": "bytes"})

    assert valid is False
    assert reason == "raw_screenshot_forbidden"

