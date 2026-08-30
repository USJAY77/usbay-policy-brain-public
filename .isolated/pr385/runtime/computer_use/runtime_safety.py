from __future__ import annotations

SECRET_MARKERS = ("password", "secret", "token", "api_key", "private_key")


def redact_screen_metadata(observation: dict) -> dict:
    return {
        "observation_id": observation.get("observation_id"),
        "has_screenshot": bool(observation.get("screenshot_hash")),
        "raw_screenshot_stored": False,
    }


def validate_safe_payload(payload: dict) -> tuple[bool, str]:
    text = str(payload.get("text", "")).lower()
    if any(marker in text for marker in SECRET_MARKERS):
        return False, "secret_like_payload"
    if payload.get("raw_screenshot"):
        return False, "raw_screenshot_forbidden"
    return True, "safe"

