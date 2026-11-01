"""Shared fail-closed replay configuration; no Gateway imports or storage effects."""
from __future__ import annotations

import json
import os
from pathlib import Path


class ReplayPolicyError(ValueError):
    """Invalid local replay configuration, with the existing bounded reason code."""


def load_replay_policy(path: Path | str | None = None) -> dict:
    """Normalize the existing Gateway contract without granting request authority."""
    path = Path(path) if path is not None else Path(os.getenv("USBAY_REPLAY_POLICY_PATH", "governance/replay_policy.json"))
    defaults = {
        "nonce_ttl_seconds": 300,
        "timestamp_skew_seconds": 30,
        "replay_fail_closed": True,
    }
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        raw = {}
    except Exception as exc:
        raise ReplayPolicyError("invalid_replay_policy:json") from exc
    if not isinstance(raw, dict):
        raise ReplayPolicyError("invalid_replay_policy:root")
    config = defaults | raw
    if "timestamp_skew_seconds" not in raw and "max_clock_skew_seconds" in raw:
        config["timestamp_skew_seconds"] = raw["max_clock_skew_seconds"]
    if "nonce_ttl_seconds" not in raw and "max_request_age_seconds" in raw:
        config["nonce_ttl_seconds"] = raw["max_request_age_seconds"]
    env_map = {
        "nonce_ttl_seconds": "USBAY_NONCE_TTL_SECONDS",
        "timestamp_skew_seconds": "USBAY_TIMESTAMP_SKEW_SECONDS",
    }
    for key, env_name in env_map.items():
        if os.getenv(env_name):
            config[key] = os.getenv(env_name)
    if os.getenv("USBAY_MAX_CLOCK_SKEW_SECONDS") and not os.getenv("USBAY_TIMESTAMP_SKEW_SECONDS"):
        config["timestamp_skew_seconds"] = os.getenv("USBAY_MAX_CLOCK_SKEW_SECONDS")
    if os.getenv("USBAY_REPLAY_FAIL_CLOSED"):
        config["replay_fail_closed"] = os.getenv("USBAY_REPLAY_FAIL_CLOSED", "").lower() == "true"
    normalized = {}
    for key in ("nonce_ttl_seconds", "timestamp_skew_seconds"):
        value = config.get(key)
        try:
            normalized[key] = int(value)
        except Exception:
            raise ReplayPolicyError(f"invalid_replay_policy:{key}")
        if normalized[key] <= 0:
            raise ReplayPolicyError(f"invalid_replay_policy:{key}")
    if config.get("replay_fail_closed") is not True:
        raise ReplayPolicyError("invalid_replay_policy:replay_fail_closed")
    normalized["replay_fail_closed"] = True
    return normalized

