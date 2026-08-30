from __future__ import annotations

import json
from pathlib import Path

from gateway.app import validate_metadata


POLICY_PATH = Path("governance/metadata_policy.json")


def load_policy() -> dict:
    return json.loads(POLICY_PATH.read_text(encoding="utf-8"))


def metadata_allowed(metadata_type: str, policy: dict) -> bool:
    if metadata_type in policy["forbidden_audit_fields"]:
        return False
    if metadata_type in policy["allowed_audit_fields"]:
        return True
    if policy.get("fail_closed_on_unknown_metadata") is True:
        return False
    return policy.get("default") == "ALLOW"


def test_policy_defaults_fail_closed() -> None:
    policy = load_policy()

    assert policy["default"] == "DENY"
    assert policy["metadata_minimization"] is True
    assert policy["allow_raw_sensitive_metadata"] is False
    assert policy["fail_closed_on_unknown_metadata"] is True


def test_raw_ip_is_denied() -> None:
    assert metadata_allowed("full_ip_address", load_policy()) is False


def test_raw_payment_id_is_denied() -> None:
    assert metadata_allowed("payment_identifier", load_policy()) is False


def test_raw_location_is_denied() -> None:
    assert metadata_allowed("precise_location", load_policy()) is False


def test_hashed_actor_id_is_allowed() -> None:
    assert metadata_allowed("actor_hash", load_policy()) is True


def test_request_hash_is_allowed() -> None:
    assert metadata_allowed("request_hash", load_policy()) is True


def test_unknown_metadata_type_fails_closed() -> None:
    assert metadata_allowed("unclassified_metadata_type", load_policy()) is False


def test_runtime_classifier_denies_forbidden_metadata() -> None:
    decision, reason = validate_metadata({"metadata": {"raw_ip": "203.0.113.20"}})

    assert decision == "DENY"
    assert reason == "metadata_forbidden:raw_ip"


def test_runtime_classifier_allows_only_safe_hash_metadata() -> None:
    decision, reason = validate_metadata(
        {
            "metadata": {
                "actor_hash": "hashed-actor",
                "request_hash": "hashed-request",
            }
        }
    )

    assert decision == "ALLOW"
    assert reason == "metadata_allowed"


def test_runtime_classifier_unknown_metadata_fails_closed() -> None:
    decision, reason = validate_metadata({"metadata": {"browser_hint": "unknown"}})

    assert decision == "DENY"
    assert reason == "metadata_unknown:browser_hint"
