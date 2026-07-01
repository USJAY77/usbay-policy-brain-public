from __future__ import annotations

from runtime_trust.pilot_activation import approval_nonce_store_contract_json, validate_nonce


def test_nonce_store_contract_defaults_blocked() -> None:
    contract = approval_nonce_store_contract_json()
    assert contract["nonce_must_be_unique"] is True
    assert contract["default_action_state"] == "BLOCKED"


def test_missing_nonce_blocks_action() -> None:
    result = validate_nonce(None, expires_at="2030-01-01T00:00:00Z")
    assert result["decision"] == "BLOCKED"
    assert "MISSING_NONCE" in result["gaps"]


def test_reused_nonce_blocks_action() -> None:
    result = validate_nonce("nonce-1", expires_at="2030-01-01T00:00:00Z", used_nonces={"nonce-1"})
    assert result["decision"] == "BLOCKED"
    assert "NONCE_REUSED" in result["gaps"]


def test_expired_nonce_blocks_action() -> None:
    result = validate_nonce("nonce-2", expires_at="2026-01-01T00:00:00Z", now="2026-06-11T00:00:00Z")
    assert result["decision"] == "BLOCKED"
    assert "NONCE_EXPIRED" in result["gaps"]


def test_unique_fresh_nonce_verifies_without_activation() -> None:
    result = validate_nonce("nonce-3", expires_at="2030-01-01T00:00:00Z", now="2026-06-11T00:00:00Z")
    assert result["decision"] == "VERIFIED"
    assert result["action_state"] == "READY_FOR_REVIEW"
