from __future__ import annotations

import pytest

from memory.governed_memory import GovernedMemory
from runtime.command_model import command_model
import runtime.policy_validator as policy_validator


def test_governed_memory_requires_device_id() -> None:
    with pytest.raises(TypeError):
        GovernedMemory()


def test_governance_fails_closed_on_invalid_input() -> None:
    with pytest.raises(RuntimeError, match="missing required fields"):
        command_model.validate_command_request_payload({})


def test_command_model_delegates_to_policy_validator(monkeypatch: pytest.MonkeyPatch) -> None:
    def mismatch_validator(_payload):
        raise RuntimeError("validator_mismatch")

    monkeypatch.setattr(policy_validator, "validate_command_request_payload", mismatch_validator)

    with pytest.raises(RuntimeError, match="validator_mismatch"):
        command_model.validate_command_request_payload(
            {"input": "test", "actor_id": "actor", "purpose": "validation"}
        )


def test_policy_validation_rejects_invalid_policy(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path
) -> None:
    invalid_policy = tmp_path / "policy.json"
    invalid_policy.write_text('{"policy_version": ', encoding="utf-8")

    monkeypatch.setattr(policy_validator, "POLICY_JSON", invalid_policy)

    with pytest.raises(ValueError, match="invalid JSON"):
        policy_validator.validate_policy_json()
