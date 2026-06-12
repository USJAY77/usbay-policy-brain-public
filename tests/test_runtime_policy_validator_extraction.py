from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

import runtime.enforcement_gateway as enforcement_gateway
import runtime.policy_validator as policy_validator


def test_policy_validator_requires_all_core_artifacts(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setattr(policy_validator, "POLICY_JSON", tmp_path / "policy.json")
    monkeypatch.setattr(policy_validator, "POLICY_SHA256", tmp_path / "policy.sha256")
    monkeypatch.setattr(policy_validator, "POLICY_SIG", tmp_path / "policy.sig")
    monkeypatch.setattr(policy_validator, "PUBLIC_KEY", tmp_path / "public_key.pem")

    with pytest.raises(FileNotFoundError, match="missing required file"):
        policy_validator.validate_required_files()


def test_policy_validator_main_fails_closed_on_validation_error(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    def fail_required_files() -> None:
        raise FileNotFoundError("missing required file: policy/policy.json")

    monkeypatch.setattr(policy_validator, "validate_required_files", fail_required_files)

    assert policy_validator.main() == 1
    assert "POLICY_VALIDATION_FAILED: missing required file" in capsys.readouterr().out


def test_policy_sha256_accepts_filename_suffix(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    policy = tmp_path / "policy.json"
    expected = tmp_path / "policy.sha256"
    policy.write_text('{"policy_version":"runtime-extraction","rules":[]}\n', encoding="utf-8")
    expected.write_text(
        f"{hashlib.sha256(policy.read_bytes()).hexdigest()}  policy.json\n",
        encoding="utf-8",
    )

    monkeypatch.setattr(policy_validator, "POLICY_JSON", policy)
    monkeypatch.setattr(policy_validator, "POLICY_SHA256", expected)

    policy_validator.validate_sha256()


def test_policy_sha256_fails_closed_on_invalid_expected_hash(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    policy = tmp_path / "policy.json"
    expected = tmp_path / "policy.sha256"
    policy.write_text('{"policy_version":"runtime-extraction","rules":[]}\n', encoding="utf-8")
    expected.write_text("not-a-sha256\n", encoding="utf-8")

    monkeypatch.setattr(policy_validator, "POLICY_JSON", policy)
    monkeypatch.setattr(policy_validator, "POLICY_SHA256", expected)

    with pytest.raises(ValueError, match="invalid sha256 format"):
        policy_validator.validate_sha256()


def test_command_request_payload_requires_actor_purpose_and_input() -> None:
    with pytest.raises(RuntimeError, match="missing required fields"):
        policy_validator.validate_command_request_payload({"input": "run", "actor_id": "operator"})

    assert policy_validator.validate_command_request_payload(
        {"input": "run", "actor_id": "operator", "purpose": "runtime extraction validation"}
    )


def test_enforcement_gateway_blocks_policy_hash_mismatch(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(enforcement_gateway.EXPECTED_POLICY_HASH_ENV, "a" * 64)

    with pytest.raises(RuntimeError, match="POLICY_MISMATCH_RUNTIME_BLOCK"):
        enforcement_gateway._enforce_expected_policy_hash(loaded_policy_hash="b" * 64)


def test_enforcement_gateway_validate_signed_policy_delegates_to_policy_validator(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[str] = []

    monkeypatch.setattr(
        enforcement_gateway.policy_validator,
        "validate_required_files",
        lambda: calls.append("required_files"),
    )
    monkeypatch.setattr(
        enforcement_gateway.policy_validator,
        "validate_policy_json",
        lambda: calls.append("policy_json"),
    )
    monkeypatch.setattr(
        enforcement_gateway.policy_validator,
        "validate_sha256",
        lambda: calls.append("sha256"),
    )
    monkeypatch.setattr(
        enforcement_gateway.policy_validator,
        "validate_signature",
        lambda: calls.append("signature"),
    )
    monkeypatch.setattr(
        enforcement_gateway.policy_validator,
        "load_policy_metadata",
        lambda: {"policy_hash": "c" * 64, "policy_version": "test"},
    )
    monkeypatch.setattr(enforcement_gateway, "_policy_sha256_from_disk", lambda: "c" * 64)
    monkeypatch.setattr(
        enforcement_gateway.policy_validator,
        "validate_approval_artifacts",
        lambda *, policy_hash, policy_version: calls.append("approvals"),
    )

    metadata = enforcement_gateway.validate_signed_policy()

    assert metadata["loaded_policy_hash"] == "c" * 64
    assert calls == ["required_files", "policy_json", "sha256", "signature", "approvals"]
