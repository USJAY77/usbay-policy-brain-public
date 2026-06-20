from __future__ import annotations

import hashlib
import json
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


def _ready_canonical_gate() -> dict:
    return {
        "execution_gate_status": "READY",
        "runtime_validation_status": "VALID",
        "production_readiness_status": "READY",
        "reason_codes": [],
        "read_only": True,
        "execution_enabled": False,
        "deployment_enabled": False,
        "runtime_modification_enabled": False,
        "policy_mutation_enabled": False,
        "connector_write_enabled": False,
    }


def test_enforcement_gateway_requires_canonical_execution_gate(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        enforcement_gateway,
        "_canonical_execution_gate_for_runtime",
        lambda: {
            **_ready_canonical_gate(),
            "execution_gate_status": "BLOCKED",
            "reason_codes": ["duplicate_ownership"],
        },
    )

    with pytest.raises(RuntimeError, match="duplicate_ownership"):
        enforcement_gateway._require_canonical_execution_gate()


def test_execute_automation_requires_canonical_gate_proof() -> None:
    request = {"automation_id": "automation-1", "action": "prepare"}

    with pytest.raises(RuntimeError, match="CANONICAL_EXECUTION_GATE_BLOCKED"):
        enforcement_gateway._execute_automation(
            request,
            canonical_gate_proof={
                **_ready_canonical_gate(),
                "execution_gate_status": "BLOCKED",
                "reason_codes": ["CANONICAL_EXECUTION_GATE_BLOCKED"],
            },
        )


def test_execute_automation_allows_only_with_ready_canonical_gate_proof() -> None:
    result, payload = enforcement_gateway._execute_automation(
        {"automation_id": "automation-1", "action": "prepare"},
        canonical_gate_proof=_ready_canonical_gate(),
    )

    assert result == "allow"
    assert '"status": "prepared"' in payload


def test_corrupted_evidence_snapshot_hash_fails_closed(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    ruleset = tmp_path / "rulesets.json"
    ruleset_hash = tmp_path / "rulesets.sha256"
    ruleset_meta = tmp_path / "rulesets.meta.json"
    ruleset.write_text(json.dumps([{"rule": "allow-readonly"}], sort_keys=True), encoding="utf-8")
    ruleset_hash.write_text("0" * 64 + "  rulesets.json\n", encoding="utf-8")
    ruleset_meta.write_text(
        json.dumps(
            {
                "source": "test",
                "fetched_at": "2026-06-20T00:00:00Z",
                "commit_sha": "a" * 40,
                "sha256": hashlib.sha256(ruleset.read_bytes()).hexdigest(),
            },
            sort_keys=True,
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr(policy_validator, "EVIDENCE_RULESET_JSON", ruleset)
    monkeypatch.setattr(policy_validator, "EVIDENCE_RULESET_SHA256", ruleset_hash)
    monkeypatch.setattr(policy_validator, "EVIDENCE_RULESET_META", ruleset_meta)

    with pytest.raises(RuntimeError, match="EVIDENCE_SNAPSHOT_HASH_MISMATCH"):
        policy_validator.validate_evidence_snapshot()


def test_corrupted_evidence_snapshot_meta_fails_closed(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    ruleset = tmp_path / "rulesets.json"
    ruleset_hash = tmp_path / "rulesets.sha256"
    ruleset_meta = tmp_path / "rulesets.meta.json"
    ruleset.write_text(json.dumps([{"rule": "allow-readonly"}], sort_keys=True), encoding="utf-8")
    digest = hashlib.sha256(ruleset.read_bytes()).hexdigest()
    ruleset_hash.write_text(digest + "  rulesets.json\n", encoding="utf-8")
    ruleset_meta.write_text(
        json.dumps(
            {
                "source": "test",
                "fetched_at": "2026-06-20T00:00:00Z",
                "commit_sha": "b" * 40,
                "sha256": "1" * 64,
            },
            sort_keys=True,
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr(policy_validator, "EVIDENCE_RULESET_JSON", ruleset)
    monkeypatch.setattr(policy_validator, "EVIDENCE_RULESET_SHA256", ruleset_hash)
    monkeypatch.setattr(policy_validator, "EVIDENCE_RULESET_META", ruleset_meta)

    with pytest.raises(RuntimeError, match="EVIDENCE_SNAPSHOT_META_INVALID"):
        policy_validator.validate_evidence_snapshot()


def _install_runtime_cli_gate_fixture(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(enforcement_gateway, "check_private_key_not_present", lambda: None)
    monkeypatch.setattr(enforcement_gateway, "check_audit_log_writability", lambda: None)
    monkeypatch.setattr(
        enforcement_gateway,
        "validate_signed_policy",
        lambda: {"policy_version": "policy-v1", "loaded_policy_hash": "a" * 64},
    )
    monkeypatch.setattr(enforcement_gateway, "generate_runtime_attestation", lambda *, loaded_policy_hash: None)
    monkeypatch.setattr(enforcement_gateway, "_record_runtime_loaded", lambda **_kwargs: None)
    monkeypatch.setattr(enforcement_gateway, "_append_audit_event", lambda _event: None)
    monkeypatch.setattr(
        enforcement_gateway,
        "_canonical_execution_gate_for_runtime",
        lambda: {
            **_ready_canonical_gate(),
            "execution_gate_status": "BLOCKED",
            "reason_codes": ["CANONICAL_EXECUTION_GATE_BLOCKED"],
        },
    )


def test_cli_automation_entrypoint_blocks_when_canonical_gate_blocks(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    _install_runtime_cli_gate_fixture(monkeypatch)
    monkeypatch.setattr(enforcement_gateway.policy_validator, "validate_runtime_attestation", lambda *, policy_hash: None)
    monkeypatch.setattr(enforcement_gateway.policy_validator, "validate_audit_chain", lambda *, policy_hash: None)
    request = tmp_path / "automation.json"
    request.write_text(
        json.dumps(
            {
                "automation_id": "automation-1",
                "action": "prepare",
                "automation_context": {
                    "context": "automation_triggered",
                    "expected_policy_hash": "a" * 64,
                    "trigger_timestamp": "2026-06-20T00:00:00Z",
                },
            },
            sort_keys=True,
        ),
        encoding="utf-8",
    )

    assert enforcement_gateway.main(["--automation-request", str(request)]) == 1
    output = capsys.readouterr().out
    assert "CANONICAL_EXECUTION_GATE_BLOCKED" in output
    assert "allow" not in output.lower()


def test_cli_command_entrypoint_blocks_before_runtime_executor_when_canonical_gate_blocks(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    _install_runtime_cli_gate_fixture(monkeypatch)
    monkeypatch.setattr(enforcement_gateway.policy_validator, "validate_runtime_attestation", lambda *, policy_hash: None)
    monkeypatch.setattr(enforcement_gateway.policy_validator, "validate_audit_chain", lambda *, policy_hash: None)
    monkeypatch.setattr(
        enforcement_gateway,
        "_load_command_request",
        lambda _path: {
            "actor": "operator",
            "device_id": "device-1",
            "command": {"input": "python3 -m py_compile security/compute_router.py"},
        },
    )

    def forbidden_executor(*_args, **_kwargs):
        raise AssertionError("runtime executor must not be reached when canonical gate blocks")

    import runtime.replit_executor as replit_executor

    monkeypatch.setattr(replit_executor, "execute_command", forbidden_executor)
    request = tmp_path / "command.json"
    request.write_text("{}", encoding="utf-8")

    assert enforcement_gateway.main(["--command-request", str(request)]) == 1
    output = capsys.readouterr().out
    assert "CANONICAL_EXECUTION_GATE_BLOCKED" in output
    assert "remote command executed" not in output
