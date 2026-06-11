from __future__ import annotations

import json
from pathlib import Path

import pytest

from audit.audit_writer import AuditWriteError, write_audit_record
from evaluators.policy_evaluator import evaluate_pr
from gateway.contract_adapter import evaluate_governed_pr_request


def registry(path: Path, *, active: bool = True) -> str:
    policy = {
        "policy_id": "usbay.governance_gateway.contract.v1",
        "policy_hash": "a" * 64,
        "policy_version": "1.0.0",
        "created_at": "2026-06-11T00:00:00Z",
        "active": active,
    }
    path.write_text(json.dumps(policy, indent=2, sort_keys=True), encoding="utf-8")
    return policy["policy_hash"]


def pr_payload(policy_hash: str | None = None) -> dict:
    payload = {
        "repository": "USJAY77/usbay-policy-brain",
        "pull_request": {
            "number": 207,
            "head_sha": "abc123",
            "base_sha": "def456",
        },
        "diff": {
            "changed_files": ["evaluators/policy_evaluator.py"],
        },
    }
    if policy_hash is not None:
        payload["policy_hash"] = policy_hash
    return payload


def test_policy_evaluator_passes_valid_request(tmp_path: Path) -> None:
    registry_path = tmp_path / "policy_registry.json"
    policy_hash = registry(registry_path)
    result = evaluate_pr(pr_payload(policy_hash), policy_registry_path=registry_path)
    assert result["decision"] == "PASS"
    assert result["gaps"] == []
    assert result["policy_hash"] == policy_hash


def test_policy_evaluator_fails_closed_on_missing_policy(tmp_path: Path) -> None:
    result = evaluate_pr(pr_payload(), policy_registry_path=tmp_path / "missing.json")
    assert result["decision"] == "FAIL"
    assert result["gaps"] == ["MISSING_POLICY"]


def test_policy_evaluator_fails_closed_on_malformed_diff(tmp_path: Path) -> None:
    registry_path = tmp_path / "policy_registry.json"
    registry(registry_path)
    payload = pr_payload()
    payload["diff"] = {"changed_files": "not-a-list"}
    result = evaluate_pr(payload, policy_registry_path=registry_path)
    assert result["decision"] == "FAIL"
    assert "MALFORMED_DIFF" in result["gaps"]


def test_policy_evaluator_fails_closed_on_unknown_policy_hash(tmp_path: Path) -> None:
    registry_path = tmp_path / "policy_registry.json"
    registry(registry_path)
    result = evaluate_pr(pr_payload("b" * 64), policy_registry_path=registry_path)
    assert result["decision"] == "FAIL"
    assert "UNKNOWN_POLICY_HASH" in result["gaps"]


def test_audit_writer_redacts_sensitive_data_and_writes_hash_chain(tmp_path: Path) -> None:
    audit_path = tmp_path / "audit_chain.json"
    result = write_audit_record(
        "governed_pr_evaluation",
        {"repository": "repo", "token": "secret-value"},
        audit_path=audit_path,
    )
    assert result["decision"] == "PASS"
    assert "token" not in result["record"]["payload"]
    assert result["audit_hash"]
    assert audit_path.exists()
    assert "secret-value" not in audit_path.read_text(encoding="utf-8")


def test_audit_writer_fails_closed_on_malformed_payload(tmp_path: Path) -> None:
    with pytest.raises(AuditWriteError, match="AUDIT_PAYLOAD_MALFORMED"):
        write_audit_record("event", ["bad"], audit_path=tmp_path / "audit.json")  # type: ignore[arg-type]


def test_gateway_adapter_blocks_malformed_request(tmp_path: Path) -> None:
    registry_path = tmp_path / "policy_registry.json"
    registry(registry_path)
    result = evaluate_governed_pr_request(
        {"repository": "repo"},
        policy_registry_path=registry_path,
        audit_path=tmp_path / "audit.json",
    )
    assert result["decision"] == "FAIL"
    assert "MISSING_PULL_REQUEST" in result["gaps"]
    assert result["audit"] is None


def test_gateway_adapter_returns_governed_response_without_external_calls(tmp_path: Path) -> None:
    registry_path = tmp_path / "policy_registry.json"
    policy_hash = registry(registry_path)
    result = evaluate_governed_pr_request(
        pr_payload(policy_hash),
        policy_registry_path=registry_path,
        audit_path=tmp_path / "audit.json",
    )
    assert result["decision"] == "PASS"
    assert result["policy_hash"] == policy_hash
    assert result["audit"]["audit_hash"]
