from __future__ import annotations

import json
from pathlib import Path

from runtime.computer_use.fail_closed_execution_gate import ALLOW, evaluate_runtime_execution_gate


EVIDENCE_PATH = Path("governance/evidence/runtime_fail_closed_execution_gate.json")
HASH1 = "sha256:" + ("1" * 64)
HASH2 = "sha256:" + ("2" * 64)
HASH3 = "sha256:" + ("3" * 64)


def _valid_gate_inputs() -> dict:
    return {
        "request": {
            "request_id": "req-p1-b1-audit-contract",
            "tenant_id": "tenant-usbay",
            "actor": "codex",
            "action": "runtime.execute",
            "target": "local-control-plane",
            "policy_version": "policy-v1",
        },
        "policy_evaluation": {"succeeded": True, "policy_hash": HASH1},
        "final_decision": ALLOW,
        "approval_state": {
            "status": "VALID",
            "valid": True,
            "expired": False,
            "approval_hash": HASH3,
            "approver": "human-governance-review",
        },
        "execution_contract": {"valid": True, "contract_hash": HASH1},
        "capability": {"authorized": True, "capability": "runtime.execute"},
        "target_policy": {"allowed": True, "target": "local-control-plane"},
        "parameter_validation": {"valid": True, "parameter_hash": HASH2},
        "replay_protection": {"passed": True, "replayed": False, "replay_hash": HASH3},
        "nonce_state": {"valid": True, "used": False, "nonce_hash": HASH1},
        "timestamp_state": {
            "valid": True,
            "observed_at": "2026-07-26T12:00:00Z",
            "not_before": "2026-07-26T11:00:00Z",
            "expires_at": "2026-07-26T13:00:00Z",
            "timestamp_hash": HASH2,
        },
        "audit_gate": {
            "write_succeeded": True,
            "verified": True,
            "before_execute": True,
            "audit_hash": HASH2,
        },
        "runtime_state": "READY",
        "dependencies": [{"component": "dependency-1", "state": "READY"}],
        "provider_execution_permitted": True,
        "production_activation_permitted": True,
        "deployment_authorized": True,
    }


def test_runtime_audit_evidence_exists_and_schema_validates() -> None:
    assert EVIDENCE_PATH.exists()
    evidence = json.loads(EVIDENCE_PATH.read_text(encoding="utf-8"))

    assert evidence["schema"] == "usbay.runtime.fail_closed_execution_gate.evidence.v1"
    assert evidence["batch"] == "P1-B1"
    assert evidence["title"] == "Runtime Fail-Closed Execution Gate"


def test_runtime_audit_evidence_mode_is_hash_only_and_redacted() -> None:
    evidence = json.loads(EVIDENCE_PATH.read_text(encoding="utf-8"))

    assert evidence["sensitive_data_policy"] == {
        "raw_payload_logging": False,
        "credential_logging": False,
        "evidence_mode": "hash-only-redacted",
    }
    for path in evidence["evidence"].values():
        assert path["evidence_mode"] == "hash-only"


def test_runtime_audit_before_execute_path_is_required() -> None:
    evidence = json.loads(EVIDENCE_PATH.read_text(encoding="utf-8"))

    assert evidence["evidence"]["audit_before_execute_path"]["required"] is True
    assert "audit_before_execute" in evidence["required_controls"]


def test_runtime_audit_contract_preserves_fail_closed_denial() -> None:
    inputs = _valid_gate_inputs()
    inputs["audit_gate"] = {
        "write_succeeded": False,
        "verified": False,
        "before_execute": False,
        "audit_hash": HASH2,
    }

    decision = evaluate_runtime_execution_gate(**inputs)

    assert decision.gate_status == "BLOCKED"
    assert decision.reason_code == "AUDIT_WRITE_FAILED"
    assert decision.execution_allowed is False
    assert decision.provider_execution is False
    assert decision.production_activation is False
    assert decision.deployment_authorized is False
