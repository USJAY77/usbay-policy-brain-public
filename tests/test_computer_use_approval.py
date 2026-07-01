from __future__ import annotations

import json
from pathlib import Path

from runtime.computer_use.action_schema import ComputerUseAction
from runtime.computer_use.approval import ComputerUseApprovalQueue, approval_request_schema
from runtime.computer_use.audit_recorder import ComputerUseAuditRecorder
from runtime.computer_use.runtime import ComputerUsePolicyEvaluator, ComputerUseRuntimeController


ROOT = Path(__file__).resolve().parents[1]


def _high_risk_action(target: str = "GitHub merge pull request") -> ComputerUseAction:
    return ComputerUseAction(
        action_type="click",
        target=target,
        coordinates={"x": 11, "y": 22},
        required_capability="computer_use.click",
        risk_level="HIGH",
    )


def _controller(tmp_path: Path, policy_path: Path | None = None) -> ComputerUseRuntimeController:
    audit_recorder = ComputerUseAuditRecorder(tmp_path / "computer_use_audit.jsonl")
    return ComputerUseRuntimeController(
        policy_evaluator=ComputerUsePolicyEvaluator(policy_path or ROOT / "policy" / "computer_use_policy.json"),
        audit_recorder=audit_recorder,
        approval_queue=ComputerUseApprovalQueue(
            audit_recorder=audit_recorder,
            evidence_path=tmp_path / "approval_evidence.json",
        ),
    )


def test_approval_request_schema_is_fail_closed() -> None:
    schema = approval_request_schema()

    assert schema["schema"] == "usbay.computer_use.approval_request.v1"
    assert schema["fail_closed_on_missing_field"] is True
    assert schema["raw_tokens_allowed"] is False
    assert {
        "request_id",
        "action_id",
        "action_hash",
        "requested_reason",
        "requested_at",
        "status",
        "approval_audit_hash",
    }.issubset(set(schema["required_fields"]))


def test_high_risk_action_does_not_execute_without_approval(tmp_path: Path) -> None:
    decision = _controller(tmp_path).decide_and_execute(_high_risk_action())

    assert decision.decision == "HUMAN_REVIEW"
    assert decision.execution["executed"] is False
    assert len(decision.audit_event["audit_hash"]) == 64


def test_approved_action_requires_policy_approval_and_audit_hash(tmp_path: Path) -> None:
    controller = _controller(tmp_path)
    action = _high_risk_action()
    request = controller.approval_queue.request_approval(action, reason="merge requires explicit approval")
    approval = controller.approval_queue.approve(
        request.request_id,
        reviewer_id="USBAY-AUDIT",
        approval_reason="human reviewed merge target",
    )

    decision = controller.decide_and_execute(action, approval_token=approval.approval_token)

    assert decision.decision == "ALLOW"
    assert decision.reason == "APPROVAL_TOKEN_VALID"
    assert decision.audit_event["approval_reference"] == request.request_id
    assert decision.audit_event["approval_audit_hash"] == approval.approval_audit_hash
    assert len(decision.audit_event["audit_hash"]) == 64
    assert decision.execution["dry_run"] is True


def test_reused_approval_token_blocks_execution(tmp_path: Path) -> None:
    controller = _controller(tmp_path)
    action = _high_risk_action("approve deployment")
    request = controller.approval_queue.request_approval(action, reason="approval required")
    approval = controller.approval_queue.approve(
        request.request_id,
        reviewer_id="USBAY-AUDIT",
        approval_reason="single use token",
    )

    first = controller.decide_and_execute(action, approval_token=approval.approval_token)
    second = controller.decide_and_execute(action, approval_token=approval.approval_token)

    assert first.decision == "ALLOW"
    assert second.decision == "BLOCK"
    assert second.reason == "APPROVAL_TOKEN_REPLAYED"
    assert second.execution["executed"] is False


def test_expired_approval_token_blocks_execution(tmp_path: Path) -> None:
    controller = _controller(tmp_path)
    action = _high_risk_action("delete production branch")
    request = controller.approval_queue.request_approval(action, reason="delete requires approval")
    approval = controller.approval_queue.approve(
        request.request_id,
        reviewer_id="USBAY-GLOBAL23",
        approval_reason="expired token test",
        ttl_seconds=-1,
    )

    decision = controller.decide_and_execute(action, approval_token=approval.approval_token)

    assert decision.decision == "BLOCK"
    assert decision.reason == "APPROVAL_TOKEN_EXPIRED"
    assert decision.execution["executed"] is False


def test_denied_approval_blocks_execution_and_remains_auditable(tmp_path: Path) -> None:
    controller = _controller(tmp_path)
    action = _high_risk_action("deploy release")
    request = controller.approval_queue.request_approval(action, reason="deploy requires approval")
    denial = controller.approval_queue.deny(
        request.request_id,
        reviewer_id="USBAY-AUDIT",
        approval_reason="deployment denied",
    )

    decision = controller.decide_and_execute(action, approval_token=denial.approval_token)

    assert denial.decision == "DENIED"
    assert denial.approval_token is None
    assert len(denial.approval_audit_hash) == 64
    assert decision.decision == "BLOCK"
    assert decision.reason == "APPROVAL_DENIED"
    assert decision.audit_event["approval_audit_hash"] == denial.approval_audit_hash


def test_missing_policy_fails_closed(tmp_path: Path) -> None:
    action = ComputerUseAction(
        action_type="read_screen",
        target="metadata-only screen read",
        required_capability="computer_use.read_screen",
    )

    decision = _controller(tmp_path, tmp_path / "missing-policy.json").decide_and_execute(action)

    assert decision.decision == "FAIL_CLOSED"
    assert "COMPUTER_USE_POLICY_MISSING" in decision.reason
    assert decision.execution["executed"] is False


def test_approval_evidence_export_redacts_tokens_and_hashes_payload(tmp_path: Path) -> None:
    controller = _controller(tmp_path)
    action = _high_risk_action()
    request = controller.approval_queue.request_approval(action, reason="merge requires approval")
    approval = controller.approval_queue.approve(
        request.request_id,
        reviewer_id="USBAY-AUDIT",
        approval_reason="export evidence",
    )

    evidence = controller.approval_queue.export_evidence()
    exported = json.loads((tmp_path / "approval_evidence.json").read_text(encoding="utf-8"))

    assert evidence == exported
    assert len(evidence["evidence_hash"]) == 64
    assert evidence["raw_tokens_exported"] is False
    assert evidence["requests"][0]["approval_audit_hash"]
    assert evidence["decisions"][0]["approval_token"] is None
    assert evidence["decisions"][0]["approval_token_hash"] == approval.approval_token_hash
