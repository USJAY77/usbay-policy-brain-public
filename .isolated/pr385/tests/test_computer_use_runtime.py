from __future__ import annotations

import json
from pathlib import Path

import pytest

from runtime.computer_use.action_schema import ComputerUseAction
from runtime.computer_use.approval import ComputerUseApprovalQueue
from runtime.computer_use.audit_recorder import ComputerUseAuditRecorder
from runtime.computer_use.runtime_controller import ComputerUsePolicyEvaluator, ComputerUseRuntimeController
from runtime.computer_use.screen_capture import ScreenCapture


ROOT = Path(__file__).resolve().parents[1]


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


def test_allow_low_risk_read_screen(tmp_path: Path) -> None:
    action = ComputerUseAction(
        action_type="read_screen",
        target="metadata-only screen read",
        required_capability="computer_use.read_screen",
    )

    decision = _controller(tmp_path).decide_and_execute(action)

    assert decision.decision == "ALLOW"
    assert decision.execution["dry_run"] is True
    assert decision.audit_event["audit_hash"]
    assert decision.audit_event["raw_screenshot_stored"] is False


def test_block_unknown_action_type() -> None:
    with pytest.raises(ValueError, match="UNKNOWN_ACTION_TYPE"):
        ComputerUseAction(
            action_type="drag",
            target="unknown target",
            required_capability="computer_use.drag",
        )


def test_unknown_action_payload_blocks_with_audit(tmp_path: Path) -> None:
    decision = _controller(tmp_path).decide_payload(
        {
            "action_id": "bad-action",
            "action_type": "drag",
            "target": "unknown target",
            "required_capability": "computer_use.drag",
            "risk_level": "LOW",
        }
    )

    assert decision.decision == "BLOCK"
    assert decision.reason == "UNKNOWN_ACTION_TYPE"
    assert decision.execution["executed"] is False
    assert len(decision.audit_event["audit_hash"]) == 64


def test_block_click_without_policy_approval(tmp_path: Path) -> None:
    action = ComputerUseAction(
        action_type="click",
        target="ordinary button",
        coordinates={"x": 10, "y": 20},
        required_capability="computer_use.click",
    )

    decision = _controller(tmp_path).decide_and_execute(action)

    assert decision.decision == "BLOCK"
    assert decision.reason == "MUTATING_ACTION_REQUIRES_POLICY_APPROVAL"
    assert decision.execution["executed"] is False


def test_block_type_action_containing_secret_like_value(tmp_path: Path) -> None:
    action = ComputerUseAction(
        action_type="type",
        target="form field",
        text="api_key=sk-secretsecretsecret",
        required_capability="computer_use.type",
    )

    decision = _controller(tmp_path).decide_and_execute(action)

    assert decision.decision == "BLOCK"
    assert decision.reason == "SECRET_LIKE_TEXT_BLOCKED"
    assert decision.audit_event["raw_text_redacted"] is True


@pytest.mark.parametrize("target", ["GitHub merge pull request", "approve deployment", "delete production branch", "deploy release"])
def test_human_review_required_for_high_risk_targets(tmp_path: Path, target: str) -> None:
    action = ComputerUseAction(
        action_type="click",
        target=target,
        coordinates={"x": 1, "y": 2},
        required_capability="computer_use.click",
        risk_level="HIGH",
    )

    decision = _controller(tmp_path).decide_and_execute(action)

    assert decision.decision == "HUMAN_REVIEW"
    assert decision.reason in {
        "HIGH_RISK_TARGET_REQUIRES_HUMAN_APPROVAL",
        "HIGH_RISK_ACTION_REQUIRES_HUMAN_APPROVAL",
    }
    assert decision.execution["executed"] is False


def test_valid_approval_token_allows_high_risk_dry_run_execution(tmp_path: Path) -> None:
    controller = _controller(tmp_path)
    action = ComputerUseAction(
        action_type="click",
        target="GitHub merge pull request",
        coordinates={"x": 1, "y": 2},
        required_capability="computer_use.click",
        risk_level="HIGH",
    )
    request = controller.approval_queue.request_approval(action, reason="merge requires reviewer approval")
    approval = controller.approval_queue.approve(
        request.request_id,
        reviewer_id="USBAY-AUDIT",
        approval_reason="reviewed merge boundary",
    )

    decision = controller.decide_and_execute(action, approval_token=approval.approval_token)

    assert decision.decision == "ALLOW"
    assert decision.reason == "APPROVAL_TOKEN_VALID"
    assert decision.execution["dry_run"] is True
    assert decision.execution["executed"] is False
    assert decision.audit_event["approval_reference"] == request.request_id
    assert decision.audit_event["approval_audit_hash"] == approval.approval_audit_hash


def test_approval_token_replay_blocks(tmp_path: Path) -> None:
    controller = _controller(tmp_path)
    action = ComputerUseAction(
        action_type="click",
        target="approve deployment",
        coordinates={"x": 1, "y": 2},
        required_capability="computer_use.click",
        risk_level="HIGH",
    )
    request = controller.approval_queue.request_approval(action, reason="approval required")
    approval = controller.approval_queue.approve(
        request.request_id,
        reviewer_id="USBAY-AUDIT",
        approval_reason="one-time approval",
    )

    assert controller.decide_and_execute(action, approval_token=approval.approval_token).decision == "ALLOW"
    replay = controller.decide_and_execute(action, approval_token=approval.approval_token)

    assert replay.decision == "BLOCK"
    assert replay.reason == "APPROVAL_TOKEN_REPLAYED"
    assert replay.execution["executed"] is False


def test_expired_approval_token_blocks(tmp_path: Path) -> None:
    controller = _controller(tmp_path)
    action = ComputerUseAction(
        action_type="click",
        target="delete production branch",
        coordinates={"x": 1, "y": 2},
        required_capability="computer_use.click",
        risk_level="HIGH",
    )
    request = controller.approval_queue.request_approval(action, reason="delete requires approval")
    approval = controller.approval_queue.approve(
        request.request_id,
        reviewer_id="USBAY-GLOBAL23",
        approval_reason="short-lived approval",
        ttl_seconds=-1,
    )

    decision = controller.decide_and_execute(action, approval_token=approval.approval_token)

    assert decision.decision == "BLOCK"
    assert decision.reason == "APPROVAL_TOKEN_EXPIRED"
    assert decision.execution["executed"] is False


def test_denial_path_is_auditable_and_blocks_execution(tmp_path: Path) -> None:
    controller = _controller(tmp_path)
    action = ComputerUseAction(
        action_type="click",
        target="deploy release",
        coordinates={"x": 1, "y": 2},
        required_capability="computer_use.click",
        risk_level="HIGH",
    )
    request = controller.approval_queue.request_approval(action, reason="deploy requires approval")
    denial = controller.approval_queue.deny(
        request.request_id,
        reviewer_id="USBAY-AUDIT",
        approval_reason="deployment window not approved",
    )
    decision = controller.decide_and_execute(action, approval_token=denial.approval_token)

    assert denial.decision == "DENIED"
    assert denial.approval_token is None
    assert denial.approval_audit_hash
    assert decision.decision == "BLOCK"
    assert decision.reason == "APPROVAL_DENIED"
    assert decision.execution["executed"] is False


def test_approval_evidence_export_redacts_tokens(tmp_path: Path) -> None:
    controller = _controller(tmp_path)
    action = ComputerUseAction(
        action_type="click",
        target="GitHub merge pull request",
        coordinates={"x": 1, "y": 2},
        required_capability="computer_use.click",
        risk_level="HIGH",
    )
    request = controller.approval_queue.request_approval(action, reason="merge requires approval")
    approval = controller.approval_queue.approve(
        request.request_id,
        reviewer_id="USBAY-AUDIT",
        approval_reason="export evidence",
    )

    evidence = controller.approval_queue.export_evidence()

    assert evidence["evidence_hash"]
    assert evidence["raw_tokens_exported"] is False
    assert evidence["decisions"][0]["approval_token"] is None
    assert evidence["decisions"][0]["approval_token_hash"] == approval.approval_token_hash
    assert (tmp_path / "approval_evidence.json").exists()


def test_fail_closed_when_policy_file_missing(tmp_path: Path) -> None:
    action = ComputerUseAction(
        action_type="read_screen",
        target="metadata-only screen read",
        required_capability="computer_use.read_screen",
    )

    decision = _controller(tmp_path, tmp_path / "missing-policy.json").decide_and_execute(action)

    assert decision.decision == "FAIL_CLOSED"
    assert "COMPUTER_USE_POLICY_MISSING" in decision.reason
    assert decision.execution["executed"] is False


def test_audit_hash_created_for_every_decision(tmp_path: Path) -> None:
    controller = _controller(tmp_path)
    actions = [
        ComputerUseAction(action_type="read_screen", target="screen", required_capability="computer_use.read_screen"),
        ComputerUseAction(action_type="stop", target="uncertain", required_capability="computer_use.stop"),
    ]

    for action in actions:
        decision = controller.decide_and_execute(action)
        assert len(decision.audit_event["audit_hash"]) == 64

    lines = (tmp_path / "computer_use_audit.jsonl").read_text(encoding="utf-8").splitlines()
    assert len(lines) == 2
    assert all(json.loads(line)["audit_hash"] for line in lines)


def test_no_raw_screenshot_persisted_by_default(tmp_path: Path) -> None:
    capture = ScreenCapture()
    metadata = capture.capture_metadata(width=100, height=50)

    assert metadata.raw_screenshot_stored is False
    assert not list(tmp_path.glob("*.png"))
    with pytest.raises(RuntimeError, match="RAW_SCREENSHOT_PERSISTENCE_DISABLED"):
        capture.persist_raw_screenshot(tmp_path / "screen.png")
