from __future__ import annotations

from runtime_trust.pilot_activation import detect_replay_event


def test_replay_protection_detects_all_duplicate_events() -> None:
    result = detect_replay_event(
        approval_id="approval-1",
        action_id="action-1",
        nonce="nonce-1",
        audit_event_hash="audit-1",
        seen_approvals={"approval-1"},
        seen_actions={"action-1"},
        seen_nonces={"nonce-1"},
        seen_audit_events={"audit-1"},
    )
    assert result["decision"] == "FAIL_CLOSED"
    assert set(result["gaps"]) == {
        "DUPLICATE_APPROVAL",
        "DUPLICATE_ACTION",
        "DUPLICATE_NONCE",
        "DUPLICATE_AUDIT_CHAIN_EVENT",
    }
    assert result["replay_evidence_hash"]


def test_replay_protection_verifies_clean_event() -> None:
    result = detect_replay_event(
        approval_id="approval-2",
        action_id="action-2",
        nonce="nonce-2",
        audit_event_hash="audit-2",
        seen_approvals=set(),
        seen_actions=set(),
        seen_nonces=set(),
        seen_audit_events=set(),
    )
    assert result["decision"] == "VERIFIED"
    assert result["gaps"] == []
