from __future__ import annotations

import json
from pathlib import Path

from audit.decision_logger import write_audit_event


def test_audit_event_writes_jsonl(tmp_path: Path) -> None:
    log_path = tmp_path / "audit_log.jsonl"

    event = write_audit_event(
        event_type="policy_decision",
        actor="USBAY-GOV",
        decision="ALLOW",
        policy_version="v1.0",
        execution_origin="codex_workspace",
        workspace="business",
        input_payload={"request_id": "abc-123", "action": "test"},
        log_path=log_path,
    )

    assert event.policy_version == "v1.0"
    assert event.previous_chain_hash == "GENESIS"
    assert len(event.chain_hash) == 64

    lines = log_path.read_text(encoding="utf-8").strip().splitlines()
    assert len(lines) == 1

    record = json.loads(lines[0])
    assert record["event_type"] == "policy_decision"
    assert record["decision"] == "ALLOW"


def test_audit_chain_links_records(tmp_path: Path) -> None:
    log_path = tmp_path / "audit_log.jsonl"

    first = write_audit_event(
        event_type="policy_decision",
        actor="USBAY-GOV",
        decision="ALLOW",
        policy_version="v1.0",
        execution_origin="codex_workspace",
        workspace="business",
        input_payload={"request_id": "1"},
        log_path=log_path,
    )

    second = write_audit_event(
        event_type="policy_decision",
        actor="USBAY-GOV",
        decision="BLOCK",
        policy_version="v1.0",
        execution_origin="codex_workspace",
        workspace="business",
        input_payload={"request_id": "2"},
        log_path=log_path,
    )

    assert second.previous_chain_hash == first.chain_hash
    assert second.chain_hash != first.chain_hash
