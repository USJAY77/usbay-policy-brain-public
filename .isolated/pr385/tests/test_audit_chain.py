from __future__ import annotations

from dataclasses import replace

from runtime.computer_use.audit_chain import (
    CHAIN_BROKEN,
    GENESIS_PREVIOUS_HASH,
    VALID,
    append_decision_record,
    audit_chain_output,
    fail_closed_decision_for_chain,
    verify_chain,
)


def _records(count: int = 3):
    records = []
    for index in range(count):
        records.append(
            append_decision_record(
                records,
                decision_id=f"decision-{index}",
                timestamp=f"2026-06-10T00:00:0{index}Z",
                decision="ALLOW" if index == 0 else "HUMAN_REVIEW",
                reason="LOW_RISK" if index == 0 else "HIGH_RISK",
                risk_level="LOW" if index == 0 else "HIGH",
                policy_version="computer-use-policy-v1",
                approval_state="NONE",
            )
        )
    return records


def test_valid_chain_verifies() -> None:
    records = _records()

    assert verify_chain(records) == VALID
    output = audit_chain_output(records)
    assert output.verification_status == VALID
    assert output.chain_length == 3
    assert output.genesis_hash == records[0].current_hash
    assert output.latest_hash == records[-1].current_hash
    assert output.audit_chain_id.startswith("cua-chain-")


def test_modified_record_breaks_chain() -> None:
    records = _records()
    tampered = [records[0], replace(records[1], decision="BLOCK"), records[2]]

    assert verify_chain(tampered) == CHAIN_BROKEN
    assert fail_closed_decision_for_chain(tampered)["decision"] == "FAIL_CLOSED"


def test_removed_record_breaks_chain() -> None:
    records = _records()
    removed_middle = [records[0], records[2]]

    assert verify_chain(removed_middle) == CHAIN_BROKEN


def test_inserted_record_breaks_chain() -> None:
    records = _records()
    inserted = append_decision_record(
        [],
        decision_id="inserted",
        timestamp="2026-06-10T00:00:09Z",
        decision="ALLOW",
        reason="LOW_RISK",
        risk_level="LOW",
        policy_version="computer-use-policy-v1",
        approval_state="NONE",
    )

    assert verify_chain([records[0], inserted, records[1], records[2]]) == CHAIN_BROKEN


def test_genesis_record_uses_genesis_previous_hash() -> None:
    record = _records(1)[0]

    assert record.previous_hash == GENESIS_PREVIOUS_HASH
    assert verify_chain([record]) == VALID


def test_chain_replay_from_dicts_verifies() -> None:
    records = _records()
    replayed = [record.to_dict() for record in records]

    assert verify_chain(replayed) == VALID
    assert audit_chain_output(replayed).latest_hash == records[-1].current_hash


def test_empty_chain_is_broken() -> None:
    assert verify_chain([]) == CHAIN_BROKEN
    assert fail_closed_decision_for_chain([])["decision"] == "FAIL_CLOSED"
