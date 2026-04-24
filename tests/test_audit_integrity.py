from audit.decision_logger import write_audit_event, _read_last_chain_hash


def test_chain_integrity(tmp_path):
    p = tmp_path / "log.jsonl"

    e1 = write_audit_event(
        event_type="policy_decision",
        actor="USBAY",
        decision="ALLOW",
        policy_version="v1",
        execution_origin="test",
        workspace="test",
        input_payload={"id": "1"},
        log_path=p,
    )

    e2 = write_audit_event(
        event_type="policy_decision",
        actor="USBAY",
        decision="BLOCK",
        policy_version="v1",
        execution_origin="test",
        workspace="test",
        input_payload={"id": "2"},
        log_path=p,
    )

    assert e2.previous_chain_hash == e1.chain_hash


def test_tamper_detection(tmp_path):
    p = tmp_path / "log.jsonl"

    write_audit_event(
        event_type="policy_decision",
        actor="USBAY",
        decision="ALLOW",
        policy_version="v1",
        execution_origin="test",
        workspace="test",
        input_payload={"id": "1"},
        log_path=p,
    )

    with p.open("a", encoding="utf-8") as f:
        f.write("corrupt\n")

    try:
        _read_last_chain_hash(p)
        assert False
    except RuntimeError:
        assert True


def test_fail_closed_on_invalid_input(tmp_path):
    p = tmp_path / "log.jsonl"

    try:
        write_audit_event(
            event_type="policy_decision",
            actor=None,
            decision="ALLOW",
            policy_version="v1",
            execution_origin="test",
            workspace="test",
            input_payload={"id": "x"},
            log_path=p,
        )
        assert False
    except Exception:
        assert True
def test_chain_never_resets(tmp_path):
    p = tmp_path / "log.jsonl"

    e1 = write_audit_event(
        event_type="policy_decision",
        actor="USBAY",
        decision="ALLOW",
        policy_version="v1",
        execution_origin="test",
        workspace="test",
        input_payload={"id": "1"},
        log_path=p,
    )

    # simuleer "reset aanval" (file leegmaken)
    p.write_text("")

    e2 = write_audit_event(
        event_type="policy_decision",
        actor="USBAY",
        decision="BLOCK",
        policy_version="v1",
        execution_origin="test",
        workspace="test",
        input_payload={"id": "2"},
        log_path=p,
    )

    # chain mag NIET gelijk zijn aan oude chain
    assert e2.previous_chain_hash != e1.chain_hash
