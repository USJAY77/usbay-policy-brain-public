from runtime.execution_authority.execution_queue import ExecutionQueue


def test_execution_queue_records_every_state_change() -> None:
    queue = ExecutionQueue()

    queue.queue("exec-1")
    queue.pending("exec-1")
    queue.complete("exec-1")

    assert queue.states["exec-1"] == "COMPLETED"
    assert len(queue.audit_records) == 3
    assert all(record.audit_hash for record in queue.audit_records)


def test_execution_queue_denies_invalid_state_fail_closed() -> None:
    queue = ExecutionQueue()
    record = queue.transition("exec-1", "RUNNING", "invalid")

    assert record.state == "DENIED"
    assert record.reason == "invalid_state_fail_closed"


def test_execution_queue_denied_execution() -> None:
    queue = ExecutionQueue()
    record = queue.deny("exec-1", "policy denied")

    assert record.state == "DENIED"
    assert queue.states["exec-1"] == "DENIED"

