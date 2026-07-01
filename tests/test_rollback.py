from runtime.computer_use.rollback import build_rollback_plan


def test_rollback_ready_with_path_and_evidence() -> None:
    plan = build_rollback_plan("action-1", "restore-main", ["audit_hash"])

    assert plan.ready is True
    assert plan.reason == "rollback_ready"


def test_rollback_blocks_missing_path() -> None:
    plan = build_rollback_plan("action-1", None, ["audit_hash"])

    assert plan.ready is False
    assert plan.reason == "rollback_path_missing"


def test_rollback_blocks_missing_evidence() -> None:
    plan = build_rollback_plan("action-1", "restore-main", [])

    assert plan.ready is False
    assert plan.reason == "rollback_evidence_missing"

