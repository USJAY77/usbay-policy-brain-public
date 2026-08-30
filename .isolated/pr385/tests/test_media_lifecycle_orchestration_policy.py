from __future__ import annotations

from tests.helpers.media_lifecycle_orchestration_policy import (
    load_media_lifecycle_orchestration_policy,
    valid_lifecycle_orchestration_manifest,
    verify_media_lifecycle_orchestration,
)


def test_valid_lifecycle_orchestration_manifest_passes() -> None:
    evidence = verify_media_lifecycle_orchestration(valid_lifecycle_orchestration_manifest())

    assert evidence["decision"] == "PASS"
    assert evidence["orchestration_reference_only"] is True


def test_missing_orchestration_manifest_fails_closed() -> None:
    evidence = verify_media_lifecycle_orchestration(None)

    assert evidence["decision"] == "FAIL_CLOSED"
    assert evidence["reason"] == "MEDIA_ORCHESTRATION_MANIFEST_MISSING"


def test_unknown_stage_fails_closed() -> None:
    manifest = valid_lifecycle_orchestration_manifest()
    manifest["executed_stages"] = [*manifest["executed_stages"], "unknown_stage"]

    evidence = verify_media_lifecycle_orchestration(manifest)

    assert evidence["decision"] == "FAIL_CLOSED"
    assert evidence["reason"] == "MEDIA_ORCHESTRATION_UNKNOWN_STAGE"


def test_stage_order_violation_fails_closed() -> None:
    manifest = valid_lifecycle_orchestration_manifest()
    manifest["executed_stages"][0], manifest["executed_stages"][1] = manifest["executed_stages"][1], manifest["executed_stages"][0]

    evidence = verify_media_lifecycle_orchestration(manifest)

    assert evidence["decision"] == "FAIL_CLOSED"
    assert evidence["reason"] == "MEDIA_ORCHESTRATION_STAGE_ORDER_VIOLATION"


def test_missing_required_gate_fails_closed() -> None:
    manifest = valid_lifecycle_orchestration_manifest()
    manifest["required_gates_present"] = False

    evidence = verify_media_lifecycle_orchestration(manifest)

    assert evidence["decision"] == "FAIL_CLOSED"
    assert evidence["reason"] == "MEDIA_ORCHESTRATION_REQUIRED_GATE_MISSING"


def test_attempted_runtime_override_fails_closed() -> None:
    manifest = valid_lifecycle_orchestration_manifest()
    manifest["attempted_runtime_override"] = True

    evidence = verify_media_lifecycle_orchestration(manifest)

    assert evidence["decision"] == "FAIL_CLOSED"
    assert evidence["reason"] == "MEDIA_ORCHESTRATION_RUNTIME_OVERRIDE_ATTEMPT"


def test_lifecycle_orchestration_policy_is_non_production_scaffolding() -> None:
    policy = load_media_lifecycle_orchestration_policy()

    assert policy["fail_closed_on_unknown_stage"] is True
    assert policy["fail_closed_on_stage_order_violation"] is True
    assert policy["fail_closed_on_missing_required_gate"] is True
    assert policy["fail_closed_on_attempted_runtime_override"] is True
    assert policy["non_production_scaffolding"] is True
