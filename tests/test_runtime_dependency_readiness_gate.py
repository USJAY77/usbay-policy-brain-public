from __future__ import annotations

from runtime.computer_use.dependency_readiness_gate import evaluate_dependency_readiness


HASH = "sha256:" + ("a" * 64)
OBSERVED = "2026-07-27T12:00:00Z"
VERIFIED = "2026-07-27T11:59:00Z"


def _dependency(**overrides):
    dependency = {
        "dependency_id": "policy-source",
        "dependency_type": "policy_source",
        "required": True,
        "readiness_status": "READY",
        "health_status": "READY",
        "compatibility_status": "READY",
        "integrity_status": "READY",
        "last_verified_at": VERIFIED,
        "freshness_window_seconds": 300,
        "expected_version": "v1",
        "observed_version": "v1",
        "evidence_hash": HASH,
        "failure_reason": "",
        "final_decision": "ALLOW",
    }
    dependency.update(overrides)
    return dependency


def _blocked(result):
    assert result.final_decision == "BLOCKED"
    assert result.execution_may_continue is False
    assert result.evidence_hash.startswith("sha256:")


def test_all_dependencies_ready_allows_next_gate() -> None:
    result = evaluate_dependency_readiness([_dependency()], observed_at=OBSERVED)

    assert result.final_decision == "ALLOW"
    assert result.execution_may_continue is True
    assert result.reason_code == "DEPENDENCIES_READY"


def test_required_dependency_missing_blocks() -> None:
    _blocked(evaluate_dependency_readiness(None, observed_at=OBSERVED))


def test_required_dependency_stale_blocks() -> None:
    _blocked(evaluate_dependency_readiness([_dependency(last_verified_at="2026-07-27T11:00:00Z")], observed_at=OBSERVED))


def test_required_dependency_degraded_blocks() -> None:
    _blocked(evaluate_dependency_readiness([_dependency(readiness_status="DEGRADED")], observed_at=OBSERVED, degraded_operation_permitted=True))


def test_optional_degraded_dependency_explicitly_permitted() -> None:
    result = evaluate_dependency_readiness(
        [_dependency(required=False, readiness_status="DEGRADED")],
        observed_at=OBSERVED,
        degraded_operation_permitted=True,
    )

    assert result.final_decision == "ALLOW"


def test_optional_degraded_dependency_not_permitted_blocks() -> None:
    _blocked(evaluate_dependency_readiness([_dependency(required=False, readiness_status="DEGRADED")], observed_at=OBSERVED))


def test_version_mismatch_blocks() -> None:
    _blocked(evaluate_dependency_readiness([_dependency(observed_version="v2")], observed_at=OBSERVED))


def test_missing_evidence_blocks() -> None:
    _blocked(evaluate_dependency_readiness([_dependency(evidence_hash="")], observed_at=OBSERVED))


def test_malformed_readiness_record_blocks() -> None:
    malformed = _dependency()
    malformed.pop("dependency_id")
    _blocked(evaluate_dependency_readiness([malformed], observed_at=OBSERVED))


def test_unknown_dependency_status_blocks() -> None:
    _blocked(evaluate_dependency_readiness([_dependency(readiness_status="READYISH")], observed_at=OBSERVED))


def test_unsupported_dependency_type_blocks() -> None:
    _blocked(evaluate_dependency_readiness([_dependency(dependency_type="external_probe")], observed_at=OBSERVED))


def test_evaluator_exception_blocks() -> None:
    class ExplodingSequence(list):
        def __iter__(self):
            raise RuntimeError("synthetic failure")

    _blocked(evaluate_dependency_readiness(ExplodingSequence([_dependency()]), observed_at=OBSERVED))
