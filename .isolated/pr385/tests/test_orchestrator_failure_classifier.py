from __future__ import annotations

import pytest

from governance.orchestrator_failure_classifier import (
    FAILURE_CLASSIFIER_VERSION,
    FailureClass,
    classify_failure,
    failure_classifier_contract,
)


pytestmark = pytest.mark.governance


def test_failure_classifier_contract_declares_required_classes() -> None:
    contract = failure_classifier_contract()

    assert contract["policy_version"] == FAILURE_CLASSIFIER_VERSION
    assert contract["failure_classes"] == [failure_class.value for failure_class in FailureClass]
    assert contract["unknown_failure_decision"] == "FAIL_CLOSED"
    assert contract["audit_reason_required"] is True


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("pytest failed with AssertionError", FailureClass.TEST_FAILURE),
        ("policy-verification rejected signature", FailureClass.POLICY_FAILURE),
        ("evidence manifest lineage mismatch", FailureClass.EVIDENCE_FAILURE),
        ("<<<<<<< conflict marker", FailureClass.MERGE_CONFLICT),
        ("required status check blocked by branch protection", FailureClass.BRANCH_PROTECTION),
        ("403 forbidden: resource not accessible", FailureClass.AUTH_FAILURE),
        ("fatal: Could not resolve host: github.com", FailureClass.NETWORK_FAILURE),
    ],
)
def test_classifier_maps_required_failure_classes(text: str, expected: FailureClass) -> None:
    result = classify_failure(text)

    assert result.failure_class == expected
    assert result.decision == "CLASSIFIED"
    assert result.audit_reason == f"{expected.value}_PATTERN_MATCH"
    assert len(result.input_hash) == 64


def test_unknown_failure_fails_closed_with_audit_reason() -> None:
    result = classify_failure({"message": "ambiguous condition"})

    assert result.failure_class == FailureClass.UNKNOWN_FAILURE
    assert result.decision == "FAIL_CLOSED"
    assert result.audit_reason == "NO_DETERMINISTIC_PATTERN_MATCH"


def test_repeated_same_input_produces_same_output() -> None:
    payload = {"stderr": "pytest failed with AssertionError", "exit_code": 1}

    first = classify_failure(payload).to_dict()
    second = classify_failure(payload).to_dict()

    assert first == second
