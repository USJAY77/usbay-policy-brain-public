from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

from governance.pq_runtime_verification import (
    PQ_RUNTIME_VERIFICATION_ERROR_CODES,
    create_pq_runtime_verification,
    explain_pq_runtime_verification_failure,
    load_pq_runtime_verification_error_registry,
    verify_pq_runtime_verification,
)
from tests.test_governance_evidence_pq_renewal_plan import _plan


ROOT = Path(__file__).resolve().parents[1]
POLICY_DECISION_ID = "a" * 64


def _runtime_record() -> tuple[dict, dict]:
    plan, _evidence_record = _plan()
    record = create_pq_runtime_verification(
        plan,
        verifier_mode="STUB_ONLY",
        policy_decision_id=POLICY_DECISION_ID,
        policy_decision="ALLOW",
        validation_policy_id="usb.pq.v1",
    )
    return record, plan


def test_valid_governance_approved_stub_only_runtime_verification() -> None:
    record, plan = _runtime_record()

    result = verify_pq_runtime_verification(record, pq_renewal_plan=plan)

    assert result.valid is True
    assert result.errors == ()
    assert result.verifier_mode == "STUB_ONLY"
    assert result.policy_decision == "ALLOW"


def test_missing_pq_renewal_plan_rejection() -> None:
    try:
        create_pq_runtime_verification(
            {},
            verifier_mode="STUB_ONLY",
            policy_decision_id=POLICY_DECISION_ID,
            policy_decision="ALLOW",
            validation_policy_id="usb.pq.v1",
        )
    except Exception as exc:
        assert str(exc) == "PQ_RUNTIME_PLAN_MISSING"
    else:
        raise AssertionError("missing PQ renewal plan was allowed")


def test_missing_policy_decision_rejection() -> None:
    plan, _evidence_record = _plan()
    try:
        create_pq_runtime_verification(
            plan,
            verifier_mode="STUB_ONLY",
            policy_decision_id="",
            policy_decision="ALLOW",
            validation_policy_id="usb.pq.v1",
        )
    except Exception as exc:
        assert str(exc) == "PQ_RUNTIME_POLICY_MISSING"
    else:
        raise AssertionError("missing policy decision was allowed")


def test_deny_policy_rejection() -> None:
    plan, _evidence_record = _plan()
    try:
        create_pq_runtime_verification(
            plan,
            verifier_mode="STUB_ONLY",
            policy_decision_id=POLICY_DECISION_ID,
            policy_decision="DENY",
            validation_policy_id="usb.pq.v1",
        )
    except Exception as exc:
        assert str(exc) == "PQ_RUNTIME_POLICY_DENIED"
    else:
        raise AssertionError("DENY policy decision was allowed")


def test_invalid_verifier_mode_rejection() -> None:
    record, plan = _runtime_record()
    record["verifier_mode"] = "LIVE_PQC"

    result = verify_pq_runtime_verification(record, pq_renewal_plan=plan)

    assert result.valid is False
    assert "PQ_RUNTIME_VERIFIER_MODE_INVALID" in result.errors


def test_invalid_signature_family_rejection() -> None:
    record, plan = _runtime_record()
    record["target_signature_family"] = "RSA"

    result = verify_pq_runtime_verification(record, pq_renewal_plan=plan)

    assert result.valid is False
    assert "PQ_RUNTIME_SIGNATURE_FAMILY_INVALID" in result.errors


def test_invalid_hash_algorithm_rejection() -> None:
    record, plan = _runtime_record()
    record["target_hash_algorithm"] = "MD5"

    result = verify_pq_runtime_verification(record, pq_renewal_plan=plan)

    assert result.valid is False
    assert "PQ_RUNTIME_HASH_ALGORITHM_INVALID" in result.errors


def test_replay_rejection() -> None:
    record, plan = _runtime_record()

    result = verify_pq_runtime_verification(record, pq_renewal_plan=plan, existing_records=[record])

    assert result.valid is False
    assert "PQ_RUNTIME_REPLAY_DETECTED" in result.errors


def test_append_only_violation_rejection() -> None:
    record, plan = _runtime_record()
    record["append_only_position"] = 8

    result = verify_pq_runtime_verification(record, pq_renewal_plan=plan)

    assert result.valid is False
    assert "PQ_RUNTIME_APPEND_ONLY_VIOLATION" in result.errors


def test_unsafe_diagnostics_rejection() -> None:
    record, plan = _runtime_record()
    record["diagnostics"] = {"approval_contents": "do-not-export"}

    result = verify_pq_runtime_verification(record, pq_renewal_plan=plan)

    assert result.valid is False
    assert "PQ_RUNTIME_DIAGNOSTICS_UNSAFE" in result.errors


def test_pq_runtime_error_registry_complete() -> None:
    registry = load_pq_runtime_verification_error_registry(ROOT)

    assert set(PQ_RUNTIME_VERIFICATION_ERROR_CODES).issubset(registry)
    assert explain_pq_runtime_verification_failure(ROOT, "PQ_RUNTIME_POLICY_DENIED")["fail_closed_reason"]


def test_create_and_verify_cli_redacts_output(tmp_path: Path) -> None:
    plan, _evidence_record = _plan()
    plan_path = tmp_path / "pq-renewal-plan.json"
    record_path = tmp_path / "pq-runtime-verification.json"
    plan_path.write_text(json.dumps(plan, sort_keys=True), encoding="utf-8")

    created = subprocess.run(
        [
            sys.executable,
            "scripts/governance_diagnostics.py",
            "create-pq-runtime-verification",
            "--pq-renewal-plan",
            str(plan_path),
            "--verifier-mode",
            "STUB_ONLY",
            "--policy-decision-id",
            POLICY_DECISION_ID,
            "--policy-decision",
            "ALLOW",
            "--validation-policy-id",
            "usb.pq.v1",
            "--output",
            str(record_path),
        ],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
    )

    assert created.returncode == 0
    assert record_path.is_file()
    assert "approval_contents" not in created.stdout
    assert "PRIVATE KEY" not in created.stdout

    verified = subprocess.run(
        [
            sys.executable,
            "scripts/governance_diagnostics.py",
            "verify-pq-runtime-verification",
            "--pq-runtime-verification",
            str(record_path),
            "--pq-renewal-plan",
            str(plan_path),
        ],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
    )

    assert verified.returncode == 0
    assert '"valid":true' in verified.stdout
