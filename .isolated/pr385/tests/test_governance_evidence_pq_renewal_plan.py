from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

from governance.evidence_pq_renewal_plan import (
    EVIDENCE_PQ_RENEWAL_PLAN_ERROR_CODES,
    create_pq_renewal_plan,
    explain_pq_renewal_plan_failure,
    load_pq_renewal_plan_error_registry,
    verify_pq_renewal_plan,
)
from tests.test_governance_evidence_record_chain import _record


ROOT = Path(__file__).resolve().parents[1]


def _plan(target_signature_family: str = "ML_DSA", target_hash_algorithm: str = "SHA3_512") -> tuple[dict, dict]:
    evidence_record, _archive = _record()
    plan = create_pq_renewal_plan(
        evidence_record,
        target_hash_algorithm=target_hash_algorithm,
        target_signature_family=target_signature_family,
        migration_reason="post_quantum_readiness",
        validation_policy_id="usb.pq.v1",
    )
    return plan, evidence_record


def test_valid_ml_dsa_renewal_plan() -> None:
    plan, evidence_record = _plan("ML_DSA")

    result = verify_pq_renewal_plan(plan, evidence_record=evidence_record)

    assert result.valid is True
    assert result.errors == ()
    assert result.target_signature_family == "ML_DSA"


def test_valid_slh_dsa_renewal_plan() -> None:
    plan, evidence_record = _plan("SLH_DSA")

    result = verify_pq_renewal_plan(plan, evidence_record=evidence_record)

    assert result.valid is True
    assert result.errors == ()
    assert result.target_signature_family == "SLH_DSA"


def test_valid_hybrid_ed25519_ml_dsa_renewal_plan() -> None:
    plan, evidence_record = _plan("HYBRID_ED25519_ML_DSA")

    result = verify_pq_renewal_plan(plan, evidence_record=evidence_record)

    assert result.valid is True
    assert result.errors == ()
    assert result.target_signature_family == "HYBRID_ED25519_ML_DSA"


def test_downgrade_rejection() -> None:
    evidence_record, _archive = _record()
    try:
        create_pq_renewal_plan(
            evidence_record,
            target_hash_algorithm="SHA256",
            target_signature_family="ML_DSA",
            migration_reason="post_quantum_readiness",
            validation_policy_id="usb.pq.v1",
        )
    except Exception as exc:
        assert str(exc) == "PQ_RENEWAL_DOWNGRADE_DETECTED"
    else:
        raise AssertionError("hash downgrade was allowed")


def test_invalid_target_algorithm_rejection() -> None:
    evidence_record, _archive = _record()
    try:
        create_pq_renewal_plan(
            evidence_record,
            target_hash_algorithm="MD5",
            target_signature_family="ML_DSA",
            migration_reason="post_quantum_readiness",
            validation_policy_id="usb.pq.v1",
        )
    except Exception as exc:
        assert str(exc) == "PQ_RENEWAL_TARGET_ALGORITHM_INVALID"
    else:
        raise AssertionError("invalid target hash algorithm was allowed")


def test_invalid_signature_family_rejection() -> None:
    evidence_record, _archive = _record()
    try:
        create_pq_renewal_plan(
            evidence_record,
            target_hash_algorithm="SHA3_512",
            target_signature_family="RSA",
            migration_reason="post_quantum_readiness",
            validation_policy_id="usb.pq.v1",
        )
    except Exception as exc:
        assert str(exc) == "PQ_RENEWAL_SIGNATURE_FAMILY_INVALID"
    else:
        raise AssertionError("invalid signature family was allowed")


def test_append_only_violation_rejection() -> None:
    plan, evidence_record = _plan()
    plan["append_only_position"] = 8

    result = verify_pq_renewal_plan(plan, evidence_record=evidence_record)

    assert result.valid is False
    assert "PQ_RENEWAL_APPEND_ONLY_VIOLATION" in result.errors


def test_replay_rejection() -> None:
    plan, evidence_record = _plan()

    result = verify_pq_renewal_plan(plan, evidence_record=evidence_record, existing_plans=[plan])

    assert result.valid is False
    assert "PQ_RENEWAL_REPLAY_DETECTED" in result.errors


def test_unsafe_diagnostics_rejection() -> None:
    plan, evidence_record = _plan()
    plan["diagnostics"] = {"approval_contents": "do-not-export"}

    result = verify_pq_renewal_plan(plan, evidence_record=evidence_record)

    assert result.valid is False
    assert "PQ_RENEWAL_DIAGNOSTICS_UNSAFE" in result.errors


def test_pq_renewal_error_registry_complete() -> None:
    registry = load_pq_renewal_plan_error_registry(ROOT)

    assert set(EVIDENCE_PQ_RENEWAL_PLAN_ERROR_CODES).issubset(registry)
    assert explain_pq_renewal_plan_failure(ROOT, "PQ_RENEWAL_DOWNGRADE_DETECTED")["fail_closed_reason"]


def test_create_and_verify_cli_redacts_output(tmp_path: Path) -> None:
    evidence_record, _archive = _record()
    evidence_record_path = tmp_path / "evidence-record.json"
    plan_path = tmp_path / "pq-renewal-plan.json"
    evidence_record_path.write_text(json.dumps(evidence_record, sort_keys=True), encoding="utf-8")

    created = subprocess.run(
        [
            sys.executable,
            "scripts/governance_diagnostics.py",
            "create-pq-renewal-plan",
            "--evidence-record",
            str(evidence_record_path),
            "--target-hash-algorithm",
            "SHA3_512",
            "--target-signature-family",
            "ML_DSA",
            "--migration-reason",
            "post_quantum_readiness",
            "--validation-policy-id",
            "usb.pq.v1",
            "--output",
            str(plan_path),
        ],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
    )

    assert created.returncode == 0
    assert plan_path.is_file()
    assert "approval_contents" not in created.stdout
    assert "PRIVATE KEY" not in created.stdout

    verified = subprocess.run(
        [
            sys.executable,
            "scripts/governance_diagnostics.py",
            "verify-pq-renewal-plan",
            "--pq-renewal-plan",
            str(plan_path),
            "--evidence-record",
            str(evidence_record_path),
        ],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
    )

    assert verified.returncode == 0
    assert '"valid":true' in verified.stdout
