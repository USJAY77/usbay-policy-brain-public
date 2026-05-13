from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

from governance.rfc3161_timestamp import DEFAULT_POLICY_OID_PLACEHOLDER
from governance.tsa_live_verification import (
    TSA_LIVE_VERIFICATION_ERROR_CODES,
    explain_tsa_live_verification_failure,
    load_tsa_live_verification_error_registry,
    prepare_tsa_live_verification_plan,
    verify_tsa_live_verification_plan,
)
from tests.test_governance_signed_bundle_timestamp import _attachment


ROOT = Path(__file__).resolve().parents[1]


def _tsa_plan() -> tuple[dict, dict, dict]:
    attachment, envelope, policy = _attachment()
    plan = prepare_tsa_live_verification_plan(
        attachment,
        expected_tsa_policy_id=DEFAULT_POLICY_OID_PLACEHOLDER,
        verification_checked_at_utc="2026-05-12T00:07:00Z",
    )
    return plan, attachment, envelope


def test_valid_tsa_live_verification_plan() -> None:
    plan, attachment, _envelope = _tsa_plan()

    result = verify_tsa_live_verification_plan(plan, timestamp_attachment=attachment)

    assert result.valid is True
    assert result.errors == ()
    assert result.verification_mode == "LOCAL_ONLY"
    assert result.timestamp_attachment_id == attachment["timestamp_attachment_id"]
    assert plan["live_verification_output_path"].startswith("tsa-live://local-only/sha256/")


def test_missing_timestamp_attachment_rejection() -> None:
    result = verify_tsa_live_verification_plan({"schema": "usbay.governance_tsa_live_verification.v1"})

    assert result.valid is False
    assert "TSA_LIVE_TIMESTAMP_ATTACHMENT_MISSING" in result.errors


def test_malformed_imprint_rejection() -> None:
    plan, attachment, _envelope = _tsa_plan()
    plan["message_imprint_hash"] = "0" * 64

    result = verify_tsa_live_verification_plan(plan, timestamp_attachment=attachment)

    assert result.valid is False
    assert "TSA_LIVE_IMPRINT_MALFORMED" in result.errors


def test_unexpected_policy_id_rejection() -> None:
    plan, attachment, _envelope = _tsa_plan()
    plan["tsa_policy_id"] = "1.2.3.999"

    result = verify_tsa_live_verification_plan(plan, timestamp_attachment=attachment)

    assert result.valid is False
    assert "TSA_LIVE_POLICY_UNEXPECTED" in result.errors


def test_stale_timestamp_metadata_rejection() -> None:
    attachment, _envelope, _policy = _attachment()

    try:
        prepare_tsa_live_verification_plan(
            attachment,
            verification_checked_at_utc="2026-05-14T00:06:01Z",
            max_metadata_age_seconds=86_400,
        )
    except Exception as exc:
        assert "TSA_LIVE_TIMESTAMP_METADATA_STALE" in str(exc)
    else:
        raise AssertionError("stale TSA metadata must fail closed")


def test_signature_hash_mismatch_rejection() -> None:
    plan, attachment, _envelope = _tsa_plan()
    plan["timestamp_token_hash"] = "f" * 64

    result = verify_tsa_live_verification_plan(plan, timestamp_attachment=attachment)

    assert result.valid is False
    assert "TSA_LIVE_SIGNATURE_HASH_MISMATCH" in result.errors


def test_mutable_live_verification_output_path_rejection() -> None:
    plan, attachment, _envelope = _tsa_plan()
    plan["live_verification_output_path"] = "/tmp/live-tsa-verification.json"

    result = verify_tsa_live_verification_plan(plan, timestamp_attachment=attachment)

    assert result.valid is False
    assert "TSA_LIVE_OUTPUT_PATH_MUTABLE" in result.errors


def test_unsafe_diagnostics_rejection() -> None:
    plan, attachment, _envelope = _tsa_plan()
    plan["diagnostics"] = {"approval_contents": "do-not-export"}

    result = verify_tsa_live_verification_plan(plan, timestamp_attachment=attachment)

    assert result.valid is False
    assert "TSA_LIVE_DIAGNOSTICS_UNSAFE" in result.errors


def test_tsa_live_verification_error_registry_complete() -> None:
    registry = load_tsa_live_verification_error_registry(ROOT)

    assert set(TSA_LIVE_VERIFICATION_ERROR_CODES).issubset(registry)
    assert explain_tsa_live_verification_failure(ROOT, "TSA_LIVE_POLICY_UNEXPECTED")["fail_closed_reason"]


def test_create_and_verify_cli_redacts_output(tmp_path: Path) -> None:
    attachment, _envelope, _policy = _attachment()
    attachment_path = tmp_path / "timestamp-attachment.json"
    plan_path = tmp_path / "tsa-live-verification.json"
    attachment_path.write_text(json.dumps(attachment, sort_keys=True), encoding="utf-8")

    created = subprocess.run(
        [
            sys.executable,
            "scripts/governance_diagnostics.py",
            "prepare-tsa-live-verification",
            "--signed-bundle-timestamp",
            str(attachment_path),
            "--validation-timestamp",
            "2026-05-12T00:07:00Z",
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
    assert "PRIVATE KEY" not in plan_path.read_text(encoding="utf-8")

    verified = subprocess.run(
        [
            sys.executable,
            "scripts/governance_diagnostics.py",
            "verify-tsa-live-verification",
            "--tsa-live-verification",
            str(plan_path),
            "--signed-bundle-timestamp",
            str(attachment_path),
        ],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
    )

    assert verified.returncode == 0
    assert '"valid":true' in verified.stdout
    assert "approval_contents" not in verified.stdout
