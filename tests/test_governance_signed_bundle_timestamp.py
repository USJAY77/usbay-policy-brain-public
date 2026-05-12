from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

from governance.rfc3161_timestamp import DEFAULT_POLICY_OID_PLACEHOLDER
from governance.signed_bundle_timestamp import (
    SIGNED_BUNDLE_TIMESTAMP_ERROR_CODES,
    attach_signed_bundle_timestamp,
    explain_signed_bundle_timestamp_failure,
    load_signed_bundle_timestamp_error_registry,
    verify_signed_bundle_timestamp,
)
from tests.test_governance_signed_auditor_bundle import _signed_envelope


ROOT = Path(__file__).resolve().parents[1]


def _attachment() -> tuple[dict, dict, dict]:
    envelope, auditor_bundle, policy = _signed_envelope()
    attachment = attach_signed_bundle_timestamp(
        envelope,
        trust_policy=policy,
        tsa_policy_id=DEFAULT_POLICY_OID_PLACEHOLDER,
        tsa_gen_time_utc="2026-05-12T00:06:00Z",
    )
    return attachment, envelope, policy


def test_valid_timestamp_attachment() -> None:
    attachment, envelope, _policy = _attachment()
    result = verify_signed_bundle_timestamp(attachment, signed_bundle=envelope)

    assert result.valid is True
    assert result.errors == ()
    assert result.signed_bundle_id == envelope["signed_bundle_id"]
    assert attachment["hash_algorithm"] == "SHA256"


def test_signed_bundle_hash_mismatch_rejection() -> None:
    attachment, envelope, _policy = _attachment()
    attachment["signed_bundle_hash"] = "0" * 64

    result = verify_signed_bundle_timestamp(attachment, signed_bundle=envelope)

    assert result.valid is False
    assert "SIGNED_BUNDLE_TIMESTAMP_HASH_MISMATCH" in result.errors


def test_invalid_timestamp_token_rejection() -> None:
    attachment, envelope, _policy = _attachment()
    attachment["timestamp_token_hash"] = "f" * 64

    result = verify_signed_bundle_timestamp(attachment, signed_bundle=envelope)

    assert result.valid is False
    assert "SIGNED_BUNDLE_TIMESTAMP_TOKEN_INVALID" in result.errors


def test_invalid_tsa_policy_rejection() -> None:
    attachment, envelope, _policy = _attachment()
    attachment["tsa_policy_id"] = "not-an-oid"

    result = verify_signed_bundle_timestamp(attachment, signed_bundle=envelope)

    assert result.valid is False
    assert "SIGNED_BUNDLE_TIMESTAMP_POLICY_INVALID" in result.errors


def test_replay_rejection() -> None:
    attachment, envelope, _policy = _attachment()

    result = verify_signed_bundle_timestamp(attachment, signed_bundle=envelope, existing_attachments=[attachment])

    assert result.valid is False
    assert "SIGNED_BUNDLE_TIMESTAMP_REPLAY_DETECTED" in result.errors


def test_invalid_scope_rejection() -> None:
    attachment, envelope, _policy = _attachment()
    attachment["verification_scope"] = {"tenant_id": "t1"}

    result = verify_signed_bundle_timestamp(attachment, signed_bundle=envelope)

    assert result.valid is False
    assert "SIGNED_BUNDLE_TIMESTAMP_SCOPE_INVALID" in result.errors


def test_unsafe_diagnostics_rejected() -> None:
    attachment, envelope, _policy = _attachment()
    attachment["diagnostics"] = {"approval_contents": "do-not-export"}

    result = verify_signed_bundle_timestamp(attachment, signed_bundle=envelope)

    assert result.valid is False
    assert "SIGNED_BUNDLE_TIMESTAMP_DIAGNOSTICS_UNSAFE" in result.errors


def test_signed_bundle_timestamp_error_registry_complete() -> None:
    registry = load_signed_bundle_timestamp_error_registry(ROOT)

    assert set(SIGNED_BUNDLE_TIMESTAMP_ERROR_CODES).issubset(registry)
    assert explain_signed_bundle_timestamp_failure(ROOT, "SIGNED_BUNDLE_TIMESTAMP_TOKEN_INVALID")["fail_closed_reason"]


def test_attach_and_verify_cli_redacts_output(tmp_path: Path) -> None:
    envelope, _auditor_bundle, policy = _signed_envelope()
    envelope_path = tmp_path / "signed-auditor-bundle.json"
    trust_policy_path = tmp_path / "trust-policy.json"
    attachment_path = tmp_path / "timestamp-attachment.json"
    envelope_path.write_text(json.dumps(envelope, sort_keys=True), encoding="utf-8")
    trust_policy_path.write_text(json.dumps(policy, sort_keys=True), encoding="utf-8")

    created = subprocess.run(
        [
            sys.executable,
            "scripts/governance_diagnostics.py",
            "attach-signed-bundle-timestamp",
            "--signed-auditor-bundle",
            str(envelope_path),
            "--trust-policy",
            str(trust_policy_path),
            "--validation-timestamp",
            "2026-05-12T00:06:00Z",
            "--output",
            str(attachment_path),
        ],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
    )

    assert created.returncode == 0
    assert attachment_path.is_file()
    assert "approval_contents" not in created.stdout
    assert "PRIVATE KEY" not in created.stdout
    assert "PRIVATE KEY" not in attachment_path.read_text(encoding="utf-8")

    verified = subprocess.run(
        [
            sys.executable,
            "scripts/governance_diagnostics.py",
            "verify-signed-bundle-timestamp",
            "--signed-bundle-timestamp",
            str(attachment_path),
            "--signed-auditor-bundle",
            str(envelope_path),
        ],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
    )

    assert verified.returncode == 0
    assert '"valid":true' in verified.stdout
