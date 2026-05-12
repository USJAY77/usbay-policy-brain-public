from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

from governance.signed_bundle_ltv import (
    SIGNED_BUNDLE_LTV_ERROR_CODES,
    create_signed_bundle_ltv_evidence,
    explain_signed_bundle_ltv_failure,
    load_signed_bundle_ltv_error_registry,
    verify_signed_bundle_ltv_evidence,
)
from tests.test_governance_signed_bundle_timestamp import _attachment


ROOT = Path(__file__).resolve().parents[1]
TSA_CERT = "a" * 64
TRUST_ANCHOR = "b" * 64
REVOCATION_HASH = "c" * 64


def _ltv() -> tuple[dict, dict]:
    attachment, _envelope, _policy = _attachment()
    ltv = create_signed_bundle_ltv_evidence(
        attachment,
        tsa_certificate_fingerprint=TSA_CERT,
        tsa_certificate_chain_fingerprints=[TSA_CERT, TRUST_ANCHOR],
        trust_anchor_fingerprint=TRUST_ANCHOR,
        revocation_evidence_type="offline_mock",
        revocation_evidence_hash=REVOCATION_HASH,
        revocation_checked_at_utc="2026-05-12T00:07:00Z",
        validation_policy_id="usb.ltv.v1",
    )
    return ltv, attachment


def test_valid_ltv_evidence() -> None:
    ltv, attachment = _ltv()
    result = verify_signed_bundle_ltv_evidence(ltv, timestamp_attachment=attachment)

    assert result.valid is True
    assert result.errors == ()
    assert result.timestamp_attachment_id == attachment["timestamp_attachment_id"]
    assert result.timestamp_token_hash == attachment["timestamp_token_hash"]


def test_missing_timestamp_rejection() -> None:
    ltv, _attachment = _ltv()
    ltv["timestamp_attachment_id"] = ""

    result = verify_signed_bundle_ltv_evidence(ltv)

    assert result.valid is False
    assert "SIGNED_BUNDLE_LTV_TIMESTAMP_MISSING" in result.errors


def test_missing_tsa_certificate_chain_rejection() -> None:
    ltv, _attachment = _ltv()
    ltv["tsa_certificate_chain_fingerprints"] = []

    result = verify_signed_bundle_ltv_evidence(ltv)

    assert result.valid is False
    assert "SIGNED_BUNDLE_LTV_CERT_CHAIN_MISSING" in result.errors


def test_missing_trust_anchor_rejection() -> None:
    ltv, _attachment = _ltv()
    ltv["trust_anchor_fingerprint"] = "d" * 64

    result = verify_signed_bundle_ltv_evidence(ltv)

    assert result.valid is False
    assert "SIGNED_BUNDLE_LTV_TRUST_ANCHOR_MISSING" in result.errors


def test_missing_revocation_evidence_rejection() -> None:
    ltv, _attachment = _ltv()
    ltv["revocation_evidence_hash"] = ""

    result = verify_signed_bundle_ltv_evidence(ltv)

    assert result.valid is False
    assert "SIGNED_BUNDLE_LTV_REVOCATION_MISSING" in result.errors


def test_hash_mismatch_rejection() -> None:
    ltv, _attachment = _ltv()
    ltv["ltv_evidence_id"] = "0" * 64

    result = verify_signed_bundle_ltv_evidence(ltv)

    assert result.valid is False
    assert "SIGNED_BUNDLE_LTV_HASH_MISMATCH" in result.errors


def test_invalid_validation_policy_rejection() -> None:
    ltv, _attachment = _ltv()
    ltv["validation_policy_id"] = ""

    result = verify_signed_bundle_ltv_evidence(ltv)

    assert result.valid is False
    assert "SIGNED_BUNDLE_LTV_POLICY_INVALID" in result.errors


def test_replay_rejection() -> None:
    ltv, attachment = _ltv()

    result = verify_signed_bundle_ltv_evidence(ltv, timestamp_attachment=attachment, existing_evidence=[ltv])

    assert result.valid is False
    assert "SIGNED_BUNDLE_LTV_REPLAY_DETECTED" in result.errors


def test_unsafe_diagnostics_rejected() -> None:
    ltv, attachment = _ltv()
    ltv["diagnostics"] = {"approval_contents": "do-not-export"}

    result = verify_signed_bundle_ltv_evidence(ltv, timestamp_attachment=attachment)

    assert result.valid is False
    assert "SIGNED_BUNDLE_LTV_DIAGNOSTICS_UNSAFE" in result.errors


def test_ltv_error_registry_complete() -> None:
    registry = load_signed_bundle_ltv_error_registry(ROOT)

    assert set(SIGNED_BUNDLE_LTV_ERROR_CODES).issubset(registry)
    assert explain_signed_bundle_ltv_failure(ROOT, "SIGNED_BUNDLE_LTV_HASH_MISMATCH")["fail_closed_reason"]


def test_create_and_verify_cli_redacts_output(tmp_path: Path) -> None:
    attachment, _envelope, _policy = _attachment()
    attachment_path = tmp_path / "timestamp-attachment.json"
    ltv_path = tmp_path / "ltv-evidence.json"
    attachment_path.write_text(json.dumps(attachment, sort_keys=True), encoding="utf-8")

    created = subprocess.run(
        [
            sys.executable,
            "scripts/governance_diagnostics.py",
            "create-signed-bundle-ltv-evidence",
            "--signed-bundle-timestamp",
            str(attachment_path),
            "--tsa-certificate-fingerprint",
            TSA_CERT,
            "--tsa-certificate-chain-fingerprint",
            TSA_CERT,
            "--tsa-certificate-chain-fingerprint",
            TRUST_ANCHOR,
            "--trust-anchor-fingerprint",
            TRUST_ANCHOR,
            "--revocation-evidence-type",
            "offline_mock",
            "--revocation-evidence-hash",
            REVOCATION_HASH,
            "--validation-policy-id",
            "usb.ltv.v1",
            "--validation-timestamp",
            "2026-05-12T00:07:00Z",
            "--output",
            str(ltv_path),
        ],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
    )

    assert created.returncode == 0
    assert ltv_path.is_file()
    assert "approval_contents" not in created.stdout
    assert "PRIVATE KEY" not in created.stdout
    assert "PRIVATE KEY" not in ltv_path.read_text(encoding="utf-8")

    verified = subprocess.run(
        [
            sys.executable,
            "scripts/governance_diagnostics.py",
            "verify-signed-bundle-ltv-evidence",
            "--signed-bundle-ltv-evidence",
            str(ltv_path),
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
