from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

from governance.signed_bundle_revocation_preflight import (
    REVOCATION_PREFLIGHT_ERROR_CODES,
    SignedBundleRevocationPreflightError,
    create_revocation_preflight,
    explain_revocation_preflight_failure,
    load_revocation_preflight_error_registry,
    verify_revocation_preflight,
)
from tests.test_governance_signed_bundle_ltv import _ltv


ROOT = Path(__file__).resolve().parents[1]
OCSP_SOURCE_HASH = "d" * 64
CRL_SOURCE_HASH = "e" * 64


def _preflight(source_type: str = "OCSP", source_hash: str = OCSP_SOURCE_HASH) -> tuple[dict, dict]:
    ltv, _attachment = _ltv()
    preflight = create_revocation_preflight(
        ltv,
        revocation_source_type=source_type,
        revocation_source_uri_hash=source_hash,
        expected_freshness_window_seconds=86400,
        checked_at_utc="2026-05-12T00:08:00Z",
        validation_policy_id="usb.ltv.v1",
    )
    return preflight, ltv


def test_valid_ocsp_preflight() -> None:
    preflight, ltv = _preflight("OCSP", OCSP_SOURCE_HASH)

    result = verify_revocation_preflight(preflight, ltv_evidence=ltv)

    assert result.valid is True
    assert result.errors == ()
    assert result.revocation_source_type == "OCSP"
    assert result.ltv_evidence_id == ltv["ltv_evidence_id"]


def test_valid_crl_preflight() -> None:
    preflight, ltv = _preflight("CRL", CRL_SOURCE_HASH)

    result = verify_revocation_preflight(preflight, ltv_evidence=ltv)

    assert result.valid is True
    assert result.errors == ()
    assert result.revocation_source_type == "CRL"


def test_missing_ltv_evidence_rejection() -> None:
    try:
        create_revocation_preflight(
            {},
            revocation_source_type="OCSP",
            revocation_source_uri_hash=OCSP_SOURCE_HASH,
            expected_freshness_window_seconds=86400,
            checked_at_utc="2026-05-12T00:08:00Z",
            validation_policy_id="usb.ltv.v1",
        )
    except SignedBundleRevocationPreflightError as exc:
        assert str(exc) == "REVOCATION_PREFLIGHT_LTV_MISSING"
    else:
        raise AssertionError("missing LTV evidence was allowed")


def test_missing_certificate_fingerprint_rejection() -> None:
    preflight, ltv = _preflight()
    preflight["tsa_certificate_fingerprint"] = ""

    result = verify_revocation_preflight(preflight, ltv_evidence=ltv)

    assert result.valid is False
    assert "REVOCATION_PREFLIGHT_CERT_MISSING" in result.errors


def test_missing_source_rejection() -> None:
    preflight, ltv = _preflight()
    preflight["revocation_source_uri_hash"] = ""

    result = verify_revocation_preflight(preflight, ltv_evidence=ltv)

    assert result.valid is False
    assert "REVOCATION_PREFLIGHT_SOURCE_MISSING" in result.errors


def test_invalid_source_type_rejection() -> None:
    preflight, ltv = _preflight()
    preflight["revocation_source_type"] = "LDAP"

    result = verify_revocation_preflight(preflight, ltv_evidence=ltv)

    assert result.valid is False
    assert "REVOCATION_PREFLIGHT_SOURCE_INVALID" in result.errors


def test_stale_freshness_window_rejection() -> None:
    preflight, ltv = _preflight()
    preflight["expected_freshness_window_seconds"] = 0

    result = verify_revocation_preflight(preflight, ltv_evidence=ltv)

    assert result.valid is False
    assert "REVOCATION_PREFLIGHT_FRESHNESS_INVALID" in result.errors


def test_hash_mismatch_rejection() -> None:
    preflight, ltv = _preflight()
    preflight["preflight_id"] = "0" * 64

    result = verify_revocation_preflight(preflight, ltv_evidence=ltv)

    assert result.valid is False
    assert "REVOCATION_PREFLIGHT_HASH_MISMATCH" in result.errors


def test_replay_rejection() -> None:
    preflight, ltv = _preflight()

    result = verify_revocation_preflight(preflight, ltv_evidence=ltv, existing_preflights=[preflight])

    assert result.valid is False
    assert "REVOCATION_PREFLIGHT_REPLAY_DETECTED" in result.errors


def test_unsafe_diagnostics_rejection() -> None:
    preflight, ltv = _preflight()
    preflight["diagnostics"] = {"approval_contents": "do-not-export"}

    result = verify_revocation_preflight(preflight, ltv_evidence=ltv)

    assert result.valid is False
    assert "REVOCATION_PREFLIGHT_DIAGNOSTICS_UNSAFE" in result.errors


def test_revocation_preflight_error_registry_complete() -> None:
    registry = load_revocation_preflight_error_registry(ROOT)

    assert set(REVOCATION_PREFLIGHT_ERROR_CODES).issubset(registry)
    assert explain_revocation_preflight_failure(ROOT, "REVOCATION_PREFLIGHT_HASH_MISMATCH")["fail_closed_reason"]


def test_create_and_verify_cli_redacts_output(tmp_path: Path) -> None:
    preflight_path = tmp_path / "revocation-preflight.json"
    ltv_path = tmp_path / "ltv-evidence.json"
    ltv, _attachment = _ltv()
    ltv_path.write_text(json.dumps(ltv, sort_keys=True), encoding="utf-8")

    created = subprocess.run(
        [
            sys.executable,
            "scripts/governance_diagnostics.py",
            "create-revocation-preflight",
            "--signed-bundle-ltv-evidence",
            str(ltv_path),
            "--revocation-source-type",
            "OCSP",
            "--revocation-source-uri-hash",
            OCSP_SOURCE_HASH,
            "--expected-freshness-window-seconds",
            "86400",
            "--validation-policy-id",
            "usb.ltv.v1",
            "--validation-timestamp",
            "2026-05-12T00:08:00Z",
            "--output",
            str(preflight_path),
        ],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
    )

    assert created.returncode == 0
    assert preflight_path.is_file()
    assert "approval_contents" not in created.stdout
    assert "PRIVATE KEY" not in created.stdout
    assert "PRIVATE KEY" not in preflight_path.read_text(encoding="utf-8")

    verified = subprocess.run(
        [
            sys.executable,
            "scripts/governance_diagnostics.py",
            "verify-revocation-preflight",
            "--revocation-preflight",
            str(preflight_path),
            "--signed-bundle-ltv-evidence",
            str(ltv_path),
        ],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
    )

    assert verified.returncode == 0
    assert '"valid":true' in verified.stdout
