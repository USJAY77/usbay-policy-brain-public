from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

from governance.signed_bundle_revocation_response import (
    REVOCATION_RESPONSE_ERROR_CODES,
    create_revocation_response,
    explain_revocation_response_failure,
    load_revocation_response_error_registry,
    verify_revocation_response,
)
from tests.test_governance_signed_bundle_revocation_preflight import CRL_SOURCE_HASH, _preflight


ROOT = Path(__file__).resolve().parents[1]
RESPONDER_KEY = "f" * 64


def _response(source_type: str = "OCSP") -> tuple[dict, dict, dict]:
    preflight, ltv = _preflight(source_type=source_type, source_hash=CRL_SOURCE_HASH if source_type == "CRL" else "d" * 64)
    response = create_revocation_response(
        preflight,
        response_status="GOOD",
        response_this_update_utc="2026-05-12T00:07:30Z",
        response_next_update_utc="2026-05-13T00:07:30Z",
        responder_key_fingerprint=RESPONDER_KEY,
        checked_at_utc="2026-05-12T00:08:30Z",
        validation_policy_id="usb.ltv.v1",
    )
    return response, preflight, ltv


def test_valid_ocsp_good_response_verification() -> None:
    response, preflight, ltv = _response("OCSP")

    result = verify_revocation_response(response, preflight=preflight, ltv_evidence=ltv)

    assert result.valid is True
    assert result.errors == ()
    assert result.response_status == "GOOD"
    assert result.revocation_source_type == "OCSP"


def test_valid_crl_good_response_verification() -> None:
    response, preflight, ltv = _response("CRL")

    result = verify_revocation_response(response, preflight=preflight, ltv_evidence=ltv)

    assert result.valid is True
    assert result.errors == ()
    assert result.revocation_source_type == "CRL"


def test_revoked_status_rejection() -> None:
    response, preflight, ltv = _response()
    response["response_status"] = "REVOKED"

    result = verify_revocation_response(response, preflight=preflight, ltv_evidence=ltv)

    assert result.valid is False
    assert "REVOCATION_RESPONSE_STATUS_REVOKED" in result.errors


def test_unknown_status_rejection() -> None:
    response, preflight, ltv = _response()
    response["response_status"] = "UNKNOWN"

    result = verify_revocation_response(response, preflight=preflight, ltv_evidence=ltv)

    assert result.valid is False
    assert "REVOCATION_RESPONSE_STATUS_UNKNOWN" in result.errors


def test_stale_response_rejection() -> None:
    response, preflight, ltv = _response()
    response["response_next_update_utc"] = "2026-05-12T00:08:00Z"

    result = verify_revocation_response(response, preflight=preflight, ltv_evidence=ltv)

    assert result.valid is False
    assert "REVOCATION_RESPONSE_STALE" in result.errors


def test_invalid_this_update_next_update_rejection() -> None:
    response, preflight, ltv = _response()
    response["response_this_update_utc"] = "2026-05-13T00:07:30Z"

    result = verify_revocation_response(response, preflight=preflight, ltv_evidence=ltv)

    assert result.valid is False
    assert "REVOCATION_RESPONSE_TIME_INVALID" in result.errors


def test_source_mismatch_rejection() -> None:
    response, preflight, ltv = _response()
    response["revocation_source_uri_hash"] = "e" * 64

    result = verify_revocation_response(response, preflight=preflight, ltv_evidence=ltv)

    assert result.valid is False
    assert "REVOCATION_RESPONSE_SOURCE_MISMATCH" in result.errors


def test_signature_mismatch_rejection() -> None:
    response, preflight, ltv = _response()
    response["response_signature_fingerprint"] = "0" * 64

    result = verify_revocation_response(response, preflight=preflight, ltv_evidence=ltv)

    assert result.valid is False
    assert "REVOCATION_RESPONSE_SIGNATURE_INVALID" in result.errors


def test_nonce_mismatch_rejection() -> None:
    response, preflight, ltv = _response()
    response["response_nonce_hash"] = "0" * 64

    result = verify_revocation_response(response, preflight=preflight, ltv_evidence=ltv)

    assert result.valid is False
    assert "REVOCATION_RESPONSE_NONCE_MISMATCH" in result.errors


def test_replay_rejection() -> None:
    response, preflight, ltv = _response()

    result = verify_revocation_response(response, preflight=preflight, ltv_evidence=ltv, existing_responses=[response])

    assert result.valid is False
    assert "REVOCATION_RESPONSE_REPLAY_DETECTED" in result.errors


def test_unsafe_diagnostics_rejection() -> None:
    response, preflight, ltv = _response()
    response["diagnostics"] = {"approval_contents": "do-not-export"}

    result = verify_revocation_response(response, preflight=preflight, ltv_evidence=ltv)

    assert result.valid is False
    assert "REVOCATION_RESPONSE_DIAGNOSTICS_UNSAFE" in result.errors


def test_revocation_response_error_registry_complete() -> None:
    registry = load_revocation_response_error_registry(ROOT)

    assert set(REVOCATION_RESPONSE_ERROR_CODES).issubset(registry)
    assert explain_revocation_response_failure(ROOT, "REVOCATION_RESPONSE_HASH_MISMATCH")["fail_closed_reason"]


def test_create_and_verify_cli_redacts_output(tmp_path: Path) -> None:
    response_path = tmp_path / "revocation-response.json"
    preflight_path = tmp_path / "revocation-preflight.json"
    ltv_path = tmp_path / "ltv-evidence.json"
    preflight, ltv = _preflight()
    preflight_path.write_text(json.dumps(preflight, sort_keys=True), encoding="utf-8")
    ltv_path.write_text(json.dumps(ltv, sort_keys=True), encoding="utf-8")

    created = subprocess.run(
        [
            sys.executable,
            "scripts/governance_diagnostics.py",
            "create-revocation-response",
            "--revocation-preflight",
            str(preflight_path),
            "--response-status",
            "GOOD",
            "--response-this-update-utc",
            "2026-05-12T00:07:30Z",
            "--response-next-update-utc",
            "2026-05-13T00:07:30Z",
            "--responder-key-fingerprint",
            RESPONDER_KEY,
            "--validation-policy-id",
            "usb.ltv.v1",
            "--validation-timestamp",
            "2026-05-12T00:08:30Z",
            "--output",
            str(response_path),
        ],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
    )

    assert created.returncode == 0
    assert response_path.is_file()
    assert "approval_contents" not in created.stdout
    assert "PRIVATE KEY" not in created.stdout
    assert "PRIVATE KEY" not in response_path.read_text(encoding="utf-8")

    verified = subprocess.run(
        [
            sys.executable,
            "scripts/governance_diagnostics.py",
            "verify-revocation-response",
            "--revocation-response",
            str(response_path),
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
