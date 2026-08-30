from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

from governance.revocation_live_fetch import (
    REVOCATION_LIVE_FETCH_ERROR_CODES,
    explain_revocation_live_fetch_failure,
    load_revocation_live_fetch_error_registry,
    prepare_revocation_live_fetch_plan,
    verify_revocation_live_fetch_plan,
)
from tests.test_governance_signed_bundle_revocation_response import _response

ROOT = Path(__file__).resolve().parents[1]


def _plan() -> tuple[dict, dict, dict]:
    response, preflight, _ltv = _response()
    plan = prepare_revocation_live_fetch_plan(
        revocation_preflight=preflight,
        revocation_response=response,
        planned_at_utc="2026-05-12T00:09:00Z",
    )
    return plan, preflight, response


def test_valid_revocation_live_fetch_plan() -> None:
    plan, preflight, response = _plan()

    result = verify_revocation_live_fetch_plan(plan, revocation_preflight=preflight, revocation_response=response)

    assert result.valid is True
    assert result.errors == ()
    assert result.live_fetch_mode == "LOCAL_ONLY"
    assert result.revocation_source_type == "OCSP"
    assert plan["live_fetch_output_path"].startswith("revocation-live-fetch://local-only/sha256/")


def test_missing_source_metadata_fails_closed() -> None:
    plan, _preflight, response = _plan()
    plan["preflight_id"] = ""

    result = verify_revocation_live_fetch_plan(plan, revocation_response=response)

    assert result.valid is False
    assert "REVOCATION_LIVE_FETCH_SOURCE_MISSING" in result.errors


def test_malformed_source_metadata_fails_closed() -> None:
    plan, preflight, response = _plan()
    plan["revocation_source_type"] = "HTTP"

    result = verify_revocation_live_fetch_plan(plan, revocation_preflight=preflight, revocation_response=response)

    assert result.valid is False
    assert "REVOCATION_LIVE_FETCH_SOURCE_MALFORMED" in result.errors


def test_stale_source_metadata_fails_closed() -> None:
    response, preflight, _ltv = _response()

    try:
        prepare_revocation_live_fetch_plan(
            revocation_preflight=preflight,
            revocation_response=response,
            planned_at_utc="2026-05-14T00:09:00Z",
        )
    except Exception as exc:
        assert str(exc) == "REVOCATION_LIVE_FETCH_SOURCE_STALE"
    else:
        raise AssertionError("stale revocation metadata was accepted")


def test_missing_response_metadata_fails_closed() -> None:
    plan, preflight, _response_payload = _plan()
    plan["revocation_response_id"] = ""

    result = verify_revocation_live_fetch_plan(plan, revocation_preflight=preflight)

    assert result.valid is False
    assert "REVOCATION_LIVE_FETCH_RESPONSE_MISSING" in result.errors


def test_unsigned_response_metadata_fails_closed() -> None:
    plan, preflight, response = _plan()
    response = dict(response)
    response["response_signature_fingerprint"] = "0" * 64

    result = verify_revocation_live_fetch_plan(plan, revocation_preflight=preflight, revocation_response=response)

    assert result.valid is False
    assert "REVOCATION_LIVE_FETCH_RESPONSE_UNSIGNED" in result.errors


def test_mismatched_response_metadata_fails_closed() -> None:
    plan, preflight, response = _plan()
    response = dict(response)
    response["revocation_source_uri_hash"] = "e" * 64

    result = verify_revocation_live_fetch_plan(plan, revocation_preflight=preflight, revocation_response=response)

    assert result.valid is False
    assert "REVOCATION_LIVE_FETCH_RESPONSE_MISMATCH" in result.errors


def test_mutable_output_path_fails_closed() -> None:
    plan, preflight, response = _plan()
    plan["live_fetch_output_path"] = "/tmp/revocation-live-fetch.json"

    result = verify_revocation_live_fetch_plan(plan, revocation_preflight=preflight, revocation_response=response)

    assert result.valid is False
    assert "REVOCATION_LIVE_FETCH_PATH_MUTABLE" in result.errors


def test_raw_payload_leakage_fails_closed() -> None:
    plan, preflight, response = _plan()
    plan["live_fetch_response_body"] = "raw ocsp payload"

    result = verify_revocation_live_fetch_plan(plan, revocation_preflight=preflight, revocation_response=response)

    assert result.valid is False
    assert "REVOCATION_LIVE_FETCH_RAW_PAYLOAD_LEAKAGE" in result.errors


def test_unsafe_diagnostics_fails_closed() -> None:
    plan, preflight, response = _plan()
    plan["diagnostics"] = {"approval_contents": "do-not-export"}

    result = verify_revocation_live_fetch_plan(plan, revocation_preflight=preflight, revocation_response=response)

    assert result.valid is False
    assert "REVOCATION_LIVE_FETCH_DIAGNOSTICS_UNSAFE" in result.errors


def test_revocation_live_fetch_error_registry_complete() -> None:
    registry = load_revocation_live_fetch_error_registry(ROOT)

    assert set(REVOCATION_LIVE_FETCH_ERROR_CODES).issubset(registry)
    assert explain_revocation_live_fetch_failure(ROOT, "REVOCATION_LIVE_FETCH_SOURCE_STALE")["fail_closed_reason"]


def test_create_and_verify_cli_redacts_output(tmp_path: Path) -> None:
    plan, preflight, response = _plan()
    preflight_path = tmp_path / "revocation-preflight.json"
    response_path = tmp_path / "revocation-response.json"
    plan_path = tmp_path / "revocation-live-fetch.json"
    preflight_path.write_text(json.dumps(preflight, sort_keys=True), encoding="utf-8")
    response_path.write_text(json.dumps(response, sort_keys=True), encoding="utf-8")

    created = subprocess.run(
        [
            sys.executable,
            "scripts/governance_diagnostics.py",
            "prepare-revocation-live-fetch",
            "--revocation-preflight",
            str(preflight_path),
            "--revocation-response",
            str(response_path),
            "--validation-timestamp",
            "2026-05-12T00:09:00Z",
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
            "verify-revocation-live-fetch",
            "--revocation-live-fetch",
            str(plan_path),
            "--revocation-preflight",
            str(preflight_path),
            "--revocation-response",
            str(response_path),
        ],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
    )

    assert verified.returncode == 0
    assert '"valid":true' in verified.stdout
    assert "approval_contents" not in verified.stdout
    assert plan["revocation_live_fetch_id"]
