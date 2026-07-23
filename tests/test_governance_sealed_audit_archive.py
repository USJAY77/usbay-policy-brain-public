from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

from governance.sealed_audit_archive import (
    SEALED_AUDIT_ARCHIVE_ERROR_CODES,
    create_sealed_audit_archive,
    explain_sealed_audit_archive_failure,
    load_sealed_audit_archive_error_registry,
    verify_sealed_audit_archive,
)
from governance.signed_bundle_ltv import create_signed_bundle_ltv_evidence
from governance.signed_bundle_revocation_preflight import create_revocation_preflight
from governance.signed_bundle_revocation_response import create_revocation_response
from tests.governance_test_builders import (
    EvidenceBuilder,
    REVOCATION_EVIDENCE_HASH,
    TRUST_ANCHOR_HASH,
    TSA_CERTIFICATE_HASH,
)
from tests.test_governance_evidence_chain import _chain


ROOT = Path(__file__).resolve().parents[1]
RESPONDER_KEY = "f" * 64
SOURCE_HASH = "d" * 64
TSA_CERT = TSA_CERTIFICATE_HASH
TRUST_ANCHOR = TRUST_ANCHOR_HASH
REVOCATION_HASH = REVOCATION_EVIDENCE_HASH
_EVIDENCE_BUILDER = EvidenceBuilder()


def _archive_artifacts() -> dict[str, dict]:
    timestamp_attachment, signed_bundle, _policy = _EVIDENCE_BUILDER.signed_bundle_timestamp_attachment()
    ltv_evidence = create_signed_bundle_ltv_evidence(
        timestamp_attachment,
        tsa_certificate_fingerprint=TSA_CERT,
        tsa_certificate_chain_fingerprints=[TSA_CERT, TRUST_ANCHOR],
        trust_anchor_fingerprint=TRUST_ANCHOR,
        revocation_evidence_type="offline_mock",
        revocation_evidence_hash=REVOCATION_HASH,
        revocation_checked_at_utc="2026-05-12T00:07:00Z",
        validation_policy_id="usb.ltv.v1",
    )
    revocation_preflight = create_revocation_preflight(
        ltv_evidence,
        revocation_source_type="OCSP",
        revocation_source_uri_hash=SOURCE_HASH,
        expected_freshness_window_seconds=86400,
        checked_at_utc="2026-05-12T00:08:00Z",
        validation_policy_id="usb.ltv.v1",
    )
    revocation_response = create_revocation_response(
        revocation_preflight,
        response_status="GOOD",
        response_this_update_utc="2026-05-12T00:07:30Z",
        response_next_update_utc="2026-05-13T00:07:30Z",
        responder_key_fingerprint=RESPONDER_KEY,
        checked_at_utc="2026-05-12T00:08:30Z",
        validation_policy_id="usb.ltv.v1",
    )
    return {
        "evidence_chain": _chain(),
        "signed_bundle": signed_bundle,
        "timestamp_attachment": timestamp_attachment,
        "ltv_evidence": ltv_evidence,
        "revocation_preflight": revocation_preflight,
        "revocation_response": revocation_response,
    }


def _archive() -> tuple[dict, dict[str, dict]]:
    artifacts = _archive_artifacts()
    archive = create_sealed_audit_archive(
        **artifacts,
        archive_created_at_utc="2026-05-12T00:09:00Z",
        archive_scope="external-audit",
    )
    return archive, artifacts


def test_valid_archive_verification() -> None:
    archive, artifacts = _archive()

    result = verify_sealed_audit_archive(archive, **artifacts, expected_archive_scope="external-audit")

    assert result.valid is True
    assert result.errors == ()
    assert result.archive_scope == "external-audit"
    assert result.evidence_chain_head_hash == archive["evidence_chain_head_hash"]


def test_missing_manifest_rejection() -> None:
    archive, artifacts = _archive()
    archive.pop("archive_manifest")

    result = verify_sealed_audit_archive(archive, **artifacts, expected_archive_scope="external-audit")

    assert result.valid is False
    assert "SEALED_ARCHIVE_MANIFEST_MISSING" in result.errors


def test_reordered_evidence_rejection() -> None:
    archive, artifacts = _archive()
    archive["archive_manifest"] = [archive["archive_manifest"][1], archive["archive_manifest"][0], *archive["archive_manifest"][2:]]

    result = verify_sealed_audit_archive(archive, **artifacts, expected_archive_scope="external-audit")

    assert result.valid is False
    assert "SEALED_ARCHIVE_POSITION_INVALID" in result.errors


def test_root_hash_mismatch_rejection() -> None:
    archive, artifacts = _archive()
    archive["archive_root_hash"] = "0" * 64

    result = verify_sealed_audit_archive(archive, **artifacts, expected_archive_scope="external-audit")

    assert result.valid is False
    assert "SEALED_ARCHIVE_ROOT_HASH_MISMATCH" in result.errors


def test_append_only_position_mismatch_rejection() -> None:
    archive, artifacts = _archive()
    archive["archive_manifest"][2]["append_only_position"] = 5

    result = verify_sealed_audit_archive(archive, **artifacts, expected_archive_scope="external-audit")

    assert result.valid is False
    assert "SEALED_ARCHIVE_POSITION_INVALID" in result.errors


def test_replay_rejection() -> None:
    archive, artifacts = _archive()

    result = verify_sealed_audit_archive(archive, **artifacts, expected_archive_scope="external-audit", existing_archives=[archive])

    assert result.valid is False
    assert "SEALED_ARCHIVE_REPLAY_DETECTED" in result.errors


def test_scope_mismatch_rejection() -> None:
    archive, artifacts = _archive()

    result = verify_sealed_audit_archive(archive, **artifacts, expected_archive_scope="regulator-export")

    assert result.valid is False
    assert "SEALED_ARCHIVE_SCOPE_INVALID" in result.errors


def test_missing_artifact_rejection() -> None:
    archive, artifacts = _archive()
    artifacts["revocation_response"] = {}

    result = verify_sealed_audit_archive(archive, **artifacts, expected_archive_scope="external-audit")

    assert result.valid is False
    assert "SEALED_ARCHIVE_ARTIFACT_MISSING" in result.errors


def test_unsafe_diagnostics_rejection() -> None:
    archive, artifacts = _archive()
    archive["diagnostics"] = {"approval_contents": "do-not-export"}

    result = verify_sealed_audit_archive(archive, **artifacts, expected_archive_scope="external-audit")

    assert result.valid is False
    assert "SEALED_ARCHIVE_DIAGNOSTICS_UNSAFE" in result.errors


def test_sealed_archive_error_registry_complete() -> None:
    registry = load_sealed_audit_archive_error_registry(ROOT)

    assert set(SEALED_AUDIT_ARCHIVE_ERROR_CODES).issubset(registry)
    assert explain_sealed_audit_archive_failure(ROOT, "SEALED_ARCHIVE_ROOT_HASH_MISMATCH")["fail_closed_reason"]


def test_create_and_verify_cli_redacts_output(tmp_path: Path) -> None:
    archive_path = tmp_path / "sealed-audit-archive.json"
    artifacts = _archive_artifacts()
    paths = {}
    for name, artifact in artifacts.items():
        path = tmp_path / f"{name}.json"
        path.write_text(json.dumps(artifact, sort_keys=True), encoding="utf-8")
        paths[name] = path

    created = subprocess.run(
        [
            sys.executable,
            "scripts/governance_diagnostics.py",
            "create-sealed-audit-archive",
            "--evidence-chain",
            str(paths["evidence_chain"]),
            "--signed-auditor-bundle",
            str(paths["signed_bundle"]),
            "--signed-bundle-timestamp",
            str(paths["timestamp_attachment"]),
            "--signed-bundle-ltv-evidence",
            str(paths["ltv_evidence"]),
            "--revocation-preflight",
            str(paths["revocation_preflight"]),
            "--revocation-response",
            str(paths["revocation_response"]),
            "--archive-scope",
            "external-audit",
            "--validation-timestamp",
            "2026-05-12T00:09:00Z",
            "--output",
            str(archive_path),
        ],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
    )

    assert created.returncode == 0
    assert archive_path.is_file()
    assert "approval_contents" not in created.stdout
    assert "PRIVATE KEY" not in created.stdout
    assert "PRIVATE KEY" not in archive_path.read_text(encoding="utf-8")

    verified = subprocess.run(
        [
            sys.executable,
            "scripts/governance_diagnostics.py",
            "verify-sealed-audit-archive",
            "--sealed-audit-archive",
            str(archive_path),
            "--evidence-chain",
            str(paths["evidence_chain"]),
            "--signed-auditor-bundle",
            str(paths["signed_bundle"]),
            "--signed-bundle-timestamp",
            str(paths["timestamp_attachment"]),
            "--signed-bundle-ltv-evidence",
            str(paths["ltv_evidence"]),
            "--revocation-preflight",
            str(paths["revocation_preflight"]),
            "--revocation-response",
            str(paths["revocation_response"]),
            "--archive-scope",
            "external-audit",
        ],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
    )

    assert verified.returncode == 0
    assert '"valid":true' in verified.stdout
