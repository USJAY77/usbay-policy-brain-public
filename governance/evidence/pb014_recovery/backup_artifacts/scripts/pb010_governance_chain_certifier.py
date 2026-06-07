#!/usr/bin/env python3
"""PB-010 local governance evidence chain certifier.

This utility validates the local PB-005 through PB-009 evidence chain and
generates a local governance chain certificate, verification report, and
scorecard. It does not call AWS, PostgreSQL, timestamp authorities, or any
external network.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


CERTIFICATE_NAME = "pb010_chain_certificate.json"
VERIFICATION_REPORT_NAME = "pb010_chain_verification_report.json"
SCORECARD_NAME = "pb010_governance_scorecard.json"
CERTIFICATE_SCHEMA = "usbay.pb010.chain_certificate.v1"
VERIFICATION_SCHEMA = "usbay.pb010.chain_verification_report.v1"
SCORECARD_SCHEMA = "usbay.pb010.governance_scorecard.v1"
CERTIFICATE_KEY_ID = "USBAY-PB010-LOCAL-GOVERNANCE-CHAIN-CONTROL"

PB005_REQUIRED = {
    "pb005_endpoint_evidence.json",
    "pb005_schema_evidence.json",
    "pb005_write_receipt.json",
    "pb005_read_receipt.json",
    "pb005_persistence_evidence.json",
    "pb005_evidence_manifest.json",
    "pb005_final_execution_report.json",
}
PB006_REQUIRED = {
    "pb006_signed_evidence_manifest.json",
    "pb006_integrity_report.json",
}
PB007_REQUIRED = {"pb007_verification_report.json"}
PB008_REQUIRED = {
    "pb008_timestamp_receipt.json",
    "pb008_non_repudiation_report.json",
}
PB005_ALLOWED = PB005_REQUIRED | PB006_REQUIRED | PB007_REQUIRED | PB008_REQUIRED
PB009_ROOT_REQUIRED = {
    "pb009_archive_manifest.json",
    "pb009_retention_report.json",
    "pb009_restore_verification_report.json",
    "pb009_archive_integrity_report.json",
}
PB009_ALLOWED_ROOT = PB009_ROOT_REQUIRED | {"artifacts"}
PB009_REQUIRED_ARCHIVE_ARTIFACTS = PB005_ALLOWED


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def canonical(data: Any) -> str:
    return json.dumps(data, sort_keys=True, separators=(",", ":"))


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def load_json(path: Path) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ValueError(f"{path.name}:JSON_INVALID:{exc.msg}") from exc
    if not isinstance(payload, dict):
        raise ValueError(f"{path.name}:JSON_OBJECT_REQUIRED")
    return payload


def write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def certificate_signature(payload: dict[str, Any]) -> str:
    return sha256_bytes(
        canonical(
            {
                "certificate_key_id": CERTIFICATE_KEY_ID,
                "payload": payload,
            }
        ).encode("utf-8")
    )


def add_schema_check(
    errors: list[str],
    path: Path,
    expected_schema: str,
    error_prefix: str,
) -> dict[str, Any]:
    try:
        payload = load_json(path)
    except Exception as exc:
        errors.append(f"{error_prefix}_INVALID:{exc}")
        return {}
    if payload.get("schema") != expected_schema:
        errors.append(f"{error_prefix}_SCHEMA_INVALID")
    return payload


def add_report_contract_check(
    errors: list[str],
    path: Path,
    expected_schema: str,
    expected_control_id: str,
    error_prefix: str,
) -> dict[str, Any]:
    try:
        payload = load_json(path)
    except Exception as exc:
        errors.append(f"{error_prefix}_INVALID:{exc}")
        return {}
    schema = payload.get("schema")
    if schema is not None:
        if schema != expected_schema:
            errors.append(f"{error_prefix}_SCHEMA_INVALID")
    elif payload.get("control_id") != expected_control_id:
        errors.append(f"{error_prefix}_SCHEMA_INVALID")
    return payload


def require_verified_report(
    errors: list[str],
    payload: dict[str, Any],
    prefix: str,
) -> None:
    if payload.get("decision") != "VERIFIED":
        errors.append(f"{prefix}_NOT_VERIFIED")
    if payload.get("fail_closed") is not False:
        errors.append(f"{prefix}_FAIL_CLOSED")
    if "errors" in payload and payload.get("errors") != []:
        errors.append(f"{prefix}_ERRORS_PRESENT")


def verify_pb005(pb005_dir: Path) -> tuple[list[str], dict[str, str]]:
    errors: list[str] = []
    hashes: dict[str, str] = {}
    if not pb005_dir.is_dir():
        return [f"PB010_PB005_DIR_MISSING:{pb005_dir}"], hashes

    present = {path.name for path in pb005_dir.iterdir() if path.is_file()}
    for artifact in sorted(PB005_ALLOWED - present):
        errors.append(f"PB010_REQUIRED_ARTIFACT_MISSING:{artifact}")
    for artifact in sorted(present - PB005_ALLOWED):
        errors.append(f"PB010_UNSUPPORTED_ARTIFACT:{artifact}")

    for artifact in sorted(PB005_ALLOWED & present):
        hashes[f"pb005/{artifact}"] = sha256_file(pb005_dir / artifact)

    manifest = add_schema_check(
        errors,
        pb005_dir / "pb005_evidence_manifest.json",
        "usbay.pb005.evidence_manifest.v1",
        "PB010_PB005_MANIFEST",
    )
    if manifest and manifest.get("classification") != "VERIFIED":
        errors.append("PB010_PB005_MANIFEST_NOT_VERIFIED")
    final_report = load_json(pb005_dir / "pb005_final_execution_report.json") if (pb005_dir / "pb005_final_execution_report.json").is_file() else {}
    if final_report and final_report.get("final_classification") != "VERIFIED":
        errors.append("PB010_PB005_FINAL_REPORT_NOT_VERIFIED")
    return errors, hashes


def verify_pb006(pb005_dir: Path) -> list[str]:
    errors: list[str] = []
    report = add_report_contract_check(
        errors,
        pb005_dir / "pb006_integrity_report.json",
        "usbay.pb006.integrity_report.v1",
        "PB-006",
        "PB010_PB006_INTEGRITY_REPORT",
    )
    if report:
        require_verified_report(errors, report, "PB010_PB006_INTEGRITY")
        if report.get("pb005_compatible") is not True:
            errors.append("PB010_PB006_NOT_PB005_COMPATIBLE")
        if report.get("artifact_modification_detected") is not False:
            errors.append("PB010_PB006_ARTIFACT_MODIFICATION_DETECTED")
        if report.get("missing_artifact_detected") is not False:
            errors.append("PB010_PB006_MISSING_ARTIFACT_DETECTED")
    return errors


def verify_pb007(pb005_dir: Path) -> list[str]:
    errors: list[str] = []
    report = add_report_contract_check(
        errors,
        pb005_dir / "pb007_verification_report.json",
        "usbay.pb007.independent_verification_report.v1",
        "PB-007",
        "PB010_PB007_VERIFICATION_REPORT",
    )
    if report:
        require_verified_report(errors, report, "PB010_PB007_INDEPENDENT_VERIFICATION")
        pb005_verified = (
            report.get("pb005_bundle_verified") is True
            or report.get("missing_pb005_artifacts") == []
        )
        if not pb005_verified:
            errors.append("PB010_PB007_PB005_NOT_VERIFIED")
        pb006_verified = (
            report.get("pb006_integrity_verified") is True
            or report.get("pb006_report_verified") is True
        )
        if not pb006_verified:
            errors.append("PB010_PB007_PB006_NOT_VERIFIED")
        unsupported_detected = (
            report.get("unsupported_artifact_detected") is True
            or bool(report.get("unsupported_artifacts"))
        )
        if unsupported_detected:
            errors.append("PB010_PB007_UNSUPPORTED_ARTIFACT_DETECTED")
    return errors


def verify_pb008(pb005_dir: Path) -> list[str]:
    errors: list[str] = []
    receipt = add_schema_check(
        errors,
        pb005_dir / "pb008_timestamp_receipt.json",
        "usbay.pb008.rfc3161_timestamp_receipt.v1",
        "PB010_PB008_TIMESTAMP_RECEIPT",
    )
    if receipt:
        if receipt.get("timestamped_artifact") != "pb006_signed_evidence_manifest.json":
            errors.append("PB010_PB008_TIMESTAMPED_ARTIFACT_INVALID")
        if receipt.get("fail_closed") is not False:
            errors.append("PB010_PB008_RECEIPT_FAIL_CLOSED")
    report = add_schema_check(
        errors,
        pb005_dir / "pb008_non_repudiation_report.json",
        "usbay.pb008.non_repudiation_report.v1",
        "PB010_PB008_NON_REPUDIATION_REPORT",
    )
    if report:
        require_verified_report(errors, report, "PB010_PB008_TIMESTAMP")
        if report.get("timestamp_valid") is not True:
            errors.append("PB010_PB008_TIMESTAMP_INVALID")
        if report.get("manifest_hash_verified") is not True:
            errors.append("PB010_PB008_MANIFEST_HASH_NOT_VERIFIED")
        if report.get("tsa_response_verified") is not True:
            errors.append("PB010_PB008_TSA_VERIFICATION_FAILED")
    return errors


def verify_pb009(pb009_archive_dir: Path) -> tuple[list[str], dict[str, str]]:
    errors: list[str] = []
    hashes: dict[str, str] = {}
    if not pb009_archive_dir.is_dir():
        return [f"PB010_PB009_ARCHIVE_DIR_MISSING:{pb009_archive_dir}"], hashes

    root_entries = {path.name for path in pb009_archive_dir.iterdir()}
    for artifact in sorted(PB009_ROOT_REQUIRED - root_entries):
        errors.append(f"PB010_REQUIRED_ARTIFACT_MISSING:{artifact}")
    for artifact in sorted(root_entries - PB009_ALLOWED_ROOT):
        errors.append(f"PB010_UNSUPPORTED_ARTIFACT:{artifact}")

    archive_artifact_dir = pb009_archive_dir / "artifacts"
    if not archive_artifact_dir.is_dir():
        errors.append("PB010_PB009_ARTIFACT_DIR_MISSING")
    else:
        archived = {path.name for path in archive_artifact_dir.iterdir() if path.is_file()}
        for artifact in sorted(PB009_REQUIRED_ARCHIVE_ARTIFACTS - archived):
            errors.append(f"PB010_ARCHIVED_ARTIFACT_MISSING:{artifact}")
        for artifact in sorted(archived - PB009_REQUIRED_ARCHIVE_ARTIFACTS):
            errors.append(f"PB010_UNSUPPORTED_ARCHIVE_ARTIFACT:{artifact}")
        for artifact in sorted(PB009_REQUIRED_ARCHIVE_ARTIFACTS & archived):
            hashes[f"pb009_archive/artifacts/{artifact}"] = sha256_file(archive_artifact_dir / artifact)

    for artifact in sorted(PB009_ROOT_REQUIRED & root_entries):
        hashes[f"pb009_archive/{artifact}"] = sha256_file(pb009_archive_dir / artifact)

    archive_manifest = add_schema_check(
        errors,
        pb009_archive_dir / "pb009_archive_manifest.json",
        "usbay.pb009.immutable_archive_manifest.v1",
        "PB010_PB009_ARCHIVE_MANIFEST",
    )
    if archive_manifest:
        manifest_hashes = archive_manifest.get("artifact_hashes")
        if not isinstance(manifest_hashes, dict) or not manifest_hashes:
            errors.append("PB010_PB009_ARCHIVE_MANIFEST_HASHES_MISSING")
        else:
            for artifact in sorted(PB009_REQUIRED_ARCHIVE_ARTIFACTS):
                expected = manifest_hashes.get(artifact)
                actual = hashes.get(f"pb009_archive/artifacts/{artifact}")
                if expected is None:
                    errors.append(f"PB010_PB009_ARCHIVE_MANIFEST_ARTIFACT_MISSING:{artifact}")
                elif actual is not None and expected != actual:
                    errors.append(f"PB010_PB009_ARCHIVE_HASH_MISMATCH:{artifact}")
    integrity = add_schema_check(
        errors,
        pb009_archive_dir / "pb009_archive_integrity_report.json",
        "usbay.pb009.archive_integrity_report.v1",
        "PB010_PB009_ARCHIVE_INTEGRITY_REPORT",
    )
    if integrity:
        require_verified_report(errors, integrity, "PB010_PB009_ARCHIVE_INTEGRITY")
        if integrity.get("archive_integrity_verified") is not True:
            errors.append("PB010_PB009_ARCHIVE_VERIFICATION_FAILED")
    retention = add_schema_check(
        errors,
        pb009_archive_dir / "pb009_retention_report.json",
        "usbay.pb009.retention_report.v1",
        "PB010_PB009_RETENTION_REPORT",
    )
    if retention:
        require_verified_report(errors, retention, "PB010_PB009_RETENTION")
        if retention.get("retention_violation_detected") is not False:
            errors.append("PB010_PB009_RETENTION_VIOLATION")
    restore = add_schema_check(
        errors,
        pb009_archive_dir / "pb009_restore_verification_report.json",
        "usbay.pb009.restore_verification_report.v1",
        "PB010_PB009_RESTORE_REPORT",
    )
    if restore:
        require_verified_report(errors, restore, "PB010_PB009_RESTORE")
        if restore.get("restore_verification_succeeded") is not True:
            errors.append("PB010_PB009_RESTORE_VERIFICATION_FAILED")
    return errors, hashes


def build_scorecard(errors_by_control: dict[str, list[str]]) -> dict[str, Any]:
    controls = {}
    verified = 0
    for control, errors in errors_by_control.items():
        status = "VERIFIED" if not errors else "BLOCKED"
        if status == "VERIFIED":
            verified += 1
        controls[control] = {
            "status": status,
            "errors": errors,
        }
    total = len(errors_by_control)
    return {
        "schema": SCORECARD_SCHEMA,
        "generated_at": utc_now(),
        "decision": "VERIFIED" if verified == total else "BLOCKED",
        "fail_closed": verified != total,
        "controls_verified": verified,
        "controls_total": total,
        "score": verified,
        "max_score": total,
        "controls": controls,
        "local_governance_validation_only": True,
        "no_external_certification_claim": True,
        "aws_access_performed": False,
        "postgresql_access_performed": False,
        "tsa_access_performed": False,
        "external_network_access_performed": False,
    }


def write_outputs(
    output_dir: Path,
    pb005_dir: Path,
    pb009_archive_dir: Path,
    errors_by_control: dict[str, list[str]],
    evidence_hashes: dict[str, str],
) -> list[str]:
    all_errors = [error for errors in errors_by_control.values() for error in errors]
    generated_at = utc_now()
    aggregate_hash = sha256_bytes(canonical(evidence_hashes).encode("utf-8"))
    certificate = {
        "schema": CERTIFICATE_SCHEMA,
        "generated_at": generated_at,
        "decision": "VERIFIED" if not all_errors else "BLOCKED",
        "fail_closed": bool(all_errors),
        "certificate_id": sha256_bytes(
            canonical(
                {
                    "pb005_dir": pb005_dir.resolve().as_posix(),
                    "pb009_archive_dir": pb009_archive_dir.resolve().as_posix(),
                    "evidence_hashes": evidence_hashes,
                }
            ).encode("utf-8")
        ),
        "chain_scope": ["PB-005", "PB-006", "PB-007", "PB-008", "PB-009"],
        "evidence_hashes": evidence_hashes,
        "aggregate_hash": aggregate_hash,
        "local_governance_validation_only": True,
        "no_external_certification_claim": True,
        "aws_access_performed": False,
        "postgresql_access_performed": False,
        "tsa_access_performed": False,
        "external_network_access_performed": False,
    }
    certificate["signature"] = {
        "algorithm": "SHA256_DETERMINISTIC_CHAIN_CERTIFICATE_SIGNATURE",
        "certificate_key_id": CERTIFICATE_KEY_ID,
        "signature_hash": certificate_signature(certificate),
    }
    verification_report = {
        "schema": VERIFICATION_SCHEMA,
        "generated_at": generated_at,
        "decision": certificate["decision"],
        "fail_closed": certificate["fail_closed"],
        "errors": all_errors,
        "errors_by_control": errors_by_control,
        "required_controls": ["PB-005", "PB-006", "PB-007", "PB-008", "PB-009"],
        "unsupported_artifact_detected": any("UNSUPPORTED" in error for error in all_errors),
        "missing_artifact_detected": any("MISSING" in error for error in all_errors),
        "integrity_verification_failed": any("INTEGRITY" in error or "HASH_MISMATCH" in error for error in all_errors),
        "timestamp_verification_failed": any("PB010_PB008" in error for error in all_errors),
        "archive_verification_failed": any("PB010_PB009" in error for error in all_errors),
        "report_schema_invalid": any("SCHEMA_INVALID" in error for error in all_errors),
        "local_governance_validation_only": True,
        "no_external_certification_claim": True,
        "aws_access_performed": False,
        "postgresql_access_performed": False,
        "tsa_access_performed": False,
        "external_network_access_performed": False,
    }
    scorecard = build_scorecard(errors_by_control)

    write_json(output_dir / CERTIFICATE_NAME, certificate)
    write_json(output_dir / VERIFICATION_REPORT_NAME, verification_report)
    write_json(output_dir / SCORECARD_NAME, scorecard)
    return all_errors


def certify(pb005_dir: Path, pb009_archive_dir: Path, output_dir: Path) -> list[str]:
    pb005_errors, pb005_hashes = verify_pb005(pb005_dir)
    pb006_errors = verify_pb006(pb005_dir)
    pb007_errors = verify_pb007(pb005_dir)
    pb008_errors = verify_pb008(pb005_dir)
    pb009_errors, pb009_hashes = verify_pb009(pb009_archive_dir)
    evidence_hashes = {**pb005_hashes, **pb009_hashes}
    errors_by_control = {
        "PB-005": pb005_errors,
        "PB-006": pb006_errors,
        "PB-007": pb007_errors,
        "PB-008": pb008_errors,
        "PB-009": pb009_errors,
    }
    return write_outputs(output_dir, pb005_dir, pb009_archive_dir, errors_by_control, evidence_hashes)


def main() -> int:
    parser = argparse.ArgumentParser(description="PB-010 local governance chain certifier.")
    parser.add_argument("pb005_dir")
    parser.add_argument("pb009_archive_dir")
    parser.add_argument("output_dir")
    args = parser.parse_args()
    errors = certify(
        Path(args.pb005_dir).resolve(),
        Path(args.pb009_archive_dir).resolve(),
        Path(args.output_dir).resolve(),
    )
    if errors:
        print("Decision: BLOCKED")
        for error in errors:
            print(error)
        return 1
    print("Decision: VERIFIED")
    print("PB010_GOVERNANCE_CHAIN_VERIFIED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
