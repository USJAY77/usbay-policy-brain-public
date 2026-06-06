#!/usr/bin/env python3
"""PB-009 immutable evidence archive control.

This utility archives PB-005 through PB-008 evidence artifacts into a local
append-only-style archive directory and verifies archive integrity, retention
metadata, and restore readiness without calling AWS, PostgreSQL, or external
providers.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any


ARCHIVE_MANIFEST = "pb009_archive_manifest.json"
RETENTION_REPORT = "pb009_retention_report.json"
RESTORE_REPORT = "pb009_restore_verification_report.json"
INTEGRITY_REPORT = "pb009_archive_integrity_report.json"
ARTIFACT_DIR = "artifacts"
MANIFEST_SCHEMA = "usbay.pb009.immutable_archive_manifest.v1"
RETENTION_SCHEMA = "usbay.pb009.retention_report.v1"
RESTORE_SCHEMA = "usbay.pb009.restore_verification_report.v1"
INTEGRITY_SCHEMA = "usbay.pb009.archive_integrity_report.v1"
ARCHIVE_KEY_ID = "USBAY-PB009-LOCAL-ARCHIVE-CONTROL"
DEFAULT_RETENTION_DAYS = 2555

REQUIRED_SOURCE_ARTIFACTS = {
    "pb005_endpoint_evidence.json",
    "pb005_schema_evidence.json",
    "pb005_write_receipt.json",
    "pb005_read_receipt.json",
    "pb005_persistence_evidence.json",
    "pb005_evidence_manifest.json",
    "pb005_final_execution_report.json",
    "pb006_signed_evidence_manifest.json",
    "pb006_integrity_report.json",
    "pb007_verification_report.json",
    "pb008_timestamp_receipt.json",
    "pb008_non_repudiation_report.json",
}


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def parse_timestamp(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


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


def archive_signature(payload: dict[str, Any]) -> str:
    return sha256_bytes(
        canonical(
            {
                "archive_key_id": ARCHIVE_KEY_ID,
                "payload": payload,
            }
        ).encode("utf-8")
    )


def archive_artifact_dir(archive_dir: Path) -> Path:
    return archive_dir / ARTIFACT_DIR


def required_source_errors(source_dir: Path) -> list[str]:
    errors: list[str] = []
    if not source_dir.is_dir():
        return [f"PB009_SOURCE_DIR_MISSING:{source_dir}"]
    for artifact in sorted(REQUIRED_SOURCE_ARTIFACTS):
        if not (source_dir / artifact).is_file():
            errors.append(f"PB009_SOURCE_ARTIFACT_MISSING:{artifact}")
    return errors


def copy_artifacts(source_dir: Path, archive_dir: Path) -> None:
    artifacts_dir = archive_artifact_dir(archive_dir)
    artifacts_dir.mkdir(parents=True, exist_ok=True)
    for artifact in sorted(REQUIRED_SOURCE_ARTIFACTS):
        destination = artifacts_dir / artifact
        if destination.exists():
            destination.unlink()
        shutil.copy2(source_dir / artifact, destination)


def build_manifest(source_dir: Path, archive_dir: Path, retention_days: int) -> dict[str, Any]:
    if retention_days <= 0:
        raise ValueError("PB009_RETENTION_DAYS_INVALID")
    archived_at = utc_now()
    retention_until = (
        parse_timestamp(archived_at) + timedelta(days=retention_days)
    ).isoformat().replace("+00:00", "Z")
    artifacts_dir = archive_artifact_dir(archive_dir)
    artifact_hashes = {
        artifact: sha256_file(artifacts_dir / artifact)
        for artifact in sorted(REQUIRED_SOURCE_ARTIFACTS)
    }
    payload = {
        "schema": MANIFEST_SCHEMA,
        "archive_id": sha256_bytes(
            canonical(
                {
                    "source_directory": source_dir.resolve().as_posix(),
                    "archive_directory": archive_dir.resolve().as_posix(),
                    "archived_at": archived_at,
                    "artifact_hashes": artifact_hashes,
                }
            ).encode("utf-8")
        ),
        "archived_at": archived_at,
        "source_directory": source_dir.resolve().as_posix(),
        "archive_directory": archive_dir.resolve().as_posix(),
        "artifact_directory": artifacts_dir.resolve().as_posix(),
        "artifact_hashes": artifact_hashes,
        "artifact_count": len(artifact_hashes),
        "aggregate_hash": sha256_bytes(canonical(artifact_hashes).encode("utf-8")),
        "retention": {
            "mode": "LOCAL_GOVERNANCE_RETENTION",
            "retention_days": retention_days,
            "retention_until": retention_until,
            "delete_allowed": False,
            "overwrite_allowed": False,
            "legal_hold_required_before_delete": True,
        },
        "fail_closed": False,
        "no_worm_provider_claim": True,
        "no_certification_claim": True,
        "aws_access_performed": False,
        "postgresql_access_performed": False,
    }
    payload["signature"] = {
        "algorithm": "SHA256_DETERMINISTIC_ARCHIVE_SIGNATURE",
        "archive_key_id": ARCHIVE_KEY_ID,
        "signature_hash": archive_signature(payload),
    }
    return payload


def verify_manifest_signature(manifest: dict[str, Any]) -> list[str]:
    signature = manifest.get("signature")
    if not isinstance(signature, dict):
        return ["PB009_ARCHIVE_MANIFEST_SIGNATURE_MISSING"]
    unsigned = dict(manifest)
    unsigned.pop("signature", None)
    errors: list[str] = []
    if signature.get("archive_key_id") != ARCHIVE_KEY_ID:
        errors.append("PB009_ARCHIVE_KEY_ID_MISMATCH")
    if signature.get("signature_hash") != archive_signature(unsigned):
        errors.append("PB009_ARCHIVE_MANIFEST_SIGNATURE_MISMATCH")
    if signature.get("algorithm") != "SHA256_DETERMINISTIC_ARCHIVE_SIGNATURE":
        errors.append("PB009_ARCHIVE_SIGNATURE_ALGORITHM_INVALID")
    return errors


def verify_archive_integrity(archive_dir: Path, manifest: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    if manifest.get("schema") != MANIFEST_SCHEMA:
        errors.append("PB009_ARCHIVE_MANIFEST_SCHEMA_INVALID")
    errors.extend(verify_manifest_signature(manifest))

    artifact_hashes = manifest.get("artifact_hashes")
    if not isinstance(artifact_hashes, dict) or not artifact_hashes:
        errors.append("PB009_ARCHIVE_MANIFEST_HASHES_MISSING")
        return errors
    expected_names = set(REQUIRED_SOURCE_ARTIFACTS)
    actual_names = {path.name for path in archive_artifact_dir(archive_dir).glob("*") if path.is_file()}

    for artifact in sorted(expected_names):
        if artifact not in artifact_hashes:
            errors.append(f"PB009_ARCHIVE_MANIFEST_ARTIFACT_MISSING:{artifact}")
            continue
        path = archive_artifact_dir(archive_dir) / artifact
        if not path.is_file():
            errors.append(f"PB009_ARCHIVED_ARTIFACT_MISSING:{artifact}")
            continue
        if sha256_file(path) != artifact_hashes[artifact]:
            errors.append(f"PB009_ARCHIVE_HASH_MISMATCH:{artifact}")

    for artifact in sorted(actual_names - expected_names):
        errors.append(f"PB009_UNSUPPORTED_ARCHIVE_ARTIFACT:{artifact}")

    if manifest.get("aggregate_hash") != sha256_bytes(canonical(artifact_hashes).encode("utf-8")):
        errors.append("PB009_ARCHIVE_AGGREGATE_HASH_MISMATCH")
    return errors


def verify_retention(manifest: dict[str, Any]) -> list[str]:
    retention = manifest.get("retention")
    if not isinstance(retention, dict):
        return ["PB009_RETENTION_METADATA_MISSING"]
    errors: list[str] = []
    if retention.get("mode") != "LOCAL_GOVERNANCE_RETENTION":
        errors.append("PB009_RETENTION_MODE_INVALID")
    if retention.get("delete_allowed") is not False:
        errors.append("PB009_RETENTION_DELETE_ALLOWED")
    if retention.get("overwrite_allowed") is not False:
        errors.append("PB009_RETENTION_OVERWRITE_ALLOWED")
    if retention.get("legal_hold_required_before_delete") is not True:
        errors.append("PB009_RETENTION_LEGAL_HOLD_REQUIREMENT_MISSING")
    retention_days = retention.get("retention_days")
    if not isinstance(retention_days, int) or retention_days <= 0:
        errors.append("PB009_RETENTION_DAYS_INVALID")
    retention_until = retention.get("retention_until")
    if not isinstance(retention_until, str):
        errors.append("PB009_RETENTION_UNTIL_MISSING")
    else:
        try:
            if parse_timestamp(retention_until) <= datetime.now(timezone.utc):
                errors.append("PB009_RETENTION_VIOLATION")
        except ValueError:
            errors.append("PB009_RETENTION_UNTIL_INVALID")
    return errors


def write_retention_report(archive_dir: Path, errors: list[str], manifest: dict[str, Any] | None) -> None:
    retention = manifest.get("retention", {}) if isinstance(manifest, dict) else {}
    report = {
        "schema": RETENTION_SCHEMA,
        "generated_at": utc_now(),
        "decision": "VERIFIED" if not errors else "BLOCKED",
        "fail_closed": bool(errors),
        "errors": errors,
        "retention": retention,
        "retention_violation_detected": any("RETENTION" in error for error in errors),
        "no_worm_provider_claim": True,
        "no_certification_claim": True,
    }
    write_json(archive_dir / RETENTION_REPORT, report)


def write_restore_report(archive_dir: Path, errors: list[str], manifest: dict[str, Any] | None) -> None:
    artifact_hashes = manifest.get("artifact_hashes", {}) if isinstance(manifest, dict) else {}
    report = {
        "schema": RESTORE_SCHEMA,
        "generated_at": utc_now(),
        "decision": "VERIFIED" if not errors else "BLOCKED",
        "fail_closed": bool(errors),
        "errors": errors,
        "restored_artifact_count": len(artifact_hashes) if not errors else 0,
        "restore_verification_succeeded": not errors,
        "archive_directory": archive_dir.resolve().as_posix(),
    }
    write_json(archive_dir / RESTORE_REPORT, report)


def write_integrity_report(archive_dir: Path, errors: list[str]) -> None:
    report = {
        "schema": INTEGRITY_SCHEMA,
        "generated_at": utc_now(),
        "decision": "VERIFIED" if not errors else "BLOCKED",
        "fail_closed": bool(errors),
        "errors": errors,
        "archive_integrity_verified": not errors,
        "missing_archive_artifact_detected": any("MISSING" in error for error in errors),
        "manifest_mismatch_detected": any("MANIFEST" in error or "AGGREGATE" in error for error in errors),
        "hash_mismatch_detected": any("HASH_MISMATCH" in error for error in errors),
        "retention_violation_detected": any("RETENTION" in error for error in errors),
        "restore_verification_failed": any(
            "MISSING" in error or "HASH_MISMATCH" in error for error in errors
        ),
        "aws_access_performed": False,
        "postgresql_access_performed": False,
    }
    write_json(archive_dir / INTEGRITY_REPORT, report)


def archive(source_dir: Path, archive_dir: Path, retention_days: int) -> list[str]:
    errors = required_source_errors(source_dir)
    if errors:
        archive_dir.mkdir(parents=True, exist_ok=True)
        write_retention_report(archive_dir, errors, None)
        write_restore_report(archive_dir, errors, None)
        write_integrity_report(archive_dir, errors)
        return errors

    copy_artifacts(source_dir, archive_dir)
    try:
        manifest = build_manifest(source_dir, archive_dir, retention_days)
    except ValueError as exc:
        errors = [str(exc)]
        write_retention_report(archive_dir, errors, None)
        write_restore_report(archive_dir, errors, None)
        write_integrity_report(archive_dir, errors)
        return errors
    write_json(archive_dir / ARCHIVE_MANIFEST, manifest)
    errors = verify_archive(archive_dir)
    return errors


def verify_archive(archive_dir: Path) -> list[str]:
    manifest_path = archive_dir / ARCHIVE_MANIFEST
    if not manifest_path.is_file():
        errors = ["PB009_ARCHIVE_MANIFEST_MISSING"]
        write_retention_report(archive_dir, errors, None)
        write_restore_report(archive_dir, errors, None)
        write_integrity_report(archive_dir, errors)
        return errors
    try:
        manifest = load_json(manifest_path)
    except ValueError as exc:
        errors = [f"PB009_ARCHIVE_MANIFEST_INVALID:{exc}"]
        write_retention_report(archive_dir, errors, None)
        write_restore_report(archive_dir, errors, None)
        write_integrity_report(archive_dir, errors)
        return errors

    integrity_errors = verify_archive_integrity(archive_dir, manifest)
    retention_errors = verify_retention(manifest)
    errors = integrity_errors + retention_errors
    write_retention_report(archive_dir, retention_errors, manifest)
    write_restore_report(archive_dir, integrity_errors, manifest)
    write_integrity_report(archive_dir, errors)
    return errors


def main() -> int:
    parser = argparse.ArgumentParser(description="PB-009 immutable evidence archive control.")
    subparsers = parser.add_subparsers(dest="mode", required=True)

    archive_parser = subparsers.add_parser("archive")
    archive_parser.add_argument("source_dir")
    archive_parser.add_argument("archive_dir")
    archive_parser.add_argument("--retention-days", type=int, default=DEFAULT_RETENTION_DAYS)

    verify_parser = subparsers.add_parser("verify")
    verify_parser.add_argument("archive_dir")

    args = parser.parse_args()
    if args.mode == "archive":
        errors = archive(Path(args.source_dir).resolve(), Path(args.archive_dir).resolve(), args.retention_days)
    else:
        errors = verify_archive(Path(args.archive_dir).resolve())

    if errors:
        print("Decision: BLOCKED")
        for error in errors:
            print(error)
        return 1
    print("Decision: VERIFIED")
    print("PB009_ARCHIVE_VERIFICATION_VERIFIED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
