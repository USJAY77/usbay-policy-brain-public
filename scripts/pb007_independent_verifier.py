#!/usr/bin/env python3
"""PB-007 independent evidence verifier.

This verifier is intentionally offline. It must not call AWS, PostgreSQL, or
any external service. It validates the PB-005 evidence bundle, PB-006 signed
integrity manifest, and PB-006 integrity report using local file hashes only.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


REPORT_NAME = "pb007_verification_report.json"
PB006_MANIFEST = "pb006_signed_evidence_manifest.json"
PB006_REPORT = "pb006_integrity_report.json"
PB006_SCHEMA = "usbay.pb006.evidence_integrity_manifest.v1"
PB006_SIGNING_KEY_ID = "USBAY-PB006-LOCAL-INTEGRITY-CONTROL"
REPORT_SCHEMA = "usbay.pb007.independent_verification_report.v1"

REQUIRED_PB005 = {
    "pb005_endpoint_evidence.json",
    "pb005_schema_evidence.json",
    "pb005_write_receipt.json",
    "pb005_read_receipt.json",
    "pb005_persistence_evidence.json",
    "pb005_evidence_manifest.json",
    "pb005_final_execution_report.json",
}
REQUIRED_PB006 = {PB006_MANIFEST, PB006_REPORT}
ALLOWED_ARTIFACTS = REQUIRED_PB005 | REQUIRED_PB006 | {
    REPORT_NAME,
    "pb008_timestamp_receipt.json",
    "pb008_non_repudiation_report.json",
}


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
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def sign_pb006_payload(payload: dict[str, Any]) -> str:
    return sha256_bytes(
        canonical(
            {
                "signing_key_id": PB006_SIGNING_KEY_ID,
                "payload": payload,
            }
        ).encode("utf-8")
    )


def verify_pb005_bundle(evidence_dir: Path) -> list[str]:
    errors: list[str] = []
    manifest_path = evidence_dir / "pb005_evidence_manifest.json"
    try:
        manifest = load_json(manifest_path)
    except Exception as exc:
        return [f"PB007_PB005_MANIFEST_INVALID:{exc}"]

    if manifest.get("classification") != "VERIFIED":
        errors.append("PB007_PB005_MANIFEST_NOT_VERIFIED")
    hashes = manifest.get("artifact_hashes")
    if not isinstance(hashes, dict) or not hashes:
        errors.append("PB007_PB005_MANIFEST_HASHES_MISSING")
        return errors

    manifest_required = REQUIRED_PB005 - {"pb005_final_execution_report.json", "pb005_evidence_manifest.json"}
    for artifact in sorted(manifest_required):
        expected_hash = hashes.get(artifact)
        if not expected_hash:
            errors.append(f"PB007_PB005_MANIFEST_ARTIFACT_MISSING:{artifact}")
            continue
        path = evidence_dir / artifact
        if not path.is_file():
            errors.append(f"PB007_ARTIFACT_MISSING:{artifact}")
            continue
        actual_hash = sha256_file(path)
        if actual_hash != expected_hash:
            errors.append(f"PB007_PB005_HASH_MISMATCH:{artifact}")

    aggregate_hash = sha256_bytes(canonical(hashes).encode("utf-8"))
    if manifest.get("aggregate_hash") != aggregate_hash:
        errors.append("PB007_PB005_AGGREGATE_HASH_MISMATCH")

    for artifact in sorted(REQUIRED_PB005):
        path = evidence_dir / artifact
        if not path.is_file():
            errors.append(f"PB007_ARTIFACT_MISSING:{artifact}")
            continue
        try:
            payload = load_json(path)
        except ValueError as exc:
            errors.append(str(exc))
            continue
        if artifact == "pb005_final_execution_report.json":
            if payload.get("final_classification") != "VERIFIED":
                errors.append("PB007_PB005_FINAL_REPORT_NOT_VERIFIED")
        elif payload.get("classification") != "VERIFIED":
            errors.append(f"PB007_PB005_ARTIFACT_NOT_VERIFIED:{artifact}")
    return errors


def verify_pb006_outputs(evidence_dir: Path) -> list[str]:
    errors: list[str] = []
    try:
        manifest = load_json(evidence_dir / PB006_MANIFEST)
    except Exception as exc:
        return [f"PB007_PB006_MANIFEST_INVALID:{exc}"]
    try:
        report = load_json(evidence_dir / PB006_REPORT)
    except Exception as exc:
        errors.append(f"PB007_PB006_REPORT_INVALID:{exc}")
        report = {}

    if manifest.get("schema") != PB006_SCHEMA:
        errors.append("PB007_PB006_MANIFEST_SCHEMA_INVALID")
    if manifest.get("pb005_compatible") is not True:
        errors.append("PB007_PB006_NOT_PB005_COMPATIBLE")

    signature = manifest.get("signature")
    if not isinstance(signature, dict):
        errors.append("PB007_PB006_SIGNATURE_MISSING")
    else:
        unsigned = dict(manifest)
        unsigned.pop("signature", None)
        if signature.get("signature_hash") != sign_pb006_payload(unsigned):
            errors.append("PB007_PB006_SIGNATURE_MISMATCH")
        if signature.get("signing_key_id") != PB006_SIGNING_KEY_ID:
            errors.append("PB007_PB006_SIGNING_KEY_MISMATCH")

    hashes = manifest.get("artifact_hashes")
    if not isinstance(hashes, dict) or not hashes:
        errors.append("PB007_PB006_ARTIFACT_HASHES_MISSING")
        return errors

    for artifact, expected_hash in sorted(hashes.items()):
        path = evidence_dir / artifact
        if not path.is_file():
            errors.append(f"PB007_ARTIFACT_MISSING:{artifact}")
            continue
        if sha256_file(path) != expected_hash:
            errors.append(f"PB007_PB006_HASH_MISMATCH:{artifact}")
    if manifest.get("aggregate_hash") != sha256_bytes(canonical(hashes).encode("utf-8")):
        errors.append("PB007_PB006_AGGREGATE_HASH_MISMATCH")

    if report.get("decision") != "VERIFIED":
        errors.append("PB007_PB006_REPORT_NOT_VERIFIED")
    if report.get("fail_closed") is not False:
        errors.append("PB007_PB006_REPORT_FAIL_CLOSED")
    if report.get("pb005_compatible") is not True:
        errors.append("PB007_PB006_REPORT_NOT_PB005_COMPATIBLE")
    return errors


def verify(evidence_dir: Path) -> list[str]:
    errors: list[str] = []
    if not evidence_dir.is_dir():
        return [f"PB007_EVIDENCE_DIR_MISSING:{evidence_dir}"]

    present = {path.name for path in evidence_dir.iterdir() if path.is_file()}
    for artifact in sorted((REQUIRED_PB005 | REQUIRED_PB006) - present):
        errors.append(f"PB007_ARTIFACT_MISSING:{artifact}")
    for artifact in sorted(present - ALLOWED_ARTIFACTS):
        errors.append(f"PB007_UNSUPPORTED_ARTIFACT:{artifact}")

    if not errors:
        errors.extend(verify_pb005_bundle(evidence_dir))
        errors.extend(verify_pb006_outputs(evidence_dir))
    return errors


def write_report(evidence_dir: Path, errors: list[str]) -> dict[str, Any]:
    report = {
        "schema": REPORT_SCHEMA,
        "generated_at": utc_now(),
        "decision": "VERIFIED" if not errors else "BLOCKED",
        "fail_closed": bool(errors),
        "errors": errors,
        "aws_access_performed": False,
        "postgresql_access_performed": False,
        "pb005_bundle_verified": not errors,
        "pb006_integrity_verified": not errors,
        "artifact_modification_detected": any("HASH_MISMATCH" in error for error in errors),
        "missing_artifact_detected": any("MISSING" in error for error in errors),
        "unsupported_artifact_detected": any("UNSUPPORTED_ARTIFACT" in error for error in errors),
    }
    evidence_dir.mkdir(parents=True, exist_ok=True)
    write_json(evidence_dir / REPORT_NAME, report)
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description="PB-007 independent evidence verifier.")
    parser.add_argument("evidence_dir")
    args = parser.parse_args()
    evidence_dir = Path(args.evidence_dir).resolve()
    errors = verify(evidence_dir)
    write_report(evidence_dir, errors)
    if errors:
        print("Decision: BLOCKED")
        for error in errors:
            print(error)
        return 1
    print("Decision: VERIFIED")
    print("PB007_INDEPENDENT_VERIFICATION_VERIFIED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
