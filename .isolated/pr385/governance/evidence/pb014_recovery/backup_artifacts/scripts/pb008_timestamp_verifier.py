#!/usr/bin/env python3
"""PB-008 RFC3161-compatible timestamp control.

This utility is independent and fail-closed. It does not call AWS,
PostgreSQL, or an external timestamp authority. It creates and verifies a
local RFC3161-style timestamp receipt that binds the PB-006 signed evidence
manifest hash to deterministic timestamp-authority response metadata.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


PB006_MANIFEST = "pb006_signed_evidence_manifest.json"
RECEIPT_NAME = "pb008_timestamp_receipt.json"
REPORT_NAME = "pb008_non_repudiation_report.json"
RECEIPT_SCHEMA = "usbay.pb008.rfc3161_timestamp_receipt.v1"
REPORT_SCHEMA = "usbay.pb008.non_repudiation_report.v1"
TSA_AUTHORITY_ID = "USBAY-PB008-LOCAL-RFC3161-TSA"
TSA_POLICY_ID = "USBAY-PB008-RFC3161-COMPATIBLE-POLICY"
SUPPORTED_RECEIPT_ARTIFACT = PB006_MANIFEST


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


def tsa_signature(tst_info: dict[str, Any]) -> str:
    payload = {
        "timestamp_authority_id": TSA_AUTHORITY_ID,
        "timestamp_policy_id": TSA_POLICY_ID,
        "tst_info": tst_info,
    }
    return sha256_bytes(canonical(payload).encode("utf-8"))


def build_receipt(evidence_dir: Path) -> dict[str, Any]:
    manifest_path = evidence_dir / PB006_MANIFEST
    manifest_hash = sha256_file(manifest_path)
    generated_at = utc_now()
    tst_info = {
        "version": 1,
        "policy_id": TSA_POLICY_ID,
        "message_imprint_algorithm": "sha256",
        "message_imprint": manifest_hash,
        "serial_number": sha256_bytes(
            canonical(
                {
                    "manifest_hash": manifest_hash,
                    "timestamp_authority_id": TSA_AUTHORITY_ID,
                    "generated_at": generated_at,
                }
            ).encode("utf-8")
        ),
        "gen_time": generated_at,
        "nonce": sha256_bytes(f"{manifest_hash}:{TSA_AUTHORITY_ID}".encode("utf-8")),
        "tsa_authority_id": TSA_AUTHORITY_ID,
    }
    response = {
        "status": "granted",
        "status_code": 0,
        "timestamp_token_hash": sha256_bytes(canonical(tst_info).encode("utf-8")),
        "signature_algorithm": "SHA256_DETERMINISTIC_TSA_SIGNATURE",
        "signature_hash": tsa_signature(tst_info),
    }
    return {
        "schema": RECEIPT_SCHEMA,
        "generated_at": generated_at,
        "receipt_type": "RFC3161_COMPATIBLE_TIMESTAMP_RECEIPT",
        "timestamped_artifact": PB006_MANIFEST,
        "timestamped_artifact_sha256": manifest_hash,
        "timestamp_authority": {
            "authority_id": TSA_AUTHORITY_ID,
            "policy_id": TSA_POLICY_ID,
            "external_tsa_call_performed": False,
            "aws_access_performed": False,
            "postgresql_access_performed": False,
        },
        "tst_info": tst_info,
        "tsa_response": response,
        "fail_closed": False,
        "no_certification_claim": True,
        "no_external_tsa_claim": True,
    }


def verify_receipt(evidence_dir: Path, receipt: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    if receipt.get("schema") != RECEIPT_SCHEMA:
        errors.append("PB008_RECEIPT_SCHEMA_INVALID")

    artifact = receipt.get("timestamped_artifact")
    if artifact != SUPPORTED_RECEIPT_ARTIFACT:
        errors.append(f"PB008_UNSUPPORTED_ARTIFACT:{artifact}")
        return errors

    manifest_path = evidence_dir / PB006_MANIFEST
    if not manifest_path.is_file():
        errors.append(f"PB008_TIMESTAMPED_ARTIFACT_MISSING:{PB006_MANIFEST}")
        return errors

    current_manifest_hash = sha256_file(manifest_path)
    expected_manifest_hash = receipt.get("timestamped_artifact_sha256")
    if expected_manifest_hash != current_manifest_hash:
        errors.append("PB008_MANIFEST_HASH_MISMATCH")

    tst_info = receipt.get("tst_info")
    if not isinstance(tst_info, dict):
        errors.append("PB008_TST_INFO_MISSING")
        return errors
    if tst_info.get("message_imprint_algorithm") != "sha256":
        errors.append("PB008_MESSAGE_IMPRINT_ALGORITHM_INVALID")
    if tst_info.get("message_imprint") != expected_manifest_hash:
        errors.append("PB008_MESSAGE_IMPRINT_MISMATCH")
    if tst_info.get("tsa_authority_id") != TSA_AUTHORITY_ID:
        errors.append("PB008_TSA_AUTHORITY_MISMATCH")
    if not tst_info.get("gen_time"):
        errors.append("PB008_TIMESTAMP_MISSING")

    authority = receipt.get("timestamp_authority")
    if not isinstance(authority, dict):
        errors.append("PB008_TIMESTAMP_AUTHORITY_MISSING")
    else:
        if authority.get("authority_id") != TSA_AUTHORITY_ID:
            errors.append("PB008_TIMESTAMP_AUTHORITY_INVALID")
        if authority.get("external_tsa_call_performed") is not False:
            errors.append("PB008_EXTERNAL_TSA_CALL_UNVERIFIED")
        if authority.get("aws_access_performed") is not False:
            errors.append("PB008_AWS_ACCESS_UNEXPECTED")
        if authority.get("postgresql_access_performed") is not False:
            errors.append("PB008_POSTGRESQL_ACCESS_UNEXPECTED")

    response = receipt.get("tsa_response")
    if not isinstance(response, dict):
        errors.append("PB008_TSA_RESPONSE_MISSING")
        return errors
    if response.get("status") != "granted" or response.get("status_code") != 0:
        errors.append("PB008_TSA_RESPONSE_NOT_GRANTED")
    if response.get("timestamp_token_hash") != sha256_bytes(canonical(tst_info).encode("utf-8")):
        errors.append("PB008_TIMESTAMP_TOKEN_HASH_MISMATCH")
    if response.get("signature_hash") != tsa_signature(tst_info):
        errors.append("PB008_TSA_VERIFICATION_FAILED")
    if response.get("signature_algorithm") != "SHA256_DETERMINISTIC_TSA_SIGNATURE":
        errors.append("PB008_TSA_SIGNATURE_ALGORITHM_INVALID")
    return errors


def write_report(evidence_dir: Path, errors: list[str]) -> dict[str, Any]:
    report = {
        "schema": REPORT_SCHEMA,
        "generated_at": utc_now(),
        "decision": "VERIFIED" if not errors else "BLOCKED",
        "fail_closed": bool(errors),
        "errors": errors,
        "receipt_path": (evidence_dir / RECEIPT_NAME).as_posix(),
        "timestamp_receipt_present": (evidence_dir / RECEIPT_NAME).is_file(),
        "timestamp_valid": not errors,
        "manifest_hash_verified": not any("MANIFEST_HASH_MISMATCH" in error for error in errors),
        "tsa_response_verified": not any("TSA" in error for error in errors),
        "aws_access_performed": False,
        "postgresql_access_performed": False,
        "no_certification_claim": True,
    }
    evidence_dir.mkdir(parents=True, exist_ok=True)
    write_json(evidence_dir / REPORT_NAME, report)
    return report


def generate(evidence_dir: Path) -> list[str]:
    if not evidence_dir.is_dir():
        errors = [f"PB008_EVIDENCE_DIR_MISSING:{evidence_dir}"]
        write_report(evidence_dir, errors)
        return errors
    if not (evidence_dir / PB006_MANIFEST).is_file():
        errors = [f"PB008_TIMESTAMPED_ARTIFACT_MISSING:{PB006_MANIFEST}"]
        write_report(evidence_dir, errors)
        return errors
    receipt = build_receipt(evidence_dir)
    write_json(evidence_dir / RECEIPT_NAME, receipt)
    errors = verify_receipt(evidence_dir, receipt)
    write_report(evidence_dir, errors)
    return errors


def verify(evidence_dir: Path) -> list[str]:
    receipt_path = evidence_dir / RECEIPT_NAME
    if not receipt_path.is_file():
        errors = ["PB008_TIMESTAMP_MISSING"]
        write_report(evidence_dir, errors)
        return errors
    try:
        receipt = load_json(receipt_path)
    except ValueError as exc:
        errors = [f"PB008_RECEIPT_INVALID:{exc}"]
        write_report(evidence_dir, errors)
        return errors
    errors = verify_receipt(evidence_dir, receipt)
    write_report(evidence_dir, errors)
    return errors


def main() -> int:
    parser = argparse.ArgumentParser(description="PB-008 RFC3161 timestamp verifier.")
    parser.add_argument("mode", choices=("generate", "verify"))
    parser.add_argument("evidence_dir")
    args = parser.parse_args()
    evidence_dir = Path(args.evidence_dir).resolve()
    errors = generate(evidence_dir) if args.mode == "generate" else verify(evidence_dir)
    if errors:
        print("Decision: BLOCKED")
        for error in errors:
            print(error)
        return 1
    print("Decision: VERIFIED")
    print("PB008_TIMESTAMP_VERIFICATION_VERIFIED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
