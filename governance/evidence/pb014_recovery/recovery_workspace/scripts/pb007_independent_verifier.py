#!/usr/bin/env python3
"""PB-007 independent evidence verifier.

Offline verifier. It does not call AWS, PostgreSQL, TSA, providers, or networks.
It validates PB-005 evidence, PB-006 signed manifest, and PB-006 integrity report.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

REPORT_NAME = "pb007_verification_report.json"
PB006_MANIFEST = "pb006_signed_evidence_manifest.json"
PB006_REPORT = "pb006_integrity_report.json"
CONTROL_ID = "PB-007"

REQUIRED_PB005 = {
    "pb005_endpoint_evidence.json",
    "pb005_schema_evidence.json",
    "pb005_write_receipt.json",
    "pb005_read_receipt.json",
    "pb005_persistence_evidence.json",
    "pb005_evidence_manifest.json",
    "pb005_final_execution_report.json",
}

ALLOWED_ARTIFACTS = REQUIRED_PB005 | {
    PB006_MANIFEST,
    PB006_REPORT,
    REPORT_NAME,
    "pb008_timestamp_receipt.json",
    "pb008_non_repudiation_report.json",
    ".DS_Store",
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


def load_json(path: Path) -> Any:
    return json.loads(path.read_text())


def verify(evidence_dir: Path) -> int:
    evidence_dir = evidence_dir.resolve()

    missing_pb005 = sorted(
        name for name in REQUIRED_PB005
        if not (evidence_dir / name).exists()
    )

    unsupported = sorted(
        p.name for p in evidence_dir.iterdir()
        if p.is_file() and p.name not in ALLOWED_ARTIFACTS
    )

    manifest_path = evidence_dir / PB006_MANIFEST
    report_path = evidence_dir / PB006_REPORT

    errors = []
    if missing_pb005:
        errors.append("pb005_artifacts_missing")
    if unsupported:
        errors.append("unsupported_artifacts_present")
    if not manifest_path.exists():
        errors.append("pb006_manifest_missing")
    if not report_path.exists():
        errors.append("pb006_report_missing")

    manifest_signature_verified = False
    pb006_report_verified = False
    hash_mismatches = []

    if manifest_path.exists():
        try:
            manifest = load_json(manifest_path)
            artifacts = manifest.get("artifacts", [])

            body = {k: v for k, v in manifest.items() if k not in {"manifest_signature", "signature_algorithm"}}
            expected_signature = sha256_bytes(canonical(body).encode())
            manifest_signature_verified = manifest.get("manifest_signature") == expected_signature

            for artifact in artifacts:
                rel = artifact.get("path")
                expected_hash = artifact.get("sha256")
                artifact_path = evidence_dir / str(rel)

                if not artifact_path.exists():
                    errors.append(f"manifest_artifact_missing:{rel}")
                    continue

                actual_hash = sha256_file(artifact_path)
                if actual_hash != expected_hash:
                    hash_mismatches.append(str(rel))

            if not manifest_signature_verified:
                errors.append("pb006_manifest_signature_invalid")
        except Exception as exc:
            errors.append(f"pb006_manifest_invalid:{exc}")

    if report_path.exists():
        try:
            pb006_report = load_json(report_path)
            pb006_report_verified = (
                pb006_report.get("decision") == "VERIFIED"
                and pb006_report.get("fail_closed") is False
            )
            if not pb006_report_verified:
                errors.append("pb006_report_not_verified")
        except Exception as exc:
            errors.append(f"pb006_report_invalid:{exc}")

    if hash_mismatches:
        errors.append("artifact_hash_mismatch")

    fail_closed = bool(errors)

    report = {
        "control_id": CONTROL_ID,
        "decision": "BLOCKED" if fail_closed else "VERIFIED",
        "fail_closed": fail_closed,
        "missing_pb005_artifacts": missing_pb005,
        "unsupported_artifacts": unsupported,
        "hash_mismatches": hash_mismatches,
        "pb006_manifest_present": manifest_path.exists(),
        "pb006_manifest_signature_verified": manifest_signature_verified,
        "pb006_report_present": report_path.exists(),
        "pb006_report_verified": pb006_report_verified,
        "errors": errors,
        "verified_at": utc_now(),
        "aws_access_performed": False,
        "postgresql_access_performed": False,
        "external_network_access_performed": False,
        "independent_verifier": True,
    }

    (evidence_dir / REPORT_NAME).write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n"
    )

    print(f"Decision: {report['decision']}")
    if report["decision"] == "VERIFIED":
        print("PB007_INDEPENDENT_VERIFICATION_VERIFIED")
        return 0

    print("PB007_INDEPENDENT_VERIFICATION_BLOCKED")
    return 1


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("evidence_dir")
    args = parser.parse_args()
    return verify(Path(args.evidence_dir))


if __name__ == "__main__":
    sys.exit(main())
