#!/usr/bin/env python3
"""PB-006 evidence integrity control.

Local, fail-closed utility. No AWS, PostgreSQL, TSA, or network calls.
Creates and verifies SHA256 manifests for governance evidence artifacts.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

MANIFEST_NAME = "pb006_signed_evidence_manifest.json"
REPORT_NAME = "pb006_integrity_report.json"
CONTROL_ID = "PB-006"
SIGNING_KEY_ID = "USBAY-PB006-LOCAL-INTEGRITY-CONTROL"

EXCLUDED_NAMES = {
    MANIFEST_NAME,
    REPORT_NAME,
    "pb007_verification_report.json",
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


def evidence_files(evidence_dir: Path) -> list[Path]:
    return sorted(
        p for p in evidence_dir.rglob("*")
        if p.is_file() and p.name not in EXCLUDED_NAMES
    )


def generate(evidence_dir: Path) -> int:
    evidence_dir = evidence_dir.resolve()
    files = evidence_files(evidence_dir)

    if not files:
        return write_report(evidence_dir, "BLOCKED", True, "missing_artifacts")

    artifacts = []
    for file_path in files:
        rel = file_path.relative_to(evidence_dir).as_posix()
        artifacts.append({
            "path": rel,
            "sha256": sha256_file(file_path),
            "size_bytes": file_path.stat().st_size,
        })

    aggregate_hash = sha256_bytes(canonical(artifacts).encode())

    manifest_body = {
        "control_id": CONTROL_ID,
        "created_at": utc_now(),
        "evidence_dir": str(evidence_dir),
        "artifacts": artifacts,
        "aggregate_hash": aggregate_hash,
        "signing_key_id": SIGNING_KEY_ID,
    }
    signature = sha256_bytes(canonical(manifest_body).encode())

    manifest = {
        **manifest_body,
        "signature_algorithm": "sha256-local-deterministic",
        "manifest_signature": signature,
    }

    (evidence_dir / MANIFEST_NAME).write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n"
    )

    return verify(evidence_dir)


def verify(evidence_dir: Path) -> int:
    evidence_dir = evidence_dir.resolve()
    manifest_path = evidence_dir / MANIFEST_NAME

    if not manifest_path.exists():
        return write_report(evidence_dir, "BLOCKED", True, "manifest_missing")

    try:
        manifest = json.loads(manifest_path.read_text())
    except Exception as exc:
        return write_report(evidence_dir, "BLOCKED", True, f"manifest_invalid:{exc}")

    artifacts = manifest.get("artifacts", [])
    if not isinstance(artifacts, list) or not artifacts:
        return write_report(evidence_dir, "BLOCKED", True, "manifest_artifacts_missing")

    missing = []
    changed = []

    for artifact in artifacts:
        rel = artifact.get("path")
        expected_hash = artifact.get("sha256")
        path = evidence_dir / str(rel)

        if not path.exists():
            missing.append(str(rel))
            continue

        actual_hash = sha256_file(path)
        if actual_hash != expected_hash:
            changed.append(str(rel))

    expected_aggregate = manifest.get("aggregate_hash")
    actual_aggregate = sha256_bytes(canonical(artifacts).encode())

    signature = manifest.get("manifest_signature")
    body = {k: v for k, v in manifest.items() if k not in {"manifest_signature", "signature_algorithm"}}
    expected_signature = sha256_bytes(canonical(body).encode())

    fail_closed = bool(
        missing
        or changed
        or expected_aggregate != actual_aggregate
        or signature != expected_signature
    )

    report = {
        "control_id": CONTROL_ID,
        "decision": "BLOCKED" if fail_closed else "VERIFIED",
        "fail_closed": fail_closed,
        "artifact_modification_detected": bool(changed),
        "missing_artifact_detected": bool(missing),
        "aggregate_hash_verified": expected_aggregate == actual_aggregate,
        "manifest_signature_verified": signature == expected_signature,
        "missing_artifacts": missing,
        "modified_artifacts": changed,
        "verified_at": utc_now(),
        "pb005_compatible": True,
        "aws_access_performed": False,
        "postgresql_access_performed": False,
        "external_network_access_performed": False,
    }

    (evidence_dir / REPORT_NAME).write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n"
    )

    print(f"Decision: {report['decision']}")
    if report["decision"] == "VERIFIED":
        print("PB006_EVIDENCE_INTEGRITY_VERIFIED")
        return 0

    print("PB006_EVIDENCE_INTEGRITY_BLOCKED")
    return 1


def write_report(evidence_dir: Path, decision: str, fail_closed: bool, reason: str) -> int:
    evidence_dir.mkdir(parents=True, exist_ok=True)
    report = {
        "control_id": CONTROL_ID,
        "decision": decision,
        "fail_closed": fail_closed,
        "reason": reason,
        "verified_at": utc_now(),
    }
    (evidence_dir / REPORT_NAME).write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n"
    )
    print(f"Decision: {decision}")
    return 1


def main() -> int:
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="command", required=True)
    for cmd in ("generate", "verify"):
        p = sub.add_parser(cmd)
        p.add_argument("evidence_dir")

    args = parser.parse_args()
    if args.command == "generate":
        return generate(Path(args.evidence_dir))
    return verify(Path(args.evidence_dir))


if __name__ == "__main__":
    sys.exit(main())
