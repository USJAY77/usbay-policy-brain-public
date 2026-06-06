#!/usr/bin/env python3
"""Generate and verify PB-006 evidence integrity manifests.

The control is local and fail-closed. It does not call providers, load
credentials, or claim WORM closure. It binds evidence artifacts to SHA256
hashes and a deterministic manifest signature so tampering is visible before
review/export.
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
SCHEMA = "usbay.pb006.evidence_integrity_manifest.v1"
REPORT_SCHEMA = "usbay.pb006.integrity_report.v1"
SIGNING_KEY_ID = "USBAY-PB006-LOCAL-INTEGRITY-CONTROL"
EXCLUDED_NAMES = {MANIFEST_NAME, REPORT_NAME, ".DS_Store"}


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
        path
        for path in evidence_dir.rglob("*")
        if path.is_file() and path.name not in EXCLUDED_NAMES
    )


def relative(path: Path, root: Path) -> str:
    return path.relative_to(root).as_posix()


def sign_payload(payload: dict[str, Any]) -> str:
    signing_body = {
        "signing_key_id": SIGNING_KEY_ID,
        "payload": payload,
    }
    return sha256_bytes(canonical(signing_body).encode("utf-8"))


def build_manifest(evidence_dir: Path) -> dict[str, Any]:
    artifacts = {
        relative(path, evidence_dir): sha256_file(path)
        for path in evidence_files(evidence_dir)
    }
    payload = {
        "schema": SCHEMA,
        "evidence_directory": evidence_dir.as_posix(),
        "generated_at": utc_now(),
        "artifact_hashes": artifacts,
        "artifact_count": len(artifacts),
        "aggregate_hash": sha256_bytes(canonical(artifacts).encode("utf-8")),
        "pb005_compatible": any(name.startswith("pb005_") for name in artifacts),
        "fail_closed": False,
        "no_provider_claim": True,
        "no_worm_closure_claim": True,
    }
    payload["signature"] = {
        "algorithm": "SHA256_DETERMINISTIC_MANIFEST_SIGNATURE",
        "signing_key_id": SIGNING_KEY_ID,
        "signature_hash": sign_payload(payload),
    }
    return payload


def write_json(path: Path, data: dict[str, Any]) -> None:
    path.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def load_json(path: Path) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ValueError(f"{path.name}:JSON_INVALID:{exc.msg}") from exc
    if not isinstance(payload, dict):
        raise ValueError(f"{path.name}:JSON_OBJECT_REQUIRED")
    return payload


def verify_manifest(evidence_dir: Path, manifest: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    if manifest.get("schema") != SCHEMA:
        errors.append("PB006_MANIFEST_SCHEMA_INVALID")
    hashes = manifest.get("artifact_hashes")
    if not isinstance(hashes, dict) or not hashes:
        errors.append("PB006_ARTIFACT_HASHES_MISSING")
        return errors

    signature = manifest.get("signature")
    if not isinstance(signature, dict):
        errors.append("PB006_SIGNATURE_MISSING")
    else:
        expected_signature = signature.get("signature_hash")
        unsigned = dict(manifest)
        unsigned.pop("signature", None)
        actual_signature = sign_payload(unsigned)
        if expected_signature != actual_signature:
            errors.append("PB006_SIGNATURE_MISMATCH")
        if signature.get("signing_key_id") != SIGNING_KEY_ID:
            errors.append("PB006_SIGNING_KEY_ID_MISMATCH")

    actual_paths = {relative(path, evidence_dir): path for path in evidence_files(evidence_dir)}
    for artifact, expected_hash in sorted(hashes.items()):
        if not isinstance(expected_hash, str) or len(expected_hash) != 64:
            errors.append(f"PB006_ARTIFACT_HASH_INVALID:{artifact}")
            continue
        path = actual_paths.get(artifact)
        if path is None:
            errors.append(f"PB006_ARTIFACT_MISSING:{artifact}")
            continue
        actual_hash = sha256_file(path)
        if actual_hash != expected_hash:
            errors.append(f"PB006_ARTIFACT_HASH_MISMATCH:{artifact}")

    unexpected = sorted(set(actual_paths) - set(hashes))
    for artifact in unexpected:
        errors.append(f"PB006_UNMANIFESTED_ARTIFACT:{artifact}")

    aggregate_hash = sha256_bytes(canonical(hashes).encode("utf-8"))
    if manifest.get("aggregate_hash") != aggregate_hash:
        errors.append("PB006_AGGREGATE_HASH_MISMATCH")
    return errors


def write_report(evidence_dir: Path, errors: list[str], manifest_path: Path) -> dict[str, Any]:
    report = {
        "schema": REPORT_SCHEMA,
        "generated_at": utc_now(),
        "decision": "VERIFIED" if not errors else "BLOCKED",
        "fail_closed": bool(errors),
        "manifest_path": manifest_path.as_posix(),
        "errors": errors,
        "artifact_modification_detected": any("HASH_MISMATCH" in error for error in errors),
        "missing_artifact_detected": any("MISSING" in error for error in errors),
        "pb005_compatible": (evidence_dir / "pb005_evidence_manifest.json").is_file(),
    }
    write_json(evidence_dir / REPORT_NAME, report)
    return report


def generate(evidence_dir: Path) -> dict[str, Any]:
    if not evidence_dir.is_dir():
        raise FileNotFoundError(f"evidence_dir_missing:{evidence_dir}")
    manifest = build_manifest(evidence_dir)
    manifest_path = evidence_dir / MANIFEST_NAME
    write_json(manifest_path, manifest)
    errors = verify_manifest(evidence_dir, manifest)
    write_report(evidence_dir, errors, manifest_path)
    return manifest


def verify(evidence_dir: Path) -> list[str]:
    manifest_path = evidence_dir / MANIFEST_NAME
    if not manifest_path.is_file():
        errors = ["PB006_SIGNED_MANIFEST_MISSING"]
        write_report(evidence_dir, errors, manifest_path)
        return errors
    try:
        manifest = load_json(manifest_path)
    except ValueError as exc:
        errors = [str(exc)]
        write_report(evidence_dir, errors, manifest_path)
        return errors
    errors = verify_manifest(evidence_dir, manifest)
    write_report(evidence_dir, errors, manifest_path)
    return errors


def main() -> int:
    parser = argparse.ArgumentParser(description="PB-006 evidence integrity control.")
    parser.add_argument("mode", choices=("generate", "verify"))
    parser.add_argument("evidence_dir")
    args = parser.parse_args()
    evidence_dir = Path(args.evidence_dir).resolve()
    try:
        if args.mode == "generate":
            generate(evidence_dir)
            errors = verify(evidence_dir)
        else:
            errors = verify(evidence_dir)
    except Exception as exc:
        errors = [f"PB006_VERIFIER_EXCEPTION:{type(exc).__name__}:{exc}"]
        evidence_dir.mkdir(parents=True, exist_ok=True)
        write_report(evidence_dir, errors, evidence_dir / MANIFEST_NAME)

    if errors:
        print("Decision: BLOCKED")
        for error in errors:
            print(error)
        return 1
    print("Decision: VERIFIED")
    print("PB006_EVIDENCE_INTEGRITY_VERIFIED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
