#!/usr/bin/env python3
"""PB-011 local governance baseline drift detector.

PB-011 creates a baseline from the PB-010 certified governance state and then
verifies PB-005 through PB-010 artifacts against that frozen baseline. It is
local-only and performs no AWS, PostgreSQL, TSA, or external network calls.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


BASELINE_NAME = "pb011_baseline_manifest.json"
DRIFT_REPORT_NAME = "pb011_drift_report.json"
SCORECARD_NAME = "pb011_drift_scorecard.json"
BASELINE_SCHEMA = "usbay.pb011.baseline_manifest.v1"
DRIFT_REPORT_SCHEMA = "usbay.pb011.drift_report.v1"
SCORECARD_SCHEMA = "usbay.pb011.drift_scorecard.v1"
BASELINE_KEY_ID = "USBAY-PB011-LOCAL-BASELINE-DRIFT-CONTROL"

PB005_ALLOWED = {
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
PB009_ROOT_ALLOWED = {
    "pb009_archive_manifest.json",
    "pb009_retention_report.json",
    "pb009_restore_verification_report.json",
    "pb009_archive_integrity_report.json",
}
PB010_ALLOWED = {
    "pb010_chain_certificate.json",
    "pb010_chain_verification_report.json",
    "pb010_governance_scorecard.json",
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
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def baseline_signature(payload: dict[str, Any]) -> str:
    return sha256_bytes(
        canonical(
            {
                "baseline_key_id": BASELINE_KEY_ID,
                "payload": payload,
            }
        ).encode("utf-8")
    )


def collect_hashes(pb005_dir: Path, pb009_archive_dir: Path, pb010_dir: Path) -> tuple[dict[str, str], list[str]]:
    hashes: dict[str, str] = {}
    errors: list[str] = []

    if not pb005_dir.is_dir():
        errors.append(f"PB011_PB005_DIR_MISSING:{pb005_dir}")
    else:
        present = {path.name for path in pb005_dir.iterdir() if path.is_file()}
        for artifact in sorted(PB005_ALLOWED - present):
            errors.append(f"PB011_CERTIFIED_ARTIFACT_MISSING:pb005/{artifact}")
        for artifact in sorted(present - PB005_ALLOWED):
            errors.append(f"PB011_UNSUPPORTED_ARTIFACT:pb005/{artifact}")
        for artifact in sorted(PB005_ALLOWED & present):
            hashes[f"pb005/{artifact}"] = sha256_file(pb005_dir / artifact)

    if not pb009_archive_dir.is_dir():
        errors.append(f"PB011_PB009_ARCHIVE_DIR_MISSING:{pb009_archive_dir}")
    else:
        present_root = {path.name for path in pb009_archive_dir.iterdir()}
        allowed_root = PB009_ROOT_ALLOWED | {"artifacts"}
        for artifact in sorted(PB009_ROOT_ALLOWED - present_root):
            errors.append(f"PB011_CERTIFIED_ARTIFACT_MISSING:pb009_archive/{artifact}")
        for artifact in sorted(present_root - allowed_root):
            errors.append(f"PB011_UNSUPPORTED_ARTIFACT:pb009_archive/{artifact}")
        for artifact in sorted(PB009_ROOT_ALLOWED & present_root):
            hashes[f"pb009_archive/{artifact}"] = sha256_file(pb009_archive_dir / artifact)

        artifacts_dir = pb009_archive_dir / "artifacts"
        if not artifacts_dir.is_dir():
            errors.append("PB011_CERTIFIED_ARTIFACT_MISSING:pb009_archive/artifacts")
        else:
            present_artifacts = {path.name for path in artifacts_dir.iterdir() if path.is_file()}
            for artifact in sorted(PB005_ALLOWED - present_artifacts):
                errors.append(f"PB011_CERTIFIED_ARTIFACT_MISSING:pb009_archive/artifacts/{artifact}")
            for artifact in sorted(present_artifacts - PB005_ALLOWED):
                errors.append(f"PB011_UNSUPPORTED_ARTIFACT:pb009_archive/artifacts/{artifact}")
            for artifact in sorted(PB005_ALLOWED & present_artifacts):
                hashes[f"pb009_archive/artifacts/{artifact}"] = sha256_file(artifacts_dir / artifact)

    if not pb010_dir.is_dir():
        errors.append(f"PB011_PB010_DIR_MISSING:{pb010_dir}")
    else:
        present = {path.name for path in pb010_dir.iterdir() if path.is_file()}
        for artifact in sorted(PB010_ALLOWED - present):
            errors.append(f"PB011_CERTIFICATION_ARTIFACT_MISSING:pb010_chain/{artifact}")
        for artifact in sorted(present - PB010_ALLOWED):
            errors.append(f"PB011_UNSUPPORTED_ARTIFACT:pb010_chain/{artifact}")
        for artifact in sorted(PB010_ALLOWED & present):
            hashes[f"pb010_chain/{artifact}"] = sha256_file(pb010_dir / artifact)

    return hashes, errors


def load_pb010_score(pb010_dir: Path) -> tuple[int | None, list[str]]:
    errors: list[str] = []
    scorecard_path = pb010_dir / "pb010_governance_scorecard.json"
    if not scorecard_path.is_file():
        return None, ["PB011_CERTIFICATION_ARTIFACT_MISSING:pb010_chain/pb010_governance_scorecard.json"]
    try:
        scorecard = load_json(scorecard_path)
    except Exception as exc:
        return None, [f"PB011_PB010_SCORECARD_INVALID:{exc}"]
    if scorecard.get("schema") != "usbay.pb010.governance_scorecard.v1":
        errors.append("PB011_PB010_SCORECARD_SCHEMA_INVALID")
    if scorecard.get("decision") != "VERIFIED":
        errors.append("PB011_PB010_SCORECARD_NOT_VERIFIED")
    score = scorecard.get("score")
    if not isinstance(score, int):
        errors.append("PB011_PB010_SCORE_INVALID")
        return None, errors
    return score, errors


def load_pb010_certificate(pb010_dir: Path) -> tuple[dict[str, Any], list[str]]:
    path = pb010_dir / "pb010_chain_certificate.json"
    if not path.is_file():
        return {}, ["PB011_CERTIFICATION_ARTIFACT_MISSING:pb010_chain/pb010_chain_certificate.json"]
    try:
        certificate = load_json(path)
    except Exception as exc:
        return {}, [f"PB011_PB010_CERTIFICATE_INVALID:{exc}"]
    errors: list[str] = []
    if certificate.get("schema") != "usbay.pb010.chain_certificate.v1":
        errors.append("PB011_PB010_CERTIFICATE_SCHEMA_INVALID")
    if certificate.get("decision") != "VERIFIED":
        errors.append("PB011_PB010_CERTIFICATE_NOT_VERIFIED")
    return certificate, errors


def build_baseline(pb005_dir: Path, pb009_archive_dir: Path, pb010_dir: Path, output_dir: Path) -> list[str]:
    hashes, errors = collect_hashes(pb005_dir, pb009_archive_dir, pb010_dir)
    score, score_errors = load_pb010_score(pb010_dir)
    certificate, certificate_errors = load_pb010_certificate(pb010_dir)
    errors.extend(score_errors)
    errors.extend(certificate_errors)
    generated_at = utc_now()
    baseline = {
        "schema": BASELINE_SCHEMA,
        "generated_at": generated_at,
        "decision": "VERIFIED" if not errors else "BLOCKED",
        "fail_closed": bool(errors),
        "errors": errors,
        "baseline_id": sha256_bytes(
            canonical(
                {
                    "hashes": hashes,
                    "pb010_certificate_id": certificate.get("certificate_id"),
                    "pb010_score": score,
                }
            ).encode("utf-8")
        ),
        "baseline_source": "PB-010",
        "tracked_controls": ["PB-005", "PB-006", "PB-007", "PB-008", "PB-009", "PB-010"],
        "artifact_hashes": hashes,
        "artifact_count": len(hashes),
        "aggregate_hash": sha256_bytes(canonical(hashes).encode("utf-8")),
        "pb010_certificate_id": certificate.get("certificate_id"),
        "pb010_aggregate_hash": certificate.get("aggregate_hash"),
        "governance_score": score,
        "local_governance_validation_only": True,
        "no_external_certification_claim": True,
        "no_worm_certification_claim": True,
        "aws_access_performed": False,
        "postgresql_access_performed": False,
        "tsa_access_performed": False,
        "external_network_access_performed": False,
    }
    baseline["signature"] = {
        "algorithm": "SHA256_DETERMINISTIC_BASELINE_SIGNATURE",
        "baseline_key_id": BASELINE_KEY_ID,
        "signature_hash": baseline_signature(baseline),
    }
    write_json(output_dir / BASELINE_NAME, baseline)
    write_drift_outputs(output_dir, baseline, hashes, errors)
    return errors


def verify_baseline_signature(baseline: dict[str, Any]) -> list[str]:
    signature = baseline.get("signature")
    if not isinstance(signature, dict):
        return ["PB011_BASELINE_SIGNATURE_MISSING"]
    unsigned = dict(baseline)
    unsigned.pop("signature", None)
    errors: list[str] = []
    if signature.get("baseline_key_id") != BASELINE_KEY_ID:
        errors.append("PB011_BASELINE_KEY_ID_MISMATCH")
    if signature.get("signature_hash") != baseline_signature(unsigned):
        errors.append("PB011_BASELINE_MANIFEST_MISMATCH")
    if signature.get("algorithm") != "SHA256_DETERMINISTIC_BASELINE_SIGNATURE":
        errors.append("PB011_BASELINE_SIGNATURE_ALGORITHM_INVALID")
    return errors


def verify_drift(pb005_dir: Path, pb009_archive_dir: Path, pb010_dir: Path, output_dir: Path) -> list[str]:
    baseline_path = output_dir / BASELINE_NAME
    if not baseline_path.is_file():
        errors = ["PB011_BASELINE_MANIFEST_MISSING"]
        write_drift_outputs(output_dir, {}, {}, errors)
        return errors
    try:
        baseline = load_json(baseline_path)
    except Exception as exc:
        errors = [f"PB011_BASELINE_MANIFEST_INVALID:{exc}"]
        write_drift_outputs(output_dir, {}, {}, errors)
        return errors

    errors: list[str] = []
    if baseline.get("schema") != BASELINE_SCHEMA:
        errors.append("PB011_BASELINE_SCHEMA_INVALID")
    errors.extend(verify_baseline_signature(baseline))
    if baseline.get("decision") != "VERIFIED":
        errors.append("PB011_BASELINE_NOT_VERIFIED")

    current_hashes, current_errors = collect_hashes(pb005_dir, pb009_archive_dir, pb010_dir)
    errors.extend(current_errors)
    baseline_hashes = baseline.get("artifact_hashes")
    if not isinstance(baseline_hashes, dict) or not baseline_hashes:
        errors.append("PB011_BASELINE_HASHES_MISSING")
        baseline_hashes = {}

    for artifact, expected_hash in sorted(baseline_hashes.items()):
        actual_hash = current_hashes.get(artifact)
        if actual_hash is None:
            errors.append(f"PB011_CERTIFIED_ARTIFACT_MISSING:{artifact}")
        elif actual_hash != expected_hash:
            errors.append(f"PB011_ARTIFACT_HASH_CHANGED:{artifact}")

    for artifact in sorted(set(current_hashes) - set(baseline_hashes)):
        errors.append(f"PB011_UNSUPPORTED_ARTIFACT:{artifact}")

    current_aggregate = sha256_bytes(canonical(current_hashes).encode("utf-8"))
    if baseline.get("aggregate_hash") != current_aggregate:
        errors.append("PB011_BASELINE_AGGREGATE_HASH_MISMATCH")

    current_score, score_errors = load_pb010_score(pb010_dir)
    errors.extend(score_errors)
    baseline_score = baseline.get("governance_score")
    if isinstance(baseline_score, int) and isinstance(current_score, int):
        if current_score < baseline_score:
            errors.append("PB011_GOVERNANCE_SCORE_DECREASED")
    else:
        errors.append("PB011_GOVERNANCE_SCORE_UNAVAILABLE")

    write_drift_outputs(output_dir, baseline, current_hashes, errors)
    return errors


def write_drift_outputs(
    output_dir: Path,
    baseline: dict[str, Any],
    current_hashes: dict[str, str],
    errors: list[str],
) -> None:
    generated_at = utc_now()
    baseline_hashes = baseline.get("artifact_hashes", {}) if isinstance(baseline, dict) else {}
    changed = sorted(
        artifact
        for artifact, expected_hash in baseline_hashes.items()
        if artifact in current_hashes and current_hashes[artifact] != expected_hash
    )
    missing = sorted(set(baseline_hashes) - set(current_hashes))
    unsupported = sorted(set(current_hashes) - set(baseline_hashes))
    drift_report = {
        "schema": DRIFT_REPORT_SCHEMA,
        "generated_at": generated_at,
        "decision": "VERIFIED" if not errors else "BLOCKED",
        "fail_closed": bool(errors),
        "errors": errors,
        "baseline_id": baseline.get("baseline_id") if isinstance(baseline, dict) else None,
        "baseline_artifact_count": len(baseline_hashes),
        "current_artifact_count": len(current_hashes),
        "changed_artifacts": changed,
        "missing_artifacts": missing,
        "unsupported_artifacts": unsupported,
        "artifact_hash_changed": bool(changed),
        "certified_artifact_missing": bool(missing),
        "unsupported_artifact_detected": bool(unsupported)
        or any("UNSUPPORTED_ARTIFACT" in error for error in errors),
        "baseline_manifest_mismatch": any("BASELINE" in error and "MISMATCH" in error for error in errors),
        "certification_report_changed": any("pb010_chain/" in artifact for artifact in changed),
        "governance_score_decreased": "PB011_GOVERNANCE_SCORE_DECREASED" in errors,
        "local_governance_validation_only": True,
        "no_external_certification_claim": True,
        "no_worm_certification_claim": True,
        "aws_access_performed": False,
        "postgresql_access_performed": False,
        "tsa_access_performed": False,
        "external_network_access_performed": False,
    }
    scorecard = {
        "schema": SCORECARD_SCHEMA,
        "generated_at": generated_at,
        "decision": drift_report["decision"],
        "fail_closed": drift_report["fail_closed"],
        "baseline_artifacts": len(baseline_hashes),
        "current_artifacts": len(current_hashes),
        "changed_artifact_count": len(changed),
        "missing_artifact_count": len(missing),
        "unsupported_artifact_count": len(unsupported),
        "drift_score": 0 if errors else len(baseline_hashes),
        "max_score": len(baseline_hashes),
        "governance_score_decreased": drift_report["governance_score_decreased"],
        "local_governance_validation_only": True,
        "no_external_certification_claim": True,
        "no_worm_certification_claim": True,
        "aws_access_performed": False,
        "postgresql_access_performed": False,
        "tsa_access_performed": False,
        "external_network_access_performed": False,
    }
    write_json(output_dir / DRIFT_REPORT_NAME, drift_report)
    write_json(output_dir / SCORECARD_NAME, scorecard)


def main() -> int:
    parser = argparse.ArgumentParser(description="PB-011 local governance baseline drift detector.")
    subparsers = parser.add_subparsers(dest="mode", required=True)

    baseline_parser = subparsers.add_parser("baseline")
    baseline_parser.add_argument("pb005_dir")
    baseline_parser.add_argument("pb009_archive_dir")
    baseline_parser.add_argument("pb010_dir")
    baseline_parser.add_argument("output_dir")

    verify_parser = subparsers.add_parser("verify")
    verify_parser.add_argument("pb005_dir")
    verify_parser.add_argument("pb009_archive_dir")
    verify_parser.add_argument("pb010_dir")
    verify_parser.add_argument("output_dir")

    args = parser.parse_args()
    pb005_dir = Path(args.pb005_dir).resolve()
    pb009_archive_dir = Path(args.pb009_archive_dir).resolve()
    pb010_dir = Path(args.pb010_dir).resolve()
    output_dir = Path(args.output_dir).resolve()

    if args.mode == "baseline":
        errors = build_baseline(pb005_dir, pb009_archive_dir, pb010_dir, output_dir)
    else:
        errors = verify_drift(pb005_dir, pb009_archive_dir, pb010_dir, output_dir)

    if errors:
        print("Decision: BLOCKED")
        for error in errors:
            print(error)
        return 1
    print("Decision: VERIFIED")
    print("PB011_BASELINE_DRIFT_VERIFICATION_VERIFIED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
