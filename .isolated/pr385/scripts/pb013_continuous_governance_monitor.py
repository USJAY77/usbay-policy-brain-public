#!/usr/bin/env python3
"""PB-013 continuous local governance monitor.

PB-013 evaluates governance health across PB-005 through PB-012 using only
local evidence artifacts. It performs no AWS, PostgreSQL, TSA, external
network, or external certification-provider calls.
"""

from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


HEALTH_REPORT = "pb013_governance_health_report.json"
RISK_SCORE = "pb013_governance_risk_score.json"
MONITOR_REPORT = "pb013_governance_monitor_report.json"
STATUS_SUMMARY = "pb013_governance_status_summary.json"
HEALTH_SCHEMA = "usbay.pb013.governance_health_report.v1"
RISK_SCHEMA = "usbay.pb013.governance_risk_score.v1"
MONITOR_SCHEMA = "usbay.pb013.governance_monitor_report.v1"
SUMMARY_SCHEMA = "usbay.pb013.governance_status_summary.v1"
REQUIRED_CONTROLS = [f"PB-{index:03d}" for index in range(5, 13)]
MIN_HEALTH_SCORE = 100

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
PB011_ALLOWED = {
    "pb011_baseline_manifest.json",
    "pb011_drift_report.json",
    "pb011_drift_scorecard.json",
}
PB012_ALLOWED = {
    "governance_control_registry.json",
    "governance_control_manifest.json",
    "governance_self_attestation.json",
}


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


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


def add_error(errors: list[str], control_errors: dict[str, list[str]], control_id: str, error: str) -> None:
    errors.append(error)
    control_errors.setdefault(control_id, []).append(error)


def check_file_set(
    directory: Path,
    required: set[str],
    allowed: set[str],
    scope: str,
    control_id: str,
    errors: list[str],
    control_errors: dict[str, list[str]],
) -> None:
    if not directory.is_dir():
        add_error(errors, control_errors, control_id, f"PB013_REQUIRED_CONTROL_MISSING:{scope}")
        return
    present = {path.name for path in directory.iterdir() if path.is_file()}
    for artifact in sorted(required - present):
        add_error(errors, control_errors, control_id, f"PB013_REQUIRED_CONTROL_MISSING:{scope}/{artifact}")
    for artifact in sorted(present - allowed):
        add_error(errors, control_errors, control_id, f"PB013_UNSUPPORTED_GOVERNANCE_ARTIFACT:{scope}/{artifact}")


def check_report(
    path: Path,
    expected_schema: str,
    control_id: str,
    errors: list[str],
    control_errors: dict[str, list[str]],
    failure_error: str,
) -> dict[str, Any]:
    if not path.is_file():
        add_error(errors, control_errors, control_id, f"PB013_REQUIRED_CONTROL_MISSING:{path.name}")
        return {}
    try:
        report = load_json(path)
    except Exception as exc:
        add_error(errors, control_errors, control_id, f"PB013_REPORT_INVALID:{path.name}:{exc}")
        return {}
    if report.get("schema") != expected_schema:
        add_error(errors, control_errors, control_id, f"PB013_REPORT_SCHEMA_INVALID:{path.name}")
    if report.get("decision") != "VERIFIED" or report.get("fail_closed") is not False:
        add_error(errors, control_errors, control_id, failure_error)
    if "errors" in report and report.get("errors") != []:
        add_error(errors, control_errors, control_id, f"{failure_error}:ERRORS_PRESENT")
    return report


def evaluate(
    pb005_dir: Path,
    pb009_archive_dir: Path,
    pb010_dir: Path,
    pb011_dir: Path,
    pb012_dir: Path,
) -> tuple[list[str], dict[str, list[str]], dict[str, Any]]:
    errors: list[str] = []
    control_errors: dict[str, list[str]] = {control: [] for control in REQUIRED_CONTROLS}

    check_file_set(pb005_dir, PB005_ALLOWED, PB005_ALLOWED, "pb005", "PB-005", errors, control_errors)
    check_file_set(pb009_archive_dir, PB009_ROOT_ALLOWED, PB009_ROOT_ALLOWED | {"artifacts"}, "pb009_archive", "PB-009", errors, control_errors)
    archive_artifacts = pb009_archive_dir / "artifacts"
    check_file_set(
        archive_artifacts,
        PB005_ALLOWED,
        PB005_ALLOWED,
        "pb009_archive/artifacts",
        "PB-009",
        errors,
        control_errors,
    )
    check_file_set(pb010_dir, PB010_ALLOWED, PB010_ALLOWED, "pb010_chain", "PB-010", errors, control_errors)
    check_file_set(pb011_dir, PB011_ALLOWED, PB011_ALLOWED, "pb011_baseline", "PB-011", errors, control_errors)
    check_file_set(pb012_dir, PB012_ALLOWED, PB012_ALLOWED, "pb012_control_registry", "PB-012", errors, control_errors)

    pb006 = check_report(
        pb005_dir / "pb006_integrity_report.json",
        "usbay.pb006.integrity_report.v1",
        "PB-006",
        errors,
        control_errors,
        "PB013_INTEGRITY_REPORT_FAILED",
    )
    if pb006.get("schema") is None and pb006.get("control_id") == "PB-006":
        control_errors["PB-006"] = [
            error for error in control_errors["PB-006"] if error != "PB013_REPORT_SCHEMA_INVALID:pb006_integrity_report.json"
        ]
        errors[:] = [error for error in errors if error != "PB013_REPORT_SCHEMA_INVALID:pb006_integrity_report.json"]

    pb007 = check_report(
        pb005_dir / "pb007_verification_report.json",
        "usbay.pb007.independent_verification_report.v1",
        "PB-007",
        errors,
        control_errors,
        "PB013_INDEPENDENT_VERIFICATION_FAILED",
    )
    if pb007.get("schema") is None and pb007.get("control_id") == "PB-007":
        control_errors["PB-007"] = [
            error for error in control_errors["PB-007"] if error != "PB013_REPORT_SCHEMA_INVALID:pb007_verification_report.json"
        ]
        errors[:] = [error for error in errors if error != "PB013_REPORT_SCHEMA_INVALID:pb007_verification_report.json"]

    check_report(
        pb005_dir / "pb008_non_repudiation_report.json",
        "usbay.pb008.non_repudiation_report.v1",
        "PB-008",
        errors,
        control_errors,
        "PB013_TIMESTAMP_REPORT_FAILED",
    )
    check_report(
        pb009_archive_dir / "pb009_archive_integrity_report.json",
        "usbay.pb009.archive_integrity_report.v1",
        "PB-009",
        errors,
        control_errors,
        "PB013_ARCHIVE_REPORT_FAILED",
    )
    certification = check_report(
        pb010_dir / "pb010_chain_verification_report.json",
        "usbay.pb010.chain_verification_report.v1",
        "PB-010",
        errors,
        control_errors,
        "PB013_CERTIFICATION_REPORT_FAILED",
    )
    drift = check_report(
        pb011_dir / "pb011_drift_report.json",
        "usbay.pb011.drift_report.v1",
        "PB-011",
        errors,
        control_errors,
        "PB013_DRIFT_REPORT_FAILED",
    )
    registry = check_report(
        pb012_dir / "governance_self_attestation.json",
        "usbay.pb012.governance_self_attestation.v1",
        "PB-012",
        errors,
        control_errors,
        "PB013_CONTROL_REGISTRY_MISMATCH",
    )

    if certification.get("unsupported_artifact_detected") is True:
        add_error(errors, control_errors, "PB-010", "PB013_UNSUPPORTED_GOVERNANCE_ARTIFACT:pb010_chain")
    if drift.get("unsupported_artifact_detected") is True:
        add_error(errors, control_errors, "PB-011", "PB013_UNSUPPORTED_GOVERNANCE_ARTIFACT:pb011_baseline")
    if registry.get("registry_hash_mismatch_detected") is True or registry.get("control_manifest_mismatch_detected") is True:
        add_error(errors, control_errors, "PB-012", "PB013_CONTROL_REGISTRY_MISMATCH")

    verified_controls = sum(1 for control in REQUIRED_CONTROLS if not control_errors[control])
    health_score = int((verified_controls / len(REQUIRED_CONTROLS)) * 100)
    if health_score < MIN_HEALTH_SCORE:
        add_error(errors, control_errors, "PB-013", "PB013_GOVERNANCE_SCORE_BELOW_THRESHOLD")

    metrics = {
        "verified_controls": verified_controls,
        "total_controls": len(REQUIRED_CONTROLS),
        "health_score": health_score,
        "risk_score": max(0, 100 - health_score) if not errors else min(100, 100 - health_score + len(errors) * 5),
    }
    return sorted(dict.fromkeys(errors)), control_errors, metrics


def write_outputs(
    output_dir: Path,
    errors: list[str],
    control_errors: dict[str, list[str]],
    metrics: dict[str, Any],
) -> None:
    generated_at = utc_now()
    decision = "VERIFIED" if not errors else "BLOCKED"
    health = {
        "schema": HEALTH_SCHEMA,
        "generated_at": generated_at,
        "decision": decision,
        "fail_closed": bool(errors),
        "errors": errors,
        "controls": {
            control: {"status": "VERIFIED" if not control_errors.get(control) else "BLOCKED", "errors": control_errors.get(control, [])}
            for control in REQUIRED_CONTROLS
        },
        "verified_controls": metrics["verified_controls"],
        "total_controls": metrics["total_controls"],
        "health_score": metrics["health_score"],
        "minimum_health_score": MIN_HEALTH_SCORE,
        "local_governance_validation_only": True,
        "no_external_certification_claim": True,
        "no_regulatory_certification_claim": True,
        "no_production_readiness_claim": True,
        "aws_access_performed": False,
        "postgresql_access_performed": False,
        "tsa_access_performed": False,
        "external_network_access_performed": False,
    }
    risk = {
        "schema": RISK_SCHEMA,
        "generated_at": generated_at,
        "decision": decision,
        "fail_closed": bool(errors),
        "risk_score": metrics["risk_score"],
        "risk_level": "LOW" if not errors else "CRITICAL",
        "score_below_threshold": metrics["health_score"] < MIN_HEALTH_SCORE,
        "local_governance_validation_only": True,
        "no_external_certification_claim": True,
        "no_regulatory_certification_claim": True,
        "no_production_readiness_claim": True,
        "aws_access_performed": False,
        "postgresql_access_performed": False,
        "tsa_access_performed": False,
        "external_network_access_performed": False,
    }
    monitor = {
        "schema": MONITOR_SCHEMA,
        "generated_at": generated_at,
        "decision": decision,
        "fail_closed": bool(errors),
        "errors": errors,
        "drift_report_failed": any("DRIFT_REPORT_FAILED" in error for error in errors),
        "certification_report_failed": any("CERTIFICATION_REPORT_FAILED" in error for error in errors),
        "control_registry_mismatch": any("CONTROL_REGISTRY_MISMATCH" in error for error in errors),
        "required_control_missing": any("REQUIRED_CONTROL_MISSING" in error for error in errors),
        "unsupported_governance_artifact_detected": any("UNSUPPORTED_GOVERNANCE_ARTIFACT" in error for error in errors),
        "governance_score_below_threshold": metrics["health_score"] < MIN_HEALTH_SCORE,
        "local_governance_validation_only": True,
        "no_external_certification_claim": True,
        "no_regulatory_certification_claim": True,
        "no_production_readiness_claim": True,
        "aws_access_performed": False,
        "postgresql_access_performed": False,
        "tsa_access_performed": False,
        "external_network_access_performed": False,
    }
    summary = {
        "schema": SUMMARY_SCHEMA,
        "generated_at": generated_at,
        "status": "HEALTHY" if not errors else "BLOCKED",
        "decision": decision,
        "fail_closed": bool(errors),
        "health_score": metrics["health_score"],
        "risk_score": metrics["risk_score"],
        "verified_controls": metrics["verified_controls"],
        "total_controls": metrics["total_controls"],
        "local_governance_validation_only": True,
        "no_external_certification_claim": True,
        "no_regulatory_certification_claim": True,
        "no_production_readiness_claim": True,
    }
    write_json(output_dir / HEALTH_REPORT, health)
    write_json(output_dir / RISK_SCORE, risk)
    write_json(output_dir / MONITOR_REPORT, monitor)
    write_json(output_dir / STATUS_SUMMARY, summary)


def monitor(
    pb005_dir: Path,
    pb009_archive_dir: Path,
    pb010_dir: Path,
    pb011_dir: Path,
    pb012_dir: Path,
    output_dir: Path,
) -> list[str]:
    errors, control_errors, metrics = evaluate(pb005_dir, pb009_archive_dir, pb010_dir, pb011_dir, pb012_dir)
    write_outputs(output_dir, errors, control_errors, metrics)
    return errors


def main() -> int:
    parser = argparse.ArgumentParser(description="PB-013 continuous local governance monitor.")
    parser.add_argument("pb005_dir")
    parser.add_argument("pb009_archive_dir")
    parser.add_argument("pb010_dir")
    parser.add_argument("pb011_dir")
    parser.add_argument("pb012_dir")
    parser.add_argument("output_dir")
    args = parser.parse_args()
    errors = monitor(
        Path(args.pb005_dir).resolve(),
        Path(args.pb009_archive_dir).resolve(),
        Path(args.pb010_dir).resolve(),
        Path(args.pb011_dir).resolve(),
        Path(args.pb012_dir).resolve(),
        Path(args.output_dir).resolve(),
    )
    if errors:
        print("Decision: BLOCKED")
        for error in errors:
            print(error)
        return 1
    print("Decision: VERIFIED")
    print("PB013_CONTINUOUS_GOVERNANCE_MONITOR_VERIFIED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
