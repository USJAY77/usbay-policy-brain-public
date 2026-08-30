#!/usr/bin/env python3
"""PB-015 local governance maturity assessment.

PB-015 reconstructs the missing governance maturity evidence expected by
PB-016. It evaluates local PB-005 through PB-014 evidence only, produces a
local maturity report, capability matrix, and governance scorecard, and makes
no regulatory, legal, external certification, or production-readiness claims.
"""

from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


MATURITY_REPORT = "pb015_maturity_report.json"
CAPABILITY_MATRIX = "pb015_capability_matrix.json"
GOVERNANCE_SCORECARD = "pb015_governance_scorecard.json"

MATURITY_SCHEMA = "usbay.pb015.governance_maturity_report.v1"
CAPABILITY_SCHEMA = "usbay.pb015.capability_matrix.v1"
SCORECARD_SCHEMA = "usbay.pb015.governance_scorecard.v1"
PB015_POLICY_VERSION = "pb015-governance-maturity-assessment-v1"

CONTROL_REQUIREMENTS = {
    "PB-005": (
        ("pb005/pb005_final_execution_report.json", None),
        ("pb005/pb005_evidence_manifest.json", None),
    ),
    "PB-006": (("pb005/pb006_integrity_report.json", None),),
    "PB-007": (("pb005/pb007_verification_report.json", None),),
    "PB-008": (
        ("pb005/pb008_non_repudiation_report.json", None),
        ("pb005/pb008_timestamp_receipt.json", None),
    ),
    "PB-009": (("pb009_archive/pb009_archive_manifest.json", None),),
    "PB-010": (
        ("pb010_chain/pb010_chain_certificate.json", "usbay.pb010.chain_certificate.v1"),
        ("pb010_chain/pb010_chain_verification_report.json", "usbay.pb010.chain_verification_report.v1"),
        ("pb010_chain/pb010_governance_scorecard.json", "usbay.pb010.governance_scorecard.v1"),
    ),
    "PB-011": (
        ("pb011_baseline/pb011_baseline_manifest.json", None),
        ("pb011_baseline/pb011_drift_report.json", "usbay.pb011.drift_report.v1"),
        ("pb011_baseline/pb011_drift_scorecard.json", "usbay.pb011.drift_scorecard.v1"),
    ),
    "PB-012": (
        ("pb012_control_registry/governance_control_registry.json", "usbay.pb012.governance_control_registry.v1"),
        ("pb012_control_registry/governance_control_manifest.json", "usbay.pb012.governance_control_manifest.v1"),
        ("pb012_control_registry/governance_self_attestation.json", "usbay.pb012.governance_self_attestation.v1"),
    ),
    "PB-013": (
        ("pb013_monitor/pb013_governance_health_report.json", "usbay.pb013.governance_health_report.v1"),
        ("pb013_monitor/pb013_governance_monitor_report.json", "usbay.pb013.governance_monitor_report.v1"),
        ("pb013_monitor/pb013_governance_risk_score.json", "usbay.pb013.governance_risk_score.v1"),
        ("pb013_monitor/pb013_governance_status_summary.json", "usbay.pb013.governance_status_summary.v1"),
    ),
    "PB-014": (
        ("pb014_recovery/pb014_recovery_backup_manifest.json", "usbay.pb014.recovery_backup_manifest.v1"),
        ("pb014_recovery/pb014_recovery_simulation_report.json", "usbay.pb014.recovery_simulation_report.v1"),
        ("pb014_recovery/pb014_recovery_verification_report.json", "usbay.pb014.recovery_verification_report.v1"),
        ("pb014_recovery/pb014_recovery_scorecard.json", "usbay.pb014.recovery_scorecard.v1"),
    ),
}

ALLOWED_OUTPUTS = {MATURITY_REPORT, CAPABILITY_MATRIX, GOVERNANCE_SCORECARD}


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


def report_verified(payload: dict[str, Any]) -> bool:
    return payload.get("decision") == "VERIFIED" and payload.get("fail_closed") is False


def validate_output_dir(output_dir: Path) -> list[str]:
    if not output_dir.exists():
        return []
    if not output_dir.is_dir():
        return [f"PB015_OUTPUT_PATH_NOT_DIRECTORY:{output_dir}"]
    return [
        f"PB015_UNSUPPORTED_GOVERNANCE_ARTIFACT:{path.name}"
        for path in sorted(output_dir.iterdir())
        if path.is_file() and path.name not in ALLOWED_OUTPUTS
    ]


def evaluate_control(control_id: str, evidence_root: Path) -> tuple[dict[str, Any], list[str]]:
    errors: list[str] = []
    evidence: list[str] = []
    for relative_path, expected_schema in CONTROL_REQUIREMENTS[control_id]:
        path = evidence_root / relative_path
        evidence.append(str(path))
        if not path.is_file():
            errors.append(f"PB015_REQUIRED_EVIDENCE_MISSING:{control_id}:{relative_path}")
            continue
        try:
            payload = load_json(path)
        except Exception as exc:
            errors.append(f"PB015_REQUIRED_EVIDENCE_INVALID:{control_id}:{relative_path}:{exc}")
            continue
        actual_schema = payload.get("schema")
        if expected_schema and actual_schema != expected_schema:
            errors.append(f"PB015_REQUIRED_EVIDENCE_SCHEMA_INVALID:{control_id}:{relative_path}")
        if not report_verified(payload):
            errors.append(f"PB015_REQUIRED_EVIDENCE_NOT_VERIFIED:{control_id}:{relative_path}")

    status = "VERIFIED" if not errors else "BLOCKED"
    return {"status": status, "evidence": evidence, "errors": errors}, errors


def evaluate(evidence_root: Path, output_dir: Path) -> tuple[list[str], dict[str, Any]]:
    errors = validate_output_dir(output_dir)
    controls: dict[str, dict[str, Any]] = {}

    if not evidence_root.is_dir():
        errors.append(f"PB015_EVIDENCE_ROOT_MISSING:{evidence_root}")

    for control_id in sorted(CONTROL_REQUIREMENTS):
        record, control_errors = evaluate_control(control_id, evidence_root)
        controls[control_id] = record
        errors.extend(control_errors)

    if errors:
        controls["PB-015"] = {
            "status": "BLOCKED",
            "evidence": [str(output_dir / MATURITY_REPORT), str(output_dir / CAPABILITY_MATRIX), str(output_dir / GOVERNANCE_SCORECARD)],
            "errors": ["PB015_SELF_ASSESSMENT_BLOCKED"],
        }
        errors.append("PB015_SELF_ASSESSMENT_BLOCKED")
    else:
        controls["PB-015"] = {
            "status": "VERIFIED",
            "evidence": [str(output_dir / MATURITY_REPORT), str(output_dir / CAPABILITY_MATRIX), str(output_dir / GOVERNANCE_SCORECARD)],
            "errors": [],
        }

    verified_controls = [control for control, record in controls.items() if record["status"] == "VERIFIED"]
    blocked_controls = [control for control, record in controls.items() if record["status"] != "VERIFIED"]
    maturity_score = round((len(verified_controls) / len(controls)) * 100, 2) if controls else 0.0
    governance_score = maturity_score
    capability_gaps = [
        {
            "gap_id": f"PB015-GAP-{index:03d}",
            "capability": error,
            "severity": "CRITICAL",
            "control": error.split(":", 2)[1] if ":" in error else "PB-015",
            "evidence_required": "Restore verified local governance evidence and rerun PB-015.",
        }
        for index, error in enumerate(sorted(dict.fromkeys(errors)), start=1)
    ]

    return sorted(dict.fromkeys(errors)), {
        "controls": controls,
        "verified_controls": verified_controls,
        "blocked_controls": blocked_controls,
        "maturity_score": maturity_score,
        "governance_score": governance_score,
        "capability_gaps": capability_gaps,
    }


def common_payload(errors: list[str], generated_at: str) -> dict[str, Any]:
    return {
        "generated_at": generated_at,
        "actor": "codex",
        "device": "local",
        "policy_version": PB015_POLICY_VERSION,
        "decision": "VERIFIED" if not errors else "BLOCKED",
        "fail_closed": bool(errors),
        "errors": errors,
        "local_governance_assessment_only": True,
        "no_external_certification_claim": True,
        "no_regulatory_certification_claim": True,
        "no_legal_compliance_certification_claim": True,
        "no_production_readiness_claim": True,
        "aws_access_performed": False,
        "postgresql_access_performed": False,
        "tsa_access_performed": False,
        "external_network_access_performed": False,
        "external_certification_provider_access_performed": False,
    }


def write_outputs(output_dir: Path, errors: list[str], context: dict[str, Any]) -> None:
    generated_at = utc_now()
    common = common_payload(errors, generated_at)
    write_json(
        output_dir / MATURITY_REPORT,
        {
            "schema": MATURITY_SCHEMA,
            **common,
            "maturity_score": context["maturity_score"],
            "controls": context["controls"],
            "verified_controls": context["verified_controls"],
            "blocked_controls": context["blocked_controls"],
            "governance_weaknesses": [gap["capability"] for gap in context["capability_gaps"]],
            "recovery_readiness": "VERIFIED" if context["controls"].get("PB-014", {}).get("status") == "VERIFIED" else "BLOCKED",
            "monitoring_readiness": "VERIFIED" if context["controls"].get("PB-013", {}).get("status") == "VERIFIED" else "BLOCKED",
            "evidence_lineage": context["controls"],
        },
    )
    write_json(
        output_dir / CAPABILITY_MATRIX,
        {
            "schema": CAPABILITY_SCHEMA,
            **common,
            "controls": context["controls"],
            "capability_gaps": context["capability_gaps"],
            "evidence_lineage": context["controls"],
        },
    )
    write_json(
        output_dir / GOVERNANCE_SCORECARD,
        {
            "schema": SCORECARD_SCHEMA,
            **common,
            "governance_score": context["governance_score"],
            "control_scores": {control: 100 if record["status"] == "VERIFIED" else 0 for control, record in context["controls"].items()},
            "verified_controls": context["verified_controls"],
            "blocked_controls": context["blocked_controls"],
            "evidence_lineage": context["controls"],
        },
    )


def assess(evidence_root: Path, output_dir: Path) -> list[str]:
    errors, context = evaluate(evidence_root, output_dir)
    write_outputs(output_dir, errors, context)
    return errors


def main() -> int:
    parser = argparse.ArgumentParser(description="PB-015 local governance maturity assessment.")
    parser.add_argument("evidence_root", type=Path)
    parser.add_argument("output_dir", type=Path)
    args = parser.parse_args()
    errors = assess(args.evidence_root.resolve(), args.output_dir.resolve())
    if errors:
        print("Decision: BLOCKED")
        for error in errors:
            print(error)
        return 1
    print("Decision: VERIFIED")
    print("PB015_GOVERNANCE_MATURITY_ASSESSMENT_VERIFIED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
