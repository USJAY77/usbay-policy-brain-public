#!/usr/bin/env python3
"""PB-020 local governance evidence freshness validation.

PB-020 detects stale governance evidence, stale decision artifacts, and schema
version drift before local governance decisions are trusted. It performs no
AWS, PostgreSQL, TSA, external network, or external certification-provider
calls.
"""

from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


FRESHNESS_REPORT = "pb020_freshness_report.json"
STALENESS_REPORT = "pb020_staleness_report.json"
VERSION_REPORT = "pb020_version_alignment_report.json"
SCORECARD = "pb020_evidence_freshness_scorecard.json"

FRESHNESS_SCHEMA = "usbay.pb020.freshness_report.v1"
STALENESS_SCHEMA = "usbay.pb020.staleness_report.v1"
VERSION_SCHEMA = "usbay.pb020.version_alignment_report.v1"
SCORECARD_SCHEMA = "usbay.pb020.evidence_freshness_scorecard.v1"
PB019_NOT_APPLICABLE_STATE = "NOT_APPLICABLE_NO_FAILURE_TO_EXPLAIN"

EXPECTED_ARTIFACTS = {
    "pb016": {
        "pb016_governance_improvement_plan.json": "usbay.pb016.governance_improvement_plan.v1",
        "pb016_governance_priority_matrix.json": "usbay.pb016.governance_priority_matrix.v1",
        "pb016_governance_roadmap.json": "usbay.pb016.governance_roadmap.v1",
        "pb016_governance_action_register.json": "usbay.pb016.governance_action_register.v1",
    },
    "pb017": {
        "pb017_governance_action_tracker.json": "usbay.pb017.governance_action_tracker.v1",
        "pb017_governance_progress_report.json": "usbay.pb017.governance_progress_report.v1",
        "pb017_governance_completion_report.json": "usbay.pb017.governance_completion_report.v1",
        "pb017_governance_status_dashboard.json": "usbay.pb017.governance_status_dashboard.v1",
    },
    "pb018": {
        "pb018_agent_governance_certificate.json": "usbay.pb018.agent_governance_certificate.v1",
        "pb018_agent_risk_assessment.json": "usbay.pb018.agent_risk_assessment.v1",
        "pb018_agent_scorecard.json": "usbay.pb018.agent_scorecard.v1",
        "pb018_agent_attestation.json": "usbay.pb018.agent_attestation.v1",
    },
    "pb019": {
        "pb019_certification_failure_report.json": "usbay.pb019.certification_failure_report.v1",
        "pb019_certification_gap_report.json": "usbay.pb019.certification_gap_report.v1",
        "pb019_required_actions.json": "usbay.pb019.required_actions.v1",
        "pb019_certification_explanation.json": "usbay.pb019.certification_explanation.v1",
    },
}


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def format_utc(value: datetime) -> str:
    return value.isoformat().replace("+00:00", "Z")


def parse_timestamp(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


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


def artifact_kind(filename: str) -> str:
    if filename.startswith("pb018_agent_governance_certificate"):
        return "certification_result"
    if filename.startswith("pb016_"):
        return "maturity_report"
    if filename.startswith("pb017_"):
        return "action_tracker"
    return "governance_artifact"


def pb018_has_no_failure_to_explain(payload: dict[str, Any]) -> bool:
    return (
        payload.get("decision") == "VERIFIED"
        and payload.get("certificate_status") == "VERIFIED"
        and payload.get("fail_closed") is False
        and payload.get("errors") == []
    )


def evaluate_dir(
    scope: str,
    directory: Path,
    now: datetime,
    max_age_hours: float,
    errors: list[str],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]], dict[str, Any]]:
    expected = EXPECTED_ARTIFACTS[scope]
    freshness: list[dict[str, Any]] = []
    stale: list[dict[str, Any]] = []
    versions: list[dict[str, Any]] = []
    payloads: dict[str, Any] = {}

    if not directory.is_dir():
        errors.append(f"PB020_EVIDENCE_DIR_MISSING:{scope}")
        for filename in sorted(expected):
            errors.append(f"PB020_GOVERNANCE_EVIDENCE_MISSING:{scope}/{filename}")
        return freshness, stale, versions, payloads

    present = {path.name for path in directory.iterdir() if path.is_file()}
    for filename in sorted(present - set(expected)):
        errors.append(f"PB020_UNSUPPORTED_GOVERNANCE_ARTIFACT:{scope}/{filename}")
    for filename in sorted(set(expected) - present):
        errors.append(f"PB020_GOVERNANCE_EVIDENCE_MISSING:{scope}/{filename}")

    for filename, expected_schema in sorted(expected.items()):
        path = directory / filename
        if not path.is_file():
            continue
        try:
            payload = load_json(path)
        except Exception as exc:
            errors.append(f"PB020_GOVERNANCE_EVIDENCE_INVALID:{scope}/{filename}:{exc}")
            continue
        payloads[filename] = payload

        actual_schema = payload.get("schema")
        version_status = "ALIGNED" if actual_schema == expected_schema else "MISMATCH"
        if version_status != "ALIGNED":
            errors.append(f"PB020_GOVERNANCE_VERSION_MISMATCH:{scope}/{filename}")
        versions.append(
            {
                "scope": scope,
                "artifact": filename,
                "expected_schema": expected_schema,
                "actual_schema": actual_schema if isinstance(actual_schema, str) else "Information not provided",
                "status": version_status,
            }
        )

        parsed = parse_timestamp(payload.get("generated_at"))
        if parsed is None:
            errors.append(f"PB020_ARTIFACT_TIMESTAMP_MISSING_OR_INVALID:{scope}/{filename}")
            age_hours = None
            status = "STALE"
        else:
            age_hours = round((now - parsed).total_seconds() / 3600, 4)
            status = "FRESH" if 0 <= age_hours <= max_age_hours else "STALE"
            if status == "STALE":
                kind = artifact_kind(filename)
                if kind == "certification_result":
                    errors.append(f"PB020_STALE_CERTIFICATION_RESULT:{scope}/{filename}")
                elif kind == "maturity_report":
                    errors.append(f"PB020_STALE_MATURITY_REPORT:{scope}/{filename}")
                elif kind == "action_tracker":
                    errors.append(f"PB020_STALE_ACTION_TRACKER:{scope}/{filename}")
                else:
                    errors.append(f"PB020_STALE_GOVERNANCE_EVIDENCE:{scope}/{filename}")

        record = {
            "scope": scope,
            "artifact": filename,
            "artifact_kind": artifact_kind(filename),
            "generated_at": payload.get("generated_at") if isinstance(payload.get("generated_at"), str) else "Information not provided",
            "age_hours": age_hours,
            "max_age_hours": max_age_hours,
            "status": status,
        }
        freshness.append(record)
        if status == "STALE":
            stale.append(record)
    return freshness, stale, versions, payloads


def evaluate(
    pb016_dir: Path,
    pb017_dir: Path,
    pb018_dir: Path,
    pb019_dir: Path,
    max_age_hours: float,
) -> tuple[list[str], dict[str, Any]]:
    errors: list[str] = []
    now = utc_now()
    all_freshness: list[dict[str, Any]] = []
    all_stale: list[dict[str, Any]] = []
    all_versions: list[dict[str, Any]] = []
    payloads_by_scope: dict[str, dict[str, Any]] = {}
    applicability_records: list[dict[str, Any]] = []

    required_dirs = {
        "pb016": pb016_dir,
        "pb017": pb017_dir,
        "pb018": pb018_dir,
    }
    for scope, directory in required_dirs.items():
        freshness, stale, versions, payloads = evaluate_dir(scope, directory, now, max_age_hours, errors)
        all_freshness.extend(freshness)
        all_stale.extend(stale)
        all_versions.extend(versions)
        payloads_by_scope[scope] = payloads

    pb018_certificate = payloads_by_scope.get("pb018", {}).get("pb018_agent_governance_certificate.json", {})
    pb019_applicability = "REQUIRED"
    if pb018_has_no_failure_to_explain(pb018_certificate):
        pb019_applicability = PB019_NOT_APPLICABLE_STATE
        payloads_by_scope["pb019"] = {}
        applicability_records.append(
            {
                "scope": "pb019",
                "status": PB019_NOT_APPLICABLE_STATE,
                "reason": "PB-018 certification is VERIFIED with no failure to explain.",
                "pb018_decision": pb018_certificate.get("decision", "Information not provided"),
            }
        )
    else:
        freshness, stale, versions, payloads = evaluate_dir("pb019", pb019_dir, now, max_age_hours, errors)
        all_freshness.extend(freshness)
        all_stale.extend(stale)
        all_versions.extend(versions)
        payloads_by_scope["pb019"] = payloads

    pb016_plan = payloads_by_scope.get("pb016", {}).get("pb016_governance_improvement_plan.json", {})
    pb017_dashboard = payloads_by_scope.get("pb017", {}).get("pb017_governance_status_dashboard.json", {})

    if pb016_plan and pb016_plan.get("decision") != "VERIFIED":
        errors.append("PB020_MATURITY_REPORT_UNTRUSTED")
    if pb017_dashboard and pb017_dashboard.get("decision") != "VERIFIED":
        errors.append("PB020_ACTION_TRACKER_UNTRUSTED")
    if pb018_certificate and pb018_certificate.get("decision") != "VERIFIED":
        errors.append("PB020_CERTIFICATION_RESULT_UNTRUSTED")

    total_artifacts = len(all_freshness)
    fresh_artifacts = sum(1 for record in all_freshness if record["status"] == "FRESH")
    aligned_versions = sum(1 for record in all_versions if record["status"] == "ALIGNED")
    context = {
        "generated_at": format_utc(now),
        "max_age_hours": max_age_hours,
        "freshness_records": all_freshness,
        "stale_records": all_stale,
        "version_records": all_versions,
        "total_artifacts": total_artifacts,
        "fresh_artifacts": fresh_artifacts,
        "stale_artifacts": len(all_stale),
        "aligned_versions": aligned_versions,
        "version_mismatches": len(all_versions) - aligned_versions,
        "freshness_score": round((fresh_artifacts / total_artifacts) * 100, 2) if total_artifacts else 0.0,
        "version_alignment_score": round((aligned_versions / len(all_versions)) * 100, 2) if all_versions else 0.0,
        "pb016_decision": pb016_plan.get("decision", "Information not provided"),
        "pb017_decision": pb017_dashboard.get("decision", "Information not provided"),
        "pb018_decision": pb018_certificate.get("decision", "Information not provided"),
        "pb019_requirement": pb019_applicability,
        "applicability_records": applicability_records,
    }
    return sorted(dict.fromkeys(errors)), context


def write_outputs(output_dir: Path, errors: list[str], context: dict[str, Any]) -> None:
    decision = "VERIFIED" if not errors else "BLOCKED"
    common = {
        "generated_at": context["generated_at"],
        "decision": decision,
        "fail_closed": bool(errors),
        "errors": errors,
        "local_governance_validation_only": True,
        "no_external_certification_claim": True,
        "no_regulatory_certification_claim": True,
        "no_legal_certification_claim": True,
        "no_production_readiness_claim": True,
        "aws_access_performed": False,
        "postgresql_access_performed": False,
        "tsa_access_performed": False,
        "external_network_access_performed": False,
        "external_certification_provider_access_performed": False,
    }
    write_json(
        output_dir / FRESHNESS_REPORT,
        {
            "schema": FRESHNESS_SCHEMA,
            **common,
            "max_age_hours": context["max_age_hours"],
            "artifact_freshness": context["freshness_records"],
            "applicability": context["applicability_records"],
            "fresh_artifacts": context["fresh_artifacts"],
            "total_artifacts": context["total_artifacts"],
        },
    )
    write_json(
        output_dir / STALENESS_REPORT,
        {
            "schema": STALENESS_SCHEMA,
            **common,
            "stale_artifacts": context["stale_records"],
            "stale_artifact_count": context["stale_artifacts"],
            "stale_certification_detected": any("STALE_CERTIFICATION_RESULT" in error for error in errors),
            "stale_maturity_report_detected": any("STALE_MATURITY_REPORT" in error for error in errors),
            "stale_action_tracker_detected": any("STALE_ACTION_TRACKER" in error for error in errors),
            "pb019_requirement": context["pb019_requirement"],
        },
    )
    write_json(
        output_dir / VERSION_REPORT,
        {
            "schema": VERSION_SCHEMA,
            **common,
            "version_alignment": context["version_records"],
            "aligned_versions": context["aligned_versions"],
            "version_mismatches": context["version_mismatches"],
            "governance_version_mismatch_detected": any("GOVERNANCE_VERSION_MISMATCH" in error for error in errors),
        },
    )
    write_json(
        output_dir / SCORECARD,
        {
            "schema": SCORECARD_SCHEMA,
            **common,
            "freshness_score": context["freshness_score"],
            "version_alignment_score": context["version_alignment_score"],
            "pb016_decision": context["pb016_decision"],
            "pb017_decision": context["pb017_decision"],
            "pb018_decision": context["pb018_decision"],
            "pb019_requirement": context["pb019_requirement"],
            "stale_artifacts": context["stale_artifacts"],
            "version_mismatches": context["version_mismatches"],
            "certification_result_trusted": context["pb018_decision"] == "VERIFIED",
            "maturity_report_trusted": context["pb016_decision"] == "VERIFIED",
            "action_tracker_trusted": context["pb017_decision"] == "VERIFIED",
        },
    )


def validate(
    pb016_dir: Path,
    pb017_dir: Path,
    pb018_dir: Path,
    pb019_dir: Path,
    output_dir: Path,
    max_age_hours: float,
) -> list[str]:
    errors, context = evaluate(pb016_dir, pb017_dir, pb018_dir, pb019_dir, max_age_hours)
    write_outputs(output_dir, errors, context)
    return errors


def main() -> int:
    parser = argparse.ArgumentParser(description="PB-020 local governance evidence freshness validation.")
    parser.add_argument("pb016_dir", type=Path)
    parser.add_argument("pb017_dir", type=Path)
    parser.add_argument("pb018_dir", type=Path)
    parser.add_argument("pb019_dir", type=Path)
    parser.add_argument("output_dir", type=Path)
    parser.add_argument("--max-age-hours", type=float, default=168.0)
    args = parser.parse_args()
    errors = validate(
        args.pb016_dir,
        args.pb017_dir,
        args.pb018_dir,
        args.pb019_dir,
        args.output_dir,
        args.max_age_hours,
    )
    if errors:
        print("Decision: BLOCKED")
        for error in errors:
            print(error)
        return 1
    print("Decision: VERIFIED")
    print("PB020_EVIDENCE_FRESHNESS_VALIDATION_VERIFIED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
