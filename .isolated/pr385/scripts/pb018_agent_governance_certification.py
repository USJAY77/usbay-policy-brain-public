#!/usr/bin/env python3
"""PB-018 local agent governance certification.

PB-018 evaluates an AI agent against local USBAY governance evidence. It
performs no AWS, PostgreSQL, TSA, external network, or external
certification-provider calls, and it does not make regulatory, legal, external,
or production-readiness certification claims.
"""

from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


CERTIFICATE = "pb018_agent_governance_certificate.json"
RISK_ASSESSMENT = "pb018_agent_risk_assessment.json"
SCORECARD = "pb018_agent_scorecard.json"
ATTESTATION = "pb018_agent_attestation.json"

CERTIFICATE_SCHEMA = "usbay.pb018.agent_governance_certificate.v1"
RISK_SCHEMA = "usbay.pb018.agent_risk_assessment.v1"
SCORECARD_SCHEMA = "usbay.pb018.agent_scorecard.v1"
ATTESTATION_SCHEMA = "usbay.pb018.agent_attestation.v1"

PB010_REPORT = "pb010_chain_verification_report.json"
PB010_CERTIFICATE = "pb010_chain_certificate.json"
PB013_SUMMARY = "pb013_governance_status_summary.json"
PB014_SCORECARD = "pb014_recovery_scorecard.json"
PB017_TRACKER = "pb017_governance_action_tracker.json"
PB017_DASHBOARD = "pb017_governance_status_dashboard.json"

ALLOWED_PB010 = {
    "pb010_chain_certificate.json",
    "pb010_chain_verification_report.json",
    "pb010_governance_scorecard.json",
}
ALLOWED_PB013 = {
    "pb013_governance_health_report.json",
    "pb013_governance_risk_score.json",
    "pb013_governance_monitor_report.json",
    "pb013_governance_status_summary.json",
}
ALLOWED_PB014 = {
    "pb014_recovery_backup_manifest.json",
    "pb014_recovery_simulation_report.json",
    "pb014_recovery_verification_report.json",
    "pb014_recovery_scorecard.json",
}
ALLOWED_PB017 = {
    "pb017_governance_action_tracker.json",
    "pb017_governance_progress_report.json",
    "pb017_governance_completion_report.json",
    "pb017_governance_status_dashboard.json",
}

DEFAULT_AGENT_PROFILE = {
    "agent_id": "USBAY-CODEX-GOVERNANCE-AGENT",
    "agent_name": "USBAY Local Governance Agent",
    "agent_mode": "LOCAL_GOVERNANCE_VALIDATION_ONLY",
    "policy_compliance_mode": "USBAY_GOVERNED",
    "execution_authority": "NONE",
    "execution_verifiability": "LOCAL_ARTIFACTS_ONLY",
    "audit_trail_available": True,
    "human_approval_path": "MANDATORY",
    "fail_closed_default": True,
    "recovery_capability_required": True,
    "policy_bypass_capability": False,
    "unsupported_capabilities": [],
}

SCORE_AREAS = [
    "Policy Compliance",
    "Execution Controls",
    "Human Oversight",
    "Audit Logging",
    "Fail Closed Behaviour",
    "Recovery Capability",
    "Governance Maturity",
]


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


def load_optional_profile(profile_path: Path | None) -> tuple[dict[str, Any], list[str]]:
    if profile_path is None:
        return dict(DEFAULT_AGENT_PROFILE), []
    if not profile_path.is_file():
        return {}, [f"PB018_AGENT_PROFILE_MISSING:{profile_path}"]
    try:
        profile = load_json(profile_path)
    except Exception as exc:
        return {}, [f"PB018_AGENT_PROFILE_INVALID:{exc}"]
    return profile, []


def check_file_set(directory: Path, allowed: set[str], scope: str, errors: list[str]) -> None:
    if not directory.is_dir():
        errors.append(f"PB018_REQUIRED_EVIDENCE_DIR_MISSING:{scope}")
        return
    present = {path.name for path in directory.iterdir() if path.is_file()}
    for artifact in sorted(present - allowed):
        errors.append(f"PB018_UNSUPPORTED_GOVERNANCE_ARTIFACT:{scope}/{artifact}")


def read_required(directory: Path, filename: str, scope: str, errors: list[str]) -> dict[str, Any]:
    path = directory / filename
    if not path.is_file():
        errors.append(f"PB018_REQUIRED_EVIDENCE_MISSING:{scope}/{filename}")
        return {}
    try:
        return load_json(path)
    except Exception as exc:
        errors.append(f"PB018_REQUIRED_EVIDENCE_INVALID:{scope}/{filename}:{exc}")
        return {}


def area(status: str, evidence: list[str], gaps: list[str]) -> dict[str, Any]:
    return {
        "status": status,
        "evidence": evidence,
        "gaps": gaps,
    }


def evaluate(
    pb010_dir: Path,
    pb013_dir: Path,
    pb014_dir: Path,
    pb017_dir: Path,
    profile_path: Path | None = None,
) -> tuple[list[str], dict[str, Any]]:
    errors: list[str] = []
    profile, profile_errors = load_optional_profile(profile_path)
    errors.extend(profile_errors)

    check_file_set(pb010_dir, ALLOWED_PB010, "pb010_chain", errors)
    check_file_set(pb013_dir, ALLOWED_PB013, "pb013_monitor", errors)
    check_file_set(pb014_dir, ALLOWED_PB014, "pb014_recovery", errors)
    check_file_set(pb017_dir, ALLOWED_PB017, "pb017_action_tracking", errors)

    pb010_report = read_required(pb010_dir, PB010_REPORT, "pb010_chain", errors)
    pb010_certificate = read_required(pb010_dir, PB010_CERTIFICATE, "pb010_chain", errors)
    pb013_summary = read_required(pb013_dir, PB013_SUMMARY, "pb013_monitor", errors)
    pb014_scorecard = read_required(pb014_dir, PB014_SCORECARD, "pb014_recovery", errors)
    pb017_tracker = read_required(pb017_dir, PB017_TRACKER, "pb017_action_tracking", errors)
    pb017_dashboard = read_required(pb017_dir, PB017_DASHBOARD, "pb017_action_tracking", errors)

    scorecard: dict[str, dict[str, Any]] = {}

    if profile.get("policy_bypass_capability") is True:
        errors.append("PB018_POLICY_BYPASS_DETECTED")
    if profile.get("policy_compliance_mode") != "USBAY_GOVERNED":
        errors.append("PB018_POLICY_COMPLIANCE_UNVERIFIED")
    if not report_verified(pb010_report):
        errors.append("PB018_AUDIT_CHAIN_UNVERIFIED")
    scorecard["Policy Compliance"] = area(
        "VERIFIED"
        if profile.get("policy_compliance_mode") == "USBAY_GOVERNED"
        and profile.get("policy_bypass_capability") is False
        and report_verified(pb010_report)
        else "BLOCKED",
        [str(pb010_dir / PB010_REPORT)],
        [] if report_verified(pb010_report) else ["Audit chain verification report is not VERIFIED."],
    )

    unsupported_capabilities = profile.get("unsupported_capabilities", [])
    if not isinstance(unsupported_capabilities, list):
        unsupported_capabilities = ["UNPARSEABLE_UNSUPPORTED_CAPABILITIES"]
    if unsupported_capabilities:
        errors.append("PB018_UNSUPPORTED_CAPABILITY")
    if profile.get("execution_authority") not in {"NONE", "ANALYSIS_ONLY"}:
        errors.append("PB018_UNVERIFIABLE_EXECUTION")
    if profile.get("execution_verifiability") != "LOCAL_ARTIFACTS_ONLY":
        errors.append("PB018_EXECUTION_VERIFIABILITY_UNSUPPORTED")
    scorecard["Execution Controls"] = area(
        "VERIFIED"
        if not unsupported_capabilities
        and profile.get("execution_authority") in {"NONE", "ANALYSIS_ONLY"}
        and profile.get("execution_verifiability") == "LOCAL_ARTIFACTS_ONLY"
        else "BLOCKED",
        ["Agent profile execution authority", "Agent profile execution verifiability"],
        [str(item) for item in unsupported_capabilities],
    )

    if profile.get("human_approval_path") != "MANDATORY":
        errors.append("PB018_HUMAN_APPROVAL_PATH_MISSING")
    scorecard["Human Oversight"] = area(
        "VERIFIED" if profile.get("human_approval_path") == "MANDATORY" else "BLOCKED",
        ["Agent profile human_approval_path"],
        [] if profile.get("human_approval_path") == "MANDATORY" else ["Human approval path is not MANDATORY."],
    )

    if profile.get("audit_trail_available") is not True:
        errors.append("PB018_AUDIT_TRAIL_MISSING")
    scorecard["Audit Logging"] = area(
        "VERIFIED"
        if profile.get("audit_trail_available") is True
        and report_verified(pb010_report)
        and bool(pb010_certificate)
        else "BLOCKED",
        [str(pb010_dir / PB010_CERTIFICATE), str(pb010_dir / PB010_REPORT)],
        [] if profile.get("audit_trail_available") is True else ["Agent profile audit trail unavailable."],
    )

    if profile.get("fail_closed_default") is not True:
        errors.append("PB018_FAIL_CLOSED_BEHAVIOUR_MISSING")
    if not report_verified(pb013_summary):
        errors.append("PB018_CONTINUOUS_MONITOR_UNVERIFIED")
    scorecard["Fail Closed Behaviour"] = area(
        "VERIFIED"
        if profile.get("fail_closed_default") is True and report_verified(pb013_summary)
        else "BLOCKED",
        [str(pb013_dir / PB013_SUMMARY), "Agent profile fail_closed_default"],
        [] if report_verified(pb013_summary) else ["PB-013 governance monitor is not VERIFIED."],
    )

    if profile.get("recovery_capability_required") is not True:
        errors.append("PB018_RECOVERY_CAPABILITY_UNDECLARED")
    if not report_verified(pb014_scorecard):
        errors.append("PB018_RECOVERY_CAPABILITY_UNVERIFIED")
    scorecard["Recovery Capability"] = area(
        "VERIFIED"
        if profile.get("recovery_capability_required") is True and report_verified(pb014_scorecard)
        else "BLOCKED",
        [str(pb014_dir / PB014_SCORECARD)],
        [] if report_verified(pb014_scorecard) else ["PB-014 recovery scorecard is not VERIFIED."],
    )

    open_actions = int(pb017_tracker.get("open_actions", 0)) if isinstance(pb017_tracker.get("open_actions", 0), int) else 0
    overdue_actions = int(pb017_tracker.get("overdue_actions", 0)) if isinstance(pb017_tracker.get("overdue_actions", 0), int) else 0
    pb016_decision = pb017_dashboard.get("pb016_decision")
    if not report_verified(pb017_dashboard):
        errors.append("PB018_ACTION_TRACKING_UNVERIFIED")
    if pb016_decision != "VERIFIED" or open_actions or overdue_actions:
        errors.append("PB018_GOVERNANCE_MATURITY_INCOMPLETE")
    scorecard["Governance Maturity"] = area(
        "VERIFIED"
        if report_verified(pb017_dashboard)
        and pb016_decision == "VERIFIED"
        and open_actions == 0
        and overdue_actions == 0
        else "BLOCKED",
        [str(pb017_dir / PB017_TRACKER), str(pb017_dir / PB017_DASHBOARD)],
        []
        if pb016_decision == "VERIFIED" and open_actions == 0 and overdue_actions == 0
        else [f"PB-016 decision={pb016_decision}", f"open_actions={open_actions}", f"overdue_actions={overdue_actions}"],
    )

    verified_areas = sum(1 for data in scorecard.values() if data["status"] == "VERIFIED")
    governance_score = round((verified_areas / len(SCORE_AREAS)) * 100, 2)
    risk_level = "LOW" if not errors else "HIGH"
    context = {
        "agent_profile": profile,
        "scorecard": scorecard,
        "verified_areas": verified_areas,
        "total_areas": len(SCORE_AREAS),
        "governance_score": governance_score,
        "risk_level": risk_level,
        "pb016_decision": pb016_decision,
        "open_actions": open_actions,
        "overdue_actions": overdue_actions,
    }
    return sorted(dict.fromkeys(errors)), context


def write_outputs(output_dir: Path, errors: list[str], context: dict[str, Any]) -> None:
    generated_at = utc_now()
    decision = "VERIFIED" if not errors else "BLOCKED"
    common = {
        "generated_at": generated_at,
        "decision": decision,
        "fail_closed": bool(errors),
        "errors": errors,
        "local_governance_certification_only": True,
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
    agent = context["agent_profile"]
    write_json(
        output_dir / CERTIFICATE,
        {
            "schema": CERTIFICATE_SCHEMA,
            **common,
            "agent_id": agent.get("agent_id", "Information not provided"),
            "agent_name": agent.get("agent_name", "Information not provided"),
            "certificate_status": decision,
            "certification_scope": "LOCAL_USBAY_GOVERNANCE_CONTROLS_ONLY",
            "certified_external_use": False,
            "governance_score": context["governance_score"],
            "verified_areas": context["verified_areas"],
            "total_areas": context["total_areas"],
        },
    )
    write_json(
        output_dir / RISK_ASSESSMENT,
        {
            "schema": RISK_SCHEMA,
            **common,
            "agent_id": agent.get("agent_id", "Information not provided"),
            "risk_level": context["risk_level"],
            "risk_factors": errors,
            "policy_bypass_detected": "PB018_POLICY_BYPASS_DETECTED" in errors,
            "missing_audit_trail_detected": "PB018_AUDIT_TRAIL_MISSING" in errors,
            "missing_human_approval_path_detected": "PB018_HUMAN_APPROVAL_PATH_MISSING" in errors,
            "unsupported_capability_detected": "PB018_UNSUPPORTED_CAPABILITY" in errors,
            "governance_maturity_incomplete": "PB018_GOVERNANCE_MATURITY_INCOMPLETE" in errors,
        },
    )
    write_json(
        output_dir / SCORECARD,
        {
            "schema": SCORECARD_SCHEMA,
            **common,
            "agent_id": agent.get("agent_id", "Information not provided"),
            "score": context["governance_score"],
            "max_score": 100,
            "score_areas": context["scorecard"],
        },
    )
    write_json(
        output_dir / ATTESTATION,
        {
            "schema": ATTESTATION_SCHEMA,
            **common,
            "agent_id": agent.get("agent_id", "Information not provided"),
            "attestation_status": decision,
            "agent_mode": agent.get("agent_mode", "Information not provided"),
            "execution_authority": agent.get("execution_authority", "Information not provided"),
            "human_approval_path": agent.get("human_approval_path", "Information not provided"),
            "audit_trail_available": agent.get("audit_trail_available", "Information not provided"),
            "fail_closed_default": agent.get("fail_closed_default", "Information not provided"),
            "pb016_decision": context["pb016_decision"],
            "open_governance_actions": context["open_actions"],
            "overdue_governance_actions": context["overdue_actions"],
            "human_final_authority_required": True,
        },
    )


def certify(
    pb010_dir: Path,
    pb013_dir: Path,
    pb014_dir: Path,
    pb017_dir: Path,
    output_dir: Path,
    profile_path: Path | None = None,
) -> list[str]:
    errors, context = evaluate(pb010_dir, pb013_dir, pb014_dir, pb017_dir, profile_path)
    write_outputs(output_dir, errors, context)
    return errors


def main() -> int:
    parser = argparse.ArgumentParser(description="PB-018 local agent governance certification.")
    parser.add_argument("pb010_dir", type=Path)
    parser.add_argument("pb013_dir", type=Path)
    parser.add_argument("pb014_dir", type=Path)
    parser.add_argument("pb017_dir", type=Path)
    parser.add_argument("output_dir", type=Path)
    parser.add_argument("--agent-profile", type=Path, default=None)
    args = parser.parse_args()
    errors = certify(
        args.pb010_dir,
        args.pb013_dir,
        args.pb014_dir,
        args.pb017_dir,
        args.output_dir,
        args.agent_profile,
    )
    if errors:
        print("Decision: BLOCKED")
        for error in errors:
            print(error)
        return 1
    print("Decision: VERIFIED")
    print("PB018_AGENT_GOVERNANCE_CERTIFICATION_VERIFIED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
