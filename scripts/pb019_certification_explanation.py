#!/usr/bin/env python3
"""PB-019 local certification explanation.

PB-019 explains why PB-018 returned BLOCKED and identifies the governance
actions required before local agent governance certification can be granted.
It does not make regulatory, legal, external, or production-readiness claims.
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

FAILURE_REPORT = "pb019_certification_failure_report.json"
GAP_REPORT = "pb019_certification_gap_report.json"
REQUIRED_ACTIONS = "pb019_required_actions.json"
EXPLANATION = "pb019_certification_explanation.json"

FAILURE_SCHEMA = "usbay.pb019.certification_failure_report.v1"
GAP_SCHEMA = "usbay.pb019.certification_gap_report.v1"
ACTION_SCHEMA = "usbay.pb019.required_actions.v1"
EXPLANATION_SCHEMA = "usbay.pb019.certification_explanation.v1"

REQUIRED_INPUTS = {CERTIFICATE, RISK_ASSESSMENT, SCORECARD, ATTESTATION}
ALLOWED_INPUTS = REQUIRED_INPUTS


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


def load_inputs(input_dir: Path) -> tuple[dict[str, dict[str, Any]], list[str]]:
    errors: list[str] = []
    payloads: dict[str, dict[str, Any]] = {}
    if not input_dir.is_dir():
        return payloads, [f"PB019_INPUT_DIR_MISSING:{input_dir}"]
    present = {path.name for path in input_dir.iterdir() if path.is_file()}
    for filename in sorted(REQUIRED_INPUTS - present):
        errors.append(f"PB019_REQUIRED_INPUT_MISSING:{filename}")
    for filename in sorted(present - ALLOWED_INPUTS):
        errors.append(f"PB019_UNSUPPORTED_GOVERNANCE_ARTIFACT:{filename}")
    for filename in sorted(REQUIRED_INPUTS & present):
        try:
            payloads[filename] = load_json(input_dir / filename)
        except Exception as exc:
            errors.append(f"PB019_INPUT_INVALID:{filename}:{exc}")
    return payloads, errors


def collect_blocked_areas(scorecard: dict[str, Any]) -> list[dict[str, Any]]:
    areas = scorecard.get("score_areas", {})
    if not isinstance(areas, dict):
        return [{"area": "Scorecard", "status": "BLOCKED", "gaps": ["PB-018 scorecard schema is invalid."]}]
    blocked: list[dict[str, Any]] = []
    for area_name, data in sorted(areas.items()):
        if not isinstance(data, dict):
            blocked.append({"area": str(area_name), "status": "BLOCKED", "gaps": ["Area data is invalid."]})
            continue
        if data.get("status") != "VERIFIED":
            gaps = data.get("gaps")
            if not isinstance(gaps, list):
                gaps = ["Information not provided"]
            blocked.append(
                {
                    "area": str(area_name),
                    "status": str(data.get("status", "Information not provided")),
                    "gaps": [str(gap) for gap in gaps],
                    "evidence": data.get("evidence", []),
                }
            )
    return blocked


def action_for_gap(area: str, gap: str, index: int) -> dict[str, Any]:
    if gap.startswith("PB-016 decision=BLOCKED"):
        title = "Resolve PB-016 governance improvement planning blockers."
        evidence = "PB-016 improvement plan, roadmap, action register, and priority matrix must validate without fail-closed errors."
    elif gap.startswith("open_actions="):
        title = "Close all open PB-017 governance improvement actions."
        evidence = "PB-017 action tracker must show open_actions=0 and completed closure evidence for every action."
    elif gap.startswith("overdue_actions="):
        title = "Resolve overdue governance actions."
        evidence = "PB-017 action tracker must show overdue_actions=0."
    else:
        title = f"Resolve {area} evidence gap."
        evidence = gap
    return {
        "action_id": f"PB019-ACTION-{index:03d}",
        "source_area": area,
        "source_gap": gap,
        "title": title,
        "required_evidence": evidence,
        "status": "OPEN",
        "fail_closed_rule": "PB-018 certification remains BLOCKED until this action has verifiable evidence.",
    }


def gap_requires_action(gap: str) -> bool:
    if gap.startswith("overdue_actions="):
        try:
            return int(gap.split("=", 1)[1]) > 0
        except ValueError:
            return True
    return True


def evaluate(input_dir: Path) -> tuple[list[str], dict[str, Any]]:
    payloads, errors = load_inputs(input_dir)
    certificate = payloads.get(CERTIFICATE, {})
    risk = payloads.get(RISK_ASSESSMENT, {})
    scorecard = payloads.get(SCORECARD, {})
    attestation = payloads.get(ATTESTATION, {})

    if certificate and certificate.get("schema") != "usbay.pb018.agent_governance_certificate.v1":
        errors.append("PB019_CERTIFICATE_SCHEMA_INVALID")
    if risk and risk.get("schema") != "usbay.pb018.agent_risk_assessment.v1":
        errors.append("PB019_RISK_ASSESSMENT_SCHEMA_INVALID")
    if scorecard and scorecard.get("schema") != "usbay.pb018.agent_scorecard.v1":
        errors.append("PB019_SCORECARD_SCHEMA_INVALID")
    if attestation and attestation.get("schema") != "usbay.pb018.agent_attestation.v1":
        errors.append("PB019_ATTESTATION_SCHEMA_INVALID")

    if certificate and certificate.get("decision") not in {"BLOCKED", "VERIFIED"}:
        errors.append("PB019_CERTIFICATE_DECISION_INVALID")
    if certificate and certificate.get("decision") == "VERIFIED":
        errors.append("PB019_NO_FAILURE_TO_EXPLAIN")

    blocked_areas = collect_blocked_areas(scorecard)
    pb018_errors = certificate.get("errors", [])
    if not isinstance(pb018_errors, list):
        pb018_errors = ["PB018_ERRORS_INVALID"]
    if certificate and certificate.get("decision") == "BLOCKED" and not blocked_areas and not pb018_errors:
        errors.append("PB019_BLOCKED_REASON_MISSING")

    actions: list[dict[str, Any]] = []
    for area in blocked_areas:
        gaps = area.get("gaps", [])
        if not gaps:
            gaps = ["Information not provided"]
        for gap in gaps:
            if gap_requires_action(str(gap)):
                actions.append(action_for_gap(str(area["area"]), str(gap), len(actions) + 1))

    context = {
        "agent_id": certificate.get("agent_id", "Information not provided"),
        "pb018_decision": certificate.get("decision", "Information not provided"),
        "pb018_certificate_status": certificate.get("certificate_status", "Information not provided"),
        "pb018_errors": [str(error) for error in pb018_errors],
        "pb018_governance_score": certificate.get("governance_score", "Information not provided"),
        "risk_level": risk.get("risk_level", "Information not provided"),
        "blocked_areas": blocked_areas,
        "required_actions": actions,
        "pb016_decision": attestation.get("pb016_decision", "Information not provided"),
        "open_governance_actions": attestation.get("open_governance_actions", "Information not provided"),
        "overdue_governance_actions": attestation.get("overdue_governance_actions", "Information not provided"),
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
        "local_governance_explanation_only": True,
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
        output_dir / FAILURE_REPORT,
        {
            "schema": FAILURE_SCHEMA,
            **common,
            "agent_id": context["agent_id"],
            "pb018_decision": context["pb018_decision"],
            "pb018_certificate_status": context["pb018_certificate_status"],
            "pb018_errors": context["pb018_errors"],
            "failure_explanation": "PB-018 is blocked because at least one required local governance area is not verified.",
        },
    )
    write_json(
        output_dir / GAP_REPORT,
        {
            "schema": GAP_SCHEMA,
            **common,
            "agent_id": context["agent_id"],
            "blocked_areas": context["blocked_areas"],
            "gap_count": len(context["blocked_areas"]),
            "pb016_decision": context["pb016_decision"],
            "open_governance_actions": context["open_governance_actions"],
            "overdue_governance_actions": context["overdue_governance_actions"],
        },
    )
    write_json(
        output_dir / REQUIRED_ACTIONS,
        {
            "schema": ACTION_SCHEMA,
            **common,
            "agent_id": context["agent_id"],
            "required_actions": context["required_actions"],
            "required_action_count": len(context["required_actions"]),
            "certification_grant_condition": "PB-018 may be re-evaluated only after all required actions have verifiable local governance evidence.",
        },
    )
    write_json(
        output_dir / EXPLANATION,
        {
            "schema": EXPLANATION_SCHEMA,
            **common,
            "agent_id": context["agent_id"],
            "summary": "PB-018 returned BLOCKED because governance maturity evidence is incomplete.",
            "pb018_governance_score": context["pb018_governance_score"],
            "risk_level": context["risk_level"],
            "blocking_condition": context["pb018_errors"],
            "next_required_action": "Resolve PB-016 blockers, close PB-017 open actions, regenerate PB-018, then regenerate PB-019.",
            "certification_granted": False,
        },
    )


def explain(input_dir: Path, output_dir: Path) -> list[str]:
    errors, context = evaluate(input_dir)
    write_outputs(output_dir, errors, context)
    return errors


def main() -> int:
    parser = argparse.ArgumentParser(description="PB-019 local certification explanation.")
    parser.add_argument("input_dir", type=Path)
    parser.add_argument("output_dir", type=Path)
    args = parser.parse_args()
    errors = explain(args.input_dir, args.output_dir)
    if errors:
        print("Decision: BLOCKED")
        for error in errors:
            print(error)
        return 1
    print("Decision: VERIFIED")
    print("PB019_CERTIFICATION_EXPLANATION_VERIFIED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
