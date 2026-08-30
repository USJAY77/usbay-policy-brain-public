#!/usr/bin/env python3
"""PB-016 local governance improvement planning.

PB-016 consumes PB-015 maturity assessment artifacts and produces a local
governance improvement plan, priority matrix, roadmap, and action register.
It performs no AWS, PostgreSQL, TSA, external network, or external
certification-provider calls.
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
PLAN = "pb016_governance_improvement_plan.json"
PRIORITY_MATRIX = "pb016_governance_priority_matrix.json"
ROADMAP = "pb016_governance_roadmap.json"
ACTION_REGISTER = "pb016_governance_action_register.json"

PLAN_SCHEMA = "usbay.pb016.governance_improvement_plan.v1"
PRIORITY_SCHEMA = "usbay.pb016.governance_priority_matrix.v1"
ROADMAP_SCHEMA = "usbay.pb016.governance_roadmap.v1"
ACTION_SCHEMA = "usbay.pb016.governance_action_register.v1"
REQUIRED_INPUTS = {MATURITY_REPORT, CAPABILITY_MATRIX, GOVERNANCE_SCORECARD}
REQUIRED_CONTROLS = [f"PB-{index:03d}" for index in range(5, 16)]


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


def numeric_score(value: Any) -> float | None:
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return float(value)
    return None


def status_from_payload(payload: dict[str, Any]) -> str:
    decision = payload.get("decision")
    if decision == "VERIFIED" and payload.get("fail_closed") is False:
        return "VERIFIED"
    return "BLOCKED"


def extract_controls(maturity: dict[str, Any], capability: dict[str, Any]) -> dict[str, str]:
    controls: dict[str, str] = {}
    raw_controls = maturity.get("controls")
    if isinstance(raw_controls, dict):
        for control_id, data in raw_controls.items():
            if isinstance(data, dict):
                controls[str(control_id)] = str(data.get("status", "UNKNOWN"))
            else:
                controls[str(control_id)] = str(data)
    raw_capabilities = capability.get("controls")
    if isinstance(raw_capabilities, dict):
        for control_id, data in raw_capabilities.items():
            if isinstance(data, dict):
                controls.setdefault(str(control_id), str(data.get("status", "UNKNOWN")))
            else:
                controls.setdefault(str(control_id), str(data))
    return controls


def extract_capability_gaps(capability: dict[str, Any]) -> list[dict[str, Any]]:
    gaps = capability.get("capability_gaps")
    if not isinstance(gaps, list):
        gaps = capability.get("gaps")
    if not isinstance(gaps, list):
        return []
    normalized: list[dict[str, Any]] = []
    for index, gap in enumerate(gaps, start=1):
        if isinstance(gap, dict):
            normalized.append(
                {
                    "gap_id": str(gap.get("gap_id", f"GAP-{index:03d}")),
                    "capability": str(gap.get("capability", gap.get("name", "Information not provided"))),
                    "severity": str(gap.get("severity", "MEDIUM")).upper(),
                    "control": str(gap.get("control", gap.get("control_id", "Information not provided"))),
                    "evidence_required": str(gap.get("evidence_required", "Information not provided")),
                }
            )
        else:
            normalized.append(
                {
                    "gap_id": f"GAP-{index:03d}",
                    "capability": str(gap),
                    "severity": "MEDIUM",
                    "control": "Information not provided",
                    "evidence_required": "Information not provided",
                }
            )
    return normalized


def priority_weight(severity: str) -> int:
    return {
        "CRITICAL": 100,
        "HIGH": 75,
        "MEDIUM": 50,
        "LOW": 25,
    }.get(severity.upper(), 50)


def load_inputs(input_dir: Path) -> tuple[dict[str, dict[str, Any]], list[str]]:
    errors: list[str] = []
    payloads: dict[str, dict[str, Any]] = {}
    if not input_dir.is_dir():
        return payloads, [
            f"PB016_MATURITY_INPUT_DIR_MISSING:{input_dir}",
            "PB016_MATURITY_REPORT_MISSING",
            "PB016_CAPABILITY_MATRIX_MISSING",
            "PB016_GOVERNANCE_SCORECARD_MISSING",
        ]
    present = {path.name for path in input_dir.iterdir() if path.is_file()}
    for filename in sorted(REQUIRED_INPUTS - present):
        if filename == MATURITY_REPORT:
            errors.append("PB016_MATURITY_REPORT_MISSING")
        elif filename == CAPABILITY_MATRIX:
            errors.append("PB016_CAPABILITY_MATRIX_MISSING")
        elif filename == GOVERNANCE_SCORECARD:
            errors.append("PB016_GOVERNANCE_SCORECARD_MISSING")
    for filename in sorted(present - REQUIRED_INPUTS):
        errors.append(f"PB016_UNSUPPORTED_GOVERNANCE_ARTIFACT:{filename}")
    for filename in sorted(REQUIRED_INPUTS & present):
        try:
            payloads[filename] = load_json(input_dir / filename)
        except Exception as exc:
            errors.append(f"PB016_INPUT_INVALID:{filename}:{exc}")
    return payloads, errors


def evaluate(input_dir: Path) -> tuple[list[str], dict[str, Any]]:
    payloads, errors = load_inputs(input_dir)
    maturity = payloads.get(MATURITY_REPORT, {})
    capability = payloads.get(CAPABILITY_MATRIX, {})
    scorecard = payloads.get(GOVERNANCE_SCORECARD, {})

    if maturity and status_from_payload(maturity) != "VERIFIED":
        errors.append("PB016_MATURITY_REPORT_NOT_VERIFIED")
    if capability and status_from_payload(capability) != "VERIFIED":
        errors.append("PB016_CAPABILITY_MATRIX_NOT_VERIFIED")
    if scorecard and status_from_payload(scorecard) != "VERIFIED":
        errors.append("PB016_GOVERNANCE_SCORECARD_NOT_VERIFIED")

    maturity_score = numeric_score(maturity.get("maturity_score"))
    governance_score = numeric_score(scorecard.get("governance_score", scorecard.get("score")))
    if maturity and maturity_score is None:
        errors.append("PB016_MATURITY_SCORE_INVALID")
    if scorecard and governance_score is None:
        errors.append("PB016_GOVERNANCE_SCORE_INVALID")
    if governance_score is not None and not 0 <= governance_score <= 100:
        errors.append("PB016_GOVERNANCE_SCORE_INVALID")

    control_status = extract_controls(maturity, capability)
    missing_controls = [control for control in REQUIRED_CONTROLS if control not in control_status]
    for control in missing_controls:
        errors.append(f"PB016_GOVERNANCE_CONTROL_MISSING:{control}")

    gaps = extract_capability_gaps(capability)
    weaknesses = maturity.get("governance_weaknesses")
    if not isinstance(weaknesses, list):
        weaknesses = maturity.get("weaknesses") if isinstance(maturity.get("weaknesses"), list) else []

    context = {
        "maturity_score": maturity_score,
        "governance_score": governance_score,
        "control_status": control_status,
        "capability_gaps": gaps,
        "governance_weaknesses": weaknesses,
        "recovery_readiness": maturity.get("recovery_readiness", "Information not provided"),
        "monitoring_readiness": maturity.get("monitoring_readiness", "Information not provided"),
    }
    return sorted(dict.fromkeys(errors)), context


def build_priority_items(errors: list[str], context: dict[str, Any]) -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []
    for error in errors:
        severity = "CRITICAL" if "MISSING" in error or "INVALID" in error else "HIGH"
        items.append(
            {
                "priority_id": f"PB016-{len(items)+1:03d}",
                "source": "FAIL_CLOSED_VALIDATION",
                "issue": error,
                "severity": severity,
                "priority_score": priority_weight(severity),
                "recommended_action": "Restore required PB-015 evidence and rerun PB-016.",
            }
        )
    for gap in context.get("capability_gaps", []):
        severity = str(gap["severity"]).upper()
        items.append(
            {
                "priority_id": f"PB016-{len(items)+1:03d}",
                "source": "CAPABILITY_GAP",
                "issue": gap["capability"],
                "control": gap["control"],
                "severity": severity,
                "priority_score": priority_weight(severity),
                "recommended_action": f"Collect evidence for {gap['evidence_required']}.",
            }
        )
    for weakness in context.get("governance_weaknesses", []):
        items.append(
            {
                "priority_id": f"PB016-{len(items)+1:03d}",
                "source": "GOVERNANCE_WEAKNESS",
                "issue": str(weakness),
                "severity": "HIGH",
                "priority_score": priority_weight("HIGH"),
                "recommended_action": "Assign owner, evidence requirement, and closure validation.",
            }
        )
    return sorted(items, key=lambda item: (-int(item["priority_score"]), str(item["priority_id"])))


def build_roadmap(priority_items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    phases = [
        ("PHASE-1", "Fail-Closed Evidence Repair", "CRITICAL"),
        ("PHASE-2", "High Priority Governance Closure", "HIGH"),
        ("PHASE-3", "Capability Hardening", "MEDIUM"),
        ("PHASE-4", "Residual Optimization", "LOW"),
    ]
    roadmap: list[dict[str, Any]] = []
    for phase_id, title, severity in phases:
        actions = [item["priority_id"] for item in priority_items if item["severity"] == severity]
        roadmap.append(
            {
                "phase_id": phase_id,
                "title": title,
                "severity": severity,
                "priority_items": actions,
                "entry_criteria": "Evidence exists and assigned owner is documented.",
                "exit_criteria": "Required evidence validates locally and fail-closed checks pass.",
            }
        )
    return roadmap


def write_outputs(output_dir: Path, errors: list[str], context: dict[str, Any]) -> None:
    generated_at = utc_now()
    decision = "VERIFIED" if not errors else "BLOCKED"
    priority_items = build_priority_items(errors, context)
    roadmap = build_roadmap(priority_items)
    actions = [
        {
            "action_id": item["priority_id"].replace("PB016", "ACTION"),
            "priority_id": item["priority_id"],
            "title": item["issue"],
            "severity": item["severity"],
            "status": "OPEN" if errors else "PLANNED",
            "owner": "Information not provided",
            "required_evidence": item.get("recommended_action", "Information not provided"),
            "fail_closed_rule": "Action cannot close until evidence validates locally.",
        }
        for item in priority_items
    ]
    common = {
        "generated_at": generated_at,
        "decision": decision,
        "fail_closed": bool(errors),
        "errors": errors,
        "local_governance_planning_only": True,
        "no_external_certification_claim": True,
        "no_regulatory_certification_claim": True,
        "no_legal_compliance_certification_claim": True,
        "no_production_readiness_claim": True,
        "aws_access_performed": False,
        "postgresql_access_performed": False,
        "tsa_access_performed": False,
        "external_network_access_performed": False,
    }
    write_json(
        output_dir / PRIORITY_MATRIX,
        {
            "schema": PRIORITY_SCHEMA,
            **common,
            "priority_count": len(priority_items),
            "priorities": priority_items,
        },
    )
    write_json(
        output_dir / ROADMAP,
        {
            "schema": ROADMAP_SCHEMA,
            **common,
            "roadmap": roadmap,
        },
    )
    write_json(
        output_dir / ACTION_REGISTER,
        {
            "schema": ACTION_SCHEMA,
            **common,
            "action_count": len(actions),
            "actions": actions,
        },
    )
    write_json(
        output_dir / PLAN,
        {
            "schema": PLAN_SCHEMA,
            **common,
            "maturity_score": context.get("maturity_score"),
            "governance_score": context.get("governance_score"),
            "control_coverage": context.get("control_status", {}),
            "capability_gap_count": len(context.get("capability_gaps", [])),
            "governance_weakness_count": len(context.get("governance_weaknesses", [])),
            "recovery_readiness": context.get("recovery_readiness"),
            "monitoring_readiness": context.get("monitoring_readiness"),
            "priority_matrix": PRIORITY_MATRIX,
            "roadmap": ROADMAP,
            "action_register": ACTION_REGISTER,
        },
    )


def plan(input_dir: Path, output_dir: Path) -> list[str]:
    errors, context = evaluate(input_dir)
    write_outputs(output_dir, errors, context)
    return errors


def main() -> int:
    parser = argparse.ArgumentParser(description="PB-016 local governance improvement planning.")
    parser.add_argument("pb015_input_dir")
    parser.add_argument("output_dir")
    args = parser.parse_args()
    errors = plan(Path(args.pb015_input_dir).resolve(), Path(args.output_dir).resolve())
    if errors:
        print("Decision: BLOCKED")
        for error in errors:
            print(error)
        return 1
    print("Decision: VERIFIED")
    print("PB016_GOVERNANCE_IMPROVEMENT_PLAN_GENERATED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
