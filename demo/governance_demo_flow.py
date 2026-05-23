#!/usr/bin/env python3
from __future__ import annotations

import argparse
import html
import json
import sys
from pathlib import Path
from typing import Any

from dashboard.governance_dashboard import (
    assert_sanitized,
    canonical_json,
    load_json_strict,
    pretty_json,
    sanitize_evidence,
    sha256_file,
    sha256_text,
)


ROOT = Path(__file__).resolve().parents[1]
TEMPLATE = Path(__file__).resolve().parent / "templates" / "governance_demo_flow.html"
DEFAULT_DASHBOARD_AUDIT = Path("artifacts/governance-dashboard-audit.json")
DEFAULT_AUDIT_OUTPUT = Path("artifacts/governance-demo-audit.json")
DEFAULT_HTML_OUTPUT = Path("artifacts/governance-demo.html")
DEFAULT_SCREENSHOT_OUTPUT = Path("artifacts/governance-demo-screenshot.svg")

DEMO_SCHEMA = "usbay.governance_demo_flow.v1"
POLICY_VERSION = "usbay.governance_demo_flow_policy.v1"
STABLE_SIGNER_ID = "usbay-demo-governance-evidence-signer"
STABLE_SIGNER_CREATED_AT = "2026-05-22T00:00:00Z"
STABLE_SIGNER_ALGORITHM = "SHA256-HASHED-DEMO-IDENTITY"
STABLE_TRUST_ANCHOR = "USBAY_DEMO_HASH_ONLY_TRUST_ANCHOR_V1"
SAFE_STATES = {"PASS", "BLOCKED", "FAIL", "WARN", "REVIEW_REQUIRED"}
PILOT_DECISION_LABELS = {
    "PASS": "ALLOWED",
    "BLOCKED": "BLOCKED",
    "FAIL": "FAIL_CLOSED",
    "WARN": "REVIEW_REQUIRED",
    "REVIEW_REQUIRED": "REVIEW_REQUIRED",
}
REQUIRED_DASHBOARD_FIELDS = {
    "actor",
    "controls",
    "decision",
    "device",
    "evidence_sources",
    "governance_anomalies",
    "policy_version",
    "provenance_export_state",
    "reviewer_approvals",
    "schema",
    "timeline",
    "timestamp",
}


class DemoValidationError(RuntimeError):
    """Raised when demo evidence cannot be safely rendered."""


def _resolve(root: Path, path: Path) -> Path:
    return path if path.is_absolute() else root / path


def _require(condition: bool, reason: str) -> None:
    if not condition:
        raise DemoValidationError(reason)


def _decision_for_controls(controls: list[dict[str, Any]], name: str) -> str:
    for control in controls:
        if control.get("name") == name:
            return str(control.get("decision") or "BLOCKED")
    return "BLOCKED"


def _reason_for_controls(controls: list[dict[str, Any]], name: str) -> str:
    for control in controls:
        if control.get("name") == name:
            return str(control.get("reason") or "EVIDENCE_MISSING")
    return "EVIDENCE_MISSING"


def _safe_state(value: Any) -> str:
    state = str(value or "BLOCKED")
    return state if state in SAFE_STATES else "BLOCKED"


def _pilot_label(value: Any) -> str:
    return PILOT_DECISION_LABELS[_safe_state(value)]


def _evidence_label(value: Any) -> str:
    text = str(value or "EVIDENCE_MISSING")
    if text == "REVIEW_CHAIN_INCOMPLETE" or "DUAL_REVIEWER_AUTHORIZATION_MISSING" in text:
        return "DUAL_REVIEW_MISSING"
    if "MISSING" in text:
        return "EVIDENCE_MISSING"
    if text == "PASS":
        return "ALLOWED"
    return text


def _stable_signer_identity() -> dict[str, Any]:
    anchor_hash = sha256_text(STABLE_TRUST_ANCHOR)
    fingerprint = sha256_text(
        canonical_json(
            {
                "signer_id": STABLE_SIGNER_ID,
                "signer_created_at": STABLE_SIGNER_CREATED_AT,
                "signer_algorithm": STABLE_SIGNER_ALGORITHM,
                "trust_anchor": anchor_hash,
            }
        )
    )
    return {
        "signer_id": STABLE_SIGNER_ID,
        "signer_fingerprint": fingerprint,
        "signer_created_at": STABLE_SIGNER_CREATED_AT,
        "signer_algorithm": STABLE_SIGNER_ALGORITHM,
        "trust_anchor": anchor_hash,
        "continuity_status": "STABLE",
        "restart_safe_trust_anchor": True,
    }


def validate_signer_identity(identity: Any) -> dict[str, Any]:
    _require(isinstance(identity, dict), "GOVERNANCE_DEMO_SIGNER_IDENTITY_MISSING")
    required = {
        "signer_id",
        "signer_fingerprint",
        "signer_created_at",
        "signer_algorithm",
        "trust_anchor",
        "continuity_status",
    }
    missing = sorted(required - set(identity))
    _require(not missing, "GOVERNANCE_DEMO_SIGNER_IDENTITY_MISSING_FIELDS:" + ",".join(missing))
    _require(identity.get("continuity_status") in {"STABLE", "REVIEW_REQUIRED"}, "GOVERNANCE_DEMO_SIGNER_CONTINUITY_INVALID")
    expected = _stable_signer_identity()
    if identity.get("signer_fingerprint") != expected["signer_fingerprint"]:
        raise DemoValidationError("GOVERNANCE_DEMO_SIGNER_FINGERPRINT_MISMATCH")
    sanitized = sanitize_evidence(identity)
    assert_sanitized(sanitized)
    return sanitized


def validate_dashboard_audit(dashboard: Any) -> dict[str, Any]:
    _require(isinstance(dashboard, dict), "GOVERNANCE_DEMO_DASHBOARD_AUDIT_INVALID")
    missing = sorted(REQUIRED_DASHBOARD_FIELDS - set(dashboard))
    _require(not missing, "GOVERNANCE_DEMO_DASHBOARD_AUDIT_MISSING_FIELDS:" + ",".join(missing))
    _require(dashboard.get("schema") == "usbay.governance_dashboard_audit.v1", "GOVERNANCE_DEMO_DASHBOARD_SCHEMA_INVALID")
    _require(isinstance(dashboard.get("timeline"), list) and dashboard["timeline"], "GOVERNANCE_DEMO_PROVENANCE_TIMELINE_INCOMPLETE")
    _require(isinstance(dashboard.get("reviewer_approvals"), list), "GOVERNANCE_DEMO_REVIEWER_EVIDENCE_INVALID")
    _require(isinstance(dashboard.get("controls"), list), "GOVERNANCE_DEMO_CONTROLS_INVALID")

    for index, item in enumerate(dashboard["timeline"]):
        _require(isinstance(item, dict), f"GOVERNANCE_DEMO_TIMELINE_ENTRY_INVALID:{index}")
        sha = str(item.get("commit_sha") or "")
        _require(len(sha) == 40, f"GOVERNANCE_DEMO_COMMIT_SHA_INVALID:{index}")
        _require(item.get("audit_timestamp"), f"GOVERNANCE_DEMO_AUDIT_TIMESTAMP_MISSING:{sha}")
        if item.get("verification_state") != "VERIFIED":
            raise DemoValidationError(f"GOVERNANCE_DEMO_UNSIGNED_COMMIT_BLOCKED:{sha}")
    anomalies = [str(item) for item in dashboard.get("governance_anomalies", [])]
    if any("PROVENANCE_CHAIN_BREAK" in anomaly for anomaly in anomalies):
        raise DemoValidationError("GOVERNANCE_DEMO_PROVENANCE_CHAIN_BREAK")
    if any("UNSIGNED_GOVERNANCE_COMMIT" in anomaly for anomaly in anomalies):
        raise DemoValidationError("GOVERNANCE_DEMO_UNSIGNED_COMMIT_BLOCKED")
    return dashboard


def _provenance_graph(timeline: list[dict[str, Any]]) -> dict[str, Any]:
    nodes = []
    edges = []
    by_source: dict[str, list[dict[str, Any]]] = {}
    for item in timeline:
        by_source.setdefault(str(item.get("source") or "unknown"), []).append(item)
        nodes.append(
            {
                "id": str(item["commit_sha"])[:12],
                "commit_sha": item["commit_sha"],
                "source": item.get("source"),
                "verification_state": item.get("verification_state"),
                "decision": item.get("governance_decision"),
            }
        )
    for source, items in sorted(by_source.items()):
        for index in range(1, len(items)):
            edges.append(
                {
                    "source": source,
                    "from": str(items[index - 1]["commit_sha"])[:12],
                    "to": str(items[index]["commit_sha"])[:12],
                    "relationship": "parent_to_child",
                }
            )
    return {"nodes": nodes, "edges": edges}


def _demo_sequence(dashboard: dict[str, Any]) -> list[dict[str, Any]]:
    controls = dashboard["controls"]
    anomalies = dashboard.get("governance_anomalies", [])
    reviewer_decision = _decision_for_controls(controls, "reviewer_approvals")
    dashboard_decision = _safe_state(dashboard.get("decision"))
    return [
        {
            "step": "signed_commit_lineage",
            "decision": _decision_for_controls(controls, "verified_commit_lineage"),
            "evidence": _reason_for_controls(controls, "verified_commit_lineage"),
        },
        {
            "step": "reviewer_approval_flow",
            "decision": reviewer_decision,
            "evidence": _reason_for_controls(controls, "reviewer_approvals"),
        },
        {
            "step": "governance_validation",
            "decision": dashboard_decision,
            "evidence": f"dashboard_decision={dashboard_decision}",
        },
        {
            "step": "anomaly_detection",
            "decision": "REVIEW_REQUIRED" if anomalies else "PASS",
            "evidence": f"anomaly_count={len(anomalies)}",
        },
        {
            "step": "blocked_state_handling",
            "decision": "PASS" if dashboard_decision == "BLOCKED" and anomalies else "REVIEW_REQUIRED",
            "evidence": "fail_closed_blocked_state_rendered" if dashboard_decision == "BLOCKED" else "blocked_state_not_triggered",
        },
        {
            "step": "governance_dashboard_rendering",
            "decision": dashboard_decision,
            "evidence": "dashboard_audit_hash=" + str(dashboard.get("dashboard_audit_hash", "")),
        },
        {
            "step": "audit_export_generation",
            "decision": "PASS",
            "evidence": "sanitized_hash_only_demo_export",
        },
        {
            "step": "provenance_visualization",
            "decision": _safe_state((dashboard.get("provenance_export_state") or {}).get("decision")),
            "evidence": str((dashboard.get("provenance_export_state") or {}).get("reason") or "EVIDENCE_MISSING"),
        },
    ]


def _runtime_demo_scenarios(
    *,
    dashboard: dict[str, Any],
    sequence: list[dict[str, Any]],
    graph: dict[str, Any],
    actor: str,
    device: str,
    timestamp: str,
) -> list[dict[str, Any]]:
    verified_lineage = _decision_for_controls(dashboard["controls"], "verified_commit_lineage")
    reviewer_decision = _decision_for_controls(dashboard["controls"], "reviewer_approvals")
    dashboard_decision = _safe_state(dashboard.get("decision"))
    source_evidence = sha256_text(canonical_json({"sequence": sequence, "graph": graph}))
    common = {
        "actor": actor,
        "device": device,
        "timestamp": timestamp,
        "policy_version": POLICY_VERSION,
        "audit_evidence_hash": source_evidence,
    }
    return [
        {
            **common,
            "name": "allowed_governance_decision",
            "decision": "PASS" if verified_lineage == "PASS" else "BLOCKED",
            "pilot_label": "ALLOWED" if verified_lineage == "PASS" else "BLOCKED",
            "governance_path": "demo_allowed_path",
            "required_evidence": ["verified_commit_lineage", "frontend_secret_exposure_validation"],
            "evidence_state": {
                "verified_commit_lineage": verified_lineage,
                "frontend_secret_exposure_validation": _decision_for_controls(dashboard["controls"], "frontend_secret_exposure_validation"),
            },
            "fail_closed": verified_lineage != "PASS",
        },
        {
            **common,
            "name": "blocked_governance_decision",
            "decision": "BLOCKED",
            "pilot_label": "BLOCKED",
            "governance_path": "demo_blocked_path",
            "required_evidence": ["reviewer_approvals", "branch_hygiene_status", "dashboard_decision"],
            "evidence_state": {
                "reviewer_approvals": reviewer_decision,
                "branch_hygiene_status": _decision_for_controls(dashboard["controls"], "branch_hygiene_status"),
                "dashboard_decision": dashboard_decision,
            },
            "fail_closed": True,
        },
        {
            **common,
            "name": "unsigned_untrusted_execution_path",
            "decision": "REVIEW_REQUIRED",
            "pilot_label": "REVIEW_REQUIRED",
            "governance_path": "demo_untrusted_pr_validation_path",
            "trusted_evidence_required": True,
            "signed_evidence_claimed": False,
            "required_evidence": ["trusted_non_pr_evidence_generation", "human_reviewer_approval"],
            "evidence_state": {
                "execution_trust": "UNTRUSTED",
                "runtime_claim": "unsigned_validation_only",
                "dashboard_decision": dashboard_decision,
            },
            "fail_closed": True,
        },
    ]


def _blocked_reasons(state: dict[str, Any]) -> list[str]:
    reasons = [_evidence_label(item) for item in state.get("anomaly_indicators", [])]
    for scenario in state.get("runtime_demo_scenarios", []):
        if scenario.get("decision") == "BLOCKED":
            evidence_state = scenario.get("evidence_state", {})
            if isinstance(evidence_state, dict):
                reasons.extend(_evidence_label(value) for value in evidence_state.values())
    ordered = []
    for reason in reasons:
        if reason not in ordered:
            ordered.append(reason)
    return ordered or ["EVIDENCE_MISSING"]


def build_demo_state(
    *,
    root: Path = ROOT,
    dashboard_audit_path: Path = DEFAULT_DASHBOARD_AUDIT,
    actor: str = "codex",
    device: str = "local",
    timestamp: str = "2026-05-22T00:00:00Z",
) -> dict[str, Any]:
    dashboard_path = _resolve(root, dashboard_audit_path)
    dashboard = validate_dashboard_audit(load_json_strict(dashboard_path))
    source_hash = sha256_file(dashboard_path)
    sequence = _demo_sequence(dashboard)
    graph = _provenance_graph(dashboard["timeline"])
    runtime_scenarios = _runtime_demo_scenarios(
        dashboard=dashboard,
        sequence=sequence,
        graph=graph,
        actor=actor,
        device=device,
        timestamp=timestamp,
    )
    controls = dashboard["controls"]
    reviewer_approvals = dashboard["reviewer_approvals"]
    anomalies = [str(item) for item in dashboard.get("governance_anomalies", [])]
    overall_decision = "BLOCKED" if any(item["decision"] == "BLOCKED" for item in sequence) or dashboard.get("decision") == "BLOCKED" else "PASS"
    state = {
        "schema": DEMO_SCHEMA,
        "actor": actor,
        "device": device,
        "decision": overall_decision,
        "timestamp": timestamp,
        "policy_version": POLICY_VERSION,
        "signer_identity": _stable_signer_identity(),
        "source_dashboard_audit": {
            "path": dashboard_audit_path.as_posix(),
            "sha256": source_hash,
            "dashboard_decision": dashboard["decision"],
            "dashboard_audit_hash": dashboard.get("dashboard_audit_hash"),
        },
        "enterprise_summary": {
            "verified_commit_count": (dashboard.get("provenance_export_state") or {}).get("verified_commit_count", 0),
            "timeline_entry_count": len(dashboard["timeline"]),
            "reviewer_evidence_count": len(reviewer_approvals),
            "anomaly_count": len(anomalies),
            "dashboard_rendering_decision": dashboard["decision"],
            "frontend_secret_validation": _decision_for_controls(controls, "frontend_secret_exposure_validation"),
            "runtime_decision_label": _pilot_label(overall_decision),
            "blocked_reason_label": "DUAL_REVIEW_MISSING" if any("DUAL_REVIEWER_AUTHORIZATION_MISSING" in item for item in anomalies) else "EVIDENCE_MISSING",
        },
        "demo_sequence": sequence,
        "runtime_demo_scenarios": runtime_scenarios,
        "governance_timeline": dashboard["timeline"],
        "reviewer_chain": reviewer_approvals,
        "verification_states": {
            "verified": sum(1 for item in dashboard["timeline"] if item.get("verification_state") == "VERIFIED"),
            "unverified": sum(1 for item in dashboard["timeline"] if item.get("verification_state") != "VERIFIED"),
        },
        "provenance_graph": graph,
        "audit_evidence_summary": {
            "controls": controls,
            "evidence_sources": dashboard.get("evidence_sources", []),
            "source_hashes_only": True,
        },
        "anomaly_indicators": anomalies,
        "fail_closed_indicators": [
            "FAIL_CLOSED",
            "EVIDENCE_MISSING" if anomalies else "NO_EVIDENCE_GAPS_DETECTED",
            "DUAL_REVIEW_MISSING" if any("DUAL_REVIEWER_AUTHORIZATION_MISSING" in item for item in anomalies) else "DUAL_REVIEW_PRESENT",
        ],
    }
    state = sanitize_evidence(state)
    assert_sanitized(state)
    state["signer_identity"] = validate_signer_identity(state.get("signer_identity"))
    state["demo_audit_hash"] = sha256_text(canonical_json(state))
    assert_sanitized(state)
    return state


def render_demo_html(state: dict[str, Any], template_path: Path = TEMPLATE) -> str:
    _require(state.get("schema") == DEMO_SCHEMA, "GOVERNANCE_DEMO_SCHEMA_INVALID")
    signer_identity = validate_signer_identity(state.get("signer_identity"))
    template = template_path.read_text(encoding="utf-8")
    summary = state["enterprise_summary"]
    summary_rows = "\n".join(
        f"          <tr><th>{html.escape(str(key))}</th><td>{html.escape(str(value))}</td></tr>"
        for key, value in summary.items()
    )
    decision_cards = "\n".join(
        "        <article class=\"decision-card {}\"><span>{}</span><strong>{}</strong><small>{}</small></article>".format(
            html.escape(_safe_state(item["decision"])),
            html.escape(str(item["name"])),
            html.escape(str(item.get("pilot_label") or _pilot_label(item["decision"]))),
            html.escape("FAIL_CLOSED" if item.get("fail_closed") else "evidence-backed demo path"),
        )
        for item in state["runtime_demo_scenarios"]
    )
    blocked_reasons = "\n".join(
        f"        <li>{html.escape(reason)}</li>"
        for reason in _blocked_reasons(state)
    )
    evidence_rows = "\n".join(
        "          <tr><td>{}</td><td class=\"{}\">{}</td><td>{}</td></tr>".format(
            html.escape(str(control.get("name"))),
            html.escape(_safe_state(control.get("decision"))),
            html.escape(_pilot_label(control.get("decision"))),
            html.escape(_evidence_label(control.get("reason"))),
        )
        for control in state["audit_evidence_summary"]["controls"]
    )
    reviewer_rows = "\n".join(
        "          <tr><td>{}</td><td class=\"{}\">{}</td><td>{}</td></tr>".format(
            html.escape(str(item.get("source"))),
            html.escape(_safe_state(item.get("decision"))),
            html.escape(_pilot_label(item.get("decision"))),
            html.escape(_evidence_label(item.get("reason"))),
        )
        for item in state["reviewer_chain"]
    )
    signer_rows = "\n".join(
        f"          <tr><th>{html.escape(str(key))}</th><td>{html.escape(str(value))}</td></tr>"
        for key, value in signer_identity.items()
    )
    sequence_rows = "\n".join(
        "          <tr><td>{}</td><td class=\"{}\">{}</td><td>{}</td></tr>".format(
            html.escape(str(item["step"])),
            html.escape(_safe_state(item["decision"])),
            html.escape(_pilot_label(item["decision"])),
            html.escape(str(item["evidence"])),
        )
        for item in state["demo_sequence"]
    )
    runtime_rows = "\n".join(
        "          <tr><td>{}</td><td class=\"{}\">{}</td><td>{}</td><td>{}</td></tr>".format(
            html.escape(str(item["name"])),
            html.escape(_safe_state(item["decision"])),
            html.escape(str(item.get("pilot_label") or _pilot_label(item["decision"]))),
            html.escape(str(item["governance_path"])),
            html.escape(str(item.get("trusted_evidence_required", False))),
        )
        for item in state["runtime_demo_scenarios"]
    )
    timeline_items = "\n".join(
        "        <div class=\"timeline-item {}\"><strong>{}</strong><br><code>{}</code><br>{}</div>".format(
            html.escape(_safe_state(item.get("governance_decision"))),
            html.escape(str(item.get("audit_timestamp"))),
            html.escape(str(item.get("commit_sha"))),
            html.escape(str(item.get("verification_state"))),
        )
        for item in state["governance_timeline"]
    )
    fail_closed_items = "\n".join(
        f"        <li>{html.escape(str(item))}</li>"
        for item in state["fail_closed_indicators"]
    )
    replacements = {
        "{decision}": html.escape(_safe_state(state["decision"])),
        "{decision_label}": html.escape(_pilot_label(state["decision"])),
        "{policy_version}": html.escape(str(state["policy_version"])),
        "{summary_rows}": summary_rows,
        "{decision_cards}": decision_cards,
        "{blocked_reasons}": blocked_reasons,
        "{evidence_rows}": evidence_rows,
        "{reviewer_rows}": reviewer_rows,
        "{signer_rows}": signer_rows,
        "{sequence_rows}": sequence_rows,
        "{runtime_rows}": runtime_rows,
        "{timeline_items}": timeline_items,
        "{fail_closed_items}": fail_closed_items,
        "{provenance_graph}": html.escape(pretty_json(state["provenance_graph"])),
        "{audit_json}": html.escape(pretty_json(state)),
    }
    rendered = template
    for placeholder, value in replacements.items():
        rendered = rendered.replace(placeholder, value)
    assert_sanitized(rendered)
    return rendered


def render_demo_screenshot_svg(state: dict[str, Any]) -> str:
    summary = state["enterprise_summary"]
    anomalies = state["anomaly_indicators"]
    decision = _safe_state(state["decision"])
    anomaly_text = " | ".join(anomalies[:3]) if anomalies else "none"
    svg = f"""<svg xmlns="http://www.w3.org/2000/svg" width="1280" height="720" viewBox="0 0 1280 720" role="img" aria-label="USBAY governance demo screenshot">
  <rect width="1280" height="720" fill="#f6f8fb"/>
  <rect x="0" y="0" width="1280" height="112" fill="#102033"/>
  <text x="48" y="62" font-family="Arial, sans-serif" font-size="34" fill="#f8fafc">USBAY Governance Evidence Demo</text>
  <text x="48" y="94" font-family="Arial, sans-serif" font-size="18" fill="#dbeafe">Decision: {html.escape(decision)} | Fail-closed rendering active</text>
  <rect x="48" y="150" width="360" height="150" fill="#ffffff" stroke="#c8d2df"/>
  <text x="72" y="192" font-family="Arial, sans-serif" font-size="22" fill="#17212f">Verified commits</text>
  <text x="72" y="250" font-family="Arial, sans-serif" font-size="54" fill="#166534">{html.escape(str(summary.get("verified_commit_count", 0)))}</text>
  <rect x="460" y="150" width="360" height="150" fill="#ffffff" stroke="#c8d2df"/>
  <text x="484" y="192" font-family="Arial, sans-serif" font-size="22" fill="#17212f">Anomalies visible</text>
  <text x="484" y="250" font-family="Arial, sans-serif" font-size="54" fill="#991b1b">{html.escape(str(summary.get("anomaly_count", 0)))}</text>
  <rect x="872" y="150" width="360" height="150" fill="#ffffff" stroke="#c8d2df"/>
  <text x="896" y="192" font-family="Arial, sans-serif" font-size="22" fill="#17212f">Dashboard state</text>
  <text x="896" y="250" font-family="Arial, sans-serif" font-size="42" fill="#991b1b">{html.escape(str(summary.get("dashboard_rendering_decision", "BLOCKED")))}</text>
  <rect x="48" y="346" width="1184" height="292" fill="#ffffff" stroke="#c8d2df"/>
  <text x="72" y="392" font-family="Arial, sans-serif" font-size="24" fill="#17212f">Evidence sequence</text>
  <text x="72" y="440" font-family="Arial, sans-serif" font-size="18" fill="#17212f">Signed commit lineage -> reviewer governance -> validation -> anomaly visibility -> BLOCKED state -> audit export</text>
  <text x="72" y="492" font-family="Arial, sans-serif" font-size="18" fill="#991b1b">Anomaly indicators: {html.escape(anomaly_text)}</text>
  <text x="72" y="544" font-family="Arial, sans-serif" font-size="18" fill="#17212f">Only sanitized, hash-first evidence summaries are rendered.</text>
  <text x="72" y="596" font-family="Arial, sans-serif" font-size="18" fill="#17212f">Demo audit hash: {html.escape(str(state.get("demo_audit_hash", ""))[:32])}</text>
</svg>
"""
    assert_sanitized(svg)
    return svg


def write_outputs(state: dict[str, Any], audit_output: Path, html_output: Path, screenshot_output: Path) -> None:
    audit_output.parent.mkdir(parents=True, exist_ok=True)
    html_output.parent.mkdir(parents=True, exist_ok=True)
    screenshot_output.parent.mkdir(parents=True, exist_ok=True)
    audit_output.write_text(canonical_json(state) + "\n", encoding="utf-8")
    html_output.write_text(render_demo_html(state), encoding="utf-8")
    screenshot_output.write_text(render_demo_screenshot_svg(state), encoding="utf-8")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Render deterministic USBAY governance evidence demo flow")
    parser.add_argument("--root", type=Path, default=ROOT)
    parser.add_argument("--dashboard-audit", type=Path, default=DEFAULT_DASHBOARD_AUDIT)
    parser.add_argument("--audit-output", type=Path, default=DEFAULT_AUDIT_OUTPUT)
    parser.add_argument("--html-output", type=Path, default=DEFAULT_HTML_OUTPUT)
    parser.add_argument("--screenshot-output", type=Path, default=DEFAULT_SCREENSHOT_OUTPUT)
    parser.add_argument("--timestamp", default="2026-05-22T00:00:00Z")
    args = parser.parse_args(argv)
    state = build_demo_state(root=args.root, dashboard_audit_path=args.dashboard_audit, timestamp=args.timestamp)
    audit_output = _resolve(args.root, args.audit_output)
    html_output = _resolve(args.root, args.html_output)
    screenshot_output = _resolve(args.root, args.screenshot_output)
    write_outputs(state, audit_output, html_output, screenshot_output)
    print(f"GOVERNANCE_DEMO_DECISION={state['decision']}")
    print(f"GOVERNANCE_DEMO_AUDIT={audit_output}")
    print(f"GOVERNANCE_DEMO_HTML={html_output}")
    print(f"GOVERNANCE_DEMO_SCREENSHOT={screenshot_output}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main(sys.argv[1:]))
    except (DemoValidationError, OSError, ValueError) as exc:
        raise SystemExit(f"GOVERNANCE_DEMO_BLOCKED:{exc}") from exc
