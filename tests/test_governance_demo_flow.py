from __future__ import annotations

import json
from pathlib import Path

import pytest

from demo.governance_demo_flow import (
    DEMO_SCHEMA,
    DemoValidationError,
    build_demo_state,
    canonical_json,
    render_demo_html,
    render_demo_screenshot_svg,
    validate_dashboard_audit,
    write_outputs,
)


ROOT = Path(__file__).resolve().parents[1]
TIMESTAMP = "2026-05-22T00:00:00Z"
FORBIDDEN = (
    "PRIVATE " + "KEY",
    "BEGIN PGP " + "SIGNATURE",
    "ghp" + "_",
    "github" + "_pat_",
    "xoxb" + "-",
    "approval" + "_contents",
)


def _dashboard_fixture(tmp_path: Path) -> Path:
    source = ROOT / "artifacts" / "governance-dashboard-audit.json"
    target = tmp_path / "artifacts" / "governance-dashboard-audit.json"
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(source.read_text(encoding="utf-8"), encoding="utf-8")
    return target


def test_governance_demo_output_is_deterministic_and_blocked(tmp_path: Path) -> None:
    _dashboard_fixture(tmp_path)

    first = build_demo_state(root=tmp_path, timestamp=TIMESTAMP)
    second = build_demo_state(root=tmp_path, timestamp=TIMESTAMP)
    html = render_demo_html(first)
    screenshot = render_demo_screenshot_svg(first)

    assert first["schema"] == DEMO_SCHEMA
    assert first["decision"] == "BLOCKED"
    assert canonical_json(first) == canonical_json(second)
    assert html == render_demo_html(second)
    assert "BRANCH_HYGIENE_EVIDENCE_MISSING" in first["anomaly_indicators"]
    assert "DUAL_REVIEWER_AUTHORIZATION_MISSING" in canonical_json(first)
    assert "USBAY Governance Evidence Demo" in html
    assert "USBAY Governance Evidence Demo" in screenshot
    assert not any(marker in canonical_json(first) + html + screenshot for marker in FORBIDDEN)


def test_provenance_visualization_contains_nodes_and_edges(tmp_path: Path) -> None:
    _dashboard_fixture(tmp_path)

    state = build_demo_state(root=tmp_path, timestamp=TIMESTAMP)
    graph = state["provenance_graph"]

    assert len(graph["nodes"]) == state["enterprise_summary"]["timeline_entry_count"]
    assert graph["edges"]
    assert all(edge["relationship"] == "parent_to_child" for edge in graph["edges"])
    assert state["verification_states"] == {"verified": 4, "unverified": 0}


def test_missing_reviewer_approval_keeps_demo_blocked(tmp_path: Path) -> None:
    _dashboard_fixture(tmp_path)

    state = build_demo_state(root=tmp_path, timestamp=TIMESTAMP)
    reviewer_step = next(item for item in state["demo_sequence"] if item["step"] == "reviewer_approval_flow")

    assert reviewer_step["decision"] == "BLOCKED"
    assert state["decision"] == "BLOCKED"
    assert "FALSE" not in canonical_json(state)


def test_unsigned_commit_fails_closed(tmp_path: Path) -> None:
    dashboard_path = _dashboard_fixture(tmp_path)
    dashboard = json.loads(dashboard_path.read_text(encoding="utf-8"))
    dashboard["timeline"][0]["verification_state"] = "UNVERIFIED"
    dashboard_path.write_text(json.dumps(dashboard, sort_keys=True), encoding="utf-8")

    with pytest.raises(DemoValidationError, match="GOVERNANCE_DEMO_UNSIGNED_COMMIT_BLOCKED"):
        build_demo_state(root=tmp_path, timestamp=TIMESTAMP)


def test_provenance_chain_break_fails_closed(tmp_path: Path) -> None:
    dashboard_path = _dashboard_fixture(tmp_path)
    dashboard = json.loads(dashboard_path.read_text(encoding="utf-8"))
    dashboard["governance_anomalies"].append("pr41_timeline.json:PROVENANCE_CHAIN_BREAK:" + "a" * 40)
    dashboard_path.write_text(json.dumps(dashboard, sort_keys=True), encoding="utf-8")

    with pytest.raises(DemoValidationError, match="GOVERNANCE_DEMO_PROVENANCE_CHAIN_BREAK"):
        build_demo_state(root=tmp_path, timestamp=TIMESTAMP)


def test_sanitizer_blocks_unsafe_rendering(tmp_path: Path) -> None:
    dashboard_path = _dashboard_fixture(tmp_path)
    dashboard = json.loads(dashboard_path.read_text(encoding="utf-8"))
    dashboard["unsafe"] = {"token": "ghp" + "_unsafe_demo" + "_value"}
    dashboard_path.write_text(json.dumps(dashboard, sort_keys=True), encoding="utf-8")

    state = build_demo_state(root=tmp_path, timestamp=TIMESTAMP)
    rendered = canonical_json(state) + render_demo_html(state) + render_demo_screenshot_svg(state)

    assert "ghp" + "_" not in rendered
    assert "[REDACTED]" not in state["source_dashboard_audit"]["sha256"]


def test_write_outputs_produces_audit_safe_artifacts(tmp_path: Path) -> None:
    _dashboard_fixture(tmp_path)
    state = build_demo_state(root=tmp_path, timestamp=TIMESTAMP)
    audit_output = tmp_path / "artifacts" / "governance-demo-audit.json"
    html_output = tmp_path / "artifacts" / "governance-demo.html"
    screenshot_output = tmp_path / "artifacts" / "governance-demo-screenshot.svg"

    write_outputs(state, audit_output, html_output, screenshot_output)

    assert audit_output.is_file()
    assert html_output.is_file()
    assert screenshot_output.is_file()
    rendered = audit_output.read_text(encoding="utf-8") + html_output.read_text(encoding="utf-8") + screenshot_output.read_text(encoding="utf-8")
    assert not any(marker in rendered for marker in FORBIDDEN)


def test_invalid_dashboard_audit_schema_is_rejected() -> None:
    with pytest.raises(DemoValidationError, match="GOVERNANCE_DEMO_DASHBOARD_AUDIT_INVALID"):
        validate_dashboard_audit([])
