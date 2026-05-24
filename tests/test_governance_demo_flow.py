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
    validate_governance_gate_history,
    write_evidence_pack,
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
    "private" + "_key",
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
    assert "Runtime Decision Summary" in html
    assert "Why Blocked?" in html
    assert "Evidence State" in html
    assert "Reviewer Authorization" in html
    assert "Provenance Graph" in html
    assert "Audit Timeline" in html
    assert "Fail-Closed Indicators" in html
    assert "BLOCKED" in html
    assert "FAIL_CLOSED" in html
    assert "EVIDENCE_MISSING" in html
    assert "DUAL_REVIEW_MISSING" in html
    assert "Stable Signer Identity" in html
    assert "signer_fingerprint" in html
    assert "continuity_status" in html
    assert "Tamper-Evident Gate History" in html
    assert "chain_integrity_status" in html
    assert "latest_event_hash" in html
    assert "Tamper-evident badge" in html
    assert "TAMPER_EVIDENT" in html
    assert "Broken-chain warning" in html
    assert "chain_position" in html
    assert "USBAY Governance Evidence Demo" in screenshot
    assert not any(marker in canonical_json(first) + html + screenshot for marker in FORBIDDEN)


def test_stable_signer_identity_survives_repeated_generation(tmp_path: Path) -> None:
    _dashboard_fixture(tmp_path)

    first = build_demo_state(root=tmp_path, timestamp=TIMESTAMP)
    second = build_demo_state(root=tmp_path, timestamp=TIMESTAMP)
    signer = first["signer_identity"]

    assert signer == second["signer_identity"]
    assert signer["signer_id"] == "usbay-demo-governance-evidence-signer"
    assert len(signer["signer_fingerprint"]) == 64
    assert signer["signer_algorithm"] == "SHA256-HASHED-DEMO-IDENTITY"
    assert signer["continuity_status"] == "STABLE"
    assert signer["restart_safe_trust_anchor"] is True
    assert signer["trust_anchor"]


def test_missing_signer_identity_fails_closed(tmp_path: Path) -> None:
    _dashboard_fixture(tmp_path)
    state = build_demo_state(root=tmp_path, timestamp=TIMESTAMP)
    del state["signer_identity"]

    with pytest.raises(DemoValidationError, match="GOVERNANCE_DEMO_SIGNER_IDENTITY_MISSING"):
        render_demo_html(state)


def test_governance_gate_history_hashes_are_deterministic(tmp_path: Path) -> None:
    _dashboard_fixture(tmp_path)

    first = build_demo_state(root=tmp_path, timestamp=TIMESTAMP)
    second = build_demo_state(root=tmp_path, timestamp=TIMESTAMP)

    assert first["governance_gate_history"] == second["governance_gate_history"]
    assert first["governance_gate_history_summary"] == second["governance_gate_history_summary"]
    assert first["governance_gate_history_summary"]["chain_integrity_status"] == "PASS"
    assert first["governance_gate_history_summary"]["chain_continuity"] == "CONTINUOUS"
    assert len(first["governance_gate_history_summary"]["latest_event_hash"]) == 64


def test_governance_gate_history_detects_tampered_prior_event(tmp_path: Path) -> None:
    _dashboard_fixture(tmp_path)
    state = build_demo_state(root=tmp_path, timestamp=TIMESTAMP)
    history = json.loads(json.dumps(state["governance_gate_history"]))
    history[0]["decision"] = "PASS"

    summary = validate_governance_gate_history(history, state["signer_identity"])

    assert summary["chain_integrity_status"] == "REVIEW_REQUIRED"
    assert summary["chain_continuity"] == "BROKEN"
    assert summary["tamper_evident_indicator"] == "TAMPER_EVIDENT"
    assert "GOVERNANCE_GATE_EVENT_HASH_MISMATCH:0" == summary["broken_chain_warning"]


def test_governance_gate_history_missing_previous_hash_requires_review(tmp_path: Path) -> None:
    _dashboard_fixture(tmp_path)
    state = build_demo_state(root=tmp_path, timestamp=TIMESTAMP)
    history = json.loads(json.dumps(state["governance_gate_history"]))
    del history[1]["previous_event_hash"]

    summary = validate_governance_gate_history(history, state["signer_identity"])

    assert summary["chain_integrity_status"] == "REVIEW_REQUIRED"
    assert summary["chain_continuity"] == "BROKEN"
    assert "previous_event_hash" in summary["broken_chain_warning"]


def test_governance_gate_history_continuity_validates(tmp_path: Path) -> None:
    _dashboard_fixture(tmp_path)
    state = build_demo_state(root=tmp_path, timestamp=TIMESTAMP)
    history = state["governance_gate_history"]

    for index, event in enumerate(history):
        assert event["chain_position"] == index
        if index == 0:
            assert event["previous_event_hash"] == "GENESIS"
        else:
            assert event["previous_event_hash"] == history[index - 1]["current_event_hash"]
        assert len(event["current_event_hash"]) == 64
        assert event["chain_integrity_status"] == "PASS"


def test_runtime_demo_paths_cover_allowed_blocked_and_untrusted(tmp_path: Path) -> None:
    _dashboard_fixture(tmp_path)

    state = build_demo_state(root=tmp_path, timestamp=TIMESTAMP)
    scenarios = {item["name"]: item for item in state["runtime_demo_scenarios"]}

    assert scenarios["allowed_governance_decision"]["decision"] == "PASS"
    assert scenarios["allowed_governance_decision"]["pilot_label"] == "ALLOWED"
    assert scenarios["allowed_governance_decision"]["fail_closed"] is False
    assert scenarios["allowed_governance_decision"]["evidence_state"]["verified_commit_lineage"] == "PASS"

    assert scenarios["blocked_governance_decision"]["decision"] == "BLOCKED"
    assert scenarios["blocked_governance_decision"]["pilot_label"] == "BLOCKED"
    assert scenarios["blocked_governance_decision"]["fail_closed"] is True
    assert scenarios["blocked_governance_decision"]["evidence_state"]["reviewer_approvals"] == "BLOCKED"

    assert scenarios["unsigned_untrusted_execution_path"]["decision"] == "REVIEW_REQUIRED"
    assert scenarios["unsigned_untrusted_execution_path"]["pilot_label"] == "REVIEW_REQUIRED"
    assert scenarios["unsigned_untrusted_execution_path"]["trusted_evidence_required"] is True
    assert scenarios["unsigned_untrusted_execution_path"]["signed_evidence_claimed"] is False
    assert scenarios["unsigned_untrusted_execution_path"]["fail_closed"] is True


def test_provenance_visualization_contains_nodes_and_edges(tmp_path: Path) -> None:
    _dashboard_fixture(tmp_path)

    state = build_demo_state(root=tmp_path, timestamp=TIMESTAMP)
    graph = state["provenance_graph"]

    assert len(graph["nodes"]) == state["enterprise_summary"]["timeline_entry_count"]
    assert graph["edges"]
    assert all(edge["relationship"] == "parent_to_child" for edge in graph["edges"])
    assert state["verification_states"] == {"verified": 4, "unverified": 0}


def test_reviewer_evidence_and_provenance_graph_render_for_pilot(tmp_path: Path) -> None:
    _dashboard_fixture(tmp_path)

    state = build_demo_state(root=tmp_path, timestamp=TIMESTAMP)
    html = render_demo_html(state)

    assert "Reviewer Authorization" in html
    assert "DUAL_REVIEW_MISSING" in html
    assert "pr41_reviews.json" in html
    assert "pr42_reviews.json" in html
    assert "Provenance Graph" in html
    assert "parent_to_child" in html


def test_demo_ui_does_not_define_production_governance_api_routes() -> None:
    demo_files = (
        ROOT / "demo" / "governance_demo_flow.py",
        ROOT / "demo" / "templates" / "governance_demo_flow.html",
    )

    for path in demo_files:
        text = path.read_text(encoding="utf-8")
        assert "/api/governance" not in text
        assert "@app." not in text


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
    audit = json.loads(audit_output.read_text(encoding="utf-8"))
    assert {item["name"] for item in audit["runtime_demo_scenarios"]} == {
        "allowed_governance_decision",
        "blocked_governance_decision",
        "unsigned_untrusted_execution_path",
    }
    rendered = audit_output.read_text(encoding="utf-8") + html_output.read_text(encoding="utf-8") + screenshot_output.read_text(encoding="utf-8")
    assert audit["signer_identity"]["signer_fingerprint"] in rendered
    assert audit["governance_gate_history_summary"]["latest_event_hash"] in rendered
    assert not any(marker in rendered for marker in FORBIDDEN)


def test_evidence_pack_exports_gate_history_and_chain_summary(tmp_path: Path) -> None:
    _dashboard_fixture(tmp_path)
    state = build_demo_state(root=tmp_path, timestamp=TIMESTAMP)
    pack_dir = tmp_path / "artifacts" / "governance-demo-evidence-pack"

    written = write_evidence_pack(state, pack_dir)

    assert set(written) == {"gate_history.json", "chain_summary.json"}
    gate_history = json.loads((pack_dir / "gate_history.json").read_text(encoding="utf-8"))
    chain_summary = json.loads((pack_dir / "chain_summary.json").read_text(encoding="utf-8"))

    assert gate_history["schema"] == "usbay.governance_demo_gate_history.v1"
    assert gate_history["events"]
    assert all(len(event["current_event_hash"]) == 64 for event in gate_history["events"])
    assert all("chain_position" in event for event in gate_history["events"])
    assert gate_history["latest_event_hash"] == state["governance_gate_history_summary"]["latest_event_hash"]
    assert chain_summary["latest_event_hash"] == state["governance_gate_history_summary"]["latest_event_hash"]
    assert chain_summary["chain_integrity_status"] == "PASS"
    assert chain_summary["chain_positions"] == [0, 1, 2]
    assert chain_summary["signer_continuity_metadata"]["signer_fingerprint"] == state["signer_identity"]["signer_fingerprint"]

    exported = (pack_dir / "gate_history.json").read_text(encoding="utf-8") + (pack_dir / "chain_summary.json").read_text(encoding="utf-8")
    assert not any(marker in exported for marker in FORBIDDEN)


def test_evidence_pack_exports_broken_chain_state(tmp_path: Path) -> None:
    _dashboard_fixture(tmp_path)
    state = build_demo_state(root=tmp_path, timestamp=TIMESTAMP)
    state["governance_gate_history"][0]["decision"] = "PASS"
    pack_dir = tmp_path / "artifacts" / "broken-governance-demo-evidence-pack"

    write_evidence_pack(state, pack_dir)

    gate_history = json.loads((pack_dir / "gate_history.json").read_text(encoding="utf-8"))
    chain_summary = json.loads((pack_dir / "chain_summary.json").read_text(encoding="utf-8"))

    assert gate_history["chain_integrity_status"] == "REVIEW_REQUIRED"
    assert gate_history["broken_chain_warning"] == "GOVERNANCE_GATE_EVENT_HASH_MISMATCH:0"
    assert chain_summary["chain_integrity_status"] == "REVIEW_REQUIRED"
    assert chain_summary["broken_chain_warning"] == "GOVERNANCE_GATE_EVENT_HASH_MISMATCH:0"
    assert chain_summary["tamper_evident_indicator"] == "TAMPER_EVIDENT"


def test_write_outputs_includes_evidence_pack_when_requested(tmp_path: Path) -> None:
    _dashboard_fixture(tmp_path)
    state = build_demo_state(root=tmp_path, timestamp=TIMESTAMP)
    audit_output = tmp_path / "artifacts" / "governance-demo-audit.json"
    html_output = tmp_path / "artifacts" / "governance-demo.html"
    screenshot_output = tmp_path / "artifacts" / "governance-demo-screenshot.svg"
    pack_dir = tmp_path / "artifacts" / "governance-demo-evidence-pack"

    write_outputs(state, audit_output, html_output, screenshot_output, pack_dir)

    assert (pack_dir / "gate_history.json").is_file()
    assert (pack_dir / "chain_summary.json").is_file()


def test_invalid_dashboard_audit_schema_is_rejected() -> None:
    with pytest.raises(DemoValidationError, match="GOVERNANCE_DEMO_DASHBOARD_AUDIT_INVALID"):
        validate_dashboard_audit([])
