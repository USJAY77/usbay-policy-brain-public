from __future__ import annotations

import json
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "pb020_evidence_freshness_validation.py"


def _write_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _run(
    pb016: Path,
    pb017: Path,
    pb018: Path,
    pb019: Path,
    output: Path,
    max_age_hours: float = 168,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [
            sys.executable,
            str(SCRIPT),
            str(pb016),
            str(pb017),
            str(pb018),
            str(pb019),
            str(output),
            "--max-age-hours",
            str(max_age_hours),
        ],
        cwd=ROOT,
        text=True,
        capture_output=True,
    )


def _timestamp(hours_ago: int = 0) -> str:
    value = datetime.now(timezone.utc) - timedelta(hours=hours_ago)
    return value.isoformat().replace("+00:00", "Z")


def _artifact(schema: str, decision: str = "VERIFIED", generated_at: str | None = None) -> dict:
    return {
        "schema": schema,
        "decision": decision,
        "fail_closed": decision != "VERIFIED",
        "errors": [] if decision == "VERIFIED" else ["BLOCKED_FOR_TEST"],
        "generated_at": generated_at or _timestamp(),
    }


def _write_inputs(
    root: Path,
    generated_at: str | None = None,
    pb016_decision: str = "VERIFIED",
    pb018_decision: str = "VERIFIED",
) -> tuple[Path, Path, Path, Path]:
    pb016 = root / "pb016"
    pb017 = root / "pb017"
    pb018 = root / "pb018"
    pb019 = root / "pb019"
    artifacts = {
        pb016: {
            "pb016_governance_improvement_plan.json": ("usbay.pb016.governance_improvement_plan.v1", pb016_decision),
            "pb016_governance_priority_matrix.json": ("usbay.pb016.governance_priority_matrix.v1", pb016_decision),
            "pb016_governance_roadmap.json": ("usbay.pb016.governance_roadmap.v1", pb016_decision),
            "pb016_governance_action_register.json": ("usbay.pb016.governance_action_register.v1", pb016_decision),
        },
        pb017: {
            "pb017_governance_action_tracker.json": ("usbay.pb017.governance_action_tracker.v1", "VERIFIED"),
            "pb017_governance_progress_report.json": ("usbay.pb017.governance_progress_report.v1", "VERIFIED"),
            "pb017_governance_completion_report.json": ("usbay.pb017.governance_completion_report.v1", "VERIFIED"),
            "pb017_governance_status_dashboard.json": ("usbay.pb017.governance_status_dashboard.v1", "VERIFIED"),
        },
        pb018: {
            "pb018_agent_governance_certificate.json": ("usbay.pb018.agent_governance_certificate.v1", pb018_decision),
            "pb018_agent_risk_assessment.json": ("usbay.pb018.agent_risk_assessment.v1", pb018_decision),
            "pb018_agent_scorecard.json": ("usbay.pb018.agent_scorecard.v1", pb018_decision),
            "pb018_agent_attestation.json": ("usbay.pb018.agent_attestation.v1", pb018_decision),
        },
        pb019: {
            "pb019_certification_failure_report.json": ("usbay.pb019.certification_failure_report.v1", "VERIFIED"),
            "pb019_certification_gap_report.json": ("usbay.pb019.certification_gap_report.v1", "VERIFIED"),
            "pb019_required_actions.json": ("usbay.pb019.required_actions.v1", "VERIFIED"),
            "pb019_certification_explanation.json": ("usbay.pb019.certification_explanation.v1", "VERIFIED"),
        },
    }
    for directory, files in artifacts.items():
        for filename, (schema, decision) in files.items():
            payload = _artifact(schema, decision=decision, generated_at=generated_at)
            if filename == "pb017_governance_status_dashboard.json":
                payload["pb016_decision"] = pb016_decision
            if filename == "pb018_agent_governance_certificate.json":
                payload["certificate_status"] = decision
            _write_json(directory / filename, payload)
    return pb016, pb017, pb018, pb019


def test_freshness_reports_generated_for_aligned_fresh_artifacts(tmp_path: Path) -> None:
    pb016, pb017, pb018, pb019 = _write_inputs(tmp_path / "inputs")
    output = tmp_path / "pb020"

    completed = _run(pb016, pb017, pb018, pb019, output)

    assert completed.returncode == 0, completed.stdout + completed.stderr
    freshness = json.loads((output / "pb020_freshness_report.json").read_text(encoding="utf-8"))
    staleness = json.loads((output / "pb020_staleness_report.json").read_text(encoding="utf-8"))
    version = json.loads((output / "pb020_version_alignment_report.json").read_text(encoding="utf-8"))
    scorecard = json.loads((output / "pb020_evidence_freshness_scorecard.json").read_text(encoding="utf-8"))
    assert freshness["fresh_artifacts"] == 12
    assert freshness["applicability"][0]["status"] == "NOT_APPLICABLE_NO_FAILURE_TO_EXPLAIN"
    assert staleness["stale_artifact_count"] == 0
    assert staleness["pb019_requirement"] == "NOT_APPLICABLE_NO_FAILURE_TO_EXPLAIN"
    assert version["version_mismatches"] == 0
    assert scorecard["freshness_score"] == 100
    assert scorecard["pb019_requirement"] == "NOT_APPLICABLE_NO_FAILURE_TO_EXPLAIN"


def test_pb019_not_applicable_when_pb018_verified_without_failure(tmp_path: Path) -> None:
    pb016, pb017, pb018, pb019 = _write_inputs(tmp_path / "inputs")
    for path in pb019.glob("*.json"):
        path.unlink()
    output = tmp_path / "pb020"

    completed = _run(pb016, pb017, pb018, pb019, output)

    assert completed.returncode == 0, completed.stdout + completed.stderr
    freshness = json.loads((output / "pb020_freshness_report.json").read_text(encoding="utf-8"))
    scorecard = json.loads((output / "pb020_evidence_freshness_scorecard.json").read_text(encoding="utf-8"))
    assert freshness["applicability"] == [
        {
            "scope": "pb019",
            "status": "NOT_APPLICABLE_NO_FAILURE_TO_EXPLAIN",
            "reason": "PB-018 certification is VERIFIED with no failure to explain.",
            "pb018_decision": "VERIFIED",
        }
    ]
    assert scorecard["pb019_requirement"] == "NOT_APPLICABLE_NO_FAILURE_TO_EXPLAIN"


def test_pb019_remains_required_when_pb018_has_failure(tmp_path: Path) -> None:
    pb016, pb017, pb018, pb019 = _write_inputs(tmp_path / "inputs", pb018_decision="BLOCKED")
    for path in pb019.glob("*.json"):
        path.unlink()
    output = tmp_path / "pb020"

    completed = _run(pb016, pb017, pb018, pb019, output)

    assert completed.returncode == 1
    assert "PB020_GOVERNANCE_EVIDENCE_MISSING:pb019/pb019_certification_failure_report.json" in completed.stdout
    assert "PB020_CERTIFICATION_RESULT_UNTRUSTED" in completed.stdout


def test_stale_evidence_fails_closed(tmp_path: Path) -> None:
    pb016, pb017, pb018, pb019 = _write_inputs(tmp_path / "inputs", generated_at=_timestamp(hours_ago=200))
    output = tmp_path / "pb020"

    completed = _run(pb016, pb017, pb018, pb019, output, max_age_hours=24)

    assert completed.returncode == 1
    assert "PB020_STALE_MATURITY_REPORT:pb016/pb016_governance_improvement_plan.json" in completed.stdout
    assert "PB020_STALE_CERTIFICATION_RESULT:pb018/pb018_agent_governance_certificate.json" in completed.stdout
    staleness = json.loads((output / "pb020_staleness_report.json").read_text(encoding="utf-8"))
    assert staleness["stale_artifact_count"] == 12
    assert staleness["pb019_requirement"] == "NOT_APPLICABLE_NO_FAILURE_TO_EXPLAIN"


def test_version_mismatch_fails_closed(tmp_path: Path) -> None:
    pb016, pb017, pb018, pb019 = _write_inputs(tmp_path / "inputs")
    payload = json.loads((pb018 / "pb018_agent_scorecard.json").read_text(encoding="utf-8"))
    payload["schema"] = "usbay.pb018.agent_scorecard.v2"
    _write_json(pb018 / "pb018_agent_scorecard.json", payload)
    output = tmp_path / "pb020"

    completed = _run(pb016, pb017, pb018, pb019, output)

    assert completed.returncode == 1
    assert "PB020_GOVERNANCE_VERSION_MISMATCH:pb018/pb018_agent_scorecard.json" in completed.stdout
    version = json.loads((output / "pb020_version_alignment_report.json").read_text(encoding="utf-8"))
    assert version["governance_version_mismatch_detected"] is True


def test_unsupported_governance_artifact_fails_closed_when_pb019_required(tmp_path: Path) -> None:
    pb016, pb017, pb018, pb019 = _write_inputs(tmp_path / "inputs", pb018_decision="BLOCKED")
    _write_json(pb019 / "unexpected.json", {"generated_at": _timestamp()})
    output = tmp_path / "pb020"

    completed = _run(pb016, pb017, pb018, pb019, output)

    assert completed.returncode == 1
    assert "PB020_UNSUPPORTED_GOVERNANCE_ARTIFACT:pb019/unexpected.json" in completed.stdout


def test_blocked_maturity_and_certification_are_untrusted(tmp_path: Path) -> None:
    pb016, pb017, pb018, pb019 = _write_inputs(
        tmp_path / "inputs",
        pb016_decision="BLOCKED",
        pb018_decision="BLOCKED",
    )
    output = tmp_path / "pb020"

    completed = _run(pb016, pb017, pb018, pb019, output)

    assert completed.returncode == 1
    assert "PB020_MATURITY_REPORT_UNTRUSTED" in completed.stdout
    assert "PB020_CERTIFICATION_RESULT_UNTRUSTED" in completed.stdout
    scorecard = json.loads((output / "pb020_evidence_freshness_scorecard.json").read_text(encoding="utf-8"))
    assert scorecard["maturity_report_trusted"] is False
    assert scorecard["certification_result_trusted"] is False
