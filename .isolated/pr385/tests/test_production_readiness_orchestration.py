from __future__ import annotations

from pathlib import Path

import pytest

from scripts import verify_production_readiness as readiness


ROOT = Path(__file__).resolve().parents[1]

pytestmark = pytest.mark.governance


def test_orchestration_lane_passes_on_repository() -> None:
    assert readiness.collect_orchestration_failures(ROOT) == []


def test_orchestration_cli_emits_timeout_governance_marker(capsys: pytest.CaptureFixture[str]) -> None:
    result = readiness.main(["--lane", "orchestration", "--event", "pull_request", "--root", str(ROOT)])
    output = capsys.readouterr().out

    assert result == 0
    assert "lane_policy_hash=" in output
    assert "selected_lane=orchestration" in output
    assert "PRODUCTION_READINESS_ORCHESTRATION=true" in output
    assert "VALIDATION_TIMEOUT_REPORTING_READY=true" in output
    assert "PRODUCTION_READINESS_HEAVY_SCAN=true" not in output


def test_orchestration_blocks_old_slow_test_path(tmp_path: Path) -> None:
    workflow = tmp_path / ".github" / "workflows" / "production-readiness.yml"
    workflow.parent.mkdir(parents=True)
    workflow.write_text(
        "python scripts/verify_production_readiness.py\n"
        "tests/test_production_readiness.py\n"
        "continue-on-error: true\n",
        encoding="utf-8",
    )
    script = tmp_path / readiness.BOUNDED_VALIDATION_SCRIPT
    script.parent.mkdir(parents=True)
    script.write_text(
        "VALIDATION_TIMEOUT_FAST_PR\n"
        "VALIDATION_TIMEOUT_DEPENDENCY\n"
        "VALIDATION_TIMEOUT_PRODUCTION_READINESS\n"
        "VALIDATION_TIMEOUT_FULL_REGRESSION\n"
        "partial_audit_preserved\n",
        encoding="utf-8",
    )

    failures = readiness.collect_orchestration_failures(tmp_path)

    assert "PRODUCTION_READINESS_OLD_SLOW_TEST_PATH_STILL_PR_BOUND" in failures
    assert "PRODUCTION_READINESS_UNBOUNDED_DEFAULT_LANE_USED" in failures
    assert "PRODUCTION_READINESS_CONTINUE_ON_ERROR_FORBIDDEN" in failures
