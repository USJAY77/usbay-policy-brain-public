from __future__ import annotations

from pathlib import Path

import pytest

from scripts import verify_production_readiness as readiness


ROOT = Path(__file__).resolve().parents[1]

pytestmark = pytest.mark.heavy


def test_heavy_scan_lane_is_explicit_and_non_default(capsys: pytest.CaptureFixture[str]) -> None:
    result = readiness.main(["--lane", "heavy-scan", "--event", "manual", "--root", str(ROOT)])
    output = capsys.readouterr().out

    assert result == 0
    assert "selected_lane=heavy-scan" in output
    assert "lane_pr_blocking=false" in output
    assert "PRODUCTION_READINESS_HEAVY_SCAN=true" in output
    assert "PRODUCTION_READINESS=true" in output
