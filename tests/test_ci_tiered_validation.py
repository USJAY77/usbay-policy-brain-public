from __future__ import annotations

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def _workflow(name: str) -> str:
    return (ROOT / ".github" / "workflows" / name).read_text(encoding="utf-8")


def test_pytest_markers_are_registered() -> None:
    text = (ROOT / "pytest.ini").read_text(encoding="utf-8")

    for marker in ("critical", "governance", "regression", "slow", "dependency"):
        assert f"{marker}:" in text


def test_pr_workflow_runs_tiered_governance_subset_not_full_suite() -> None:
    text = _workflow("codex-autofix-ci.yml")

    assert '--collect-only -q -m "critical or governance or dependency"' in text
    assert 'pytest -q -m "critical or governance or dependency"' in text
    assert "grep -E 'tests/.+::test_'" in text
    assert "python3 -m pytest -q\n" not in text


def test_production_readiness_pr_uses_guardrail_subset_and_canonical_evidence_flow() -> None:
    text = _workflow("production-readiness.yml")

    assert '--collect-only -q -m "critical or dependency"' in text
    assert "tests/test_ci_tiered_validation.py tests/test_production_readiness.py" in text
    assert 'pytest -q -m "critical or dependency"' in text
    assert "python scripts/verify_production_readiness.py" in text
    assert "generate_ci_evidence_manifest.py --output evidence/governance-evidence-manifest.json" in text
    assert "--verify evidence/governance-evidence-manifest.json" in text
    assert "TEMPORARY DIAGNOSTIC" not in text


def test_full_regression_runs_on_schedule_and_manual_dispatch() -> None:
    text = _workflow("full-regression.yml")

    assert "schedule:" in text
    assert "workflow_dispatch" in text
    assert '--collect-only -q -m "regression or slow"' in text
    assert "python -m pytest -q" in text
    assert "grep -E 'tests/.+::test_'" in text


def test_pytest_failures_are_not_hidden_in_workflows() -> None:
    for workflow in (ROOT / ".github" / "workflows").glob("*.yml"):
        for line in workflow.read_text(encoding="utf-8").splitlines():
            if "pytest" in line:
                assert "|| true" not in line, f"pytest failure suppression in {workflow}: {line}"
                assert "continue-on-error" not in line, f"pytest continue-on-error in {workflow}: {line}"
