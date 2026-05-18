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

    assert "timeout-minutes: 15" in text
    assert "--collect-only -q -m" in text
    assert "critical or governance or dependency" in text
    assert 'pytest -q -m "critical or governance or dependency"' in text
    assert "scripts/run_bounded_validation.py" in text
    assert "--lane fast_pr" in text
    assert "evidence/pr-critical-validation.json" in text
    assert "grep -E 'tests/.+::test_'" in text
    assert "python3 -m pytest -q\n" not in text


def test_production_readiness_pr_uses_guardrail_subset_and_canonical_evidence_flow() -> None:
    text = _workflow("production-readiness.yml")

    assert "timeout-minutes: 30" in text
    assert "--collect-only -q tests/test_production_readiness_fast_contract.py tests/test_ci_tiered_validation.py" in text
    assert "tests/test_production_readiness.py" not in text
    assert "pytest -q tests/test_production_readiness_fast_contract.py tests/test_ci_tiered_validation.py" in text
    assert "scripts/run_bounded_validation.py" in text
    assert "--lane fast_pr" in text
    assert "evidence/production-readiness-tests-validation.json" in text
    assert "scan-repo-production-readiness" in text
    assert "evidence/repo-production-readiness-validation.json" in text
    assert "python scripts/verify_production_readiness.py --lane fast-contract --event pull_request" in text
    assert "generate_ci_evidence_manifest.py --output evidence/governance-evidence-manifest.json" in text
    assert "--verify evidence/governance-evidence-manifest.json" in text
    assert "TEMPORARY DIAGNOSTIC" not in text


def test_full_regression_runs_on_schedule_and_manual_dispatch() -> None:
    text = _workflow("full-regression.yml")

    assert "timeout-minutes: 130" in text
    assert "schedule:" in text
    assert "workflow_dispatch" in text
    assert "--collect-only -q -m" in text
    assert "regression or slow" in text
    assert "python -m pytest -q" in text
    assert "scripts/run_bounded_validation.py" in text
    assert "--lane full_regression" in text
    assert "evidence/full-regression-validation.json" in text
    assert "grep -E 'tests/.+::test_'" in text


def test_pytest_failures_are_not_hidden_in_workflows() -> None:
    for workflow in (ROOT / ".github" / "workflows").glob("*.yml"):
        for line in workflow.read_text(encoding="utf-8").splitlines():
            if "pytest" in line:
                assert "|| true" not in line, f"pytest failure suppression in {workflow}: {line}"
                assert "continue-on-error" not in line, f"pytest continue-on-error in {workflow}: {line}"


def test_validation_timeout_reason_codes_are_declared() -> None:
    text = (ROOT / "scripts" / "run_bounded_validation.py").read_text(encoding="utf-8")

    for reason in (
        "VALIDATION_TIMEOUT_FAST_PR",
        "VALIDATION_TIMEOUT_DEPENDENCY",
        "VALIDATION_TIMEOUT_PRODUCTION_READINESS",
        "VALIDATION_TIMEOUT_FULL_REGRESSION",
    ):
        assert reason in text
    assert "partial_audit_preserved" in text


def test_dependabot_automerge_workflow_is_bounded_and_required_check_gated() -> None:
    text = _workflow("dependabot-governed-automerge.yml")

    assert "timeout-minutes: 10" in text
    assert "production-readiness" in text
    assert "audit-artifact-guard production-readiness governance-check policy-verification codeql-quality" in text
    assert "scripts/governed_dependabot_pr_automation.py" in text
    assert "continue-on-error" not in text


def test_branch_hygiene_workflow_is_bounded_and_uses_watchdog() -> None:
    text = _workflow("governed-branch-hygiene.yml")

    assert "timeout-minutes: 10" in text
    assert "scripts/run_bounded_validation.py" in text
    assert "--lane fast_pr" in text
    assert "scripts/governed_branch_hygiene.py" in text
    assert "evidence/branch-hygiene-audit.json" in text
    assert "continue-on-error" not in text
