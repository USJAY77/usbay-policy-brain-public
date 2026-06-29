from __future__ import annotations

from pathlib import Path

from tests.helpers.github_actions_policy import (
    approved_action_ref,
    evaluate_action_ref,
    load_github_actions_policy,
    workflow_action_refs,
)


ROOT = Path(__file__).resolve().parents[1]


def _workflow(name: str) -> str:
    return (ROOT / ".github" / "workflows" / name).read_text(encoding="utf-8")


def test_pytest_markers_are_registered() -> None:
    text = (ROOT / "pytest.ini").read_text(encoding="utf-8")

    for marker in ("critical", "governance", "regression", "slow", "dependency", "resilience", "stress"):
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
    assert "-m resilience" not in text
    assert "test_timestamp_queue_pressure.py" not in text
    assert "evidence/production-readiness-tests-validation.json" in text
    assert "scan-repo-production-readiness" in text
    assert "evidence/repo-production-readiness-validation.json" in text
    assert "python scripts/verify_production_readiness.py --lane fast-contract --event pull_request" in text
    assert "from fastapi.testclient import TestClient" in text
    assert "GOVERNANCE_FASTAPI_IMPORTS_VALID=true" in text
    assert "import requests" in text
    assert "GOVERNANCE_REQUESTS_IMPORTS_VALID=true" in text
    assert "Generate pull request governance validation evidence" in text
    assert "if: github.event_name == 'pull_request'" in text
    assert "generate_ci_evidence_manifest.py --unsigned-pr-validation --output evidence/governance-evidence-manifest.json" in text
    assert "generate_ci_evidence_manifest.py --verify-unsigned-pr-validation evidence/governance-evidence-manifest.json" in text
    pull_request_step = text.split("Generate pull request governance validation evidence", 1)[1].split("Generate signed governance evidence chain", 1)[0]
    assert "USBAY_CI_EVIDENCE_PRIVATE_KEY_PEM" not in pull_request_step
    assert "Generate signed governance evidence chain" in text
    assert "if: github.event_name != 'pull_request'" in text
    assert 'test -n "${USBAY_CI_EVIDENCE_PRIVATE_KEY_PEM}"' in text
    assert "generate_ci_evidence_manifest.py --output evidence/governance-evidence-manifest.json" in text
    assert "--verify evidence/governance-evidence-manifest.json" in text
    assert "TEMPORARY DIAGNOSTIC" not in text


def test_approved_github_actions_policy_passes_known_actions() -> None:
    policy = load_github_actions_policy()

    for action_name in policy["actions"]:
        action_ref = approved_action_ref(action_name, policy)
        decision = evaluate_action_ref(action_ref, context="manual_resilience", policy=policy)
        assert decision["decision"] == "PASS"


def test_unknown_github_actions_fail_closed() -> None:
    policy = load_github_actions_policy()
    unknown_ref = "actions/unapproved-example@v1"

    decision = evaluate_action_ref(unknown_ref, context="fast_pr", policy=policy)

    assert decision["decision"] == "FAIL_CLOSED"
    assert decision["reason"] == "UNKNOWN_GITHUB_ACTION"
    assert decision["silent_pass"] is False


def test_disallowed_github_action_versions_fail_closed() -> None:
    policy = load_github_actions_policy()
    action_name = "actions/upload-artifact"
    approved_ref = approved_action_ref(action_name, policy)
    disallowed_ref = f"{action_name}@v999"

    decision = evaluate_action_ref(disallowed_ref, context="fast_pr", policy=policy)

    assert approved_ref != disallowed_ref
    assert decision["decision"] == "FAIL_CLOSED"
    assert decision["reason"] == "UNAPPROVED_GITHUB_ACTION_VERSION"
    assert decision["silent_pass"] is False


def test_upload_artifact_uses_repository_approved_version_and_v7_fails_closed() -> None:
    policy = load_github_actions_policy()

    approved_decision = evaluate_action_ref("actions/upload-artifact@v4", context="fast_pr", policy=policy)
    v7_decision = evaluate_action_ref("actions/upload-artifact@v7", context="fast_pr", policy=policy)

    assert approved_action_ref("actions/upload-artifact", policy) == "actions/upload-artifact@v4"
    assert approved_decision["decision"] == "PASS"
    assert approved_decision["reason"] == "APPROVED_GITHUB_ACTION"
    assert v7_decision["decision"] == "FAIL_CLOSED"
    assert v7_decision["reason"] == "UNAPPROVED_GITHUB_ACTION_VERSION"
    assert v7_decision["silent_pass"] is False


def test_checkout_v6_is_policy_approved() -> None:
    policy = load_github_actions_policy()

    decision = evaluate_action_ref("actions/checkout@v6", context="fast_pr", policy=policy)

    assert approved_action_ref("actions/checkout", policy) == "actions/checkout@v6"
    assert decision["decision"] == "PASS"
    assert decision["reason"] == "APPROVED_GITHUB_ACTION"


def test_older_checkout_versions_fail_closed_after_v6_approval() -> None:
    policy = load_github_actions_policy()

    for disallowed_ref in ("actions/checkout@v4", "actions/checkout@v5"):
        decision = evaluate_action_ref(disallowed_ref, context="fast_pr", policy=policy)

        assert decision["decision"] == "FAIL_CLOSED"
        assert decision["reason"] == "UNAPPROVED_GITHUB_ACTION_VERSION"
        assert decision["silent_pass"] is False


def test_fast_pr_workflows_use_only_policy_approved_actions() -> None:
    policy = load_github_actions_policy()
    fast_pr_workflows = (
        "codex-autofix-ci.yml",
        "production-readiness.yml",
    )

    for workflow in fast_pr_workflows:
        for action_ref in workflow_action_refs(_workflow(workflow)):
            decision = evaluate_action_ref(action_ref, context="fast_pr", policy=policy)
            assert decision["decision"] == "PASS", f"{workflow}: {decision}"


def test_github_actions_policy_defaults_unknown_action_to_fail_closed() -> None:
    policy = load_github_actions_policy()

    assert policy["fail_closed_on_unknown_action"] is True


def test_governance_resilience_workflow_is_manual_or_scheduled_only() -> None:
    text = _workflow("governance-resilience.yml")
    policy = load_github_actions_policy()

    assert "workflow_dispatch" in text
    assert "schedule:" in text
    assert "pull_request" not in text
    assert "push:" not in text
    assert "python -m pytest -m resilience -vv" in text
    assert "--lane full_regression" in text
    assert "continue-on-error" not in text
    for action_ref in workflow_action_refs(text):
        decision = evaluate_action_ref(action_ref, context="manual_resilience", policy=policy)
        assert decision["decision"] == "PASS", decision


def test_full_regression_runs_on_schedule_and_manual_dispatch() -> None:
    text = _workflow("full-regression.yml")

    assert "timeout-minutes: 130" in text
    assert "schedule:" in text
    assert "workflow_dispatch" in text
    assert "--collect-only -q -m" in text
    assert "regression or slow" in text
    assert "scripts/run_full_regression_phases.py" in text
    assert "validation/full-regression-validation.json" in text
    assert "validation/full-regression/*.json" in text
    assert "scripts/run_bounded_validation.py" in text
    assert "--lane full_regression" in text
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
        "PHASE_TIMEOUT_compile_import",
        "PHASE_TIMEOUT_publication_runtime_tests",
        "PHASE_TIMEOUT_gateway_security_governance_tests",
        "PHASE_TIMEOUT_heavy_slow_tests",
    ):
        assert reason in text
    assert "partial_audit_preserved" in text


def test_dependabot_automerge_workflow_is_bounded_and_required_check_gated() -> None:
    text = _workflow("dependabot-governed-automerge.yml")

    assert "timeout-minutes: 10" in text
    assert "production-readiness" in text
    assert "audit-artifact-guard production-readiness governance-check policy-verification codeql-quality" in text
    assert "Determine governed Dependabot applicability" in text
    assert "HEAD_BRANCH: ${{ steps.pr.outputs.head_branch }}" in text
    assert '"${HEAD_BRANCH}" != dependabot/*' in text
    assert "DEPENDABOT_GOVERNED_AUTOMERGE_APPLICABLE=false" in text
    assert "NON_DEPENDABOT_WORKFLOW_RUN" in text
    assert "if: steps.applicability.outputs.applicable == 'true'" in text
    assert "PYTHONPATH: ${{ github.workspace }}" in text
    assert "scripts/governed_dependabot_pr_automation.py" in text
    assert "continue-on-error" not in text
    assert "--admin" not in text


def test_governance_action_workflows_pin_pythonpath_to_workspace() -> None:
    workflows = (
        "audit-artifact-guard.yml",
        "dependabot-governed-automerge.yml",
        "policy-verification.yml",
        "usbay-policy-validation.yml",
    )

    for workflow in workflows:
        assert "PYTHONPATH: ${{ github.workspace }}" in _workflow(workflow)


def test_branch_hygiene_workflow_is_bounded_and_uses_watchdog() -> None:
    text = _workflow("governed-branch-hygiene.yml")

    assert "delete: {}" in text
    assert "github.event_name == 'delete'" in text
    assert "--head \"${EVENT_REF}\"" in text
    assert "timeout-minutes: 10" in text
    assert "scripts/run_bounded_validation.py" in text
    assert "--lane fast_pr" in text
    assert "scripts/governed_branch_hygiene.py" in text
    assert "evidence/branch-hygiene-audit.json" in text
    assert "continue-on-error" not in text
