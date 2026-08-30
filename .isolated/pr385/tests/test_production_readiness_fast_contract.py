from __future__ import annotations

from pathlib import Path

import pytest

from scripts import verify_production_readiness as readiness


ROOT = Path(__file__).resolve().parents[1]

pytestmark = pytest.mark.critical


def test_fast_contract_lane_passes_on_repository() -> None:
    assert readiness.collect_fast_contract_failures(ROOT) == []


def test_fast_contract_cli_emits_only_fast_marker(capsys: pytest.CaptureFixture[str]) -> None:
    result = readiness.main(["--lane", "fast-contract", "--event", "pull_request", "--root", str(ROOT)])
    output = capsys.readouterr().out

    assert result == 0
    assert "lane_policy_hash=" in output
    assert "selected_lane=fast-contract" in output
    assert "lane_pr_blocking=true" in output
    assert "allowed_trigger=true" in output
    assert "PRODUCTION_READINESS_FAST_CONTRACT=true" in output
    assert "CANONICAL_GOVERNANCE_STATE_READY=true" in output
    assert "PRODUCTION_READINESS_HEAVY_SCAN=true" not in output
    assert "PRODUCTION_READINESS=true" not in output


def test_default_lane_is_bounded_fast_contract(capsys: pytest.CaptureFixture[str]) -> None:
    result = readiness.main(["--root", str(ROOT)])
    output = capsys.readouterr().out

    assert result == 0
    assert "PRODUCTION_READINESS_FAST_CONTRACT=true" in output
    assert "PRODUCTION_READINESS_HEAVY_SCAN=true" not in output


def test_unknown_lane_fails_closed(capsys: pytest.CaptureFixture[str]) -> None:
    result = readiness.main(["--lane", "unknown", "--event", "pull_request", "--root", str(ROOT)])
    output = capsys.readouterr().out

    assert result == 1
    assert "PRODUCTION_READINESS_LANE_UNKNOWN" in output
    assert "PRODUCTION_READINESS_HEAVY_SCAN=true" not in output


def test_heavy_scan_on_pull_request_is_blocked(capsys: pytest.CaptureFixture[str]) -> None:
    result = readiness.main(["--lane", "heavy-scan", "--event", "pull_request", "--root", str(ROOT)])
    output = capsys.readouterr().out

    assert result == 1
    assert "selected_lane=heavy-scan" in output
    assert "lane_pr_blocking=false" in output
    assert "allowed_trigger=false" in output
    assert "PRODUCTION_READINESS_LANE_TRIGGER_BLOCKED" in output
    assert "PRODUCTION_READINESS_HEAVY_SCAN=true" not in output


def test_heavy_scan_manual_scheduled_and_nightly_are_policy_allowed() -> None:
    for event in ("manual", "workflow_dispatch", "scheduled", "schedule", "nightly"):
        _policy, _policy_hash, evidence = readiness.validate_lane_policy(ROOT, "heavy-scan", event)
        assert evidence["selected_lane"] == "heavy-scan"
        assert evidence["lane_pr_blocking"] is False
        assert evidence["allowed_trigger"] is True


def test_fast_contract_detects_missing_canonical_registry(tmp_path: Path) -> None:
    governance = tmp_path / "governance"
    scripts = tmp_path / "scripts"
    workflows = tmp_path / ".github" / "workflows"
    governance.mkdir(parents=True)
    scripts.mkdir(parents=True)
    workflows.mkdir(parents=True)
    (governance / "canonical_governance_state.py").write_text("# missing registry\n", encoding="utf-8")
    (scripts / "governed_dependabot_pr_automation.py").write_text(
        "build_canonical_governance_state\n\"canonical_governance_state\"\nsignature_status\n"
        "dependabot[bot]\nhead_branch_not_dependabot\nrequired_check_not_success\n"
        "governance-review-required\nGoverned auto-merge approved.\n"
        "SAFE_DEPENDENCY_SCOPE_ALLOWED\nSAFE_WORKFLOW_VERSION_SCOPE_ALLOWED\n"
        "GOVERNANCE_SENSITIVE_SCOPE_BLOCKED\nRUNTIME_SENSITIVE_SCOPE_BLOCKED\n"
        "CRYPTOGRAPHIC_SENSITIVE_SCOPE_BLOCKED\nUNKNOWN_SCOPE_BLOCKED\n"
        "NON_DEPENDABOT_AUTHOR_BLOCKED\nNON_DEPENDABOT_BRANCH_BLOCKED\n"
        "PERMISSION_WIDENING_BLOCKED\nWORKFLOW_LOGIC_CHANGE_BLOCKED\n"
        "PR_NOT_FOUND\nPR_BRANCH_MISMATCH\nPR_SHA_MISMATCH\nHEAD_SHA_MISMATCH\n"
        "PR_NOT_OPEN\nPR_AUTHOR_INVALID\nPR_LINEAGE_INVALID\nMERGE_COMMIT_MISMATCH\n"
        "BASE_BRANCH_MISMATCH\nBRANCH_DELETED_BEFORE_RECONCILIATION\n"
        "WORKFLOW_EVENT_STALE\nWORKFLOW_EVENT_AMBIGUOUS\nMERGE_PROVENANCE_UNVERIFIED\n"
        "MERGE_LINEAGE_RECONCILED\nWORKFLOW_CONTEXT_UNTRUSTED\n"
        "REQUIRED_CHECK_NOT_PUBLISHED\nGOVERNANCE_LABEL_NOT_STATUS_CHECK\n"
        "GOVERNANCE_REVIEW_REQUIRED\nGOVERNANCE_REVIEW_MISSING\n"
        "\"pr\", \"merge\"\n--squash\n--delete-branch\n",
        encoding="utf-8",
    )
    (scripts / "governed_branch_hygiene.py").write_text(
        "build_canonical_governance_state\n\"canonical_governance_state\"\n"
        "BRANCH_ALREADY_MERGED\nRESTORED_AFTER_MERGE\nBRANCH_NOT_MERGED_BLOCKED\n"
        "OPEN_PR_BRANCH_BLOCKED\nPROTECTED_BRANCH_BLOCKED\nLINEAGE_UNCLEAR_BLOCKED\n"
        "VALID_NON_PROTECTED_BRANCH\nPROTECTED_BRANCH_REQUIRED\n"
        "BRANCH_PROTECTION_LOOKUP_FAILED\nMAIN_BRANCH_POLICY_REQUIRED\n"
        "GOVERNANCE_FEATURE_BRANCH_ALLOWED\nRULESET_ENFORCEMENT_VERIFIED\n"
        "RULESET_ENFORCEMENT_ACTIVE\n"
        "RULESET_ENFORCEMENT_MISSING\nRULESET_LOOKUP_FAILED\nMAIN_RULESET_VALIDATED\n"
        "REVIEW_AUTHORIZATION_REQUIRED\n"
        "DUAL_REVIEWER_AUTHORIZATION_VERIFIED\nDUAL_REVIEWER_AUTHORIZATION_MISSING\n"
        "MERGE_AUTHORIZATION_FINALIZED\nMERGE_AUTHORIZATION_NOT_FINALIZED\n"
        "governance_enforcement\nBRANCH_HYGIENE_GOVERNANCE_EVIDENCE_JSON\n"
        "BRANCH_HYGIENE_SELF_TEST=true\n_main_ruleset_state\n_reviewer_authorization_state\n"
        "audit_record_created_before_delete\n",
        encoding="utf-8",
    )
    (workflows / "dependabot-governed-automerge.yml").write_text(
        "audit-artifact-guard\nproduction-readiness\ngovernance-check\npolicy-verification\n"
        "codeql-quality\nscripts/resolve_ci_changed_files.py\n"
        "scripts/governed_dependabot_pr_automation.py\n--merge\n",
        encoding="utf-8",
    )
    (workflows / "governed-branch-hygiene.yml").write_text(
        "timeout-minutes: 10\nscripts/run_bounded_validation.py\n"
        "scripts/governed_branch_hygiene.py\n--self-test\n--delete\n"
        "evidence/branch-hygiene-validation.json\nevidence/branch-hygiene-audit.json\n",
        encoding="utf-8",
    )
    (workflows / "production-readiness.yml").write_text("--lane fast-contract\n", encoding="utf-8")

    failures = readiness.collect_fast_contract_failures(tmp_path)

    assert "CANONICAL_GOVERNANCE_STATE_ERROR_REGISTRY_MISSING" in failures


def test_fast_contract_workflow_does_not_bind_old_slow_tests() -> None:
    text = (ROOT / ".github" / "workflows" / "production-readiness.yml").read_text(encoding="utf-8")

    assert "python scripts/verify_production_readiness.py --lane fast-contract --event pull_request" in text
    assert "tests/test_production_readiness_fast_contract.py" in text
    assert "tests/test_production_readiness.py" not in text
    assert "continue-on-error" not in text
