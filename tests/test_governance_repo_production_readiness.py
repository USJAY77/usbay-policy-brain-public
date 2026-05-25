from __future__ import annotations

import json
from pathlib import Path

import governance.repo_production_readiness as readiness
from governance.repo_production_readiness import (
    REPO_BLOCKED,
    REPO_PRODUCTION_READY,
    REPO_READINESS_ERROR_CODES,
    REPO_REVIEW_REQUIRED,
    RepoProductionReadinessError,
    assert_repo_readiness_safe,
    explain_repo_readiness,
    load_repo_readiness_error_registry,
    repo_readiness_summary,
    scan_repo_production_readiness,
)


ROOT = Path(__file__).resolve().parents[1]


def _write_ready_repo(root: Path) -> None:
    (root / ".git").mkdir()
    (root / ".github" / "workflows").mkdir(parents=True)
    (root / ".github" / "CODEOWNERS").write_text("* @usbay/security\n", encoding="utf-8")
    (root / "LICENSE").write_text("MIT License\nPermission is hereby granted...\n", encoding="utf-8")
    (root / "requirements-ci.txt").write_text(
        "pytest==8.3.5 --hash=sha256:" + "a" * 64 + "\n",
        encoding="utf-8",
    )
    (root / ".github" / "workflows" / "ci.yml").write_text(
        "name: ci\npermissions:\n  contents: read\njobs:\n  test:\n    steps:\n      - uses: actions/checkout@" + "a" * 40 + "\n",
        encoding="utf-8",
    )
    (root / "tests").mkdir()
    (root / "tests" / "test_smoke.py").write_text("def test_smoke():\n    assert True\n", encoding="utf-8")
    (root / "scripts").mkdir()
    (root / "scripts" / "verify_production_readiness.py").write_text("print('PRODUCTION_READINESS=true')\n", encoding="utf-8")
    (root / "audit").mkdir()
    (root / "audit" / "evidence.json").write_text("{}\n", encoding="utf-8")
    (root / "governance").mkdir()
    (root / "governance" / "runtime_parity.py").write_text("RUNTIME_PARITY_SCHEMA='test'\n", encoding="utf-8")


def test_missing_license_blocks_production_ready_verdict(tmp_path: Path) -> None:
    _write_ready_repo(tmp_path)
    (tmp_path / "LICENSE").unlink()

    result = scan_repo_production_readiness(tmp_path, timestamp_utc="2026-05-17T00:00:00Z")

    assert result.verdict == REPO_REVIEW_REQUIRED
    assert "MISSING_LICENSE" in result.reason_codes
    assert "HUMAN_REVIEW_REQUIRED" in result.reason_codes


def test_workflow_permission_widening_blocks(tmp_path: Path) -> None:
    _write_ready_repo(tmp_path)
    (tmp_path / ".github" / "workflows" / "ci.yml").write_text("permissions: write-all\n", encoding="utf-8")

    result = scan_repo_production_readiness(tmp_path)

    assert result.verdict == REPO_BLOCKED
    assert "WORKFLOW_PERMISSION_WIDENING" in result.reason_codes


def test_read_all_permission_is_blocked(tmp_path: Path) -> None:
    _write_ready_repo(tmp_path)
    (tmp_path / ".github" / "workflows" / "ci.yml").write_text("permissions: read-all\n", encoding="utf-8")

    result = scan_repo_production_readiness(tmp_path)

    assert result.verdict == REPO_BLOCKED
    assert "READ_ALL_PERMISSION_BLOCKED" in result.reason_codes
    assert "WORKFLOW_PERMISSION_TOO_BROAD" in result.reason_codes


def test_write_all_permission_is_blocked(tmp_path: Path) -> None:
    _write_ready_repo(tmp_path)
    (tmp_path / ".github" / "workflows" / "ci.yml").write_text("permissions: write-all\n", encoding="utf-8")

    result = scan_repo_production_readiness(tmp_path)

    assert result.verdict == REPO_BLOCKED
    assert "WRITE_ALL_PERMISSION_BLOCKED" in result.reason_codes
    assert "WORKFLOW_PERMISSION_TOO_BROAD" in result.reason_codes


def test_contents_read_permission_passes_permission_gate(tmp_path: Path) -> None:
    _write_ready_repo(tmp_path)

    result = scan_repo_production_readiness(tmp_path)

    assert "LEAST_PRIVILEGE_ENFORCED" in result.reason_codes
    assert "WORKFLOW_PERMISSION_SCOPE_APPROVED" in result.reason_codes
    assert "READ_ALL_PERMISSION_BLOCKED" not in result.reason_codes
    assert "IMPLICIT_PERMISSION_WIDENING" not in result.reason_codes


def test_missing_permissions_blocked(tmp_path: Path) -> None:
    _write_ready_repo(tmp_path)
    (tmp_path / ".github" / "workflows" / "ci.yml").write_text(
        "name: ci\njobs:\n  test:\n    steps:\n      - uses: actions/checkout@" + "a" * 40 + "\n",
        encoding="utf-8",
    )

    result = scan_repo_production_readiness(tmp_path)

    assert result.verdict == REPO_BLOCKED
    assert "IMPLICIT_PERMISSION_WIDENING" in result.reason_codes


def test_scoped_pr_write_passes_only_when_workflow_needs_it(tmp_path: Path) -> None:
    _write_ready_repo(tmp_path)
    workflow = tmp_path / ".github" / "workflows" / "dependabot-governed-automerge.yml"
    (tmp_path / ".github" / "workflows" / "ci.yml").unlink()
    workflow.write_text(
        "permissions:\n  contents: read\n  pull-requests: write\n  issues: write\njobs:\n  x:\n    steps: []\n",
        encoding="utf-8",
    )

    result = scan_repo_production_readiness(tmp_path)

    assert "UNNECESSARY_WRITE_SCOPE" not in result.reason_codes
    assert "WORKFLOW_PERMISSION_WIDENING" not in result.reason_codes
    assert "WORKFLOW_PERMISSION_SCOPE_APPROVED" in result.reason_codes


def test_unjustified_write_scope_fails_review(tmp_path: Path) -> None:
    _write_ready_repo(tmp_path)
    (tmp_path / ".github" / "workflows" / "ci.yml").write_text(
        "permissions:\n  contents: read\n  pull-requests: write\n",
        encoding="utf-8",
    )

    result = scan_repo_production_readiness(tmp_path)

    assert result.verdict == REPO_BLOCKED
    assert "UNNECESSARY_WRITE_SCOPE" in result.reason_codes
    assert "WORKFLOW_PERMISSION_WIDENING" in result.reason_codes


def test_unknown_permission_scope_blocks(tmp_path: Path) -> None:
    _write_ready_repo(tmp_path)
    (tmp_path / ".github" / "workflows" / "ci.yml").write_text(
        "permissions:\n  contents: read\n  quantum-admin: read\njobs:\n  test:\n    steps: []\n",
        encoding="utf-8",
    )

    result = scan_repo_production_readiness(tmp_path)

    assert result.verdict == REPO_BLOCKED
    assert "WORKFLOW_STRUCTURE_UNKNOWN" in result.reason_codes
    assert result.audit["workflow_manifests"][0]["permission_graph"]["final_governance_verdict"] == "BLOCK"


def test_yaml_anchors_fail_closed(tmp_path: Path) -> None:
    _write_ready_repo(tmp_path)
    (tmp_path / ".github" / "workflows" / "ci.yml").write_text(
        "permissions: &default_permissions\n  contents: read\njobs:\n  test:\n    steps: []\n",
        encoding="utf-8",
    )

    result = scan_repo_production_readiness(tmp_path)

    assert "YAML_STRUCTURE_UNSAFE" in result.reason_codes
    assert "WORKFLOW_CAPABILITY_UNCLEAR" in result.reason_codes


def test_yaml_aliases_fail_closed(tmp_path: Path) -> None:
    _write_ready_repo(tmp_path)
    (tmp_path / ".github" / "workflows" / "ci.yml").write_text(
        "x-permissions: &perms\n  contents: write\npermissions: *perms\njobs:\n  test:\n    steps: []\n",
        encoding="utf-8",
    )

    result = scan_repo_production_readiness(tmp_path)

    assert "YAML_STRUCTURE_UNSAFE" in result.reason_codes


def test_nested_job_permissions_are_structurally_detected(tmp_path: Path) -> None:
    _write_ready_repo(tmp_path)
    (tmp_path / ".github" / "workflows" / "ci.yml").write_text(
        "permissions:\n  contents: read\njobs:\n  test:\n    permissions:\n      contents: write\n    steps: []\n",
        encoding="utf-8",
    )

    result = scan_repo_production_readiness(tmp_path)

    assert "UNNECESSARY_WRITE_SCOPE" in result.reason_codes
    assert result.audit["workflow_manifests"][0]["permission_graph"]["job_permissions"]["test"] == ["contents:write"]


def test_multiline_run_formatting_is_not_authoritative_permission_bypass(tmp_path: Path) -> None:
    _write_ready_repo(tmp_path)
    (tmp_path / ".github" / "workflows" / "ci.yml").write_text(
        "permissions:\n  contents: read\njobs:\n  test:\n    steps:\n      - run: |\n          npm ci --ignore-scripts\n",
        encoding="utf-8",
    )

    result = scan_repo_production_readiness(tmp_path)

    assert "YAML_STRUCTURE_UNSAFE" not in result.reason_codes
    assert "NPM_LIFECYCLE_SCRIPT_BLOCKED" not in result.reason_codes


def test_reusable_workflow_usage_fails_closed_without_fetching_remote(tmp_path: Path) -> None:
    _write_ready_repo(tmp_path)
    (tmp_path / ".github" / "workflows" / "ci.yml").write_text(
        "permissions:\n  contents: read\njobs:\n  call:\n    uses: org/repo/.github/workflows/reuse.yml@" + "a" * 40 + "\n",
        encoding="utf-8",
    )

    result = scan_repo_production_readiness(tmp_path)

    assert "WORKFLOW_STRUCTURE_UNKNOWN" in result.reason_codes


def test_workflow_call_is_reflected_in_capability_graph(tmp_path: Path) -> None:
    _write_ready_repo(tmp_path)
    (tmp_path / ".github" / "workflows" / "ci.yml").write_text(
        "on:\n  workflow_call:\npermissions:\n  contents: read\njobs:\n  test:\n    steps: []\n",
        encoding="utf-8",
    )

    result = scan_repo_production_readiness(tmp_path)

    assert "GOVERNANCE" in result.audit["workflow_manifests"][0]["capability_graph"]


def test_matrix_expansion_is_reflected_in_capability_graph(tmp_path: Path) -> None:
    _write_ready_repo(tmp_path)
    (tmp_path / ".github" / "workflows" / "ci.yml").write_text(
        "permissions:\n  contents: read\njobs:\n  test:\n    strategy:\n      matrix:\n        python: ['3.11']\n    steps: []\n",
        encoding="utf-8",
    )

    result = scan_repo_production_readiness(tmp_path)

    assert "GOVERNANCE" in result.audit["workflow_manifests"][0]["capability_graph"]


def test_malformed_yaml_permissions_fail_closed(tmp_path: Path) -> None:
    _write_ready_repo(tmp_path)
    (tmp_path / ".github" / "workflows" / "ci.yml").write_text(
        "permissions:\n  contents read\njobs:\n  test:\n    steps: []\n",
        encoding="utf-8",
    )

    result = scan_repo_production_readiness(tmp_path)

    assert "WORKFLOW_STRUCTURE_UNKNOWN" in result.reason_codes


def test_fake_multiline_permission_widening_fails_closed(tmp_path: Path) -> None:
    _write_ready_repo(tmp_path)
    (tmp_path / ".github" / "workflows" / "ci.yml").write_text(
        "permissions: >\n  write-all\njobs:\n  test:\n    steps: []\n",
        encoding="utf-8",
    )

    result = scan_repo_production_readiness(tmp_path)

    assert "YAML_STRUCTURE_UNSAFE" in result.reason_codes
    assert "WORKFLOW_CAPABILITY_UNCLEAR" in result.reason_codes


def test_workflow_manifest_contains_signed_hashable_governance_fields(tmp_path: Path) -> None:
    _write_ready_repo(tmp_path)

    result = scan_repo_production_readiness(tmp_path)
    manifest = result.audit["workflow_manifests"][0]

    assert manifest["schema"] == "usbay.governance_workflow_manifest.v1"
    assert manifest["parser_version"] == "semantic-workflow-parser.v1"
    assert manifest["semantic_schema_version"] == "usbay.semantic_workflow.v1"
    assert manifest["parser_mode"] == "SEMANTIC"
    assert manifest["workflow_fingerprint"]
    assert manifest["workflow_manifest_hash"]
    assert manifest["capability_graph_hash"]
    assert manifest["permission_graph"]["permission_model_fingerprint"]
    assert manifest["mutation_intent"] == []
    assert manifest["sha_pinning_status"] == "PASS"
    assert manifest["audit_hash"]


def test_regex_style_permission_bypass_attempt_is_not_authoritative(tmp_path: Path) -> None:
    _write_ready_repo(tmp_path)
    (tmp_path / ".github" / "workflows" / "ci.yml").write_text(
        "permissions:\n  contents: read\njobs:\n  test:\n    steps:\n      - run: |\n          echo 'permissions: write-all'\n",
        encoding="utf-8",
    )

    result = scan_repo_production_readiness(tmp_path)
    manifest = result.audit["workflow_manifests"][0]

    assert "WORKFLOW_PERMISSION_WIDENING" not in result.reason_codes
    assert manifest["permission_graph"]["detected_scopes"] == ["contents:read"]


def test_hidden_mutation_path_is_semantically_classified(tmp_path: Path) -> None:
    _write_ready_repo(tmp_path)
    (tmp_path / ".github" / "workflows" / "ci.yml").write_text(
        "permissions:\n  contents: read\njobs:\n  test:\n    steps:\n      - run: |\n          git push origin HEAD:main\n",
        encoding="utf-8",
    )

    result = scan_repo_production_readiness(tmp_path)
    manifest = result.audit["workflow_manifests"][0]

    assert "pushes_commits" in manifest["mutation_intent"]
    assert "mutates_branches_or_tags" in manifest["mutation_intent"]
    assert "MUTATING" in manifest["capability_graph"]


def test_semantic_parser_unavailable_fails_closed(tmp_path: Path, monkeypatch) -> None:
    _write_ready_repo(tmp_path)
    monkeypatch.setattr(readiness, "_parse_semantic_workflow", lambda _root, _rel: None)

    result = scan_repo_production_readiness(tmp_path)
    manifest = result.audit["workflow_manifests"][0]

    assert result.verdict == REPO_BLOCKED
    assert "SEMANTIC_WORKFLOW_ANALYSIS_UNAVAILABLE" in result.reason_codes
    assert "WORKFLOW_CAPABILITY_UNCLEAR" in result.reason_codes
    assert manifest["parser_mode"] == "UNAVAILABLE"
    assert manifest["permission_graph"]["final_governance_verdict"] == "BLOCK"


def test_unpinned_github_action_version_blocks(tmp_path: Path) -> None:
    _write_ready_repo(tmp_path)
    (tmp_path / ".github" / "workflows" / "ci.yml").write_text(
        "jobs:\n  test:\n    steps:\n      - uses: actions/checkout@main\n",
        encoding="utf-8",
    )

    result = scan_repo_production_readiness(tmp_path)

    assert result.verdict == REPO_BLOCKED
    assert "UNPINNED_ACTION_VERSION" in result.reason_codes
    assert "ACTION_NOT_SHA_PINNED" in result.reason_codes


def test_npm_install_scripts_are_blocked_unless_ignore_scripts(tmp_path: Path) -> None:
    _write_ready_repo(tmp_path)
    (tmp_path / ".github" / "workflows" / "ci.yml").write_text(
        "jobs:\n  test:\n    steps:\n      - run: npm ci\n",
        encoding="utf-8",
    )

    result = scan_repo_production_readiness(tmp_path)

    assert result.verdict == REPO_BLOCKED
    assert "NPM_LIFECYCLE_SCRIPT_BLOCKED" in result.reason_codes
    assert "DEPENDENCY_INSTALL_UNTRUSTED" in result.reason_codes


def test_npm_ignore_scripts_is_not_lifecycle_blocked(tmp_path: Path) -> None:
    _write_ready_repo(tmp_path)
    (tmp_path / ".github" / "workflows" / "ci.yml").write_text(
        "jobs:\n  test:\n    steps:\n      - run: npm ci --ignore-scripts\n",
        encoding="utf-8",
    )

    result = scan_repo_production_readiness(tmp_path)

    assert "NPM_LIFECYCLE_SCRIPT_BLOCKED" not in result.reason_codes


def test_pip_install_without_hash_lock_evidence_triggers_review(tmp_path: Path) -> None:
    _write_ready_repo(tmp_path)
    (tmp_path / ".github" / "workflows" / "ci.yml").write_text(
        "jobs:\n  test:\n    steps:\n      - run: python -m pip install -r requirements.txt\n",
        encoding="utf-8",
    )

    result = scan_repo_production_readiness(tmp_path)

    assert result.verdict == REPO_BLOCKED
    assert "PIP_HASH_LOCK_MISSING" in result.reason_codes
    assert "DEPENDENCY_INSTALL_UNTRUSTED" in result.reason_codes


def test_workflow_with_install_and_write_permissions_flags_token_exfiltration_risk(tmp_path: Path) -> None:
    _write_ready_repo(tmp_path)
    (tmp_path / ".github" / "workflows" / "ci.yml").write_text(
        "on:\n  pull_request:\npermissions:\n  contents: write\njobs:\n  test:\n    steps:\n      - run: npm ci\n",
        encoding="utf-8",
    )

    result = scan_repo_production_readiness(tmp_path)

    assert result.verdict == REPO_BLOCKED
    assert "CI_TOKEN_EXFILTRATION_RISK" in result.reason_codes


def test_env_presence_blocks(tmp_path: Path) -> None:
    _write_ready_repo(tmp_path)
    (tmp_path / ".env").write_text("SHOULD_NOT_BE_READ=secret-value\n", encoding="utf-8")

    result = scan_repo_production_readiness(tmp_path)

    assert result.verdict == REPO_BLOCKED
    assert "ENV_FILE_PRESENT_BLOCKED" in result.reason_codes


def test_secret_like_values_are_redacted_and_never_printed(tmp_path: Path) -> None:
    _write_ready_repo(tmp_path)
    secret = "api_key=abcdef1234567890abcdef1234567890"
    (tmp_path / "config.py").write_text(secret + "\n", encoding="utf-8")

    result = scan_repo_production_readiness(tmp_path)
    encoded = json.dumps(result.to_dict(), sort_keys=True)

    assert result.verdict == REPO_BLOCKED
    assert "SECRET_PATTERN_DETECTED" in result.reason_codes
    assert "abcdef1234567890" not in encoded
    assert "api_key=" not in encoded


def test_workflow_secret_exposure_risk_is_redacted(tmp_path: Path) -> None:
    _write_ready_repo(tmp_path)
    (tmp_path / ".github" / "workflows" / "ci.yml").write_text(
        "jobs:\n  test:\n    steps:\n      - run: echo ${GITHUB_TOKEN}\n",
        encoding="utf-8",
    )

    result = scan_repo_production_readiness(tmp_path)
    encoded = json.dumps(result.to_dict(), sort_keys=True)

    assert "SECRET_EXPOSURE_RISK" in result.reason_codes
    assert "GITHUB_TOKEN" not in encoded


def test_unsigned_artifacts_trigger_attestation_missing(tmp_path: Path) -> None:
    _write_ready_repo(tmp_path)
    (tmp_path / ".github" / "workflows" / "ci.yml").write_text(
        "jobs:\n  test:\n    steps:\n      - uses: actions/upload-artifact@" + "a" * 40 + "\n",
        encoding="utf-8",
    )

    result = scan_repo_production_readiness(tmp_path)

    assert "ARTIFACT_ATTESTATION_MISSING" in result.reason_codes


def test_missing_runtime_parity_forces_review(tmp_path: Path) -> None:
    _write_ready_repo(tmp_path)
    (tmp_path / "governance" / "runtime_parity.py").unlink()

    result = scan_repo_production_readiness(tmp_path)

    assert result.verdict == REPO_REVIEW_REQUIRED
    assert "RUNTIME_PARITY_MISSING" in result.reason_codes


def test_missing_audit_evidence_forces_review(tmp_path: Path) -> None:
    _write_ready_repo(tmp_path)
    (tmp_path / "audit" / "evidence.json").unlink()

    result = scan_repo_production_readiness(tmp_path)

    assert result.verdict == REPO_REVIEW_REQUIRED
    assert "AUDIT_EVIDENCE_MISSING" in result.reason_codes


def test_all_green_signals_produce_ready_with_governance(tmp_path: Path) -> None:
    _write_ready_repo(tmp_path)

    result = scan_repo_production_readiness(tmp_path, timestamp_utc="2026-05-17T00:00:00Z")

    assert result.valid is True
    assert result.verdict == REPO_PRODUCTION_READY
    assert result.reason_codes == (
        "LEAST_PRIVILEGE_ENFORCED",
        "REPO_READY_WITH_GOVERNANCE",
        "WORKFLOW_PERMISSION_SCOPE_APPROVED",
    )
    assert result.audit["audit_hash"]
    assert result.audit["dependency_manifest_fingerprints"]
    assert result.audit["workflow_fingerprints"]
    assert result.audit["classified_signals"]["maintainer_trust_signal"] == "PASS"
    assert result.audit["classified_signals"]["runtime_parity_signal"] == "PASS"


def test_no_raw_payloads_or_secrets_appear_in_audit_output(tmp_path: Path) -> None:
    _write_ready_repo(tmp_path)
    result = scan_repo_production_readiness(tmp_path)

    encoded = json.dumps(result.audit, sort_keys=True)

    assert "PRIVATE KEY" not in encoded
    assert "approval_contents" not in encoded
    assert str(tmp_path) not in encoded
    assert "requirements-ci.txt" not in encoded
    assert "ci.yml" not in encoded
    assert repo_readiness_summary(result)["audit_hash"] == result.audit["audit_hash"]


def test_error_registry_complete_and_explainable() -> None:
    registry = load_repo_readiness_error_registry(ROOT)

    assert set(REPO_READINESS_ERROR_CODES).issubset(registry)
    assert explain_repo_readiness(ROOT, "MISSING_LICENSE")["fail_closed_reason"]


def test_unsafe_diagnostics_fail_closed() -> None:
    try:
        assert_repo_readiness_safe({"diagnostics": {"raw_payload": "do-not-log"}})
    except RepoProductionReadinessError as exc:
        assert str(exc) == "REPO_READINESS_DIAGNOSTICS_UNSAFE"
    else:
        raise AssertionError("unsafe diagnostics were not rejected")
