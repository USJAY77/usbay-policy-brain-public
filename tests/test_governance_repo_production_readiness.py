from __future__ import annotations

import json
from pathlib import Path

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
        "name: ci\njobs:\n  test:\n    steps:\n      - uses: actions/checkout@" + "a" * 40 + "\n",
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


def test_unpinned_github_action_version_blocks(tmp_path: Path) -> None:
    _write_ready_repo(tmp_path)
    (tmp_path / ".github" / "workflows" / "ci.yml").write_text(
        "jobs:\n  test:\n    steps:\n      - uses: actions/checkout@main\n",
        encoding="utf-8",
    )

    result = scan_repo_production_readiness(tmp_path)

    assert result.verdict == REPO_BLOCKED
    assert "UNPINNED_ACTION_VERSION" in result.reason_codes


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
    assert result.reason_codes == ("REPO_READY_WITH_GOVERNANCE",)
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
