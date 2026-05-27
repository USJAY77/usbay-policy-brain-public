"""Tests for auditable diagnostics emitted when
``validate_no_forbidden_runtime_files`` blocks startup.

Locks the observability contract:

  - The exact repo-relative offending path is logged.
  - The matched forbidden-rule identifier is logged.
  - File contents are never logged or surfaced in the exception.
  - Fail-closed startup blocking is preserved (PolicyRegistryError
    is raised with the historical ``forbidden_runtime_file_present``
    sentinel substring).

Does not modify enforcement logic, forbidden-file rules, replay
protection, deployment semantics, or fail-closed behaviour.
"""

from __future__ import annotations

import logging
from pathlib import Path

import pytest

import gateway.app as gateway_app
from security.policy_registry import PolicyRegistryError


SECRET_CONTENT_MARKER = "DO_NOT_LEAK_THIS_SECRET_PAYLOAD_42"


def _seed_forbidden_dotenv(repo_root: Path) -> Path:
    target = repo_root / ".env"
    target.write_text(f"API_TOKEN={SECRET_CONTENT_MARKER}\n", encoding="utf-8")
    return target


def test_findings_emit_path_and_rule(tmp_path: Path) -> None:
    _seed_forbidden_dotenv(tmp_path)
    findings = gateway_app.forbidden_runtime_file_findings(repo_root=tmp_path)
    assert findings, "validator must surface the offender"
    entry = findings[0]
    assert entry["path"] == ".env"
    assert entry["rule"] == gateway_app.FORBIDDEN_RUNTIME_RULE_DOTENV_FILE


def test_validator_blocks_and_logs_path_and_rule(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    _seed_forbidden_dotenv(tmp_path)
    caplog.set_level(logging.ERROR, logger="usbay.gateway.forbidden_runtime")

    with pytest.raises(PolicyRegistryError, match="forbidden_runtime_file_present"):
        gateway_app.validate_no_forbidden_runtime_files(repo_root=tmp_path)

    messages = [record.getMessage() for record in caplog.records]
    assert any("path=.env" in msg for msg in messages), messages
    assert any(
        f"rule={gateway_app.FORBIDDEN_RUNTIME_RULE_DOTENV_FILE}" in msg
        for msg in messages
    ), messages


def test_log_and_exception_do_not_leak_file_contents(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    _seed_forbidden_dotenv(tmp_path)
    caplog.set_level(logging.DEBUG, logger="usbay.gateway.forbidden_runtime")

    with pytest.raises(PolicyRegistryError) as excinfo:
        gateway_app.validate_no_forbidden_runtime_files(repo_root=tmp_path)

    for record in caplog.records:
        assert SECRET_CONTENT_MARKER not in record.getMessage()
    assert SECRET_CONTENT_MARKER not in str(excinfo.value)
    # Structured diagnostics on the exception carry only path + rule.
    findings = getattr(excinfo.value, "findings", None)
    assert findings is not None
    for entry in findings:
        assert set(entry.keys()) == {"path", "rule"}
        assert SECRET_CONTENT_MARKER not in entry["path"]
        assert SECRET_CONTENT_MARKER not in entry["rule"]


def test_startup_still_blocks_with_enriched_error(tmp_path: Path) -> None:
    _seed_forbidden_dotenv(tmp_path)

    with pytest.raises(PolicyRegistryError) as excinfo:
        gateway_app.validate_no_forbidden_runtime_files(repo_root=tmp_path)

    # Historical sentinel preserved for upstream matchers.
    assert str(excinfo.value).startswith("forbidden_runtime_file_present")
    diagnostics = getattr(excinfo.value, "diagnostics", None)
    assert diagnostics is not None
    assert diagnostics["count"] >= 1
    assert {"path": ".env", "rule": gateway_app.FORBIDDEN_RUNTIME_RULE_DOTENV_FILE} in diagnostics["findings"]


def test_clean_tree_passes(tmp_path: Path) -> None:
    # No forbidden artifacts -> validator returns True, emits no logs.
    assert gateway_app.validate_no_forbidden_runtime_files(repo_root=tmp_path) is True


def test_distinct_rules_for_different_offenders(tmp_path: Path) -> None:
    (tmp_path / ".env").write_text("X=1\n", encoding="utf-8")
    secrets_dir = tmp_path / "secrets"
    secrets_dir.mkdir()
    (secrets_dir / "anything.txt").write_text("placeholder\n", encoding="utf-8")
    tmp_dir = tmp_path / "tmp"
    tmp_dir.mkdir()
    (tmp_dir / "private.pem").write_text("placeholder\n", encoding="utf-8")

    findings = gateway_app.forbidden_runtime_file_findings(repo_root=tmp_path)
    rules = {entry["rule"] for entry in findings}
    paths = {entry["path"] for entry in findings}

    assert gateway_app.FORBIDDEN_RUNTIME_RULE_DOTENV_FILE in rules
    assert gateway_app.FORBIDDEN_RUNTIME_RULE_SECRETS_DIRECTORY in rules
    assert gateway_app.FORBIDDEN_RUNTIME_RULE_TMP_PRIVATE_ARTIFACT in rules
    assert ".env" in paths
    assert "secrets/anything.txt" in paths
    assert "tmp/private.pem" in paths
