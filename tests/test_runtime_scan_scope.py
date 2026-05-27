"""Tests for the runtime-vs-test scoping of the forbidden-runtime-file
validator.

Locks the contract:
  - Files under ``tests/`` (and other test-only directories) never
    appear as findings, even when they contain literal private-key
    marker strings (which legitimate negative-path tests do).
  - Real runtime private-key material outside the test scope still
    blocks startup fail-closed.
  - Governance helpers built on top of the validator
    (``validate_no_private_keys_in_repo``, ``private_key_files_in_repo``)
    inherit the same scope without semantic drift.

Does not modify fail-closed behaviour, private-key detection rules,
PEM classification semantics, runtime startup semantics, or
governance enforcement logic.
"""

from __future__ import annotations

from pathlib import Path

import pytest

import gateway.app as gateway_app
from security.policy_registry import PolicyRegistryError


PRIVATE_MARKER_TEXT = (
    "fixture-only-do-not-deploy\n"
    "-----BEGIN PRIVATE KEY-----\n"
    "MC4CAQAwBQYDK2VwBCIEIN3kZJ1+placeholder+not+a+real+secret==\n"
    "-----END PRIVATE KEY-----\n"
)


def _write(path: Path, body: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(body, encoding="utf-8")
    return path


def test_tests_directory_is_excluded_from_runtime_scan(tmp_path: Path) -> None:
    _write(tmp_path / "tests" / "test_negative_paths.py", PRIVATE_MARKER_TEXT)
    _write(tmp_path / "tests" / "fixtures" / "fake_private_key.txt", PRIVATE_MARKER_TEXT)

    findings = gateway_app.forbidden_runtime_file_findings(repo_root=tmp_path)
    assert findings == []
    assert gateway_app.validate_no_forbidden_runtime_files(repo_root=tmp_path) is True


def test_other_test_scopes_excluded(tmp_path: Path) -> None:
    for sub in ("test", "fixtures", "test_fixtures", "testdata", "test_data"):
        _write(tmp_path / sub / "fake.txt", PRIVATE_MARKER_TEXT)
    assert gateway_app.forbidden_runtime_file_findings(repo_root=tmp_path) == []


def test_runtime_private_key_still_blocks_fail_closed(tmp_path: Path) -> None:
    _write(tmp_path / "runtime" / "leaked_signing.key", PRIVATE_MARKER_TEXT)

    findings = gateway_app.forbidden_runtime_file_findings(repo_root=tmp_path)
    assert findings, "real runtime private key must be caught"
    rules = {entry["rule"] for entry in findings}
    # `.key` extension without public marker -> key_extension_not_public;
    # the same file also matches the private-key text marker on the
    # second pass. Either is sufficient evidence; assert at least one.
    assert (
        gateway_app.FORBIDDEN_RUNTIME_RULE_KEY_EXTENSION_NOT_PUBLIC in rules
        or gateway_app.FORBIDDEN_RUNTIME_RULE_PRIVATE_KEY_MARKER in rules
    )

    with pytest.raises(PolicyRegistryError, match="forbidden_runtime_file_present"):
        gateway_app.validate_no_forbidden_runtime_files(repo_root=tmp_path)


def test_runtime_private_pem_outside_tests_still_blocks(tmp_path: Path) -> None:
    _write(tmp_path / "keys_runtime" / "release_signing.pem", PRIVATE_MARKER_TEXT)
    with pytest.raises(PolicyRegistryError, match="forbidden_runtime_file_present"):
        gateway_app.validate_no_forbidden_runtime_files(repo_root=tmp_path)


def test_mixed_tree_only_flags_runtime_offender(tmp_path: Path) -> None:
    # Test fixture should be ignored, runtime offender should be flagged.
    _write(tmp_path / "tests" / "test_x.py", PRIVATE_MARKER_TEXT)
    _write(tmp_path / "runtime" / "evil.key", PRIVATE_MARKER_TEXT)

    findings = gateway_app.forbidden_runtime_file_findings(repo_root=tmp_path)
    paths = {entry["path"] for entry in findings}
    assert "runtime/evil.key" in paths
    assert not any(p.startswith("tests/") for p in paths)


def test_private_key_helper_inherits_scope(tmp_path: Path) -> None:
    # `private_key_files_in_repo` is a thin filter over
    # `forbidden_runtime_files_in_repo`; it must inherit the test
    # exclusion without weakening detection on the runtime surface.
    _write(tmp_path / "tests" / "test_x.py", PRIVATE_MARKER_TEXT)
    _write(tmp_path / "tmp" / "private_seed.bin", PRIVATE_MARKER_TEXT)

    private_offenders = gateway_app.private_key_files_in_repo(repo_root=tmp_path)
    assert "tmp/private_seed.bin" in private_offenders
    assert not any(p.startswith("tests/") for p in private_offenders)


def test_validator_passes_on_real_repo_tests_only_pollution() -> None:
    # Sanity: the live repo's own `tests/` directory contains files
    # with the literal "BEGIN PRIVATE KEY" marker (negative-path
    # tests). The validator must not flag any path under `tests/`.
    findings = gateway_app.forbidden_runtime_file_findings()
    flagged = [entry for entry in findings if entry["path"].startswith("tests/")]
    assert flagged == [], (
        f"test files wrongly flagged as runtime offenders: {flagged}"
    )
