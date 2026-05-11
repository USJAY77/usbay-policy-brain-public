from __future__ import annotations

import subprocess
from pathlib import Path

from security.deployment_attestation import RuntimeProvenanceAuthority
from tests.provenance_helpers import install_runtime_authority


FORBIDDEN_TEST_PATTERNS = (
    "install_valid_test_provenance",
    "valid_test_provenance_context",
    '"runtime_provenance_context",',
    'Path("governance_release.json")',
    "Path('governance_release.json')",
    'open("governance_release.json"',
    "open('governance_release.json'",
    "provenance_context=install_runtime_authority",
    "runtime-context-only",
    "sequence-context-only",
    "no-git-runtime-context",
)

FORBIDDEN_RUNTIME_LINEAGE_PATTERNS = (
    "GITHUB_SHA",
    "GITHUB_HEAD_SHA",
    "GITHUB_BASE_SHA",
    "release_commit=",
    '"1" * 40',
    '"d" * 40',
)

RUNTIME_LINEAGE_TEST_PATHS = (
    Path("tests/test_live_pilot_v1.py"),
    Path("tests/test_simulation_governance.py"),
    Path("tests/test_tenant_audit_package.py"),
    Path("scripts/verify_live_pilot_v1.py"),
)


def _test_python_files() -> list[Path]:
    return sorted(Path("tests").glob("test_*.py")) + [Path("scripts/verify_live_pilot_v1.py")]


def test_runtime_authority_helper_installs_immutable_authority(tmp_path, monkeypatch) -> None:
    authority = install_runtime_authority(monkeypatch, tmp_path)

    assert isinstance(authority, RuntimeProvenanceAuthority)
    assert authority.context_dict()["release_lineage"] is True
    diagnostics_dir = tmp_path / "runtime_authority_diagnostics"
    assert (diagnostics_dir / "test_runtime_authority_identity.json").is_file()
    assert (diagnostics_dir / "test_authority_lineage_summary.json").is_file()
    assert (diagnostics_dir / "test_lineage_sync_report.json").is_file()
    assert (diagnostics_dir / "expected_vs_actual_commit.json").is_file()
    assert (diagnostics_dir / "authority_lineage_resolution.json").is_file()
    assert (diagnostics_dir / "generated_manifest_path.json").is_file()
    assert (diagnostics_dir / "manifest_generation_audit.json").is_file()


def test_tests_do_not_use_legacy_loose_provenance_injection() -> None:
    findings: list[str] = []
    for path in _test_python_files():
        text = path.read_text(encoding="utf-8")
        for pattern in FORBIDDEN_TEST_PATTERNS:
            if path.name == "test_runtime_authority_injection.py":
                continue
            if pattern in text:
                findings.append(f"{path}:{pattern}")

    assert findings == []


def test_repo_root_governance_release_manifest_is_not_tracked() -> None:
    tracked = subprocess.run(
        ["git", "ls-files", "--error-unmatch", "governance_release.json"],
        text=True,
        capture_output=True,
        check=False,
    )
    ignored = subprocess.run(
        ["git", "check-ignore", "governance_release.json"],
        text=True,
        capture_output=True,
        check=False,
    )

    assert tracked.returncode != 0
    assert ignored.returncode == 0


def test_runtime_lineage_tests_do_not_inject_manual_ci_commit_state() -> None:
    findings: list[str] = []
    for path in RUNTIME_LINEAGE_TEST_PATHS:
        text = path.read_text(encoding="utf-8")
        for pattern in FORBIDDEN_RUNTIME_LINEAGE_PATTERNS:
            if pattern in text:
                findings.append(f"{path}:{pattern}")

    assert findings == []
