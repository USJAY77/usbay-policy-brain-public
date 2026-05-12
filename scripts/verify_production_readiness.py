#!/usr/bin/env python3
from __future__ import annotations

import argparse
import fnmatch
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import Iterable

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

MAX_HELPER_BYTES = 1_000_000
MAX_TRACKED_BYTES = 50_000_000
GENERATED_ARTIFACT_NAMES = {
    "generated_manifest_path.json",
    "manifest_generation_audit.json",
}
REQUIRED_DOCS = (
    "docs/usbay-production-readiness-checklist.md",
    "docs/usbay-governance-release-readiness-audit.md",
    "docs/provenance-helper-modularization.md",
    "docs/runtime-governance-health.md",
    "docs/runtime-provenance-authority.md",
    "docs/governance-architecture-boundaries.md",
    "docs/governance-dependency-map.md",
    "docs/governance-release-integrity.md",
    "docs/governance-operations-observability.md",
    "docs/governance-incident-response.md",
    "docs/governance-policy-pack-validation.md",
)
REQUIRED_CI_REQUIREMENTS = "requirements-ci.txt"
PRODUCTION_READINESS_WORKFLOW = ".github/workflows/production-readiness.yml"
CI_SBOM_SCRIPT = "scripts/generate_ci_dependency_sbom.py"
CI_SBOM_ARTIFACT_PATH = "sbom/production-readiness-ci-sbom.json"
CI_EVIDENCE_SCRIPT = "scripts/generate_ci_evidence_manifest.py"
CI_EVIDENCE_MANIFEST_PATH = "evidence/governance-evidence-manifest.json"
CI_EVIDENCE_TRUST_POLICY = "governance/ci_evidence_trust_policy.json"
CI_EVIDENCE_TRUST_POLICY_SIGNATURE = "governance/ci_evidence_trust_policy.sig"
CI_EVIDENCE_TRUST_POLICY_AUTHORITY = "governance/ci_evidence_trust_policy_authority.json"
CI_EVIDENCE_TRUST_POLICY_AUDIT = "governance/ci_evidence_trust_policy_audit.jsonl"
CI_GOVERNANCE_TIMESTAMP_DIR = "evidence/governance-timestamps"
CI_CHRONOLOGY_CONSENSUS_FILE = f"{CI_GOVERNANCE_TIMESTAMP_DIR}/chronology_consensus.json"
CI_CHRONOLOGY_CONSENSUS_AUDIT_FILE = f"{CI_GOVERNANCE_TIMESTAMP_DIR}/chronology_consensus_audit.jsonl"
CI_TRANSPARENCY_ANCHOR_FILE = f"{CI_GOVERNANCE_TIMESTAMP_DIR}/transparency_anchor.json"
CI_WITNESS_PROOFS_FILE = f"{CI_GOVERNANCE_TIMESTAMP_DIR}/witness_proofs.json"
CI_WITNESS_VERIFICATION_FILE = f"{CI_GOVERNANCE_TIMESTAMP_DIR}/witness_verification.json"
CI_WITNESS_AUDIT_FILE = f"{CI_GOVERNANCE_TIMESTAMP_DIR}/witness_audit.jsonl"
CI_WITNESS_TRUST_AUDIT_FILE = f"{CI_GOVERNANCE_TIMESTAMP_DIR}/witness_trust_audit.jsonl"
CI_WITNESS_REPUTATION_HISTORY_FILE = f"{CI_GOVERNANCE_TIMESTAMP_DIR}/witness_reputation_history.jsonl"
REQUIREMENT_LINE_RE = re.compile(r"^\s*([A-Za-z0-9_.-]+)==([A-Za-z0-9_.!+-]+)\s*\\?\s*$")
REQUIRED_CI_PACKAGES = frozenset({"pytest", "cryptography", "cffi", "pycparser"})
GOVERNANCE_CRYPTO_PACKAGES = frozenset({"cryptography", "cffi", "pycparser"})
SECRET_MARKERS = (
    "BEGIN " + "PRIVATE KEY",
    "BEGIN RSA " + "PRIVATE KEY",
    "BEGIN OPENSSH " + "PRIVATE KEY",
    "PRIVATE " + "KEY",
    "raw_secret",
    "approval_contents",
    "private_key",
    "USBAY_SECRET",
)


def run_git_ls_files(root: Path) -> list[str]:
    completed = subprocess.run(
        ["git", "-C", str(root), "ls-files"],
        text=True,
        capture_output=True,
        check=True,
    )
    return [line.strip() for line in completed.stdout.splitlines() if line.strip()]


def tracked_file_size(root: Path, tracked_path: str) -> int:
    path = root / tracked_path
    if not path.is_file():
        return 0
    return path.stat().st_size


def is_repo_root_governance_release(path: str) -> bool:
    return "/" not in path and fnmatch.fnmatch(path, "governance_release*.json")


def is_generated_artifact(path: str) -> bool:
    name = Path(path).name
    return name in GENERATED_ARTIFACT_NAMES or is_repo_root_governance_release(path)


def check_helper_size(root: Path) -> list[str]:
    helper = root / "tests" / "provenance_helpers.py"
    if not helper.is_file():
        return ["PROVENANCE_HELPER_MISSING"]
    if helper.stat().st_size >= MAX_HELPER_BYTES:
        return [f"PROVENANCE_HELPER_OVERSIZED:{helper.stat().st_size}"]
    return []


def check_tracked_file_sizes(root: Path, tracked_files: Iterable[str]) -> list[str]:
    failures: list[str] = []
    for tracked in tracked_files:
        size = tracked_file_size(root, tracked)
        if size > MAX_TRACKED_BYTES:
            failures.append(f"TRACKED_FILE_OVERSIZED:{tracked}:{size}")
    return failures


def check_tracked_generated_artifacts(tracked_files: Iterable[str]) -> list[str]:
    failures: list[str] = []
    for tracked in tracked_files:
        if is_repo_root_governance_release(tracked):
            failures.append(f"TRACKED_ROOT_GOVERNANCE_RELEASE:{tracked}")
        elif Path(tracked).name in GENERATED_ARTIFACT_NAMES:
            failures.append(f"TRACKED_GENERATED_MANIFEST_ARTIFACT:{tracked}")
    return failures


def check_required_docs(root: Path) -> list[str]:
    return [f"READINESS_DOC_MISSING:{doc}" for doc in REQUIRED_DOCS if not (root / doc).is_file()]


def _logical_requirement_lines(text: str) -> list[str]:
    lines: list[str] = []
    current = ""
    for raw in text.splitlines():
        stripped = raw.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if current:
            current += " " + stripped
        else:
            current = stripped
        if current.endswith("\\"):
            current = current[:-1].strip()
            continue
        lines.append(current)
        current = ""
    if current:
        lines.append(current)
    return lines


def parse_ci_dependency_lock(root: Path) -> tuple[list[dict[str, object]], list[str]]:
    failures: list[str] = []
    lock = root / REQUIRED_CI_REQUIREMENTS
    if not lock.is_file():
        return [], [f"CI_REQUIREMENTS_LOCK_MISSING:{REQUIRED_CI_REQUIREMENTS}"]
    requirement_lines = _logical_requirement_lines(lock.read_text(encoding="utf-8"))
    if not requirement_lines:
        return [], [f"CI_REQUIREMENTS_LOCK_EMPTY:{REQUIRED_CI_REQUIREMENTS}"]
    entries: list[dict[str, object]] = []
    for line in requirement_lines:
        requirement = line.split("--hash=", 1)[0].strip()
        match = REQUIREMENT_LINE_RE.match(requirement)
        if not match:
            failures.append(f"CI_REQUIREMENT_UNPINNED:{requirement}")
            name = requirement
            version = ""
        else:
            name = match.group(1)
            version = match.group(2)
        hashes = re.findall(r"--hash=sha256:([0-9a-f]{64})", line)
        if not hashes:
            failures.append(f"CI_REQUIREMENT_HASH_MISSING:{requirement}")
        entries.append(
            {
                "name": name,
                "version": version,
                "sha256_hashes": sorted(set(hashes)),
                "source_registry": "https://pypi.org/simple",
            }
        )
    return entries, failures


def check_ci_dependency_lock(root: Path) -> list[str]:
    entries, failures = parse_ci_dependency_lock(root)
    pinned_names = {str(entry["name"]).lower() for entry in entries if entry.get("version")}
    for package in sorted(REQUIRED_CI_PACKAGES):
        if package not in pinned_names:
            failures.append(f"CI_REQUIREMENT_REQUIRED_PACKAGE_MISSING:{package}")
    for package in sorted(GOVERNANCE_CRYPTO_PACKAGES):
        if package not in pinned_names:
            failures.append(f"CI_REQUIREMENT_GOVERNANCE_CRYPTO_MISSING:{package}")
    return failures


def check_workflow_dependency_bootstrap(root: Path) -> list[str]:
    workflow = root / PRODUCTION_READINESS_WORKFLOW
    if not workflow.is_file():
        return [f"PRODUCTION_READINESS_WORKFLOW_MISSING:{PRODUCTION_READINESS_WORKFLOW}"]
    text = workflow.read_text(encoding="utf-8")
    failures: list[str] = []
    if "actions/setup-python@v5" not in text:
        failures.append("WORKFLOW_PYTHON_SETUP_MISSING")
    if "requirements-ci.txt" not in text:
        failures.append("WORKFLOW_CI_REQUIREMENTS_MISSING")
    if "--require-hashes -r requirements-ci.txt" not in text:
        failures.append("WORKFLOW_REQUIRE_HASHES_MISSING")
    if "importlib.metadata.version('cryptography')" not in text and 'importlib.metadata.version("cryptography")' not in text:
        failures.append("WORKFLOW_CRYPTOGRAPHY_VERSION_AUDIT_MISSING")
    if "GOVERNANCE_CRYPTO_IMPORTS_VALID=true" not in text:
        failures.append("WORKFLOW_GOVERNANCE_CRYPTO_IMPORT_CHECK_MISSING")
    if CI_SBOM_SCRIPT not in text:
        failures.append("WORKFLOW_CI_SBOM_GENERATION_MISSING")
    if CI_SBOM_ARTIFACT_PATH not in text:
        failures.append("WORKFLOW_CI_SBOM_ARTIFACT_PATH_MISSING")
    if "actions/upload-artifact@v4" not in text:
        failures.append("WORKFLOW_CI_SBOM_UPLOAD_MISSING")
    if "production-readiness-ci-sbom" not in text:
        failures.append("WORKFLOW_CI_SBOM_ARTIFACT_UPLOAD_NAME_MISSING")
    if f"test -s {CI_SBOM_ARTIFACT_PATH}" not in text:
        failures.append("WORKFLOW_CI_SBOM_EXISTENCE_CHECK_MISSING")
    if CI_EVIDENCE_SCRIPT not in text:
        failures.append("WORKFLOW_CI_EVIDENCE_CHAIN_MISSING")
    if CI_EVIDENCE_MANIFEST_PATH not in text:
        failures.append("WORKFLOW_CI_EVIDENCE_MANIFEST_PATH_MISSING")
    if f"test -s {CI_EVIDENCE_MANIFEST_PATH}" not in text:
        failures.append("WORKFLOW_CI_EVIDENCE_EXISTENCE_CHECK_MISSING")
    if f"--verify {CI_EVIDENCE_MANIFEST_PATH}" not in text:
        failures.append("WORKFLOW_CI_EVIDENCE_VERIFY_MISSING")
    if "production-readiness-governance-evidence" not in text:
        failures.append("WORKFLOW_CI_EVIDENCE_ARTIFACT_UPLOAD_NAME_MISSING")
    if "USBAY_CI_EVIDENCE_PRIVATE_KEY_PEM" not in text:
        failures.append("WORKFLOW_CI_EVIDENCE_PRIVATE_KEY_MISSING")
    if "secrets.USBAY_CI_EVIDENCE_PRIVATE_KEY_PEM" not in text:
        failures.append("WORKFLOW_CI_EVIDENCE_PRIVATE_KEY_SECRET_MISSING")
    if "USBAY_CI_EVIDENCE_SIGNER_ID" not in text:
        failures.append("WORKFLOW_CI_EVIDENCE_SIGNER_ID_MISSING")
    if CI_EVIDENCE_TRUST_POLICY not in text:
        failures.append("WORKFLOW_CI_EVIDENCE_TRUST_POLICY_MISSING")
    if "--timestamp-output evidence/governance-timestamps" not in text:
        failures.append("WORKFLOW_CI_GOVERNANCE_TIMESTAMP_MISSING")
    if "--verify-timestamps evidence/governance-timestamps" not in text:
        failures.append("WORKFLOW_CI_GOVERNANCE_TIMESTAMP_VERIFY_MISSING")
    if f"test -s {CI_CHRONOLOGY_CONSENSUS_FILE}" not in text:
        failures.append("WORKFLOW_CI_CHRONOLOGY_CONSENSUS_CHECK_MISSING")
    if f"test -s {CI_CHRONOLOGY_CONSENSUS_AUDIT_FILE}" not in text:
        failures.append("WORKFLOW_CI_CHRONOLOGY_CONSENSUS_AUDIT_CHECK_MISSING")
    for expected_file, failure_code in (
        (CI_TRANSPARENCY_ANCHOR_FILE, "WORKFLOW_CI_TRANSPARENCY_ANCHOR_CHECK_MISSING"),
        (CI_WITNESS_PROOFS_FILE, "WORKFLOW_CI_WITNESS_PROOFS_CHECK_MISSING"),
        (CI_WITNESS_VERIFICATION_FILE, "WORKFLOW_CI_WITNESS_VERIFICATION_CHECK_MISSING"),
        (CI_WITNESS_AUDIT_FILE, "WORKFLOW_CI_WITNESS_AUDIT_CHECK_MISSING"),
        (CI_WITNESS_TRUST_AUDIT_FILE, "WORKFLOW_CI_WITNESS_TRUST_AUDIT_CHECK_MISSING"),
        (CI_WITNESS_REPUTATION_HISTORY_FILE, "WORKFLOW_CI_WITNESS_REPUTATION_HISTORY_CHECK_MISSING"),
    ):
        if f"test -s {expected_file}" not in text:
            failures.append(failure_code)
    if "production-readiness-governance-timestamps" not in text:
        failures.append("WORKFLOW_CI_GOVERNANCE_TIMESTAMP_ARTIFACT_MISSING")
    for policy_file in (
        CI_EVIDENCE_TRUST_POLICY,
        CI_EVIDENCE_TRUST_POLICY_SIGNATURE,
        CI_EVIDENCE_TRUST_POLICY_AUTHORITY,
        CI_EVIDENCE_TRUST_POLICY_AUDIT,
    ):
        if not (root / policy_file).is_file():
            failures.append(f"CI_EVIDENCE_TRUST_POLICY_GOVERNANCE_FILE_MISSING:{policy_file}")
    forbidden = (
        "pip install -r requirements.txt",
        "pip install pytest",
        "pip install \"pytest",
        "pip install 'pytest",
        "pip install --upgrade pip",
        "--allow-test-key",
    )
    for pattern in forbidden:
        if pattern in text:
            failures.append(f"WORKFLOW_UNHASHED_INSTALL:{pattern}")
    return failures


def check_secret_markers_in_generated_artifacts(root: Path, tracked_files: Iterable[str]) -> list[str]:
    failures: list[str] = []
    for tracked in tracked_files:
        if not is_generated_artifact(tracked):
            continue
        path = root / tracked
        if not path.is_file():
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except Exception:
            failures.append(f"GENERATED_ARTIFACT_UNREADABLE:{tracked}")
            continue
        for marker in SECRET_MARKERS:
            if marker in text:
                failures.append(f"SECRET_MARKER_IN_GENERATED_ARTIFACT:{tracked}:{marker}")
    return failures


def check_production_manifest_required() -> list[str]:
    from security.deployment_attestation import DeploymentAttestationError, resolve_release_manifest_path

    old_env = {
        "USBAY_ENV": os.environ.get("USBAY_ENV"),
        "USBAY_ENVIRONMENT": os.environ.get("USBAY_ENVIRONMENT"),
        "USBAY_GOVERNANCE_RELEASE_PATH": os.environ.get("USBAY_GOVERNANCE_RELEASE_PATH"),
    }
    try:
        os.environ["USBAY_ENV"] = "production"
        os.environ.pop("USBAY_ENVIRONMENT", None)
        os.environ.pop("USBAY_GOVERNANCE_RELEASE_PATH", None)
        try:
            resolve_release_manifest_path()
        except DeploymentAttestationError as exc:
            if str(exc) == "release_manifest_path_required":
                return []
            return [f"PRODUCTION_MANIFEST_WRONG_FAILURE:{exc}"]
        return ["PRODUCTION_MANIFEST_BYPASS_ALLOWED"]
    finally:
        for key, value in old_env.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value


def check_governance_dependency_boundaries(root: Path) -> list[str]:
    from governance.dependencies import validate_governance_dependency_map

    result = validate_governance_dependency_map(root)
    return list(result.failures)


def check_governance_release_integrity_tooling(root: Path) -> list[str]:
    script = root / "scripts" / "verify_governance_release_integrity.py"
    module = root / "governance" / "release_integrity.py"
    failures: list[str] = []
    if not script.is_file():
        failures.append("GOVERNANCE_RELEASE_INTEGRITY_TOOL_MISSING")
    if not module.is_file():
        failures.append("GOVERNANCE_RELEASE_INTEGRITY_MODULE_MISSING")
    return failures


def check_governance_operations_observability_tooling(root: Path) -> list[str]:
    failures: list[str] = []
    if not (root / "governance" / "operations_observability.py").is_file():
        failures.append("GOVERNANCE_OPERATIONS_OBSERVABILITY_MODULE_MISSING")
    if not (root / "scripts" / "governance_diagnostics.py").is_file():
        failures.append("GOVERNANCE_DIAGNOSTICS_CLI_MISSING")
    return failures


def check_governance_incident_runbooks(root: Path) -> list[str]:
    from governance.incidents import (
        REQUIRED_INCIDENT_CODES,
        GovernanceIncidentError,
        assert_audit_safe_payload,
        incident_summary,
        load_incident_runbooks,
        validate_runbook_coverage,
    )

    failures: list[str] = []
    try:
        runbooks = load_incident_runbooks(root)
    except GovernanceIncidentError as exc:
        return [str(exc)]
    for code in REQUIRED_INCIDENT_CODES:
        if code not in runbooks:
            failures.append(f"INCIDENT_CODE_MISSING:{code}")
    representative_failures = (
        "trust_policy_fingerprint_mismatch:0",
        "GOVERNANCE_DEPENDENCY_GRAPH_DRIFT",
        "release_integrity_signature_invalid",
        "release_integrity_rollback_target_invalid",
        "release_integrity_trust_policy_mismatch",
        "GOVERNANCE_TELEMETRY_UNSAFE",
    )
    try:
        validate_runbook_coverage(root, representative_failures)
        assert_audit_safe_payload(incident_summary(root, representative_failures))
    except GovernanceIncidentError as exc:
        failures.append(str(exc))
    diagnostics = root / "scripts" / "governance_diagnostics.py"
    if not diagnostics.is_file():
        failures.append("GOVERNANCE_DIAGNOSTICS_CLI_MISSING")
    else:
        text = diagnostics.read_text(encoding="utf-8")
        forbidden = ("os.environ", "PRIVATE_KEY_ENV", "USBAY_CI_EVIDENCE_PRIVATE_KEY_PEM")
        for marker in forbidden:
            if marker in text:
                failures.append(f"GOVERNANCE_DIAGNOSTICS_SECRET_PRINT_RISK:{marker}")
    return failures


def check_governance_policy_pack_validation(root: Path) -> list[str]:
    from datetime import datetime, timezone

    from governance.policy_pack import (
        POLICY_ERROR_CODES,
        POLICY_PACK_SCHEMA,
        PolicyPackValidationError,
        assert_policy_diagnostics_safe,
        load_policy_error_registry,
        redacted_policy_payload,
        validate_policy_pack,
    )

    failures: list[str] = []
    if not (root / "governance" / "policy_pack.py").is_file():
        failures.append("GOVERNANCE_POLICY_VALIDATOR_MISSING")
    if not (root / "governance" / "policy_errors.json").is_file():
        failures.append("GOVERNANCE_POLICY_ERROR_REGISTRY_MISSING")
    try:
        registry = load_policy_error_registry(root)
        for code in POLICY_ERROR_CODES:
            if code not in registry:
                failures.append(f"GOVERNANCE_POLICY_ERROR_CODE_MISSING:{code}")
    except PolicyPackValidationError as exc:
        failures.append(str(exc))
    invalid_pack = {
        "schema": POLICY_PACK_SCHEMA,
        "fail_closed": False,
        "valid_from": "2026-01-01T00:00:00Z",
        "valid_until": "2026-01-02T00:00:00Z",
        "scope": {"tenant_ids": ["foreign"], "environments": ["invalid"]},
        "policies": [
            {
                "policy_id": "policy.raw_secret",
                "risk_level": "critical",
                "requires_human_approval": False,
                "valid_from": "2026-01-01T00:00:00Z",
                "valid_until": "2026-01-02T00:00:00Z",
                "scope": {"tenant_ids": ["foreign"], "environments": ["invalid"]},
                "allow_rules": [{"action": "read", "resource": "ledger"}],
                "deny_rules": [{"action": "read", "resource": "ledger"}],
            }
        ],
    }
    result = validate_policy_pack(invalid_pack, now=datetime(2026, 5, 12, tzinfo=timezone.utc))
    if result.valid:
        failures.append("GOVERNANCE_INVALID_POLICY_PACK_ALLOWED")
    try:
        assert_policy_diagnostics_safe(redacted_policy_payload(result.to_dict()))
    except PolicyPackValidationError as exc:
        failures.append(str(exc))
    return failures


def collect_failures(root: Path, tracked_files: list[str] | None = None) -> list[str]:
    root = root.resolve()
    tracked = tracked_files if tracked_files is not None else run_git_ls_files(root)
    failures: list[str] = []
    failures.extend(check_helper_size(root))
    failures.extend(check_tracked_file_sizes(root, tracked))
    failures.extend(check_tracked_generated_artifacts(tracked))
    failures.extend(check_required_docs(root))
    failures.extend(check_ci_dependency_lock(root))
    failures.extend(check_workflow_dependency_bootstrap(root))
    failures.extend(check_secret_markers_in_generated_artifacts(root, tracked))
    failures.extend(check_production_manifest_required())
    failures.extend(check_governance_dependency_boundaries(root))
    failures.extend(check_governance_release_integrity_tooling(root))
    failures.extend(check_governance_operations_observability_tooling(root))
    failures.extend(check_governance_incident_runbooks(root))
    failures.extend(check_governance_policy_pack_validation(root))
    return sorted(failures)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Verify USBAY production-readiness guardrails")
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    args = parser.parse_args(argv)
    failures = collect_failures(args.root)
    if failures:
        print("PRODUCTION_READINESS=false")
        for failure in failures:
            print(failure)
        return 1
    print("PRODUCTION_READINESS=true")
    print("PROVENANCE_HELPER_SIZE_OK=true")
    print("TRACKED_OVERSIZED_FILES=false")
    print("TRACKED_GOVERNANCE_RELEASE_ARTIFACTS=false")
    print("PRODUCTION_SIGNED_MANIFEST_REQUIRED=true")
    print("GOVERNANCE_DEPENDENCY_BOUNDARIES_VALID=true")
    print("GOVERNANCE_RELEASE_INTEGRITY_TOOLING_VALID=true")
    print("GOVERNANCE_OPERATIONS_OBSERVABILITY_VALID=true")
    print("GOVERNANCE_INCIDENT_RUNBOOKS_VALID=true")
    print("GOVERNANCE_POLICY_PACK_VALIDATION_READY=true")
    print("FAIL_CLOSED_BEHAVIOR_PRESERVED=true")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
