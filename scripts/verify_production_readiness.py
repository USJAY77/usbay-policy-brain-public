#!/usr/bin/env python3
from __future__ import annotations

import argparse
import fnmatch
import json
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
    "docs/governance-policy-simulation.md",
    "docs/governance-policy-parity.md",
    "docs/governance-policy-proof-bundles.md",
    "docs/governance-proof-timestamp-anchoring.md",
    "docs/governance-rfc3161-timestamp-preflight.md",
    "docs/governance-worm-evidence-manifests.md",
    "docs/governance-evidence-chain.md",
    "docs/governance-evidence-merkle-checkpoints.md",
    "docs/governance-evidence-merkle-inclusion-proofs.md",
    "docs/governance-evidence-merkle-consistency-proofs.md",
    "docs/governance-auditor-verification-bundles.md",
    "docs/governance-signed-auditor-bundles.md",
    "docs/governance-signed-bundle-timestamps.md",
    "docs/governance-tsa-live-verification.md",
    "docs/governance-signed-bundle-ltv-evidence.md",
    "docs/governance-signed-bundle-revocation-preflight.md",
    "docs/governance-signed-bundle-revocation-response.md",
    "docs/governance-revocation-live-fetch.md",
    "docs/governance-sealed-audit-archives.md",
    "docs/governance-evidence-record-chains.md",
    "docs/governance-worm-immutable-storage.md",
    "docs/governance-regulator-export-profile.md",
    "docs/governance-evidence-renewal-runtime.md",
    "docs/governance-pq-renewal-planning.md",
    "docs/governance-pq-runtime-verification.md",
    "docs/governance-hidden-trust-assumption-scanner.md",
    "docs/governance-repo-production-readiness.md",
)
REQUIRED_CI_REQUIREMENTS = "requirements-ci.txt"
PRODUCTION_READINESS_WORKFLOW = ".github/workflows/production-readiness.yml"
PRODUCTION_READINESS_HEAVY_SCAN_WORKFLOW = ".github/workflows/production-readiness-heavy-scan.yml"
CI_SBOM_SCRIPT = "scripts/generate_ci_dependency_sbom.py"
CI_SBOM_ARTIFACT_PATH = "sbom/production-readiness-ci-sbom.json"
CI_EVIDENCE_SCRIPT = "scripts/generate_ci_evidence_manifest.py"
CI_CHANGED_FILES_RESOLVER = "scripts/resolve_ci_changed_files.py"
BOUNDED_VALIDATION_SCRIPT = "scripts/run_bounded_validation.py"
DEPENDABOT_GOVERNED_AUTOMERGE_SCRIPT = "scripts/governed_dependabot_pr_automation.py"
DEPENDABOT_GOVERNED_AUTOMERGE_WORKFLOW = ".github/workflows/dependabot-governed-automerge.yml"
GOVERNED_BRANCH_HYGIENE_SCRIPT = "scripts/governed_branch_hygiene.py"
GOVERNED_BRANCH_HYGIENE_WORKFLOW = ".github/workflows/governed-branch-hygiene.yml"
LANE_FAST_CONTRACT = "fast-contract"
LANE_HEAVY_SCAN = "heavy-scan"
LANE_ORCHESTRATION = "orchestration"
PRODUCTION_READINESS_LANE_POLICY = "governance/production_readiness_lanes.json"
PRODUCTION_READINESS_LANE_POLICY_SCHEMA = "usbay.production_readiness_lanes.v1"
GOVERNANCE_PROVENANCE_SCHEMA = "governance/governance_provenance_schema.json"
GOVERNANCE_PROVENANCE_SCRIPT = "scripts/generate_governance_provenance.py"
GOVERNANCE_PROVENANCE_OUTPUT = "evidence/governance-provenance.json"
ATTESTATION_PERMISSION_WORKFLOWS = frozenset(
    {
        ".github/workflows/governance-export-attestation.yml",
        ".github/workflows/governance-provenance-attestation-stub.yml",
    }
)
ATTESTATION_REASON_CODES = (
    "GOVERNANCE_ATTESTATION_NOT_WIRED",
    "GOVERNANCE_ATTESTATION_PERMISSION_MISSING",
    "GOVERNANCE_ATTESTATION_PERMISSION_TOO_BROAD",
    "GOVERNANCE_ATTESTATION_SUBJECT_MISSING",
    "GOVERNANCE_ATTESTATION_UNSIGNED_HASH_ONLY",
    "GOVERNANCE_ATTESTATION_FAKE_SIGNING_BLOCKED",
)
CI_EVIDENCE_MANIFEST_PATH = "evidence/governance-evidence-manifest.json"
CI_STALE_LINEAGE_INVALIDATION_PATH = "evidence/stale-lineage-invalidation.json"
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


def canonical_json(payload: object) -> str:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"))


def sha256_text(value: str) -> str:
    import hashlib

    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def normalize_event(value: str) -> str:
    normalized = value.strip().lower().replace("-", "_")
    aliases = {
        "workflow_dispatch": "manual",
        "schedule": "scheduled",
        "scheduled": "scheduled",
        "nightly": "nightly",
        "pull_request": "pull_request",
    }
    return aliases.get(normalized, normalized)


def load_lane_policy(root: Path) -> tuple[dict, str]:
    path = root / PRODUCTION_READINESS_LANE_POLICY
    try:
        policy = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        raise SystemExit("PRODUCTION_READINESS_LANE_POLICY_MISSING") from exc
    if not isinstance(policy, dict) or policy.get("schema") != PRODUCTION_READINESS_LANE_POLICY_SCHEMA:
        raise SystemExit("PRODUCTION_READINESS_LANE_POLICY_INVALID")
    lanes = policy.get("lanes")
    if not isinstance(lanes, dict):
        raise SystemExit("PRODUCTION_READINESS_LANE_POLICY_INVALID")
    if policy.get("fail_closed_on_unknown_lane") is not True or policy.get("no_implicit_heavy_scan") is not True:
        raise SystemExit("PRODUCTION_READINESS_LANE_POLICY_FAIL_CLOSED_MISSING")
    return policy, sha256_text(canonical_json(policy))


def lane_policy_evidence(policy: dict, policy_hash: str, lane: str, event: str) -> dict[str, object]:
    normalized_event = normalize_event(event)
    lane_policy = policy.get("lanes", {}).get(lane, {})
    return {
        "lane_policy_hash": policy_hash,
        "selected_lane": lane,
        "lane_pr_blocking": bool(lane_policy.get("pr_blocking", False)),
        "allowed_trigger": normalized_event in set(lane_policy.get("allowed_triggers", [])),
        "event": normalized_event,
    }


def validate_lane_policy(root: Path, lane: str, event: str) -> tuple[dict, str, dict[str, object]]:
    policy, policy_hash = load_lane_policy(root)
    lanes = policy.get("lanes", {})
    normalized_event = normalize_event(event)
    if lane not in lanes:
        raise SystemExit("PRODUCTION_READINESS_LANE_UNKNOWN")
    lane_policy = lanes[lane]
    allowed = set(lane_policy.get("allowed_triggers", []))
    forbidden = set(lane_policy.get("forbidden_triggers", []))
    evidence = lane_policy_evidence(policy, policy_hash, lane, normalized_event)
    if normalized_event in forbidden or normalized_event not in allowed:
        raise SystemExit("PRODUCTION_READINESS_LANE_TRIGGER_BLOCKED")
    if lane == LANE_HEAVY_SCAN and normalized_event == "pull_request":
        raise SystemExit("PRODUCTION_READINESS_HEAVY_SCAN_PR_FORBIDDEN")
    return policy, policy_hash, evidence


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
    if "rm -rf evidence/governance-evidence-manifest.json evidence/governance-timestamps" not in text:
        failures.append("WORKFLOW_CI_STALE_EVIDENCE_EXPIRATION_MISSING")
    if CI_EVIDENCE_MANIFEST_PATH not in text:
        failures.append("WORKFLOW_CI_EVIDENCE_MANIFEST_PATH_MISSING")
    if f"test -s {CI_EVIDENCE_MANIFEST_PATH}" not in text:
        failures.append("WORKFLOW_CI_EVIDENCE_EXISTENCE_CHECK_MISSING")
    if CI_STALE_LINEAGE_INVALIDATION_PATH not in text:
        failures.append("WORKFLOW_CI_STALE_LINEAGE_INVALIDATION_MISSING")
    if f"test -s {CI_STALE_LINEAGE_INVALIDATION_PATH}" not in text:
        failures.append("WORKFLOW_CI_STALE_LINEAGE_INVALIDATION_CHECK_MISSING")
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
    forbidden_evidence_diagnostics = (
        "TEMPORARY DIAGNOSTIC",
        "TEMPORARY_DIAGNOSTIC_CI_EVIDENCE_PUBLIC_KEY_PEM_BEGIN",
        "TEMPORARY_DIAGNOSTIC_CI_EVIDENCE_PUBLIC_KEY_PEM_END",
        "openssl pkey -in",
        "openssl pkey -pubin",
        "cat \"${public_key_path}\"",
    )
    for pattern in forbidden_evidence_diagnostics:
        if pattern in text:
            failures.append(f"WORKFLOW_CI_EVIDENCE_UNSAFE_DIAGNOSTIC:{pattern}")
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


def check_bounded_validation_tooling(root: Path) -> list[str]:
    failures: list[str] = []
    script = root / BOUNDED_VALIDATION_SCRIPT
    if not script.is_file():
        return ["BOUNDED_VALIDATION_SCRIPT_MISSING"]
    script_text = script.read_text(encoding="utf-8")
    for marker in (
        "VALIDATION_TIMEOUT_FAST_PR",
        "VALIDATION_TIMEOUT_DEPENDENCY",
        "VALIDATION_TIMEOUT_PRODUCTION_READINESS",
        "VALIDATION_TIMEOUT_FULL_REGRESSION",
        "partial_audit_preserved",
    ):
        if marker not in script_text:
            failures.append(f"BOUNDED_VALIDATION_MARKER_MISSING:{marker}")
    workflow_expectations = {
        ".github/workflows/codex-autofix-ci.yml": ("--lane fast_pr", "evidence/pr-critical-validation.json"),
        ".github/workflows/production-readiness.yml": (
            "--lane fast_pr",
            "--lane fast-contract",
            "evidence/production-readiness-tests-validation.json",
            "scan-repo-production-readiness",
            "evidence/repo-production-readiness-validation.json",
        ),
        ".github/workflows/full-regression.yml": ("--lane full_regression", "evidence/full-regression-validation.json"),
    }
    for rel, markers in workflow_expectations.items():
        workflow = root / rel
        if not workflow.is_file():
            failures.append(f"BOUNDED_VALIDATION_WORKFLOW_MISSING:{rel}")
            continue
        text = workflow.read_text(encoding="utf-8")
        if BOUNDED_VALIDATION_SCRIPT not in text:
            failures.append(f"BOUNDED_VALIDATION_WORKFLOW_NOT_USED:{rel}")
        for marker in markers:
            if marker not in text:
                failures.append(f"BOUNDED_VALIDATION_WORKFLOW_MARKER_MISSING:{rel}:{marker}")
    return failures


def check_audit_artifact_guard_lineage_recovery(root: Path) -> list[str]:
    workflow = root / ".github" / "workflows" / "audit-artifact-guard.yml"
    resolver = root / CI_CHANGED_FILES_RESOLVER
    failures: list[str] = []
    if not workflow.is_file():
        failures.append("AUDIT_ARTIFACT_GUARD_WORKFLOW_MISSING")
        return failures
    text = workflow.read_text(encoding="utf-8")
    if not resolver.is_file():
        failures.append("AUDIT_ARTIFACT_LINEAGE_RESOLVER_MISSING")
    if CI_CHANGED_FILES_RESOLVER not in text:
        failures.append("AUDIT_ARTIFACT_LINEAGE_RESOLVER_NOT_USED")
    if "--audit-output" not in text:
        failures.append("AUDIT_ARTIFACT_LINEAGE_AUDIT_OUTPUT_MISSING")
    if "git diff --name-only --diff-filter=ACMR \"$base\" \"$head\"" in text:
        failures.append("AUDIT_ARTIFACT_RAW_EVENT_DIFF_STALE_LINEAGE_RISK")
    return failures


def check_dependabot_governed_automation(root: Path) -> list[str]:
    failures: list[str] = []
    workflow = root / DEPENDABOT_GOVERNED_AUTOMERGE_WORKFLOW
    script = root / DEPENDABOT_GOVERNED_AUTOMERGE_SCRIPT
    if not workflow.is_file():
        failures.append("DEPENDABOT_GOVERNED_AUTOMERGE_WORKFLOW_MISSING")
        return failures
    if not script.is_file():
        failures.append("DEPENDABOT_GOVERNED_AUTOMERGE_SCRIPT_MISSING")
        return failures
    workflow_text = workflow.read_text(encoding="utf-8")
    script_text = script.read_text(encoding="utf-8")
    required_workflow_markers = (
        "audit-artifact-guard",
        "production-readiness",
        "governance-check",
        "policy-verification",
        "codeql-quality",
        "scripts/resolve_ci_changed_files.py",
        "scripts/governed_dependabot_pr_automation.py",
        "--merge",
    )
    for marker in required_workflow_markers:
        if marker not in workflow_text:
            failures.append(f"DEPENDABOT_GOVERNED_AUTOMERGE_WORKFLOW_MARKER_MISSING:{marker}")
    if "continue-on-error" in workflow_text:
        failures.append("DEPENDABOT_GOVERNED_AUTOMERGE_CONTINUE_ON_ERROR_FORBIDDEN")
    if '"pr", "merge"' not in script_text or "--squash" not in script_text or "--delete-branch" not in script_text:
        failures.append("DEPENDABOT_GOVERNED_AUTOMERGE_MERGE_CLEANUP_MISSING")
    for required in (
        "dependabot[bot]",
        "head_branch_not_dependabot",
        "required_check_not_success",
        "governance-review-required",
        "Governed auto-merge approved.",
        "SAFE_DEPENDENCY_SCOPE_ALLOWED",
        "SAFE_WORKFLOW_VERSION_SCOPE_ALLOWED",
        "GOVERNANCE_SENSITIVE_SCOPE_BLOCKED",
        "RUNTIME_SENSITIVE_SCOPE_BLOCKED",
        "CRYPTOGRAPHIC_SENSITIVE_SCOPE_BLOCKED",
        "UNKNOWN_SCOPE_BLOCKED",
        "NON_DEPENDABOT_AUTHOR_BLOCKED",
        "NON_DEPENDABOT_BRANCH_BLOCKED",
        "PERMISSION_WIDENING_BLOCKED",
        "WORKFLOW_LOGIC_CHANGE_BLOCKED",
        "PR_NOT_FOUND",
        "PR_BRANCH_MISMATCH",
        "PR_SHA_MISMATCH",
        "HEAD_SHA_MISMATCH",
        "PR_NOT_OPEN",
        "PR_AUTHOR_INVALID",
        "PR_LINEAGE_INVALID",
        "MERGE_COMMIT_MISMATCH",
        "BASE_BRANCH_MISMATCH",
        "BRANCH_DELETED_BEFORE_RECONCILIATION",
        "WORKFLOW_EVENT_STALE",
        "WORKFLOW_EVENT_AMBIGUOUS",
        "MERGE_PROVENANCE_UNVERIFIED",
        "MERGE_LINEAGE_RECONCILED",
        "WORKFLOW_CONTEXT_UNTRUSTED",
        "REQUIRED_CHECK_NOT_PUBLISHED",
        "GOVERNANCE_LABEL_NOT_STATUS_CHECK",
        "GOVERNANCE_REVIEW_REQUIRED",
        "GOVERNANCE_REVIEW_MISSING",
    ):
        if required not in script_text:
            failures.append(f"DEPENDABOT_GOVERNED_AUTOMERGE_GATE_MISSING:{required}")
    return failures


def check_governed_branch_hygiene(root: Path) -> list[str]:
    failures: list[str] = []
    workflow = root / GOVERNED_BRANCH_HYGIENE_WORKFLOW
    script = root / GOVERNED_BRANCH_HYGIENE_SCRIPT
    if not workflow.is_file():
        failures.append("GOVERNED_BRANCH_HYGIENE_WORKFLOW_MISSING")
        return failures
    if not script.is_file():
        failures.append("GOVERNED_BRANCH_HYGIENE_SCRIPT_MISSING")
        return failures
    workflow_text = workflow.read_text(encoding="utf-8")
    script_text = script.read_text(encoding="utf-8")
    for marker in (
        "timeout-minutes: 10",
        "scripts/run_bounded_validation.py",
        "scripts/governed_branch_hygiene.py",
        "--delete",
        "evidence/branch-hygiene-audit.json",
    ):
        if marker not in workflow_text:
            failures.append(f"GOVERNED_BRANCH_HYGIENE_WORKFLOW_MARKER_MISSING:{marker}")
    if "continue-on-error" in workflow_text:
        failures.append("GOVERNED_BRANCH_HYGIENE_CONTINUE_ON_ERROR_FORBIDDEN")
    for marker in (
        "BRANCH_ALREADY_MERGED",
        "RESTORED_AFTER_MERGE",
        "BRANCH_NOT_MERGED_BLOCKED",
        "OPEN_PR_BRANCH_BLOCKED",
        "PROTECTED_BRANCH_BLOCKED",
        "LINEAGE_UNCLEAR_BLOCKED",
        "VALID_NON_PROTECTED_BRANCH",
        "PROTECTED_BRANCH_REQUIRED",
        "BRANCH_PROTECTION_LOOKUP_FAILED",
        "MAIN_BRANCH_POLICY_REQUIRED",
        "GOVERNANCE_FEATURE_BRANCH_ALLOWED",
        "audit_record_created_before_delete",
    ):
        if marker not in script_text:
            failures.append(f"GOVERNED_BRANCH_HYGIENE_REASON_MISSING:{marker}")
    return failures


def check_fast_contract_safety(root: Path) -> list[str]:
    failures: list[str] = []
    relevant_paths = (
        PRODUCTION_READINESS_WORKFLOW,
        DEPENDABOT_GOVERNED_AUTOMERGE_SCRIPT,
        DEPENDABOT_GOVERNED_AUTOMERGE_WORKFLOW,
        GOVERNED_BRANCH_HYGIENE_SCRIPT,
        GOVERNED_BRANCH_HYGIENE_WORKFLOW,
        "governance/canonical_governance_state.py",
        "governance/canonical_governance_state_errors.json",
    )
    unsafe_text_markers = (
        "BEGIN " + "PRIVATE KEY",
        "PRIVATE " + "KEY",
        "raw_" + "payload",
        "approval_contents",
    )
    for rel in relevant_paths:
        path = root / rel
        if not path.is_file():
            failures.append(f"PRODUCTION_READINESS_FAST_CONTRACT_FILE_MISSING:{rel}")
            continue
        text = path.read_text(encoding="utf-8", errors="replace")
        if rel.startswith(".github/workflows/") and "continue-on-error" in text:
            failures.append(f"PRODUCTION_READINESS_FAST_CONTRACT_CONTINUE_ON_ERROR:{rel}")
        for marker in unsafe_text_markers:
            if marker in text:
                failures.append(f"PRODUCTION_READINESS_FAST_CONTRACT_UNSAFE_MARKER:{rel}:{marker}")
    try:
        policy, _policy_hash = load_lane_policy(root)
    except SystemExit as exc:
        failures.append(str(exc))
    else:
        lanes = policy.get("lanes", {})
        heavy = lanes.get(LANE_HEAVY_SCAN, {})
        if lanes.get(LANE_FAST_CONTRACT, {}).get("pr_blocking") is not True:
            failures.append("PRODUCTION_READINESS_FAST_CONTRACT_NOT_PR_BLOCKING")
        if lanes.get(LANE_ORCHESTRATION, {}).get("pr_blocking") is not True:
            failures.append("PRODUCTION_READINESS_ORCHESTRATION_NOT_PR_BLOCKING")
        if heavy.get("pr_blocking") is not False:
            failures.append("PRODUCTION_READINESS_HEAVY_SCAN_PR_BLOCKING")
        if "pull_request" not in set(heavy.get("forbidden_triggers", [])):
            failures.append("PRODUCTION_READINESS_HEAVY_SCAN_PR_NOT_FORBIDDEN")
        if policy.get("no_implicit_heavy_scan") is not True:
            failures.append("PRODUCTION_READINESS_IMPLICIT_HEAVY_SCAN_ALLOWED")
    workflow_text = (root / PRODUCTION_READINESS_WORKFLOW).read_text(encoding="utf-8", errors="replace")
    if "PRODUCTION_READINESS_FAST_CONTRACT=true" not in Path(__file__).read_text(encoding="utf-8"):
        failures.append("PRODUCTION_READINESS_FAST_CONTRACT_MARKER_MISSING")
    if "gh pr merge --admin" in workflow_text or "--admin" in (root / DEPENDABOT_GOVERNED_AUTOMERGE_SCRIPT).read_text(encoding="utf-8"):
        failures.append("PRODUCTION_READINESS_FAST_CONTRACT_BRANCH_PROTECTION_BYPASS")
    if "auto-approve" in workflow_text.lower() or "auto_approve" in workflow_text.lower():
        failures.append("PRODUCTION_READINESS_FAST_CONTRACT_AUTO_APPROVAL")
    return failures


def check_canonical_authority_integration(root: Path) -> list[str]:
    failures: list[str] = []
    dependabot = root / DEPENDABOT_GOVERNED_AUTOMERGE_SCRIPT
    branch_hygiene = root / GOVERNED_BRANCH_HYGIENE_SCRIPT
    if dependabot.is_file():
        text = dependabot.read_text(encoding="utf-8")
        for marker in ("build_canonical_governance_state", '"canonical_governance_state"', "signature_status"):
            if marker not in text:
                failures.append(f"CANONICAL_AUTHORITY_DEPENDABOT_INTEGRATION_MISSING:{marker}")
    if branch_hygiene.is_file():
        text = branch_hygiene.read_text(encoding="utf-8")
        for marker in ("build_canonical_governance_state", '"canonical_governance_state"'):
            if marker not in text:
                failures.append(f"CANONICAL_AUTHORITY_BRANCH_HYGIENE_INTEGRATION_MISSING:{marker}")
    return failures


def governance_provenance_available(root: Path) -> bool:
    return (
        (root / GOVERNANCE_PROVENANCE_SCHEMA).is_file()
        and (root / GOVERNANCE_PROVENANCE_SCRIPT).is_file()
        and (root / GOVERNANCE_PROVENANCE_OUTPUT).is_file()
    )


def check_governance_provenance_foundation(root: Path) -> list[str]:
    failures: list[str] = []
    schema = root / GOVERNANCE_PROVENANCE_SCHEMA
    script = root / GOVERNANCE_PROVENANCE_SCRIPT
    if not schema.is_file():
        failures.append("GOVERNANCE_PROVENANCE_SCHEMA_MISSING")
    if not script.is_file():
        failures.append("GOVERNANCE_PROVENANCE_SCRIPT_MISSING")
    if script.is_file():
        text = script.read_text(encoding="utf-8")
        for marker in (
            "hash-only-local",
            "github-oidc-attestation-ready",
            "OIDC_ATTESTATION_NOT_WIRED",
            "sha256-detached-hash",
            "provenance_fingerprint",
            "GOVERNANCE_PROVENANCE_EVIDENCE_MISSING",
            "GOVERNANCE_ATTESTATION_FAKE_SIGNING_BLOCKED",
        ):
            if marker not in text:
                failures.append(f"GOVERNANCE_PROVENANCE_SCRIPT_MARKER_MISSING:{marker}")
    if schema.is_file():
        try:
            payload = json.loads(schema.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            failures.append("GOVERNANCE_PROVENANCE_SCHEMA_INVALID")
        else:
            required = set(payload.get("required", [])) if isinstance(payload, dict) else set()
            for field in (
                "provenance_version",
                "governance_lane",
                "workflow_name",
                "workflow_sha",
                "commit_sha",
                "policy_hash",
                "orchestration_hash",
                "evidence_hash",
                "attestation_status",
                "timestamp_utc",
                "validation_result",
                "signer_mode",
                "reason",
                "signature",
                "signature_algorithm",
            ):
                if field not in required:
                    failures.append(f"GOVERNANCE_PROVENANCE_SCHEMA_FIELD_MISSING:{field}")
    for code in ATTESTATION_REASON_CODES:
        if code not in Path(__file__).read_text(encoding="utf-8") and (script.is_file() and code not in script.read_text(encoding="utf-8")):
            failures.append(f"GOVERNANCE_ATTESTATION_REASON_CODE_MISSING:{code}")
    return failures


def workflow_has_permission(text: str, permission: str) -> bool:
    return permission in text


def check_governance_attestation_permissions(root: Path) -> list[str]:
    failures: list[str] = []
    workflows = sorted((root / ".github" / "workflows").glob("*.yml")) + sorted((root / ".github" / "workflows").glob("*.yaml"))
    attestation_workflow_found = False
    for path in workflows:
        rel = path.relative_to(root).as_posix()
        text = path.read_text(encoding="utf-8")
        has_oidc = workflow_has_permission(text, "id-token: write")
        has_attestations = workflow_has_permission(text, "attestations: write")
        if "permissions: read-all" in text or "permissions: write-all" in text:
            failures.append(f"GOVERNANCE_ATTESTATION_PERMISSION_TOO_BROAD:{rel}")
        if (has_oidc or has_attestations) and rel not in ATTESTATION_PERMISSION_WORKFLOWS:
            failures.append(f"GOVERNANCE_ATTESTATION_PERMISSION_TOO_BROAD:{rel}")
        if rel in ATTESTATION_PERMISSION_WORKFLOWS:
            attestation_workflow_found = True
            if "contents: read" not in text:
                failures.append(f"GOVERNANCE_ATTESTATION_PERMISSION_MISSING:{rel}:contents:read")
            if not has_oidc:
                failures.append(f"GOVERNANCE_ATTESTATION_PERMISSION_MISSING:{rel}:id-token:write")
            if not has_attestations:
                failures.append(f"GOVERNANCE_ATTESTATION_PERMISSION_MISSING:{rel}:attestations:write")
            if "subject-path:" not in text:
                if "path: evidence/governance-provenance.json" not in text:
                    failures.append(f"GOVERNANCE_ATTESTATION_SUBJECT_MISSING:{rel}")
            if "actions/attest-build-provenance" in text and "if: steps.verify_package.outputs.package_verified == 'true'" not in text:
                failures.append(f"GOVERNANCE_ATTESTATION_SUBJECT_MISSING:{rel}:verified-subject-gate")
            if rel.endswith("governance-provenance-attestation-stub.yml"):
                for marker in (
                    "workflow_dispatch:",
                    "ATTESTATION_WORKFLOW_STUB_ONLY=true",
                    "REAL_ATTESTATION_NOT_ENABLED=true",
                    "path: evidence/governance-provenance.json",
                    "--signer-mode github-oidc-attestation-ready",
                ):
                    if marker not in text:
                        failures.append(f"GOVERNANCE_ATTESTATION_SUBJECT_MISSING:{rel}:{marker}")
                for forbidden in ("pull_request:", "push:", "actions/attest-build-provenance", "secrets."):
                    if forbidden in text:
                        failures.append(f"GOVERNANCE_ATTESTATION_PERMISSION_TOO_BROAD:{rel}:{forbidden}")
    if not attestation_workflow_found:
        failures.append("GOVERNANCE_ATTESTATION_NOT_WIRED")
    return failures


def check_heavy_scan_workflow(root: Path) -> list[str]:
    workflow = root / PRODUCTION_READINESS_HEAVY_SCAN_WORKFLOW
    if not workflow.is_file():
        return ["PRODUCTION_READINESS_HEAVY_SCAN_WORKFLOW_MISSING"]
    text = workflow.read_text(encoding="utf-8")
    failures: list[str] = []
    required_markers = (
        "workflow_dispatch:",
        "schedule:",
        "permissions:",
        "contents: read",
        "scripts/verify_production_readiness.py",
        "--lane heavy-scan",
        "--event \"${event_context}\"",
        "event_context=\"manual\"",
        "event_context=\"scheduled\"",
        "evidence/production-readiness-heavy-scan-output.txt",
        "selected_lane=heavy-scan",
        "lane_pr_blocking=false",
        "allowed_trigger=true",
        "lane_policy_hash=",
        "PRODUCTION_READINESS_HEAVY_SCAN=true",
    )
    for marker in required_markers:
        if marker not in text:
            failures.append(f"PRODUCTION_READINESS_HEAVY_SCAN_WORKFLOW_MARKER_MISSING:{marker}")
    forbidden_markers = (
        "pull_request:",
        "push:",
        "contents: write",
        "pull-requests: write",
        "issues: write",
        "id-token: write",
        "attestations: write",
        "continue-on-error",
        "gh pr merge",
        "auto-merge",
    )
    for marker in forbidden_markers:
        if marker in text:
            failures.append(f"PRODUCTION_READINESS_HEAVY_SCAN_WORKFLOW_FORBIDDEN:{marker}")
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


def check_governance_policy_simulation(root: Path) -> list[str]:
    from governance.policy_pack import POLICY_PACK_SCHEMA
    from governance.policy_simulation import (
        DECISION_FAIL_CLOSED,
        SIMULATION_ERROR_CODES,
        PolicySimulationError,
        assert_simulation_diagnostics_safe,
        load_simulation_error_registry,
        redacted_simulation_payload,
        simulate_policy_decision,
    )

    failures: list[str] = []
    if not (root / "governance" / "policy_simulation.py").is_file():
        failures.append("GOVERNANCE_POLICY_SIMULATION_MODULE_MISSING")
    if not (root / "governance" / "policy_simulation_errors.json").is_file():
        failures.append("GOVERNANCE_POLICY_SIMULATION_ERROR_REGISTRY_MISSING")
    try:
        registry = load_simulation_error_registry(root)
        for code in SIMULATION_ERROR_CODES:
            if code not in registry:
                failures.append(f"GOVERNANCE_POLICY_SIMULATION_ERROR_CODE_MISSING:{code}")
    except PolicySimulationError as exc:
        failures.append(str(exc))
    invalid_pack = {
        "schema": POLICY_PACK_SCHEMA,
        "fail_closed": False,
        "valid_from": "2026-01-01T00:00:00Z",
        "valid_until": "2027-01-01T00:00:00Z",
        "scope": {"tenant_ids": ["t1"], "environments": ["test"]},
        "policies": [],
    }
    result = simulate_policy_decision(
        invalid_pack,
        {"action": "read", "resource": "ledger", "approval_contents": "do-not-log"},
        tenant_id="t1",
        environment="test",
        risk_level="low",
    )
    if result.decision != DECISION_FAIL_CLOSED or "SIM_POLICY_PACK_INVALID" not in result.errors:
        failures.append("GOVERNANCE_INVALID_POLICY_SIMULATION_ALLOWED")
    try:
        assert_simulation_diagnostics_safe(redacted_simulation_payload(result.to_dict()))
    except PolicySimulationError as exc:
        failures.append(str(exc))
    return failures


def check_governance_policy_parity(root: Path) -> list[str]:
    from governance.policy_pack import POLICY_PACK_SCHEMA
    from governance.policy_parity import (
        PARITY_ERROR_CODES,
        PolicyParityError,
        assert_parity_diagnostics_safe,
        build_runtime_decision_record,
        load_parity_error_registry,
        redacted_parity_payload,
        verify_policy_parity,
    )
    from governance.policy_simulation import DECISION_ALLOW

    failures: list[str] = []
    if not (root / "governance" / "policy_parity.py").is_file():
        failures.append("GOVERNANCE_POLICY_PARITY_MODULE_MISSING")
    if not (root / "governance" / "policy_parity_errors.json").is_file():
        failures.append("GOVERNANCE_POLICY_PARITY_ERROR_REGISTRY_MISSING")
    try:
        registry = load_parity_error_registry(root)
        for code in PARITY_ERROR_CODES:
            if code not in registry:
                failures.append(f"GOVERNANCE_POLICY_PARITY_ERROR_CODE_MISSING:{code}")
    except PolicyParityError as exc:
        failures.append(str(exc))
    policy_pack = {
        "schema": POLICY_PACK_SCHEMA,
        "fail_closed": True,
        "valid_from": "2026-01-01T00:00:00Z",
        "valid_until": "2027-01-01T00:00:00Z",
        "scope": {"tenant_ids": ["t1"], "environments": ["test"]},
        "policies": [
            {
                "policy_id": "policy.allow.read",
                "risk_level": "low",
                "requires_human_approval": False,
                "fail_closed": True,
                "valid_from": "2026-01-01T00:00:00Z",
                "valid_until": "2027-01-01T00:00:00Z",
                "scope": {"tenant_ids": ["t1"], "environments": ["test"]},
                "allow_rules": [{"action": "read", "resource": "ledger"}],
                "deny_rules": [],
            }
        ],
    }
    request_context = {"action": "read", "resource": "ledger", "approval_contents": "do-not-log"}
    runtime_record = build_runtime_decision_record(
        decision=DECISION_ALLOW,
        policy_pack=policy_pack,
        request_context=request_context,
        tenant_id="t1",
        environment="test",
        risk_level="low",
    )
    runtime_record["policy_hash"] = "0" * 64
    result = verify_policy_parity(
        policy_pack,
        request_context,
        runtime_record,
        tenant_id="t1",
        environment="test",
        risk_level="low",
    )
    if result.valid or "PARITY_POLICY_HASH_MISMATCH" not in result.errors:
        failures.append("GOVERNANCE_UNVERIFIABLE_POLICY_PARITY_ALLOWED")
    try:
        assert_parity_diagnostics_safe(redacted_parity_payload(result.to_dict()))
    except PolicyParityError as exc:
        failures.append(str(exc))
    return failures


def check_governance_policy_proof_bundle(root: Path) -> list[str]:
    from governance.policy_pack import POLICY_PACK_SCHEMA
    from governance.policy_parity import build_runtime_decision_record
    from governance.policy_proof_bundle import (
        PROOF_BUNDLE_ERROR_CODES,
        PolicyProofBundleError,
        assert_proof_bundle_safe,
        build_policy_proof_bundle,
        load_proof_bundle_error_registry,
        redacted_proof_bundle_payload,
        verify_policy_proof_bundle,
    )
    from governance.policy_simulation import DECISION_ALLOW

    failures: list[str] = []
    if not (root / "governance" / "policy_proof_bundle.py").is_file():
        failures.append("GOVERNANCE_POLICY_PROOF_BUNDLE_MODULE_MISSING")
    if not (root / "governance" / "policy_proof_bundle_errors.json").is_file():
        failures.append("GOVERNANCE_POLICY_PROOF_BUNDLE_ERROR_REGISTRY_MISSING")
    try:
        registry = load_proof_bundle_error_registry(root)
        for code in PROOF_BUNDLE_ERROR_CODES:
            if code not in registry:
                failures.append(f"GOVERNANCE_POLICY_PROOF_BUNDLE_ERROR_CODE_MISSING:{code}")
    except PolicyProofBundleError as exc:
        failures.append(str(exc))
    policy_pack = {
        "schema": POLICY_PACK_SCHEMA,
        "fail_closed": True,
        "valid_from": "2026-01-01T00:00:00Z",
        "valid_until": "2027-01-01T00:00:00Z",
        "scope": {"tenant_ids": ["t1"], "environments": ["test"]},
        "policies": [
            {
                "policy_id": "policy.allow.read",
                "risk_level": "low",
                "requires_human_approval": False,
                "fail_closed": True,
                "valid_from": "2026-01-01T00:00:00Z",
                "valid_until": "2027-01-01T00:00:00Z",
                "scope": {"tenant_ids": ["t1"], "environments": ["test"]},
                "allow_rules": [{"action": "read", "resource": "ledger"}],
                "deny_rules": [],
            }
        ],
    }
    request_context = {"action": "read", "resource": "ledger"}
    runtime_record = build_runtime_decision_record(
        decision=DECISION_ALLOW,
        policy_pack=policy_pack,
        request_context=request_context,
        tenant_id="t1",
        environment="test",
        risk_level="low",
    )
    try:
        bundle = build_policy_proof_bundle(
            policy_pack,
            request_context,
            runtime_record,
            tenant_id="t1",
            environment="test",
            risk_level="low",
            validation_timestamp="2026-05-12T00:00:00Z",
        )
    except PolicyProofBundleError as exc:
        failures.append(str(exc))
        bundle = {}
    verification = verify_policy_proof_bundle({"schema": "usbay.governance_policy_proof_bundle.v1"})
    if verification.valid or "PROOF_POLICY_HASH_MISSING" not in verification.errors:
        failures.append("GOVERNANCE_INVALID_POLICY_PROOF_BUNDLE_ALLOWED")
    unsafe_bundle = dict(bundle)
    unsafe_bundle["redacted_diagnostics_summary"] = {"approval_contents": "do-not-log"}
    unsafe_verification = verify_policy_proof_bundle(unsafe_bundle)
    if unsafe_verification.valid or "PROOF_DIAGNOSTICS_UNSAFE" not in unsafe_verification.errors:
        failures.append("GOVERNANCE_UNSAFE_POLICY_PROOF_BUNDLE_ALLOWED")
    try:
        assert_proof_bundle_safe(redacted_proof_bundle_payload(bundle))
    except PolicyProofBundleError as exc:
        failures.append(str(exc))
    return failures


def check_governance_proof_timestamp_anchor(root: Path) -> list[str]:
    from governance.policy_pack import POLICY_PACK_SCHEMA
    from governance.policy_parity import build_runtime_decision_record
    from governance.policy_proof_bundle import build_policy_proof_bundle
    from governance.policy_simulation import DECISION_ALLOW
    from governance.proof_timestamp_anchor import (
        TIMESTAMP_ANCHOR_ERROR_CODES,
        ProofTimestampAnchorError,
        anchor_proof_bundle,
        assert_timestamp_anchor_safe,
        load_timestamp_anchor_error_registry,
        redacted_timestamp_anchor_payload,
        verify_proof_timestamp_anchor,
    )

    failures: list[str] = []
    if not (root / "governance" / "proof_timestamp_anchor.py").is_file():
        failures.append("GOVERNANCE_PROOF_TIMESTAMP_ANCHOR_MODULE_MISSING")
    if not (root / "governance" / "proof_timestamp_anchor_errors.json").is_file():
        failures.append("GOVERNANCE_PROOF_TIMESTAMP_ANCHOR_ERROR_REGISTRY_MISSING")
    try:
        registry = load_timestamp_anchor_error_registry(root)
        for code in TIMESTAMP_ANCHOR_ERROR_CODES:
            if code not in registry:
                failures.append(f"GOVERNANCE_PROOF_TIMESTAMP_ANCHOR_ERROR_CODE_MISSING:{code}")
    except ProofTimestampAnchorError as exc:
        failures.append(str(exc))
    policy_pack = {
        "schema": POLICY_PACK_SCHEMA,
        "fail_closed": True,
        "valid_from": "2026-01-01T00:00:00Z",
        "valid_until": "2027-01-01T00:00:00Z",
        "scope": {"tenant_ids": ["t1"], "environments": ["test"]},
        "policies": [
            {
                "policy_id": "policy.allow.read",
                "risk_level": "low",
                "requires_human_approval": False,
                "fail_closed": True,
                "valid_from": "2026-01-01T00:00:00Z",
                "valid_until": "2027-01-01T00:00:00Z",
                "scope": {"tenant_ids": ["t1"], "environments": ["test"]},
                "allow_rules": [{"action": "read", "resource": "ledger"}],
                "deny_rules": [],
            }
        ],
    }
    request_context = {"action": "read", "resource": "ledger"}
    runtime_record = build_runtime_decision_record(
        decision=DECISION_ALLOW,
        policy_pack=policy_pack,
        request_context=request_context,
        tenant_id="t1",
        environment="test",
        risk_level="low",
    )
    try:
        bundle = build_policy_proof_bundle(
            policy_pack,
            request_context,
            runtime_record,
            tenant_id="t1",
            environment="test",
            risk_level="low",
            validation_timestamp="2026-05-12T00:00:00Z",
        )
        anchor = anchor_proof_bundle(bundle, timestamp="2026-05-12T00:00:00Z")
    except (ProofTimestampAnchorError, Exception) as exc:
        failures.append(str(exc))
        anchor = {}
    invalid = verify_proof_timestamp_anchor({"schema": "usbay.governance_proof_timestamp_anchor.v1"})
    if invalid.valid or "TIMESTAMP_BUNDLE_HASH_MISSING" not in invalid.errors:
        failures.append("GOVERNANCE_INVALID_PROOF_TIMESTAMP_ANCHOR_ALLOWED")
    unsafe_anchor = dict(anchor)
    unsafe_anchor["diagnostics"] = {"approval_contents": "do-not-log"}
    unsafe_verification = verify_proof_timestamp_anchor(unsafe_anchor)
    if unsafe_verification.valid or "TIMESTAMP_DIAGNOSTICS_UNSAFE" not in unsafe_verification.errors:
        failures.append("GOVERNANCE_UNSAFE_PROOF_TIMESTAMP_ANCHOR_ALLOWED")
    try:
        assert_timestamp_anchor_safe(redacted_timestamp_anchor_payload(anchor))
    except ProofTimestampAnchorError as exc:
        failures.append(str(exc))
    return failures


def check_governance_rfc3161_preflight(root: Path) -> list[str]:
    from governance.policy_pack import POLICY_PACK_SCHEMA
    from governance.policy_parity import build_runtime_decision_record
    from governance.policy_proof_bundle import build_policy_proof_bundle
    from governance.policy_simulation import DECISION_ALLOW
    from governance.proof_timestamp_anchor import anchor_proof_bundle
    from governance.rfc3161_timestamp import (
        RFC3161_ERROR_CODES,
        RFC3161TimestampError,
        assert_rfc3161_safe,
        load_rfc3161_error_registry,
        prepare_rfc3161_request_material,
        redacted_rfc3161_payload,
        verify_rfc3161_request_material,
    )

    failures: list[str] = []
    if not (root / "governance" / "rfc3161_timestamp.py").is_file():
        failures.append("GOVERNANCE_RFC3161_TIMESTAMP_PREFLIGHT_MODULE_MISSING")
    if not (root / "governance" / "rfc3161_timestamp_errors.json").is_file():
        failures.append("GOVERNANCE_RFC3161_TIMESTAMP_PREFLIGHT_ERROR_REGISTRY_MISSING")
    try:
        registry = load_rfc3161_error_registry(root)
        for code in RFC3161_ERROR_CODES:
            if code not in registry:
                failures.append(f"GOVERNANCE_RFC3161_TIMESTAMP_PREFLIGHT_ERROR_CODE_MISSING:{code}")
    except RFC3161TimestampError as exc:
        failures.append(str(exc))
    policy_pack = {
        "schema": POLICY_PACK_SCHEMA,
        "fail_closed": True,
        "valid_from": "2026-01-01T00:00:00Z",
        "valid_until": "2027-01-01T00:00:00Z",
        "scope": {"tenant_ids": ["t1"], "environments": ["test"]},
        "policies": [
            {
                "policy_id": "policy.allow.read",
                "risk_level": "low",
                "requires_human_approval": False,
                "fail_closed": True,
                "valid_from": "2026-01-01T00:00:00Z",
                "valid_until": "2027-01-01T00:00:00Z",
                "scope": {"tenant_ids": ["t1"], "environments": ["test"]},
                "allow_rules": [{"action": "read", "resource": "ledger"}],
                "deny_rules": [],
            }
        ],
    }
    request_context = {"action": "read", "resource": "ledger"}
    runtime_record = build_runtime_decision_record(
        decision=DECISION_ALLOW,
        policy_pack=policy_pack,
        request_context=request_context,
        tenant_id="t1",
        environment="test",
        risk_level="low",
    )
    try:
        bundle = build_policy_proof_bundle(
            policy_pack,
            request_context,
            runtime_record,
            tenant_id="t1",
            environment="test",
            risk_level="low",
            validation_timestamp="2026-05-12T00:00:00Z",
        )
        anchor = anchor_proof_bundle(bundle, timestamp="2026-05-12T00:00:00Z")
        first = prepare_rfc3161_request_material(bundle, anchor)
        second = prepare_rfc3161_request_material(bundle, anchor)
        if first != second:
            failures.append("GOVERNANCE_RFC3161_TIMESTAMP_PREFLIGHT_NOT_DETERMINISTIC")
    except RFC3161TimestampError as exc:
        failures.append(str(exc))
        first = {}
    invalid = verify_rfc3161_request_material({"schema": "usbay.governance_rfc3161_timestamp_request_preflight.v1"})
    if invalid.valid or "RFC3161_BUNDLE_HASH_MISSING" not in invalid.errors:
        failures.append("GOVERNANCE_INVALID_RFC3161_TIMESTAMP_PREFLIGHT_ALLOWED")
    unsafe_request = dict(first)
    unsafe_request["redacted_metadata_summary"] = {"approval_contents": "do-not-log"}
    unsafe_verification = verify_rfc3161_request_material(unsafe_request)
    if unsafe_verification.valid or "RFC3161_DIAGNOSTICS_UNSAFE" not in unsafe_verification.errors:
        failures.append("GOVERNANCE_UNSAFE_RFC3161_TIMESTAMP_PREFLIGHT_ALLOWED")
    try:
        assert_rfc3161_safe(redacted_rfc3161_payload(first))
    except RFC3161TimestampError as exc:
        failures.append(str(exc))
    return failures


def check_governance_worm_manifest(root: Path) -> list[str]:
    from governance.policy_pack import POLICY_PACK_SCHEMA
    from governance.policy_parity import build_runtime_decision_record
    from governance.policy_proof_bundle import build_policy_proof_bundle
    from governance.policy_simulation import DECISION_ALLOW
    from governance.proof_timestamp_anchor import anchor_proof_bundle
    from governance.rfc3161_timestamp import prepare_rfc3161_request_material
    from governance.worm_evidence_manifest import (
        WORM_ERROR_CODES,
        WORMEvidenceManifestError,
        assert_worm_safe,
        load_worm_error_registry,
        prepare_worm_manifest,
        redacted_worm_payload,
        verify_worm_manifest,
    )

    failures: list[str] = []
    if not (root / "governance" / "worm_evidence_manifest.py").is_file():
        failures.append("GOVERNANCE_WORM_EVIDENCE_MANIFEST_MODULE_MISSING")
    if not (root / "governance" / "worm_evidence_manifest_errors.json").is_file():
        failures.append("GOVERNANCE_WORM_EVIDENCE_MANIFEST_ERROR_REGISTRY_MISSING")
    try:
        registry = load_worm_error_registry(root)
        for code in WORM_ERROR_CODES:
            if code not in registry:
                failures.append(f"GOVERNANCE_WORM_EVIDENCE_MANIFEST_ERROR_CODE_MISSING:{code}")
    except WORMEvidenceManifestError as exc:
        failures.append(str(exc))
    policy_pack = {
        "schema": POLICY_PACK_SCHEMA,
        "fail_closed": True,
        "valid_from": "2026-01-01T00:00:00Z",
        "valid_until": "2027-01-01T00:00:00Z",
        "scope": {"tenant_ids": ["t1"], "environments": ["test"]},
        "policies": [
            {
                "policy_id": "policy.allow.read",
                "risk_level": "low",
                "requires_human_approval": False,
                "fail_closed": True,
                "valid_from": "2026-01-01T00:00:00Z",
                "valid_until": "2027-01-01T00:00:00Z",
                "scope": {"tenant_ids": ["t1"], "environments": ["test"]},
                "allow_rules": [{"action": "read", "resource": "ledger"}],
                "deny_rules": [],
            }
        ],
    }
    request_context = {"action": "read", "resource": "ledger"}
    runtime_record = build_runtime_decision_record(
        decision=DECISION_ALLOW,
        policy_pack=policy_pack,
        request_context=request_context,
        tenant_id="t1",
        environment="test",
        risk_level="low",
    )
    try:
        bundle = build_policy_proof_bundle(
            policy_pack,
            request_context,
            runtime_record,
            tenant_id="t1",
            environment="test",
            risk_level="low",
            validation_timestamp="2026-05-12T00:00:00Z",
        )
        anchor = anchor_proof_bundle(bundle, timestamp="2026-05-12T00:00:00Z")
        rfc3161_request = prepare_rfc3161_request_material(bundle, anchor)
        first = prepare_worm_manifest(
            bundle,
            anchor,
            rfc3161_request,
            retention_policy_label="governance-retain-7y",
            created_at="2026-05-12T00:00:00Z",
        )
        second = prepare_worm_manifest(
            bundle,
            anchor,
            rfc3161_request,
            retention_policy_label="governance-retain-7y",
            created_at="2026-05-12T00:00:00Z",
        )
        if first != second:
            failures.append("GOVERNANCE_WORM_EVIDENCE_MANIFEST_NOT_DETERMINISTIC")
    except WORMEvidenceManifestError as exc:
        failures.append(str(exc))
        first = {}
    invalid = verify_worm_manifest({"schema": "usbay.governance_worm_evidence_manifest.v1"})
    if invalid.valid or "WORM_PROOF_BUNDLE_HASH_MISSING" not in invalid.errors:
        failures.append("GOVERNANCE_INVALID_WORM_EVIDENCE_MANIFEST_ALLOWED")
    unsafe_manifest = dict(first)
    unsafe_manifest["diagnostics"] = {"approval_contents": "do-not-log"}
    unsafe_verification = verify_worm_manifest(unsafe_manifest)
    if unsafe_verification.valid or "WORM_DIAGNOSTICS_UNSAFE" not in unsafe_verification.errors:
        failures.append("GOVERNANCE_UNSAFE_WORM_EVIDENCE_MANIFEST_ALLOWED")
    try:
        assert_worm_safe(redacted_worm_payload(first))
    except WORMEvidenceManifestError as exc:
        failures.append(str(exc))
    return failures


def check_governance_evidence_chain(root: Path) -> list[str]:
    from governance.evidence_chain import (
        EVIDENCE_CHAIN_ERROR_CODES,
        EvidenceChainError,
        append_evidence_chain,
        assert_evidence_chain_safe,
        load_evidence_chain_error_registry,
        redacted_evidence_chain_payload,
        verify_evidence_chain,
    )
    from governance.policy_pack import POLICY_PACK_SCHEMA
    from governance.policy_parity import build_runtime_decision_record
    from governance.policy_proof_bundle import build_policy_proof_bundle
    from governance.policy_simulation import DECISION_ALLOW
    from governance.proof_timestamp_anchor import anchor_proof_bundle
    from governance.rfc3161_timestamp import prepare_rfc3161_request_material
    from governance.worm_evidence_manifest import prepare_worm_manifest

    failures: list[str] = []
    if not (root / "governance" / "evidence_chain.py").is_file():
        failures.append("GOVERNANCE_EVIDENCE_CHAIN_MODULE_MISSING")
    if not (root / "governance" / "evidence_chain_errors.json").is_file():
        failures.append("GOVERNANCE_EVIDENCE_CHAIN_ERROR_REGISTRY_MISSING")
    try:
        registry = load_evidence_chain_error_registry(root)
        for code in EVIDENCE_CHAIN_ERROR_CODES:
            if code not in registry:
                failures.append(f"GOVERNANCE_EVIDENCE_CHAIN_ERROR_CODE_MISSING:{code}")
    except EvidenceChainError as exc:
        failures.append(str(exc))

    def _worm_manifest(policy_id: str):
        policy_pack = {
            "schema": POLICY_PACK_SCHEMA,
            "fail_closed": True,
            "valid_from": "2026-01-01T00:00:00Z",
            "valid_until": "2027-01-01T00:00:00Z",
            "scope": {"tenant_ids": ["t1"], "environments": ["test"]},
            "policies": [
                {
                    "policy_id": policy_id,
                    "risk_level": "low",
                    "requires_human_approval": False,
                    "fail_closed": True,
                    "valid_from": "2026-01-01T00:00:00Z",
                    "valid_until": "2027-01-01T00:00:00Z",
                    "scope": {"tenant_ids": ["t1"], "environments": ["test"]},
                    "allow_rules": [{"action": "read", "resource": "ledger"}],
                    "deny_rules": [],
                }
            ],
        }
        request_context = {"action": "read", "resource": "ledger"}
        runtime_record = build_runtime_decision_record(
            decision=DECISION_ALLOW,
            policy_pack=policy_pack,
            request_context=request_context,
            tenant_id="t1",
            environment="test",
            risk_level="low",
        )
        bundle = build_policy_proof_bundle(
            policy_pack,
            request_context,
            runtime_record,
            tenant_id="t1",
            environment="test",
            risk_level="low",
            validation_timestamp="2026-05-12T00:00:00Z",
        )
        anchor = anchor_proof_bundle(bundle, timestamp="2026-05-12T00:00:00Z")
        rfc3161_request = prepare_rfc3161_request_material(bundle, anchor)
        return prepare_worm_manifest(
            bundle,
            anchor,
            rfc3161_request,
            retention_policy_label="governance-retain-7y",
            created_at="2026-05-12T00:00:00Z",
        )

    try:
        first_manifest = _worm_manifest("policy.allow.read")
        second_manifest = _worm_manifest("policy.allow.other")
        chain = append_evidence_chain(None, first_manifest, timestamp="2026-05-12T00:00:00Z")
        chain = append_evidence_chain(chain, second_manifest, timestamp="2026-05-12T00:01:00Z")
        verification = verify_evidence_chain(chain)
        if not verification.valid or verification.chain_length != 2:
            failures.append("GOVERNANCE_EVIDENCE_CHAIN_APPEND_ONLY_INVALID")
        try:
            append_evidence_chain(chain, second_manifest, timestamp="2026-05-12T00:02:00Z")
            failures.append("GOVERNANCE_EVIDENCE_CHAIN_REPLAY_ALLOWED")
        except EvidenceChainError as exc:
            if str(exc) != "EVIDENCE_CHAIN_REPLAY_DETECTED":
                failures.append(str(exc))
    except EvidenceChainError as exc:
        failures.append(str(exc))
        chain = {}
    invalid = verify_evidence_chain({"schema": "usbay.governance_evidence_chain.v1", "entries": [{}], "chain_hash": ""})
    if invalid.valid or "EVIDENCE_CHAIN_PREVIOUS_HASH_MISSING" not in invalid.errors:
        failures.append("GOVERNANCE_INVALID_EVIDENCE_CHAIN_ALLOWED")
    broken = dict(chain)
    if broken.get("entries"):
        broken["entries"] = [dict(entry) for entry in broken["entries"]]
        broken["entries"][0]["previous_chain_hash"] = "f" * 64
        broken_verification = verify_evidence_chain(broken)
        if broken_verification.valid or "EVIDENCE_CHAIN_CONTINUITY_BROKEN" not in broken_verification.errors:
            failures.append("GOVERNANCE_EVIDENCE_CHAIN_BROKEN_CONTINUITY_ALLOWED")
    unsafe_chain = dict(chain)
    unsafe_chain["diagnostics"] = {"approval_contents": "do-not-log"}
    unsafe_verification = verify_evidence_chain(unsafe_chain)
    if unsafe_verification.valid or "EVIDENCE_CHAIN_DIAGNOSTICS_UNSAFE" not in unsafe_verification.errors:
        failures.append("GOVERNANCE_UNSAFE_EVIDENCE_CHAIN_ALLOWED")
    try:
        assert_evidence_chain_safe(redacted_evidence_chain_payload(chain))
    except EvidenceChainError as exc:
        failures.append(str(exc))
    return failures


def check_governance_merkle_checkpoint(root: Path) -> list[str]:
    from governance.evidence_chain import append_evidence_chain
    from governance.evidence_merkle_checkpoint import (
        MERKLE_ERROR_CODES,
        EvidenceMerkleCheckpointError,
        assert_merkle_safe,
        create_merkle_checkpoint,
        load_merkle_error_registry,
        redacted_merkle_payload,
        verify_merkle_checkpoint,
    )
    from governance.policy_pack import POLICY_PACK_SCHEMA
    from governance.policy_parity import build_runtime_decision_record
    from governance.policy_proof_bundle import build_policy_proof_bundle
    from governance.policy_simulation import DECISION_ALLOW
    from governance.proof_timestamp_anchor import anchor_proof_bundle
    from governance.rfc3161_timestamp import prepare_rfc3161_request_material
    from governance.worm_evidence_manifest import prepare_worm_manifest

    failures: list[str] = []
    if not (root / "governance" / "evidence_merkle_checkpoint.py").is_file():
        failures.append("GOVERNANCE_MERKLE_CHECKPOINT_MODULE_MISSING")
    if not (root / "governance" / "evidence_merkle_checkpoint_errors.json").is_file():
        failures.append("GOVERNANCE_MERKLE_CHECKPOINT_ERROR_REGISTRY_MISSING")
    try:
        registry = load_merkle_error_registry(root)
        for code in MERKLE_ERROR_CODES:
            if code not in registry:
                failures.append(f"GOVERNANCE_MERKLE_CHECKPOINT_ERROR_CODE_MISSING:{code}")
    except EvidenceMerkleCheckpointError as exc:
        failures.append(str(exc))

    def _worm_manifest(policy_id: str):
        policy_pack = {
            "schema": POLICY_PACK_SCHEMA,
            "fail_closed": True,
            "valid_from": "2026-01-01T00:00:00Z",
            "valid_until": "2027-01-01T00:00:00Z",
            "scope": {"tenant_ids": ["t1"], "environments": ["test"]},
            "policies": [
                {
                    "policy_id": policy_id,
                    "risk_level": "low",
                    "requires_human_approval": False,
                    "fail_closed": True,
                    "valid_from": "2026-01-01T00:00:00Z",
                    "valid_until": "2027-01-01T00:00:00Z",
                    "scope": {"tenant_ids": ["t1"], "environments": ["test"]},
                    "allow_rules": [{"action": "read", "resource": "ledger"}],
                    "deny_rules": [],
                }
            ],
        }
        request_context = {"action": "read", "resource": "ledger"}
        runtime_record = build_runtime_decision_record(
            decision=DECISION_ALLOW,
            policy_pack=policy_pack,
            request_context=request_context,
            tenant_id="t1",
            environment="test",
            risk_level="low",
        )
        bundle = build_policy_proof_bundle(
            policy_pack,
            request_context,
            runtime_record,
            tenant_id="t1",
            environment="test",
            risk_level="low",
            validation_timestamp="2026-05-12T00:00:00Z",
        )
        anchor = anchor_proof_bundle(bundle, timestamp="2026-05-12T00:00:00Z")
        rfc3161_request = prepare_rfc3161_request_material(bundle, anchor)
        return prepare_worm_manifest(
            bundle,
            anchor,
            rfc3161_request,
            retention_policy_label="governance-retain-7y",
            created_at="2026-05-12T00:00:00Z",
        )

    try:
        chain = append_evidence_chain(None, _worm_manifest("policy.allow.read"), timestamp="2026-05-12T00:00:00Z")
        chain = append_evidence_chain(chain, _worm_manifest("policy.allow.other"), timestamp="2026-05-12T00:01:00Z")
        checkpoint = create_merkle_checkpoint(
            chain,
            chain_start_position=0,
            chain_end_position=1,
            timestamp="2026-05-12T00:02:00Z",
        )
        verification = verify_merkle_checkpoint(checkpoint, evidence_chain=chain)
        if not verification.valid:
            failures.append("GOVERNANCE_MERKLE_CHECKPOINT_INVALID")
    except EvidenceMerkleCheckpointError as exc:
        failures.append(str(exc))
        checkpoint = {}
    invalid = verify_merkle_checkpoint({"schema": "usbay.governance_evidence_merkle_checkpoint.v1"})
    if invalid.valid or "MERKLE_LEAVES_MISSING" not in invalid.errors:
        failures.append("GOVERNANCE_INVALID_MERKLE_CHECKPOINT_ALLOWED")
    unsafe_checkpoint = dict(checkpoint)
    unsafe_checkpoint["diagnostics"] = {"approval_contents": "do-not-log"}
    unsafe_verification = verify_merkle_checkpoint(unsafe_checkpoint)
    if unsafe_verification.valid or "MERKLE_DIAGNOSTICS_UNSAFE" not in unsafe_verification.errors:
        failures.append("GOVERNANCE_UNSAFE_MERKLE_CHECKPOINT_ALLOWED")
    try:
        assert_merkle_safe(redacted_merkle_payload(checkpoint))
    except EvidenceMerkleCheckpointError as exc:
        failures.append(str(exc))
    return failures


def check_governance_merkle_inclusion(root: Path) -> list[str]:
    from governance.evidence_chain import append_evidence_chain
    from governance.evidence_merkle_checkpoint import create_merkle_checkpoint
    from governance.evidence_merkle_inclusion import (
        MERKLE_INCLUSION_ERROR_CODES,
        EvidenceMerkleInclusionError,
        assert_inclusion_safe,
        create_merkle_inclusion_proof,
        load_merkle_inclusion_error_registry,
        redacted_inclusion_payload,
        verify_merkle_inclusion_proof,
    )
    from governance.policy_pack import POLICY_PACK_SCHEMA
    from governance.policy_parity import build_runtime_decision_record
    from governance.policy_proof_bundle import build_policy_proof_bundle
    from governance.policy_simulation import DECISION_ALLOW
    from governance.proof_timestamp_anchor import anchor_proof_bundle
    from governance.rfc3161_timestamp import prepare_rfc3161_request_material
    from governance.worm_evidence_manifest import prepare_worm_manifest

    failures: list[str] = []
    if not (root / "governance" / "evidence_merkle_inclusion.py").is_file():
        failures.append("GOVERNANCE_MERKLE_INCLUSION_MODULE_MISSING")
    if not (root / "governance" / "evidence_merkle_inclusion_errors.json").is_file():
        failures.append("GOVERNANCE_MERKLE_INCLUSION_ERROR_REGISTRY_MISSING")
    try:
        registry = load_merkle_inclusion_error_registry(root)
        for code in MERKLE_INCLUSION_ERROR_CODES:
            if code not in registry:
                failures.append(f"GOVERNANCE_MERKLE_INCLUSION_ERROR_CODE_MISSING:{code}")
    except EvidenceMerkleInclusionError as exc:
        failures.append(str(exc))

    def _worm_manifest(policy_id: str):
        policy_pack = {
            "schema": POLICY_PACK_SCHEMA,
            "fail_closed": True,
            "valid_from": "2026-01-01T00:00:00Z",
            "valid_until": "2027-01-01T00:00:00Z",
            "scope": {"tenant_ids": ["t1"], "environments": ["test"]},
            "policies": [
                {
                    "policy_id": policy_id,
                    "risk_level": "low",
                    "requires_human_approval": False,
                    "fail_closed": True,
                    "valid_from": "2026-01-01T00:00:00Z",
                    "valid_until": "2027-01-01T00:00:00Z",
                    "scope": {"tenant_ids": ["t1"], "environments": ["test"]},
                    "allow_rules": [{"action": "read", "resource": "ledger"}],
                    "deny_rules": [],
                }
            ],
        }
        request_context = {"action": "read", "resource": "ledger"}
        runtime_record = build_runtime_decision_record(
            decision=DECISION_ALLOW,
            policy_pack=policy_pack,
            request_context=request_context,
            tenant_id="t1",
            environment="test",
            risk_level="low",
        )
        bundle = build_policy_proof_bundle(
            policy_pack,
            request_context,
            runtime_record,
            tenant_id="t1",
            environment="test",
            risk_level="low",
            validation_timestamp="2026-05-12T00:00:00Z",
        )
        anchor = anchor_proof_bundle(bundle, timestamp="2026-05-12T00:00:00Z")
        rfc3161_request = prepare_rfc3161_request_material(bundle, anchor)
        return prepare_worm_manifest(
            bundle,
            anchor,
            rfc3161_request,
            retention_policy_label="governance-retain-7y",
            created_at="2026-05-12T00:00:00Z",
        )

    try:
        chain = append_evidence_chain(None, _worm_manifest("policy.allow.read"), timestamp="2026-05-12T00:00:00Z")
        chain = append_evidence_chain(chain, _worm_manifest("policy.allow.other"), timestamp="2026-05-12T00:01:00Z")
        checkpoint = create_merkle_checkpoint(
            chain,
            chain_start_position=0,
            chain_end_position=1,
            timestamp="2026-05-12T00:02:00Z",
        )
        proof = create_merkle_inclusion_proof(checkpoint, leaf_index=1)
        verification = verify_merkle_inclusion_proof(proof, checkpoint=checkpoint)
        if not verification.valid:
            failures.append("GOVERNANCE_MERKLE_INCLUSION_INVALID")
    except EvidenceMerkleInclusionError as exc:
        failures.append(str(exc))
        proof = {}
    invalid = verify_merkle_inclusion_proof({"schema": "usbay.governance_evidence_merkle_inclusion.v1"})
    if invalid.valid or "MERKLE_INCLUSION_LEAF_MISSING" not in invalid.errors:
        failures.append("GOVERNANCE_INVALID_MERKLE_INCLUSION_ALLOWED")
    unsafe_proof = dict(proof)
    unsafe_proof["diagnostics"] = {"approval_contents": "do-not-log"}
    unsafe_verification = verify_merkle_inclusion_proof(unsafe_proof)
    if unsafe_verification.valid or "MERKLE_INCLUSION_DIAGNOSTICS_UNSAFE" not in unsafe_verification.errors:
        failures.append("GOVERNANCE_UNSAFE_MERKLE_INCLUSION_ALLOWED")
    try:
        assert_inclusion_safe(redacted_inclusion_payload(proof))
    except EvidenceMerkleInclusionError as exc:
        failures.append(str(exc))
    return failures


def check_governance_merkle_consistency(root: Path) -> list[str]:
    from governance.evidence_chain import append_evidence_chain
    from governance.evidence_merkle_checkpoint import create_merkle_checkpoint
    from governance.evidence_merkle_consistency import (
        MERKLE_CONSISTENCY_ERROR_CODES,
        EvidenceMerkleConsistencyError,
        assert_consistency_safe,
        create_merkle_consistency_proof,
        load_merkle_consistency_error_registry,
        redacted_consistency_payload,
        verify_merkle_consistency_proof,
    )
    from governance.policy_pack import POLICY_PACK_SCHEMA
    from governance.policy_parity import build_runtime_decision_record
    from governance.policy_proof_bundle import build_policy_proof_bundle
    from governance.policy_simulation import DECISION_ALLOW
    from governance.proof_timestamp_anchor import anchor_proof_bundle
    from governance.rfc3161_timestamp import prepare_rfc3161_request_material
    from governance.worm_evidence_manifest import prepare_worm_manifest

    failures: list[str] = []
    if not (root / "governance" / "evidence_merkle_consistency.py").is_file():
        failures.append("GOVERNANCE_MERKLE_CONSISTENCY_MODULE_MISSING")
    if not (root / "governance" / "evidence_merkle_consistency_errors.json").is_file():
        failures.append("GOVERNANCE_MERKLE_CONSISTENCY_ERROR_REGISTRY_MISSING")
    try:
        registry = load_merkle_consistency_error_registry(root)
        for code in MERKLE_CONSISTENCY_ERROR_CODES:
            if code not in registry:
                failures.append(f"GOVERNANCE_MERKLE_CONSISTENCY_ERROR_CODE_MISSING:{code}")
    except EvidenceMerkleConsistencyError as exc:
        failures.append(str(exc))

    def _worm_manifest(policy_id: str):
        policy_pack = {
            "schema": POLICY_PACK_SCHEMA,
            "fail_closed": True,
            "valid_from": "2026-01-01T00:00:00Z",
            "valid_until": "2027-01-01T00:00:00Z",
            "scope": {"tenant_ids": ["t1"], "environments": ["test"]},
            "policies": [
                {
                    "policy_id": policy_id,
                    "risk_level": "low",
                    "requires_human_approval": False,
                    "fail_closed": True,
                    "valid_from": "2026-01-01T00:00:00Z",
                    "valid_until": "2027-01-01T00:00:00Z",
                    "scope": {"tenant_ids": ["t1"], "environments": ["test"]},
                    "allow_rules": [{"action": "read", "resource": "ledger"}],
                    "deny_rules": [],
                }
            ],
        }
        request_context = {"action": "read", "resource": "ledger"}
        runtime_record = build_runtime_decision_record(
            decision=DECISION_ALLOW,
            policy_pack=policy_pack,
            request_context=request_context,
            tenant_id="t1",
            environment="test",
            risk_level="low",
        )
        bundle = build_policy_proof_bundle(
            policy_pack,
            request_context,
            runtime_record,
            tenant_id="t1",
            environment="test",
            risk_level="low",
            validation_timestamp="2026-05-12T00:00:00Z",
        )
        anchor = anchor_proof_bundle(bundle, timestamp="2026-05-12T00:00:00Z")
        rfc3161_request = prepare_rfc3161_request_material(bundle, anchor)
        return prepare_worm_manifest(
            bundle,
            anchor,
            rfc3161_request,
            retention_policy_label="governance-retain-7y",
            created_at="2026-05-12T00:00:00Z",
        )

    try:
        chain = append_evidence_chain(None, _worm_manifest("policy.allow.read"), timestamp="2026-05-12T00:00:00Z")
        previous_checkpoint = create_merkle_checkpoint(
            chain,
            chain_start_position=0,
            chain_end_position=0,
            timestamp="2026-05-12T00:01:00Z",
        )
        chain = append_evidence_chain(chain, _worm_manifest("policy.allow.other"), timestamp="2026-05-12T00:02:00Z")
        current_checkpoint = create_merkle_checkpoint(
            chain,
            chain_start_position=0,
            chain_end_position=1,
            timestamp="2026-05-12T00:03:00Z",
        )
        proof = create_merkle_consistency_proof(previous_checkpoint, current_checkpoint)
        verification = verify_merkle_consistency_proof(
            proof,
            previous_checkpoint=previous_checkpoint,
            current_checkpoint=current_checkpoint,
        )
        if not verification.valid:
            failures.append("GOVERNANCE_MERKLE_CONSISTENCY_INVALID")
    except EvidenceMerkleConsistencyError as exc:
        failures.append(str(exc))
        proof = {}
    invalid = verify_merkle_consistency_proof({"schema": "usbay.governance_evidence_merkle_consistency.v1"})
    if invalid.valid or "MERKLE_CONSISTENCY_PREVIOUS_MISSING" not in invalid.errors:
        failures.append("GOVERNANCE_INVALID_MERKLE_CONSISTENCY_ALLOWED")
    unsafe_proof = dict(proof)
    unsafe_proof["diagnostics"] = {"approval_contents": "do-not-log"}
    unsafe_verification = verify_merkle_consistency_proof(unsafe_proof)
    if unsafe_verification.valid or "MERKLE_CONSISTENCY_DIAGNOSTICS_UNSAFE" not in unsafe_verification.errors:
        failures.append("GOVERNANCE_UNSAFE_MERKLE_CONSISTENCY_ALLOWED")
    try:
        assert_consistency_safe(redacted_consistency_payload(proof))
    except EvidenceMerkleConsistencyError as exc:
        failures.append(str(exc))
    return failures


def check_governance_auditor_bundle(root: Path) -> list[str]:
    from governance.auditor_verification_bundle import (
        AUDITOR_BUNDLE_ERROR_CODES,
        AuditorVerificationBundleError,
        assert_auditor_bundle_safe,
        create_auditor_verification_bundle,
        load_auditor_bundle_error_registry,
        redacted_auditor_bundle_payload,
        verify_auditor_verification_bundle,
    )
    from governance.evidence_chain import append_evidence_chain
    from governance.evidence_merkle_checkpoint import create_merkle_checkpoint
    from governance.evidence_merkle_consistency import create_merkle_consistency_proof
    from governance.evidence_merkle_inclusion import create_merkle_inclusion_proof
    from governance.policy_pack import POLICY_PACK_SCHEMA
    from governance.policy_parity import build_runtime_decision_record
    from governance.policy_proof_bundle import build_policy_proof_bundle
    from governance.policy_simulation import DECISION_ALLOW
    from governance.proof_timestamp_anchor import anchor_proof_bundle
    from governance.rfc3161_timestamp import prepare_rfc3161_request_material
    from governance.worm_evidence_manifest import prepare_worm_manifest

    failures: list[str] = []
    if not (root / "governance" / "auditor_verification_bundle.py").is_file():
        failures.append("GOVERNANCE_AUDITOR_BUNDLE_MODULE_MISSING")
    if not (root / "governance" / "auditor_verification_bundle_errors.json").is_file():
        failures.append("GOVERNANCE_AUDITOR_BUNDLE_ERROR_REGISTRY_MISSING")
    try:
        registry = load_auditor_bundle_error_registry(root)
        for code in AUDITOR_BUNDLE_ERROR_CODES:
            if code not in registry:
                failures.append(f"GOVERNANCE_AUDITOR_BUNDLE_ERROR_CODE_MISSING:{code}")
    except AuditorVerificationBundleError as exc:
        failures.append(str(exc))

    def _worm_manifest(policy_id: str):
        policy_pack = {
            "schema": POLICY_PACK_SCHEMA,
            "fail_closed": True,
            "valid_from": "2026-01-01T00:00:00Z",
            "valid_until": "2027-01-01T00:00:00Z",
            "scope": {"tenant_ids": ["t1"], "environments": ["test"]},
            "policies": [
                {
                    "policy_id": policy_id,
                    "risk_level": "low",
                    "requires_human_approval": False,
                    "fail_closed": True,
                    "valid_from": "2026-01-01T00:00:00Z",
                    "valid_until": "2027-01-01T00:00:00Z",
                    "scope": {"tenant_ids": ["t1"], "environments": ["test"]},
                    "allow_rules": [{"action": "read", "resource": "ledger"}],
                    "deny_rules": [],
                }
            ],
        }
        request_context = {"action": "read", "resource": "ledger"}
        runtime_record = build_runtime_decision_record(
            decision=DECISION_ALLOW,
            policy_pack=policy_pack,
            request_context=request_context,
            tenant_id="t1",
            environment="test",
            risk_level="low",
        )
        bundle = build_policy_proof_bundle(
            policy_pack,
            request_context,
            runtime_record,
            tenant_id="t1",
            environment="test",
            risk_level="low",
            validation_timestamp="2026-05-12T00:00:00Z",
        )
        anchor = anchor_proof_bundle(bundle, timestamp="2026-05-12T00:00:00Z")
        rfc3161_request = prepare_rfc3161_request_material(bundle, anchor)
        return prepare_worm_manifest(
            bundle,
            anchor,
            rfc3161_request,
            retention_policy_label="governance-retain-7y",
            created_at="2026-05-12T00:00:00Z",
        )

    try:
        chain = append_evidence_chain(None, _worm_manifest("policy.allow.read"), timestamp="2026-05-12T00:00:00Z")
        previous_checkpoint = create_merkle_checkpoint(chain, chain_start_position=0, chain_end_position=0, timestamp="2026-05-12T00:01:00Z")
        chain = append_evidence_chain(chain, _worm_manifest("policy.allow.other"), timestamp="2026-05-12T00:02:00Z")
        current_checkpoint = create_merkle_checkpoint(chain, chain_start_position=0, chain_end_position=1, timestamp="2026-05-12T00:03:00Z")
        inclusion_proof = create_merkle_inclusion_proof(current_checkpoint, leaf_index=1)
        consistency_proof = create_merkle_consistency_proof(previous_checkpoint, current_checkpoint)
        bundle = create_auditor_verification_bundle(
            current_checkpoint,
            inclusion_proof,
            consistency_proof,
            verification_scope={"tenant_id": "t1", "environment": "test", "purpose": "production-readiness"},
            timestamp="2026-05-12T00:04:00Z",
        )
        verification = verify_auditor_verification_bundle(bundle)
        if not verification.valid:
            failures.append("GOVERNANCE_AUDITOR_BUNDLE_INVALID")
    except AuditorVerificationBundleError as exc:
        failures.append(str(exc))
        bundle = {}
    invalid = verify_auditor_verification_bundle({"schema": "usbay.governance_auditor_verification_bundle.v1"})
    if invalid.valid or "AUDITOR_BUNDLE_CHECKPOINT_MISSING" not in invalid.errors:
        failures.append("GOVERNANCE_INVALID_AUDITOR_BUNDLE_ALLOWED")
    unsafe_bundle = dict(bundle)
    unsafe_bundle["diagnostics"] = {"approval_contents": "do-not-log"}
    unsafe_verification = verify_auditor_verification_bundle(unsafe_bundle)
    if unsafe_verification.valid or "AUDITOR_BUNDLE_DIAGNOSTICS_UNSAFE" not in unsafe_verification.errors:
        failures.append("GOVERNANCE_UNSAFE_AUDITOR_BUNDLE_ALLOWED")
    try:
        assert_auditor_bundle_safe(redacted_auditor_bundle_payload(bundle))
    except AuditorVerificationBundleError as exc:
        failures.append(str(exc))
    return failures


def check_governance_signed_auditor_bundle(root: Path) -> list[str]:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    from governance.auditor_verification_bundle import create_auditor_verification_bundle
    from governance.evidence_chain import append_evidence_chain
    from governance.evidence_merkle_checkpoint import create_merkle_checkpoint
    from governance.evidence_merkle_consistency import create_merkle_consistency_proof
    from governance.evidence_merkle_inclusion import create_merkle_inclusion_proof
    from governance.policy_pack import POLICY_PACK_SCHEMA
    from governance.policy_parity import build_runtime_decision_record
    from governance.policy_proof_bundle import build_policy_proof_bundle
    from governance.policy_simulation import DECISION_ALLOW
    from governance.proof_timestamp_anchor import anchor_proof_bundle
    from governance.rfc3161_timestamp import prepare_rfc3161_request_material
    from governance.signed_auditor_bundle import (
        SIGNED_AUDITOR_BUNDLE_ERROR_CODES,
        SignedAuditorBundleError,
        assert_signed_auditor_bundle_safe,
        create_signed_auditor_bundle,
        load_signed_auditor_bundle_error_registry,
        redacted_signed_auditor_bundle_payload,
        signer_key_fingerprint,
        verify_signed_auditor_bundle,
    )
    from governance.worm_evidence_manifest import prepare_worm_manifest

    failures: list[str] = []
    if not (root / "governance" / "signed_auditor_bundle.py").is_file():
        failures.append("GOVERNANCE_SIGNED_AUDITOR_BUNDLE_MODULE_MISSING")
    if not (root / "governance" / "signed_auditor_bundle_errors.json").is_file():
        failures.append("GOVERNANCE_SIGNED_AUDITOR_BUNDLE_ERROR_REGISTRY_MISSING")
    try:
        registry = load_signed_auditor_bundle_error_registry(root)
        for code in SIGNED_AUDITOR_BUNDLE_ERROR_CODES:
            if code not in registry:
                failures.append(f"GOVERNANCE_SIGNED_AUDITOR_BUNDLE_ERROR_CODE_MISSING:{code}")
    except SignedAuditorBundleError as exc:
        failures.append(str(exc))

    def _worm_manifest(policy_id: str):
        policy_pack = {
            "schema": POLICY_PACK_SCHEMA,
            "fail_closed": True,
            "valid_from": "2026-01-01T00:00:00Z",
            "valid_until": "2027-01-01T00:00:00Z",
            "scope": {"tenant_ids": ["t1"], "environments": ["test"]},
            "policies": [
                {
                    "policy_id": policy_id,
                    "risk_level": "low",
                    "requires_human_approval": False,
                    "fail_closed": True,
                    "valid_from": "2026-01-01T00:00:00Z",
                    "valid_until": "2027-01-01T00:00:00Z",
                    "scope": {"tenant_ids": ["t1"], "environments": ["test"]},
                    "allow_rules": [{"action": "read", "resource": "ledger"}],
                    "deny_rules": [],
                }
            ],
        }
        request_context = {"action": "read", "resource": "ledger"}
        runtime_record = build_runtime_decision_record(
            decision=DECISION_ALLOW,
            policy_pack=policy_pack,
            request_context=request_context,
            tenant_id="t1",
            environment="test",
            risk_level="low",
        )
        bundle = build_policy_proof_bundle(
            policy_pack,
            request_context,
            runtime_record,
            tenant_id="t1",
            environment="test",
            risk_level="low",
            validation_timestamp="2026-05-12T00:00:00Z",
        )
        anchor = anchor_proof_bundle(bundle, timestamp="2026-05-12T00:00:00Z")
        rfc3161_request = prepare_rfc3161_request_material(bundle, anchor)
        return prepare_worm_manifest(
            bundle,
            anchor,
            rfc3161_request,
            retention_policy_label="governance-retain-7y",
            created_at="2026-05-12T00:00:00Z",
        )

    try:
        key = Ed25519PrivateKey.generate()
        private_key = key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ).decode("utf-8")
        public_key = key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode("utf-8")
        signer_id = "production-readiness-signed-auditor-test"
        trust_policy = {
            "policy_version": "signed-auditor-test-v1",
            "allowed_signers": [
                {
                    "signer_id": signer_id,
                    "public_key_fingerprint": signer_key_fingerprint(public_key),
                    "public_key_pem": public_key,
                    "valid_from": "2026-01-01T00:00:00Z",
                    "valid_until": "2027-01-01T00:00:00Z",
                }
            ],
            "revoked_fingerprints": [],
        }
        chain = append_evidence_chain(None, _worm_manifest("policy.allow.read"), timestamp="2026-05-12T00:00:00Z")
        previous_checkpoint = create_merkle_checkpoint(chain, chain_start_position=0, chain_end_position=0, timestamp="2026-05-12T00:01:00Z")
        chain = append_evidence_chain(chain, _worm_manifest("policy.allow.other"), timestamp="2026-05-12T00:02:00Z")
        current_checkpoint = create_merkle_checkpoint(chain, chain_start_position=0, chain_end_position=1, timestamp="2026-05-12T00:03:00Z")
        auditor_bundle = create_auditor_verification_bundle(
            current_checkpoint,
            create_merkle_inclusion_proof(current_checkpoint, leaf_index=1),
            create_merkle_consistency_proof(previous_checkpoint, current_checkpoint),
            verification_scope={"tenant_id": "t1", "environment": "test", "purpose": "production-readiness"},
            timestamp="2026-05-12T00:04:00Z",
        )
        envelope = create_signed_auditor_bundle(
            auditor_bundle,
            private_key_pem=private_key,
            public_key_pem=public_key,
            signer_id=signer_id,
            trust_policy=trust_policy,
            signed_at_utc="2026-05-12T00:05:00Z",
        )
        verification = verify_signed_auditor_bundle(envelope, auditor_bundle=auditor_bundle, trust_policy=trust_policy)
        if not verification.valid:
            failures.append("GOVERNANCE_SIGNED_AUDITOR_BUNDLE_INVALID")
    except SignedAuditorBundleError as exc:
        failures.append(str(exc))
        envelope = {}
        trust_policy = {}
    invalid = verify_signed_auditor_bundle({"schema": "usbay.governance_signed_auditor_bundle.v1"}, trust_policy=trust_policy)
    if invalid.valid or "SIGNED_BUNDLE_HASH_MISMATCH" not in invalid.errors:
        failures.append("GOVERNANCE_INVALID_SIGNED_AUDITOR_BUNDLE_ALLOWED")
    unsafe_envelope = dict(envelope)
    unsafe_envelope["diagnostics"] = {"approval_contents": "do-not-log"}
    unsafe_verification = verify_signed_auditor_bundle(unsafe_envelope, trust_policy=trust_policy)
    if unsafe_verification.valid or "SIGNED_BUNDLE_DIAGNOSTICS_UNSAFE" not in unsafe_verification.errors:
        failures.append("GOVERNANCE_UNSAFE_SIGNED_AUDITOR_BUNDLE_ALLOWED")
    try:
        assert_signed_auditor_bundle_safe(redacted_signed_auditor_bundle_payload(envelope))
    except SignedAuditorBundleError as exc:
        failures.append(str(exc))
    return failures


def check_governance_signed_bundle_timestamp(root: Path) -> list[str]:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    from governance.auditor_verification_bundle import create_auditor_verification_bundle
    from governance.evidence_chain import append_evidence_chain
    from governance.evidence_merkle_checkpoint import create_merkle_checkpoint
    from governance.evidence_merkle_consistency import create_merkle_consistency_proof
    from governance.evidence_merkle_inclusion import create_merkle_inclusion_proof
    from governance.policy_pack import POLICY_PACK_SCHEMA
    from governance.policy_parity import build_runtime_decision_record
    from governance.policy_proof_bundle import build_policy_proof_bundle
    from governance.policy_simulation import DECISION_ALLOW
    from governance.proof_timestamp_anchor import anchor_proof_bundle
    from governance.rfc3161_timestamp import DEFAULT_POLICY_OID_PLACEHOLDER, prepare_rfc3161_request_material
    from governance.signed_auditor_bundle import create_signed_auditor_bundle, signer_key_fingerprint
    from governance.signed_bundle_timestamp import (
        SIGNED_BUNDLE_TIMESTAMP_ERROR_CODES,
        SignedBundleTimestampError,
        assert_signed_bundle_timestamp_safe,
        attach_signed_bundle_timestamp,
        load_signed_bundle_timestamp_error_registry,
        redacted_signed_bundle_timestamp_payload,
        verify_signed_bundle_timestamp,
    )
    from governance.worm_evidence_manifest import prepare_worm_manifest

    failures: list[str] = []
    if not (root / "governance" / "signed_bundle_timestamp.py").is_file():
        failures.append("GOVERNANCE_SIGNED_BUNDLE_TIMESTAMP_MODULE_MISSING")
    if not (root / "governance" / "signed_bundle_timestamp_errors.json").is_file():
        failures.append("GOVERNANCE_SIGNED_BUNDLE_TIMESTAMP_ERROR_REGISTRY_MISSING")
    try:
        registry = load_signed_bundle_timestamp_error_registry(root)
        for code in SIGNED_BUNDLE_TIMESTAMP_ERROR_CODES:
            if code not in registry:
                failures.append(f"GOVERNANCE_SIGNED_BUNDLE_TIMESTAMP_ERROR_CODE_MISSING:{code}")
    except SignedBundleTimestampError as exc:
        failures.append(str(exc))

    def _worm_manifest(policy_id: str):
        policy_pack = {
            "schema": POLICY_PACK_SCHEMA,
            "fail_closed": True,
            "valid_from": "2026-01-01T00:00:00Z",
            "valid_until": "2027-01-01T00:00:00Z",
            "scope": {"tenant_ids": ["t1"], "environments": ["test"]},
            "policies": [
                {
                    "policy_id": policy_id,
                    "risk_level": "low",
                    "requires_human_approval": False,
                    "fail_closed": True,
                    "valid_from": "2026-01-01T00:00:00Z",
                    "valid_until": "2027-01-01T00:00:00Z",
                    "scope": {"tenant_ids": ["t1"], "environments": ["test"]},
                    "allow_rules": [{"action": "read", "resource": "ledger"}],
                    "deny_rules": [],
                }
            ],
        }
        request_context = {"action": "read", "resource": "ledger"}
        runtime_record = build_runtime_decision_record(
            decision=DECISION_ALLOW,
            policy_pack=policy_pack,
            request_context=request_context,
            tenant_id="t1",
            environment="test",
            risk_level="low",
        )
        bundle = build_policy_proof_bundle(
            policy_pack,
            request_context,
            runtime_record,
            tenant_id="t1",
            environment="test",
            risk_level="low",
            validation_timestamp="2026-05-12T00:00:00Z",
        )
        anchor = anchor_proof_bundle(bundle, timestamp="2026-05-12T00:00:00Z")
        rfc3161_request = prepare_rfc3161_request_material(bundle, anchor)
        return prepare_worm_manifest(
            bundle,
            anchor,
            rfc3161_request,
            retention_policy_label="governance-retain-7y",
            created_at="2026-05-12T00:00:00Z",
        )

    try:
        key = Ed25519PrivateKey.generate()
        private_key = key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ).decode("utf-8")
        public_key = key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode("utf-8")
        signer_id = "production-readiness-signed-bundle-timestamp-test"
        trust_policy = {
            "policy_version": "signed-bundle-timestamp-test-v1",
            "allowed_signers": [
                {
                    "signer_id": signer_id,
                    "public_key_fingerprint": signer_key_fingerprint(public_key),
                    "public_key_pem": public_key,
                    "valid_from": "2026-01-01T00:00:00Z",
                    "valid_until": "2027-01-01T00:00:00Z",
                }
            ],
            "revoked_fingerprints": [],
        }
        chain = append_evidence_chain(None, _worm_manifest("policy.allow.read"), timestamp="2026-05-12T00:00:00Z")
        previous_checkpoint = create_merkle_checkpoint(chain, chain_start_position=0, chain_end_position=0, timestamp="2026-05-12T00:01:00Z")
        chain = append_evidence_chain(chain, _worm_manifest("policy.allow.other"), timestamp="2026-05-12T00:02:00Z")
        current_checkpoint = create_merkle_checkpoint(chain, chain_start_position=0, chain_end_position=1, timestamp="2026-05-12T00:03:00Z")
        auditor_bundle = create_auditor_verification_bundle(
            current_checkpoint,
            create_merkle_inclusion_proof(current_checkpoint, leaf_index=1),
            create_merkle_consistency_proof(previous_checkpoint, current_checkpoint),
            verification_scope={"tenant_id": "t1", "environment": "test", "purpose": "production-readiness"},
            timestamp="2026-05-12T00:04:00Z",
        )
        envelope = create_signed_auditor_bundle(
            auditor_bundle,
            private_key_pem=private_key,
            public_key_pem=public_key,
            signer_id=signer_id,
            trust_policy=trust_policy,
            signed_at_utc="2026-05-12T00:05:00Z",
        )
        attachment = attach_signed_bundle_timestamp(
            envelope,
            trust_policy=trust_policy,
            tsa_policy_id=DEFAULT_POLICY_OID_PLACEHOLDER,
            tsa_gen_time_utc="2026-05-12T00:06:00Z",
        )
        verification = verify_signed_bundle_timestamp(attachment, signed_bundle=envelope)
        if not verification.valid:
            failures.append("GOVERNANCE_SIGNED_BUNDLE_TIMESTAMP_INVALID")
    except SignedBundleTimestampError as exc:
        failures.append(str(exc))
        attachment = {}
    invalid = verify_signed_bundle_timestamp({"schema": "usbay.governance_signed_bundle_timestamp.v1"})
    if invalid.valid or "SIGNED_BUNDLE_TIMESTAMP_HASH_MISMATCH" not in invalid.errors:
        failures.append("GOVERNANCE_INVALID_SIGNED_BUNDLE_TIMESTAMP_ALLOWED")
    unsafe_attachment = dict(attachment)
    unsafe_attachment["diagnostics"] = {"approval_contents": "do-not-log"}
    unsafe_verification = verify_signed_bundle_timestamp(unsafe_attachment)
    if unsafe_verification.valid or "SIGNED_BUNDLE_TIMESTAMP_DIAGNOSTICS_UNSAFE" not in unsafe_verification.errors:
        failures.append("GOVERNANCE_UNSAFE_SIGNED_BUNDLE_TIMESTAMP_ALLOWED")
    try:
        assert_signed_bundle_timestamp_safe(redacted_signed_bundle_timestamp_payload(attachment))
    except SignedBundleTimestampError as exc:
        failures.append(str(exc))
    return failures


def check_governance_signed_bundle_ltv(root: Path) -> list[str]:
    from governance.signed_bundle_ltv import (
        SIGNED_BUNDLE_LTV_ERROR_CODES,
        SignedBundleLTVError,
        assert_signed_bundle_ltv_safe,
        create_signed_bundle_ltv_evidence,
        load_signed_bundle_ltv_error_registry,
        redacted_signed_bundle_ltv_payload,
        verify_signed_bundle_ltv_evidence,
    )
    from tests.test_governance_signed_bundle_timestamp import _attachment

    failures: list[str] = []
    if not (root / "governance" / "signed_bundle_ltv.py").is_file():
        failures.append("GOVERNANCE_SIGNED_BUNDLE_LTV_MODULE_MISSING")
    if not (root / "governance" / "signed_bundle_ltv_errors.json").is_file():
        failures.append("GOVERNANCE_SIGNED_BUNDLE_LTV_ERROR_REGISTRY_MISSING")
    try:
        registry = load_signed_bundle_ltv_error_registry(root)
        for code in SIGNED_BUNDLE_LTV_ERROR_CODES:
            if code not in registry:
                failures.append(f"GOVERNANCE_SIGNED_BUNDLE_LTV_ERROR_CODE_MISSING:{code}")
    except SignedBundleLTVError as exc:
        failures.append(str(exc))
    try:
        timestamp_attachment, _signed_bundle, _policy = _attachment()
        evidence = create_signed_bundle_ltv_evidence(
            timestamp_attachment,
            tsa_certificate_fingerprint="a" * 64,
            tsa_certificate_chain_fingerprints=["a" * 64, "b" * 64],
            trust_anchor_fingerprint="b" * 64,
            revocation_evidence_type="offline_mock",
            revocation_evidence_hash="c" * 64,
            revocation_checked_at_utc="2026-05-12T00:07:00Z",
            validation_policy_id="usb.ltv.v1",
        )
        verification = verify_signed_bundle_ltv_evidence(evidence, timestamp_attachment=timestamp_attachment)
        if not verification.valid:
            failures.append("GOVERNANCE_SIGNED_BUNDLE_LTV_INVALID")
    except SignedBundleLTVError as exc:
        failures.append(str(exc))
        evidence = {}
    invalid = verify_signed_bundle_ltv_evidence({"schema": "usbay.governance_signed_bundle_ltv.v1"})
    if invalid.valid or "SIGNED_BUNDLE_LTV_TIMESTAMP_MISSING" not in invalid.errors:
        failures.append("GOVERNANCE_INVALID_SIGNED_BUNDLE_LTV_ALLOWED")
    unsafe_evidence = dict(evidence)
    unsafe_evidence["diagnostics"] = {"approval_contents": "do-not-log"}
    unsafe_verification = verify_signed_bundle_ltv_evidence(unsafe_evidence)
    if unsafe_verification.valid or "SIGNED_BUNDLE_LTV_DIAGNOSTICS_UNSAFE" not in unsafe_verification.errors:
        failures.append("GOVERNANCE_UNSAFE_SIGNED_BUNDLE_LTV_ALLOWED")
    try:
        assert_signed_bundle_ltv_safe(redacted_signed_bundle_ltv_payload(evidence))
    except SignedBundleLTVError as exc:
        failures.append(str(exc))
    return failures


def check_governance_tsa_live_verification(root: Path) -> list[str]:
    from governance.tsa_live_verification import (
        TSA_LIVE_VERIFICATION_ERROR_CODES,
        TSALiveVerificationError,
        assert_tsa_live_verification_safe,
        load_tsa_live_verification_error_registry,
        prepare_tsa_live_verification_plan,
        redacted_tsa_live_verification_payload,
        verify_tsa_live_verification_plan,
    )
    from tests.test_governance_signed_bundle_timestamp import _attachment

    failures: list[str] = []
    if not (root / "governance" / "tsa_live_verification.py").is_file():
        failures.append("GOVERNANCE_TSA_LIVE_VERIFICATION_MODULE_MISSING")
    if not (root / "governance" / "tsa_live_verification_errors.json").is_file():
        failures.append("GOVERNANCE_TSA_LIVE_VERIFICATION_ERROR_REGISTRY_MISSING")
    try:
        registry = load_tsa_live_verification_error_registry(root)
        for code in TSA_LIVE_VERIFICATION_ERROR_CODES:
            if code not in registry:
                failures.append(f"GOVERNANCE_TSA_LIVE_VERIFICATION_ERROR_CODE_MISSING:{code}")
    except TSALiveVerificationError as exc:
        failures.append(str(exc))
    try:
        attachment, _signed_bundle, _policy = _attachment()
        plan = prepare_tsa_live_verification_plan(
            attachment,
            verification_checked_at_utc="2026-05-12T00:07:00Z",
        )
        verification = verify_tsa_live_verification_plan(plan, timestamp_attachment=attachment)
        if not verification.valid:
            failures.append("GOVERNANCE_TSA_LIVE_VERIFICATION_INVALID")
    except TSALiveVerificationError as exc:
        failures.append(str(exc))
        plan = {}
    invalid = verify_tsa_live_verification_plan({"schema": "usbay.governance_tsa_live_verification.v1"})
    if invalid.valid or "TSA_LIVE_TIMESTAMP_ATTACHMENT_MISSING" not in invalid.errors:
        failures.append("GOVERNANCE_INVALID_TSA_LIVE_VERIFICATION_ALLOWED")
    unsafe_plan = dict(plan)
    unsafe_plan["diagnostics"] = {"approval_contents": "do-not-log"}
    unsafe_verification = verify_tsa_live_verification_plan(unsafe_plan)
    if unsafe_verification.valid or "TSA_LIVE_DIAGNOSTICS_UNSAFE" not in unsafe_verification.errors:
        failures.append("GOVERNANCE_UNSAFE_TSA_LIVE_VERIFICATION_ALLOWED")
    try:
        assert_tsa_live_verification_safe(redacted_tsa_live_verification_payload(plan))
    except TSALiveVerificationError as exc:
        failures.append(str(exc))
    return failures


def check_governance_revocation_preflight(root: Path) -> list[str]:
    from governance.signed_bundle_revocation_preflight import (
        REVOCATION_PREFLIGHT_ERROR_CODES,
        SignedBundleRevocationPreflightError,
        assert_revocation_preflight_safe,
        create_revocation_preflight,
        load_revocation_preflight_error_registry,
        redacted_revocation_preflight_payload,
        verify_revocation_preflight,
    )
    from tests.test_governance_signed_bundle_ltv import _ltv

    failures: list[str] = []
    if not (root / "governance" / "signed_bundle_revocation_preflight.py").is_file():
        failures.append("GOVERNANCE_REVOCATION_PREFLIGHT_MODULE_MISSING")
    if not (root / "governance" / "signed_bundle_revocation_preflight_errors.json").is_file():
        failures.append("GOVERNANCE_REVOCATION_PREFLIGHT_ERROR_REGISTRY_MISSING")
    try:
        registry = load_revocation_preflight_error_registry(root)
        for code in REVOCATION_PREFLIGHT_ERROR_CODES:
            if code not in registry:
                failures.append(f"GOVERNANCE_REVOCATION_PREFLIGHT_ERROR_CODE_MISSING:{code}")
    except SignedBundleRevocationPreflightError as exc:
        failures.append(str(exc))
    try:
        ltv_evidence, _timestamp_attachment = _ltv()
        preflight = create_revocation_preflight(
            ltv_evidence,
            revocation_source_type="OCSP",
            revocation_source_uri_hash="d" * 64,
            expected_freshness_window_seconds=86400,
            checked_at_utc="2026-05-12T00:08:00Z",
            validation_policy_id="usb.ltv.v1",
        )
        verification = verify_revocation_preflight(preflight, ltv_evidence=ltv_evidence)
        if not verification.valid:
            failures.append("GOVERNANCE_REVOCATION_PREFLIGHT_INVALID")
    except SignedBundleRevocationPreflightError as exc:
        failures.append(str(exc))
        preflight = {}
    invalid = verify_revocation_preflight({"schema": "usbay.governance_signed_bundle_revocation_preflight.v1"})
    if invalid.valid or "REVOCATION_PREFLIGHT_LTV_MISSING" not in invalid.errors:
        failures.append("GOVERNANCE_INVALID_REVOCATION_PREFLIGHT_ALLOWED")
    unsafe_preflight = dict(preflight)
    unsafe_preflight["diagnostics"] = {"approval_contents": "do-not-log"}
    unsafe_verification = verify_revocation_preflight(unsafe_preflight)
    if unsafe_verification.valid or "REVOCATION_PREFLIGHT_DIAGNOSTICS_UNSAFE" not in unsafe_verification.errors:
        failures.append("GOVERNANCE_UNSAFE_REVOCATION_PREFLIGHT_ALLOWED")
    try:
        assert_revocation_preflight_safe(redacted_revocation_preflight_payload(preflight))
    except SignedBundleRevocationPreflightError as exc:
        failures.append(str(exc))
    return failures


def check_governance_revocation_response(root: Path) -> list[str]:
    from governance.signed_bundle_revocation_response import (
        REVOCATION_RESPONSE_ERROR_CODES,
        SignedBundleRevocationResponseError,
        assert_revocation_response_safe,
        create_revocation_response,
        load_revocation_response_error_registry,
        redacted_revocation_response_payload,
        verify_revocation_response,
    )
    from tests.test_governance_signed_bundle_revocation_preflight import _preflight

    failures: list[str] = []
    if not (root / "governance" / "signed_bundle_revocation_response.py").is_file():
        failures.append("GOVERNANCE_REVOCATION_RESPONSE_MODULE_MISSING")
    if not (root / "governance" / "signed_bundle_revocation_response_errors.json").is_file():
        failures.append("GOVERNANCE_REVOCATION_RESPONSE_ERROR_REGISTRY_MISSING")
    try:
        registry = load_revocation_response_error_registry(root)
        for code in REVOCATION_RESPONSE_ERROR_CODES:
            if code not in registry:
                failures.append(f"GOVERNANCE_REVOCATION_RESPONSE_ERROR_CODE_MISSING:{code}")
    except SignedBundleRevocationResponseError as exc:
        failures.append(str(exc))
    try:
        preflight, ltv_evidence = _preflight()
        response = create_revocation_response(
            preflight,
            response_status="GOOD",
            response_this_update_utc="2026-05-12T00:07:30Z",
            response_next_update_utc="2026-05-13T00:07:30Z",
            responder_key_fingerprint="f" * 64,
            checked_at_utc="2026-05-12T00:08:30Z",
            validation_policy_id="usb.ltv.v1",
        )
        verification = verify_revocation_response(response, preflight=preflight, ltv_evidence=ltv_evidence)
        if not verification.valid:
            failures.append("GOVERNANCE_REVOCATION_RESPONSE_INVALID")
    except SignedBundleRevocationResponseError as exc:
        failures.append(str(exc))
        response = {}
    invalid = verify_revocation_response({"schema": "usbay.governance_signed_bundle_revocation_response.v1"})
    if invalid.valid or "REVOCATION_RESPONSE_PREFLIGHT_MISSING" not in invalid.errors:
        failures.append("GOVERNANCE_INVALID_REVOCATION_RESPONSE_ALLOWED")
    unsafe_response = dict(response)
    unsafe_response["diagnostics"] = {"approval_contents": "do-not-log"}
    unsafe_verification = verify_revocation_response(unsafe_response)
    if unsafe_verification.valid or "REVOCATION_RESPONSE_DIAGNOSTICS_UNSAFE" not in unsafe_verification.errors:
        failures.append("GOVERNANCE_UNSAFE_REVOCATION_RESPONSE_ALLOWED")
    try:
        assert_revocation_response_safe(redacted_revocation_response_payload(response))
    except SignedBundleRevocationResponseError as exc:
        failures.append(str(exc))
    return failures


def check_governance_revocation_live_fetch(root: Path) -> list[str]:
    from governance.revocation_live_fetch import (
        REVOCATION_LIVE_FETCH_ERROR_CODES,
        RevocationLiveFetchError,
        assert_revocation_live_fetch_safe,
        load_revocation_live_fetch_error_registry,
        prepare_revocation_live_fetch_plan,
        redacted_revocation_live_fetch_payload,
        verify_revocation_live_fetch_plan,
    )
    from tests.test_governance_signed_bundle_revocation_response import _response

    failures: list[str] = []
    if not (root / "governance" / "revocation_live_fetch.py").is_file():
        failures.append("GOVERNANCE_REVOCATION_LIVE_FETCH_MODULE_MISSING")
    if not (root / "governance" / "revocation_live_fetch_errors.json").is_file():
        failures.append("GOVERNANCE_REVOCATION_LIVE_FETCH_ERROR_REGISTRY_MISSING")
    try:
        registry = load_revocation_live_fetch_error_registry(root)
        for code in REVOCATION_LIVE_FETCH_ERROR_CODES:
            if code not in registry:
                failures.append(f"GOVERNANCE_REVOCATION_LIVE_FETCH_ERROR_CODE_MISSING:{code}")
    except RevocationLiveFetchError as exc:
        failures.append(str(exc))
    try:
        response, preflight, _ltv = _response()
        plan = prepare_revocation_live_fetch_plan(
            revocation_preflight=preflight,
            revocation_response=response,
            planned_at_utc="2026-05-12T00:09:00Z",
        )
        verification = verify_revocation_live_fetch_plan(plan, revocation_preflight=preflight, revocation_response=response)
        if not verification.valid:
            failures.append("GOVERNANCE_REVOCATION_LIVE_FETCH_INVALID")
    except RevocationLiveFetchError as exc:
        failures.append(str(exc))
        plan = {}
    invalid = verify_revocation_live_fetch_plan({"schema": "usbay.governance_revocation_live_fetch.v1"})
    if invalid.valid or "REVOCATION_LIVE_FETCH_SOURCE_MISSING" not in invalid.errors:
        failures.append("GOVERNANCE_INVALID_REVOCATION_LIVE_FETCH_ALLOWED")
    unsafe_plan = dict(plan)
    unsafe_plan["diagnostics"] = {"approval_contents": "do-not-log"}
    unsafe_verification = verify_revocation_live_fetch_plan(unsafe_plan)
    if unsafe_verification.valid or "REVOCATION_LIVE_FETCH_DIAGNOSTICS_UNSAFE" not in unsafe_verification.errors:
        failures.append("GOVERNANCE_UNSAFE_REVOCATION_LIVE_FETCH_ALLOWED")
    try:
        assert_revocation_live_fetch_safe(redacted_revocation_live_fetch_payload(plan))
    except RevocationLiveFetchError as exc:
        failures.append(str(exc))
    return failures


def check_governance_sealed_audit_archive(root: Path) -> list[str]:
    from governance.sealed_audit_archive import (
        SEALED_AUDIT_ARCHIVE_ERROR_CODES,
        SealedAuditArchiveError,
        assert_sealed_audit_archive_safe,
        create_sealed_audit_archive,
        load_sealed_audit_archive_error_registry,
        redacted_sealed_audit_archive_payload,
        verify_sealed_audit_archive,
    )
    from tests.test_governance_sealed_audit_archive import _archive_artifacts

    failures: list[str] = []
    if not (root / "governance" / "sealed_audit_archive.py").is_file():
        failures.append("GOVERNANCE_SEALED_AUDIT_ARCHIVE_MODULE_MISSING")
    if not (root / "governance" / "sealed_audit_archive_errors.json").is_file():
        failures.append("GOVERNANCE_SEALED_AUDIT_ARCHIVE_ERROR_REGISTRY_MISSING")
    try:
        registry = load_sealed_audit_archive_error_registry(root)
        for code in SEALED_AUDIT_ARCHIVE_ERROR_CODES:
            if code not in registry:
                failures.append(f"GOVERNANCE_SEALED_AUDIT_ARCHIVE_ERROR_CODE_MISSING:{code}")
    except SealedAuditArchiveError as exc:
        failures.append(str(exc))
    try:
        artifacts = _archive_artifacts()
        archive = create_sealed_audit_archive(
            **artifacts,
            archive_created_at_utc="2026-05-12T00:09:00Z",
            archive_scope="external-audit",
        )
        verification = verify_sealed_audit_archive(archive, **artifacts, expected_archive_scope="external-audit")
        if not verification.valid:
            failures.append("GOVERNANCE_SEALED_AUDIT_ARCHIVE_INVALID")
    except SealedAuditArchiveError as exc:
        failures.append(str(exc))
        archive = {}
    invalid = verify_sealed_audit_archive({"schema": "usbay.governance_sealed_audit_archive.v1"})
    if invalid.valid or "SEALED_ARCHIVE_MANIFEST_MISSING" not in invalid.errors:
        failures.append("GOVERNANCE_INVALID_SEALED_AUDIT_ARCHIVE_ALLOWED")
    unsafe_archive = dict(archive)
    unsafe_archive["diagnostics"] = {"approval_contents": "do-not-log"}
    unsafe_verification = verify_sealed_audit_archive(unsafe_archive)
    if unsafe_verification.valid or "SEALED_ARCHIVE_DIAGNOSTICS_UNSAFE" not in unsafe_verification.errors:
        failures.append("GOVERNANCE_UNSAFE_SEALED_AUDIT_ARCHIVE_ALLOWED")
    try:
        assert_sealed_audit_archive_safe(redacted_sealed_audit_archive_payload(archive))
    except SealedAuditArchiveError as exc:
        failures.append(str(exc))
    return failures


def check_governance_evidence_record_chain(root: Path) -> list[str]:
    from governance.evidence_record_chain import (
        EVIDENCE_RECORD_CHAIN_ERROR_CODES,
        EvidenceRecordChainError,
        assert_evidence_record_safe,
        create_evidence_record,
        load_evidence_record_chain_error_registry,
        redacted_evidence_record_payload,
        verify_evidence_record,
    )
    from tests.test_governance_sealed_audit_archive import _archive

    failures: list[str] = []
    if not (root / "governance" / "evidence_record_chain.py").is_file():
        failures.append("GOVERNANCE_EVIDENCE_RECORD_CHAIN_MODULE_MISSING")
    if not (root / "governance" / "evidence_record_chain_errors.json").is_file():
        failures.append("GOVERNANCE_EVIDENCE_RECORD_CHAIN_ERROR_REGISTRY_MISSING")
    try:
        registry = load_evidence_record_chain_error_registry(root)
        for code in EVIDENCE_RECORD_CHAIN_ERROR_CODES:
            if code not in registry:
                failures.append(f"GOVERNANCE_EVIDENCE_RECORD_CHAIN_ERROR_CODE_MISSING:{code}")
    except EvidenceRecordChainError as exc:
        failures.append(str(exc))
    try:
        archive, _artifacts = _archive()
        record = create_evidence_record(
            archive,
            renewal_timestamp_utc="2026-05-12T00:10:00Z",
            renewal_reason="initial_archive_timestamp",
        )
        verification = verify_evidence_record(record, sealed_archive=archive)
        if not verification.valid:
            failures.append("GOVERNANCE_EVIDENCE_RECORD_CHAIN_INVALID")
    except EvidenceRecordChainError as exc:
        failures.append(str(exc))
        record = {}
    invalid = verify_evidence_record({"schema": "usbay.governance_evidence_record_chain.v1"})
    if invalid.valid or "EVIDENCE_RECORD_TIMESTAMP_MISSING" not in invalid.errors:
        failures.append("GOVERNANCE_INVALID_EVIDENCE_RECORD_CHAIN_ALLOWED")
    unsafe_record = dict(record)
    unsafe_record["diagnostics"] = {"approval_contents": "do-not-log"}
    unsafe_verification = verify_evidence_record(unsafe_record)
    if unsafe_verification.valid or "EVIDENCE_RECORD_DIAGNOSTICS_UNSAFE" not in unsafe_verification.errors:
        failures.append("GOVERNANCE_UNSAFE_EVIDENCE_RECORD_CHAIN_ALLOWED")
    try:
        assert_evidence_record_safe(redacted_evidence_record_payload(record))
    except EvidenceRecordChainError as exc:
        failures.append(str(exc))
    return failures


def check_governance_pq_renewal_plan(root: Path) -> list[str]:
    from governance.evidence_pq_renewal_plan import (
        EVIDENCE_PQ_RENEWAL_PLAN_ERROR_CODES,
        EvidencePQRenewalPlanError,
        assert_pq_renewal_plan_safe,
        create_pq_renewal_plan,
        load_pq_renewal_plan_error_registry,
        redacted_pq_renewal_plan_payload,
        verify_pq_renewal_plan,
    )
    from tests.test_governance_evidence_record_chain import _record

    failures: list[str] = []
    if not (root / "governance" / "evidence_pq_renewal_plan.py").is_file():
        failures.append("GOVERNANCE_PQ_RENEWAL_PLAN_MODULE_MISSING")
    if not (root / "governance" / "evidence_pq_renewal_plan_errors.json").is_file():
        failures.append("GOVERNANCE_PQ_RENEWAL_PLAN_ERROR_REGISTRY_MISSING")
    try:
        registry = load_pq_renewal_plan_error_registry(root)
        for code in EVIDENCE_PQ_RENEWAL_PLAN_ERROR_CODES:
            if code not in registry:
                failures.append(f"GOVERNANCE_PQ_RENEWAL_PLAN_ERROR_CODE_MISSING:{code}")
    except EvidencePQRenewalPlanError as exc:
        failures.append(str(exc))
    try:
        evidence_record, _archive = _record()
        plan = create_pq_renewal_plan(
            evidence_record,
            target_hash_algorithm="SHA3_512",
            target_signature_family="ML_DSA",
            migration_reason="post_quantum_readiness",
            validation_policy_id="usb.pq.v1",
        )
        verification = verify_pq_renewal_plan(plan, evidence_record=evidence_record)
        if not verification.valid:
            failures.append("GOVERNANCE_PQ_RENEWAL_PLAN_INVALID")
    except EvidencePQRenewalPlanError as exc:
        failures.append(str(exc))
        plan = {}
    invalid = verify_pq_renewal_plan({"schema": "usbay.governance_evidence_pq_renewal_plan.v1"})
    if invalid.valid or "PQ_RENEWAL_EVIDENCE_RECORD_MISSING" not in invalid.errors:
        failures.append("GOVERNANCE_INVALID_PQ_RENEWAL_PLAN_ALLOWED")
    unsafe_plan = dict(plan)
    unsafe_plan["diagnostics"] = {"approval_contents": "do-not-log"}
    unsafe_verification = verify_pq_renewal_plan(unsafe_plan)
    if unsafe_verification.valid or "PQ_RENEWAL_DIAGNOSTICS_UNSAFE" not in unsafe_verification.errors:
        failures.append("GOVERNANCE_UNSAFE_PQ_RENEWAL_PLAN_ALLOWED")
    try:
        assert_pq_renewal_plan_safe(redacted_pq_renewal_plan_payload(plan))
    except EvidencePQRenewalPlanError as exc:
        failures.append(str(exc))
    return failures


def check_governance_worm_immutable_storage(root: Path) -> list[str]:
    from governance.worm_immutable_storage import (
        WORM_IMMUTABLE_STORAGE_ERROR_CODES,
        WORMImmutableStorageError,
        assert_worm_immutable_storage_safe,
        load_worm_immutable_storage_error_registry,
        prepare_worm_immutable_storage_plan,
        redacted_worm_immutable_storage_payload,
        verify_worm_immutable_storage_plan,
    )
    from tests.test_governance_evidence_record_chain import _record

    failures: list[str] = []
    if not (root / "governance" / "worm_immutable_storage.py").is_file():
        failures.append("GOVERNANCE_WORM_IMMUTABLE_STORAGE_MODULE_MISSING")
    if not (root / "governance" / "worm_immutable_storage_errors.json").is_file():
        failures.append("GOVERNANCE_WORM_IMMUTABLE_STORAGE_ERROR_REGISTRY_MISSING")
    try:
        registry = load_worm_immutable_storage_error_registry(root)
        for code in WORM_IMMUTABLE_STORAGE_ERROR_CODES:
            if code not in registry:
                failures.append(f"GOVERNANCE_WORM_IMMUTABLE_STORAGE_ERROR_CODE_MISSING:{code}")
    except WORMImmutableStorageError as exc:
        failures.append(str(exc))
    try:
        evidence_record, archive = _record()
        plan = prepare_worm_immutable_storage_plan(
            sealed_archive=archive,
            evidence_record_chain=evidence_record,
            created_at_utc="2026-05-12T00:12:00Z",
        )
        verification = verify_worm_immutable_storage_plan(plan, sealed_archive=archive, evidence_record_chain=evidence_record)
        if not verification.valid:
            failures.append("GOVERNANCE_WORM_IMMUTABLE_STORAGE_INVALID")
    except WORMImmutableStorageError as exc:
        failures.append(str(exc))
        plan = {}
    invalid = verify_worm_immutable_storage_plan({"schema": "usbay.governance_worm_immutable_storage.v1"})
    if invalid.valid or "WORM_IMMUTABLE_ARCHIVE_ROOT_HASH_MISSING" not in invalid.errors:
        failures.append("GOVERNANCE_INVALID_WORM_IMMUTABLE_STORAGE_ALLOWED")
    unsafe_plan = dict(plan)
    unsafe_plan["diagnostics"] = {"approval_contents": "do-not-log"}
    unsafe_verification = verify_worm_immutable_storage_plan(unsafe_plan)
    if unsafe_verification.valid or "WORM_IMMUTABLE_DIAGNOSTICS_UNSAFE" not in unsafe_verification.errors:
        failures.append("GOVERNANCE_UNSAFE_WORM_IMMUTABLE_STORAGE_ALLOWED")
    try:
        assert_worm_immutable_storage_safe(redacted_worm_immutable_storage_payload(plan))
    except WORMImmutableStorageError as exc:
        failures.append(str(exc))
    return failures


def check_governance_regulator_export_profile(root: Path) -> list[str]:
    from governance.regulator_export_profile import (
        REGULATOR_EXPORT_PROFILE_ERROR_CODES,
        RegulatorExportProfileError,
        assert_regulator_export_profile_safe,
        load_regulator_export_profile_error_registry,
        prepare_regulator_export_profile,
        redacted_regulator_export_profile_payload,
        verify_regulator_export_profile,
    )
    from governance.tsa_live_verification import prepare_tsa_live_verification_plan
    from governance.worm_immutable_storage import prepare_worm_immutable_storage_plan
    from tests.test_governance_evidence_record_chain import _record
    from tests.test_governance_regulator_export_profile import _policy_metadata
    from tests.test_governance_signed_bundle_timestamp import _attachment

    failures: list[str] = []
    if not (root / "governance" / "regulator_export_profile.py").is_file():
        failures.append("GOVERNANCE_REGULATOR_EXPORT_PROFILE_MODULE_MISSING")
    if not (root / "governance" / "regulator_export_profile_errors.json").is_file():
        failures.append("GOVERNANCE_REGULATOR_EXPORT_PROFILE_ERROR_REGISTRY_MISSING")
    try:
        registry = load_regulator_export_profile_error_registry(root)
        for code in REGULATOR_EXPORT_PROFILE_ERROR_CODES:
            if code not in registry:
                failures.append(f"GOVERNANCE_REGULATOR_EXPORT_PROFILE_ERROR_CODE_MISSING:{code}")
    except RegulatorExportProfileError as exc:
        failures.append(str(exc))
    try:
        evidence_record, archive = _record()
        worm = prepare_worm_immutable_storage_plan(sealed_archive=archive, evidence_record_chain=evidence_record, created_at_utc="2026-05-12T00:12:00Z")
        attachment, _signed_bundle, _policy = _attachment()
        tsa = prepare_tsa_live_verification_plan(attachment, verification_checked_at_utc="2026-05-12T00:07:00Z")
        policy_metadata = _policy_metadata()
        profile = prepare_regulator_export_profile(
            sealed_archive=archive,
            evidence_record_chain=evidence_record,
            worm_immutable_storage=worm,
            tsa_live_verification=tsa,
            policy_decision_metadata=policy_metadata,
            export_profile_type="EU_AI_ACT_AUDIT",
            created_at_utc="2026-05-12T00:14:00Z",
        )
        verification = verify_regulator_export_profile(
            profile,
            sealed_archive=archive,
            evidence_record_chain=evidence_record,
            worm_immutable_storage=worm,
            tsa_live_verification=tsa,
            policy_decision_metadata=policy_metadata,
        )
        if not verification.valid:
            failures.append("GOVERNANCE_REGULATOR_EXPORT_PROFILE_INVALID")
    except RegulatorExportProfileError as exc:
        failures.append(str(exc))
        profile = {}
    invalid = verify_regulator_export_profile({"schema": "usbay.governance_regulator_export_profile.v1"})
    if invalid.valid or "REGULATOR_EXPORT_SEALED_ARCHIVE_MISSING" not in invalid.errors:
        failures.append("GOVERNANCE_INVALID_REGULATOR_EXPORT_PROFILE_ALLOWED")
    unsafe_profile = dict(profile)
    unsafe_profile["diagnostics"] = {"debug": "approval_contents"}
    unsafe_verification = verify_regulator_export_profile(unsafe_profile)
    if unsafe_verification.valid or "REGULATOR_EXPORT_DIAGNOSTICS_UNSAFE" not in unsafe_verification.errors:
        failures.append("GOVERNANCE_UNSAFE_REGULATOR_EXPORT_PROFILE_ALLOWED")
    try:
        assert_regulator_export_profile_safe(redacted_regulator_export_profile_payload(profile))
    except RegulatorExportProfileError as exc:
        failures.append(str(exc))
    return failures


def check_governance_evidence_renewal_runtime(root: Path) -> list[str]:
    from governance.evidence_renewal_runtime import (
        EVIDENCE_RENEWAL_RUNTIME_ERROR_CODES,
        EvidenceRenewalRuntimeError,
        assert_evidence_renewal_runtime_safe,
        load_evidence_renewal_runtime_error_registry,
        prepare_evidence_renewal_runtime_record,
        redacted_evidence_renewal_runtime_payload,
        verify_evidence_renewal_runtime_record,
    )
    from tests.test_governance_regulator_export_profile import _profile

    failures: list[str] = []
    if not (root / "governance" / "evidence_renewal_runtime.py").is_file():
        failures.append("GOVERNANCE_EVIDENCE_RENEWAL_RUNTIME_MODULE_MISSING")
    if not (root / "governance" / "evidence_renewal_runtime_errors.json").is_file():
        failures.append("GOVERNANCE_EVIDENCE_RENEWAL_RUNTIME_ERROR_REGISTRY_MISSING")
    try:
        registry = load_evidence_renewal_runtime_error_registry(root)
        for code in EVIDENCE_RENEWAL_RUNTIME_ERROR_CODES:
            if code not in registry:
                failures.append(f"GOVERNANCE_EVIDENCE_RENEWAL_RUNTIME_ERROR_CODE_MISSING:{code}")
    except EvidenceRenewalRuntimeError as exc:
        failures.append(str(exc))
    try:
        profile, archive, evidence_record, worm, tsa, policy_metadata = _profile()
        record = prepare_evidence_renewal_runtime_record(
            evidence_record_chain=evidence_record,
            sealed_archive=archive,
            worm_immutable_storage=worm,
            tsa_live_verification=tsa,
            regulator_export_profile=profile,
            policy_decision_metadata=policy_metadata,
            created_at_utc="2026-05-12T00:15:00Z",
        )
        verification = verify_evidence_renewal_runtime_record(
            record,
            evidence_record_chain=evidence_record,
            sealed_archive=archive,
            worm_immutable_storage=worm,
            tsa_live_verification=tsa,
            regulator_export_profile=profile,
            policy_decision_metadata=policy_metadata,
        )
        if not verification.valid:
            failures.append("GOVERNANCE_EVIDENCE_RENEWAL_RUNTIME_INVALID")
    except EvidenceRenewalRuntimeError as exc:
        failures.append(str(exc))
        record = {}
    invalid = verify_evidence_renewal_runtime_record({"schema": "usbay.governance_evidence_renewal_runtime.v1"})
    if invalid.valid or "EVIDENCE_RENEWAL_RUNTIME_EVIDENCE_CHAIN_MISSING" not in invalid.errors:
        failures.append("GOVERNANCE_INVALID_EVIDENCE_RENEWAL_RUNTIME_ALLOWED")
    unsafe_record = dict(record)
    unsafe_record["diagnostics"] = {"approval_contents": "do-not-log"}
    unsafe_verification = verify_evidence_renewal_runtime_record(unsafe_record)
    if unsafe_verification.valid or "EVIDENCE_RENEWAL_RUNTIME_DIAGNOSTICS_UNSAFE" not in unsafe_verification.errors:
        failures.append("GOVERNANCE_UNSAFE_EVIDENCE_RENEWAL_RUNTIME_ALLOWED")
    try:
        assert_evidence_renewal_runtime_safe(redacted_evidence_renewal_runtime_payload(record))
    except EvidenceRenewalRuntimeError as exc:
        failures.append(str(exc))
    return failures


def check_governance_pq_runtime_verification(root: Path) -> list[str]:
    from governance.pq_runtime_verification import (
        PQ_RUNTIME_VERIFICATION_ERROR_CODES,
        PQRuntimeVerificationError,
        assert_pq_runtime_verification_safe,
        create_pq_runtime_verification,
        load_pq_runtime_verification_error_registry,
        redacted_pq_runtime_verification_payload,
        verify_pq_runtime_verification,
    )
    from tests.test_governance_evidence_pq_renewal_plan import _plan

    failures: list[str] = []
    if not (root / "governance" / "pq_runtime_verification.py").is_file():
        failures.append("GOVERNANCE_PQ_RUNTIME_VERIFICATION_MODULE_MISSING")
    if not (root / "governance" / "pq_runtime_verification_errors.json").is_file():
        failures.append("GOVERNANCE_PQ_RUNTIME_VERIFICATION_ERROR_REGISTRY_MISSING")
    try:
        registry = load_pq_runtime_verification_error_registry(root)
        for code in PQ_RUNTIME_VERIFICATION_ERROR_CODES:
            if code not in registry:
                failures.append(f"GOVERNANCE_PQ_RUNTIME_VERIFICATION_ERROR_CODE_MISSING:{code}")
    except PQRuntimeVerificationError as exc:
        failures.append(str(exc))
    try:
        plan, _evidence_record = _plan()
        record = create_pq_runtime_verification(
            plan,
            verifier_mode="STUB_ONLY",
            policy_decision_id="a" * 64,
            policy_decision="ALLOW",
            validation_policy_id="usb.pq.v1",
        )
        verification = verify_pq_runtime_verification(record, pq_renewal_plan=plan)
        if not verification.valid:
            failures.append("GOVERNANCE_PQ_RUNTIME_VERIFICATION_INVALID")
    except PQRuntimeVerificationError as exc:
        failures.append(str(exc))
        record = {}
    invalid = verify_pq_runtime_verification({"schema": "usbay.governance_pq_runtime_verification.v1"})
    if invalid.valid or "PQ_RUNTIME_PLAN_MISSING" not in invalid.errors:
        failures.append("GOVERNANCE_INVALID_PQ_RUNTIME_VERIFICATION_ALLOWED")
    unsafe_record = dict(record)
    unsafe_record["diagnostics"] = {"approval_contents": "do-not-log"}
    unsafe_verification = verify_pq_runtime_verification(unsafe_record)
    if unsafe_verification.valid or "PQ_RUNTIME_DIAGNOSTICS_UNSAFE" not in unsafe_verification.errors:
        failures.append("GOVERNANCE_UNSAFE_PQ_RUNTIME_VERIFICATION_ALLOWED")
    try:
        assert_pq_runtime_verification_safe(redacted_pq_runtime_verification_payload(record))
    except PQRuntimeVerificationError as exc:
        failures.append(str(exc))
    return failures


def check_governance_hidden_trust_assumption_scanner(root: Path) -> list[str]:
    from governance.hidden_trust_assumption_scanner import (
        HIDDEN_TRUST_SCANNER_ERROR_CODES,
        HIDDEN_TRUST_SCANNER_SCHEMA,
        HiddenTrustAssumptionScannerError,
        assert_hidden_trust_scanner_safe,
        load_hidden_trust_error_registry,
        redacted_hidden_trust_payload,
        scan_hidden_trust_assumptions,
    )

    failures: list[str] = []
    module_path = root / "governance" / "hidden_trust_assumption_scanner.py"
    registry_path = root / "governance" / "hidden_trust_assumption_errors.json"
    scan_target = root / "governance" / "__init__.py"
    if not module_path.is_file():
        failures.append("GOVERNANCE_HIDDEN_TRUST_ASSUMPTION_SCANNER_MODULE_MISSING")
    if not registry_path.is_file():
        failures.append("GOVERNANCE_HIDDEN_TRUST_ASSUMPTION_ERROR_REGISTRY_MISSING")
    try:
        registry = load_hidden_trust_error_registry(root)
        for code in HIDDEN_TRUST_SCANNER_ERROR_CODES:
            if code not in registry:
                failures.append(f"GOVERNANCE_HIDDEN_TRUST_ASSUMPTION_ERROR_CODE_MISSING:{code}")
    except HiddenTrustAssumptionScannerError as exc:
        failures.append(str(exc))
    metadata = {
        "schema": HIDDEN_TRUST_SCANNER_SCHEMA,
        "signed": True,
        "policy_hash": "a" * 64,
        "signature_hash": "b" * 64,
        "generated_at_utc": "2026-05-15T00:00:00Z",
        "scan_scope": "production-readiness-self-test",
    }
    if module_path.is_file() and registry_path.is_file() and scan_target.is_file():
        result = scan_hidden_trust_assumptions(
            root,
            metadata=metadata,
            scan_paths=[scan_target],
            now_utc="2026-05-15T00:01:00Z",
        )
        if not result.valid:
            failures.append("GOVERNANCE_HIDDEN_TRUST_ASSUMPTION_SCANNER_INVALID")
    invalid = scan_hidden_trust_assumptions(root, metadata={}, now_utc="2026-05-15T00:01:00Z")
    if invalid.valid or "HIDDEN_TRUST_INPUT_UNSIGNED" not in invalid.errors:
        failures.append("GOVERNANCE_INVALID_HIDDEN_TRUST_SCANNER_ALLOWED")
    unsafe = {"diagnostics": {"approval_contents": "do-not-log"}}
    try:
        assert_hidden_trust_scanner_safe(unsafe)
    except HiddenTrustAssumptionScannerError:
        pass
    else:
        failures.append("GOVERNANCE_UNSAFE_HIDDEN_TRUST_SCANNER_ALLOWED")
    try:
        assert_hidden_trust_scanner_safe({"diagnostics": "[REDACTED]"})
    except HiddenTrustAssumptionScannerError as exc:
        failures.append(str(exc))
    return failures


def check_governance_runtime_parity(root: Path) -> list[str]:
    from governance.runtime_parity import (
        RUNTIME_PARITY_ERROR_CODES,
        RuntimeParityError,
        assert_runtime_parity_safe,
        canonical_governance_state_hash,
        create_runtime_manifest,
        load_runtime_parity_error_registry,
        runtime_attestation_parity_metadata,
        runtime_attestation_metadata,
        verify_runtime_attestation_parity,
        verify_runtime_parity,
    )

    failures: list[str] = []
    if not (root / "governance" / "runtime_parity.py").is_file():
        failures.append("GOVERNANCE_RUNTIME_PARITY_MODULE_MISSING")
    if not (root / "governance" / "runtime_parity_errors.json").is_file():
        failures.append("GOVERNANCE_RUNTIME_PARITY_ERROR_REGISTRY_MISSING")
    try:
        registry = load_runtime_parity_error_registry(root)
        for code in RUNTIME_PARITY_ERROR_CODES:
            if code not in registry:
                failures.append(f"GOVERNANCE_RUNTIME_PARITY_ERROR_CODE_MISSING:{code}")
    except RuntimeParityError as exc:
        failures.append(str(exc))
    runtime = {
        "commit_hash": "a" * 64,
        "policy_hash": "b" * 64,
        "manifest_hash": "c" * 64,
        "evidence_hash": "d" * 64,
        "build_artifact_signature_hash": "e" * 64,
        "build_timestamp": "2026-05-17T00:00:00Z",
        "runtime_environment": "production-readiness-self-test",
        "deployment_source": "github_main",
    }
    canonical = {
        "github_main_head": "a" * 64,
        "approved_governance_branch_heads": {},
        "approved_deployment_sources": ["github_main"],
        "allowed_stale_commits": [],
        "expected_policy_hash": "b" * 64,
        "expected_manifest_hash": "c" * 64,
        "expected_evidence_hash": "d" * 64,
        "expected_build_artifact_signature_hash": "e" * 64,
    }
    result = verify_runtime_parity(runtime, canonical)
    if not result.valid:
        failures.append("GOVERNANCE_RUNTIME_PARITY_INVALID")
    invalid = verify_runtime_parity({**runtime, "evidence_hash": ""}, canonical)
    if invalid.parity_status != "FAIL_CLOSED" or "RUNTIME_PARITY_EVIDENCE_MANIFEST_MISSING" not in invalid.errors:
        failures.append("GOVERNANCE_INVALID_RUNTIME_PARITY_ALLOWED")
    try:
        assert_runtime_parity_safe(runtime_attestation_metadata(result))
        assert_runtime_parity_safe({"diagnostics": {"approval_contents": "do-not-log"}})
    except RuntimeParityError:
        pass
    else:
        failures.append("GOVERNANCE_UNSAFE_RUNTIME_PARITY_ALLOWED")
    attestation_canonical = {
        "schema_version": "usbay.gateway_runtime_canonical_state.v1",
        "commit_sha": "a" * 40,
        "policy_version_hash": "b" * 64,
        "provenance_fingerprint": "c" * 64,
        "authority_id_hash": "d" * 64,
    }
    manifest = create_runtime_manifest(
        runtime_id="production-readiness-self-test",
        runtime_version="v1",
        commit_sha=attestation_canonical["commit_sha"],
        policy_hash=attestation_canonical["policy_version_hash"],
        provenance_fingerprint=attestation_canonical["provenance_fingerprint"],
        deployment_mode="production-readiness",
        generated_at_utc="2026-05-18T00:00:00Z",
        canonical_governance_state_hash=canonical_governance_state_hash(attestation_canonical),
    )
    attestation_result = verify_runtime_attestation_parity(manifest, attestation_canonical)
    if not attestation_result.valid:
        failures.append("GOVERNANCE_RUNTIME_ATTESTATION_PARITY_INVALID")
    mismatch = verify_runtime_attestation_parity({**manifest, "policy_hash": "0" * 64}, attestation_canonical)
    if mismatch.valid or "RUNTIME_PARITY_MISMATCH" not in mismatch.reason_codes:
        failures.append("GOVERNANCE_RUNTIME_ATTESTATION_PARITY_MISMATCH_ALLOWED")
    missing = verify_runtime_attestation_parity(None, attestation_canonical)
    if missing.valid or "RUNTIME_MANIFEST_MISSING" not in missing.reason_codes:
        failures.append("GOVERNANCE_RUNTIME_ATTESTATION_MISSING_MANIFEST_ALLOWED")
    try:
        assert_runtime_parity_safe(runtime_attestation_parity_metadata(attestation_result))
    except RuntimeParityError as exc:
        failures.append(str(exc))
    return failures


def check_governance_repo_production_readiness(root: Path) -> list[str]:
    from governance.repo_production_readiness import (
        REPO_PRODUCTION_READY,
        REPO_READINESS_ERROR_CODES,
        RepoProductionReadinessError,
        assert_repo_readiness_safe,
        load_repo_readiness_error_registry,
        scan_repo_production_readiness,
    )

    failures: list[str] = []
    if not (root / "governance" / "repo_production_readiness.py").is_file():
        failures.append("GOVERNANCE_REPO_PRODUCTION_READINESS_MODULE_MISSING")
    if not (root / "governance" / "repo_production_readiness_errors.json").is_file():
        failures.append("GOVERNANCE_REPO_PRODUCTION_READINESS_ERROR_REGISTRY_MISSING")
    if not (root / "docs" / "governance-repo-production-readiness.md").is_file():
        failures.append("GOVERNANCE_REPO_PRODUCTION_READINESS_DOC_MISSING")
    try:
        registry = load_repo_readiness_error_registry(root)
        for code in REPO_READINESS_ERROR_CODES:
            if code not in registry:
                failures.append(f"GOVERNANCE_REPO_PRODUCTION_READINESS_ERROR_CODE_MISSING:{code}")
    except RepoProductionReadinessError as exc:
        failures.append(str(exc))
    try:
        result = scan_repo_production_readiness(root, timestamp_utc="2026-05-17T00:00:00Z")
        if result.verdict not in {REPO_PRODUCTION_READY, "REPO_REVIEW_REQUIRED", "REPO_BLOCKED", "REPO_UNKNOWN"}:
            failures.append("GOVERNANCE_REPO_PRODUCTION_READINESS_VERDICT_INVALID")
        if not result.audit.get("audit_hash"):
            failures.append("GOVERNANCE_REPO_PRODUCTION_READINESS_AUDIT_HASH_MISSING")
    except RepoProductionReadinessError as exc:
        failures.append(str(exc))
    try:
        assert_repo_readiness_safe({"diagnostics": {"raw_payload": "do-not-log"}})
    except RepoProductionReadinessError:
        pass
    else:
        failures.append("GOVERNANCE_UNSAFE_REPO_PRODUCTION_READINESS_ALLOWED")
    return failures


def check_canonical_governance_state(root: Path) -> list[str]:
    from governance.canonical_governance_state import (
        CANONICAL_GOVERNANCE_STATE_REASON_CODES,
        CANONICAL_GOVERNANCE_STATE_SCHEMA,
        CanonicalGovernanceStateError,
        build_canonical_governance_state,
        load_canonical_governance_state_error_registry,
    )

    failures: list[str] = []
    if not (root / "governance" / "canonical_governance_state.py").is_file():
        failures.append("CANONICAL_GOVERNANCE_STATE_MODULE_MISSING")
    if not (root / "governance" / "canonical_governance_state_errors.json").is_file():
        failures.append("CANONICAL_GOVERNANCE_STATE_ERROR_REGISTRY_MISSING")
    try:
        registry = load_canonical_governance_state_error_registry(root)
        for code in CANONICAL_GOVERNANCE_STATE_REASON_CODES:
            if code not in registry:
                failures.append(f"CANONICAL_GOVERNANCE_STATE_ERROR_CODE_MISSING:{code}")
    except CanonicalGovernanceStateError as exc:
        failures.append(str(exc))
    state = build_canonical_governance_state(
        pr_number=77,
        repository_full_name="usbay/policy-brain",
        base_branch="main",
        head_branch="dependabot/pip/example",
        head_sha="a" * 40,
        actor="dependabot[bot]",
        event_type="pull_request",
        workflow_name="production-readiness",
        checks_status="PENDING",
        runtime_evidence_hash="b" * 64,
        policy_version_hash="c" * 64,
        timestamp_utc="2026-05-18T00:00:00Z",
    )
    if state.get("schema_version") != CANONICAL_GOVERNANCE_STATE_SCHEMA:
        failures.append("CANONICAL_GOVERNANCE_STATE_SCHEMA_INVALID")
    if not state.get("event_fingerprint") or not state.get("reconciliation_hash") or not state.get("audit_hash"):
        failures.append("CANONICAL_GOVERNANCE_STATE_HASH_MISSING")
    if state.get("signature_status") != "SIGNATURE_UNVERIFIED":
        failures.append("CANONICAL_GOVERNANCE_STATE_SIGNATURE_STATUS_INVALID")
    encoded = json.dumps(state, sort_keys=True)
    unsafe_markers = ("PRIVATE KEY", "raw_" + "payload", "approval_contents", "/Users/", "Traceback")
    if any(marker in encoded for marker in unsafe_markers):
        failures.append("CANONICAL_GOVERNANCE_STATE_DIAGNOSTICS_UNSAFE")
    return failures


def collect_fast_contract_failures(root: Path, tracked_files: list[str] | None = None) -> list[str]:
    root = root.resolve()
    failures: list[str] = []
    failures.extend(check_canonical_governance_state(root))
    failures.extend(check_governance_runtime_parity(root))
    failures.extend(check_fast_contract_safety(root))
    failures.extend(check_canonical_authority_integration(root))
    failures.extend(check_governance_provenance_foundation(root))
    failures.extend(check_governance_attestation_permissions(root))
    failures.extend(check_dependabot_governed_automation(root))
    failures.extend(check_governed_branch_hygiene(root))
    return sorted(failures)


def collect_orchestration_failures(root: Path, tracked_files: list[str] | None = None) -> list[str]:
    root = root.resolve()
    failures: list[str] = []
    failures.extend(check_bounded_validation_tooling(root))
    failures.extend(check_governance_provenance_foundation(root))
    failures.extend(check_governance_attestation_permissions(root))
    failures.extend(check_heavy_scan_workflow(root))
    workflow = root / PRODUCTION_READINESS_WORKFLOW
    if workflow.is_file():
        text = workflow.read_text(encoding="utf-8")
        if "--lane fast-contract" not in text:
            failures.append("PRODUCTION_READINESS_FAST_CONTRACT_LANE_NOT_USED")
        if "--event pull_request" not in text:
            failures.append("PRODUCTION_READINESS_EVENT_CONTEXT_MISSING")
        if "tests/test_production_readiness.py" in text:
            failures.append("PRODUCTION_READINESS_OLD_SLOW_TEST_PATH_STILL_PR_BOUND")
        if "python scripts/verify_production_readiness.py" in text and "--lane" not in text:
            failures.append("PRODUCTION_READINESS_UNBOUNDED_DEFAULT_LANE_USED")
        if "python -m pytest -q\n" in text or "python3 -m pytest -q\n" in text:
            failures.append("PRODUCTION_READINESS_PARALLEL_FULL_SUITE_RISK")
        if "continue-on-error" in text:
            failures.append("PRODUCTION_READINESS_CONTINUE_ON_ERROR_FORBIDDEN")
    return sorted(failures)


def collect_heavy_scan_failures(root: Path, tracked_files: list[str] | None = None) -> list[str]:
    root = root.resolve()
    tracked = tracked_files if tracked_files is not None else run_git_ls_files(root)
    failures: list[str] = []
    failures.extend(check_helper_size(root))
    failures.extend(check_tracked_file_sizes(root, tracked))
    failures.extend(check_tracked_generated_artifacts(tracked))
    failures.extend(check_required_docs(root))
    failures.extend(check_ci_dependency_lock(root))
    failures.extend(check_workflow_dependency_bootstrap(root))
    failures.extend(check_bounded_validation_tooling(root))
    failures.extend(check_audit_artifact_guard_lineage_recovery(root))
    failures.extend(check_dependabot_governed_automation(root))
    failures.extend(check_governed_branch_hygiene(root))
    failures.extend(check_secret_markers_in_generated_artifacts(root, tracked))
    failures.extend(check_production_manifest_required())
    failures.extend(check_governance_dependency_boundaries(root))
    failures.extend(check_governance_release_integrity_tooling(root))
    failures.extend(check_governance_operations_observability_tooling(root))
    failures.extend(check_governance_incident_runbooks(root))
    failures.extend(check_governance_policy_pack_validation(root))
    failures.extend(check_governance_policy_simulation(root))
    failures.extend(check_governance_policy_parity(root))
    failures.extend(check_governance_policy_proof_bundle(root))
    failures.extend(check_governance_proof_timestamp_anchor(root))
    failures.extend(check_governance_rfc3161_preflight(root))
    failures.extend(check_governance_worm_manifest(root))
    failures.extend(check_governance_evidence_chain(root))
    failures.extend(check_governance_merkle_checkpoint(root))
    failures.extend(check_governance_merkle_inclusion(root))
    failures.extend(check_governance_merkle_consistency(root))
    failures.extend(check_governance_auditor_bundle(root))
    failures.extend(check_governance_signed_auditor_bundle(root))
    failures.extend(check_governance_signed_bundle_timestamp(root))
    failures.extend(check_governance_tsa_live_verification(root))
    failures.extend(check_governance_signed_bundle_ltv(root))
    failures.extend(check_governance_revocation_preflight(root))
    failures.extend(check_governance_revocation_response(root))
    failures.extend(check_governance_revocation_live_fetch(root))
    failures.extend(check_governance_sealed_audit_archive(root))
    failures.extend(check_governance_evidence_record_chain(root))
    failures.extend(check_governance_worm_immutable_storage(root))
    failures.extend(check_governance_regulator_export_profile(root))
    failures.extend(check_governance_evidence_renewal_runtime(root))
    failures.extend(check_governance_pq_renewal_plan(root))
    failures.extend(check_governance_pq_runtime_verification(root))
    failures.extend(check_governance_hidden_trust_assumption_scanner(root))
    failures.extend(check_governance_runtime_parity(root))
    failures.extend(check_governance_repo_production_readiness(root))
    failures.extend(check_canonical_governance_state(root))
    failures.extend(check_governance_provenance_foundation(root))
    failures.extend(check_governance_attestation_permissions(root))
    return sorted(failures)


def collect_failures(root: Path, tracked_files: list[str] | None = None) -> list[str]:
    return collect_heavy_scan_failures(root, tracked_files=tracked_files)


def _collect_lane_failures(lane: str, root: Path) -> list[str]:
    if lane == LANE_FAST_CONTRACT:
        return collect_fast_contract_failures(root)
    if lane == LANE_HEAVY_SCAN:
        return collect_heavy_scan_failures(root)
    if lane == LANE_ORCHESTRATION:
        return collect_orchestration_failures(root)
    raise SystemExit(f"PRODUCTION_READINESS_LANE_UNKNOWN:{lane}")


def _print_lane_success(lane: str) -> None:
    if lane == LANE_FAST_CONTRACT:
        print("PRODUCTION_READINESS_FAST_CONTRACT=true")
        print("CANONICAL_GOVERNANCE_STATE_READY=true")
        print("CANONICAL_AUTHORITY_INTEGRATION_READY=true")
        print("FAIL_CLOSED_BEHAVIOR_PRESERVED=true")
        return
    if lane == LANE_ORCHESTRATION:
        print("PRODUCTION_READINESS_ORCHESTRATION=true")
        print("BOUNDED_VALIDATION_READY=true")
        print("VALIDATION_TIMEOUT_REPORTING_READY=true")
        print("FAIL_CLOSED_BEHAVIOR_PRESERVED=true")
        return
    print("PRODUCTION_READINESS_HEAVY_SCAN=true")


def _print_policy_evidence(evidence: dict[str, object]) -> None:
    print(f"lane_policy_hash={evidence['lane_policy_hash']}")
    print(f"selected_lane={evidence['selected_lane']}")
    print(f"lane_pr_blocking={str(evidence['lane_pr_blocking']).lower()}")
    print(f"allowed_trigger={str(evidence['allowed_trigger']).lower()}")


def _print_provenance_availability(root: Path) -> None:
    if not governance_provenance_available(root):
        print("GOVERNANCE_PROVENANCE_UNAVAILABLE")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Verify USBAY production-readiness guardrails")
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument(
        "--lane",
        default=LANE_FAST_CONTRACT,
        help="Bounded production-readiness lane. Defaults to fast-contract for PR usage.",
    )
    parser.add_argument("--event", default="pull_request", help="Governed trigger context for lane policy enforcement.")
    args = parser.parse_args(argv)
    try:
        _policy, _policy_hash, evidence = validate_lane_policy(args.root, args.lane, args.event)
    except SystemExit as exc:
        try:
            policy, policy_hash = load_lane_policy(args.root)
            evidence = lane_policy_evidence(policy, policy_hash, args.lane, args.event)
            _print_policy_evidence(evidence)
        except SystemExit:
            pass
        print(f"PRODUCTION_READINESS_{args.lane.upper().replace('-', '_')}=false")
        print(str(exc))
        return 1
    _print_policy_evidence(evidence)
    _print_provenance_availability(args.root)
    failures = _collect_lane_failures(args.lane, args.root)
    if failures:
        print(f"PRODUCTION_READINESS_{args.lane.upper().replace('-', '_')}=false")
        for failure in failures:
            print(failure)
        return 1
    _print_lane_success(args.lane)
    if args.lane != LANE_HEAVY_SCAN:
        return 0
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
    print("GOVERNANCE_POLICY_SIMULATION_READY=true")
    print("GOVERNANCE_POLICY_PARITY_READY=true")
    print("GOVERNANCE_POLICY_PROOF_BUNDLE_READY=true")
    print("GOVERNANCE_PROOF_TIMESTAMP_ANCHOR_READY=true")
    print("GOVERNANCE_RFC3161_TIMESTAMP_PREFLIGHT_READY=true")
    print("GOVERNANCE_WORM_EVIDENCE_MANIFEST_READY=true")
    print("GOVERNANCE_EVIDENCE_CHAIN_READY=true")
    print("GOVERNANCE_MERKLE_CHECKPOINT_READY=true")
    print("GOVERNANCE_MERKLE_INCLUSION_READY=true")
    print("GOVERNANCE_MERKLE_CONSISTENCY_READY=true")
    print("GOVERNANCE_AUDITOR_BUNDLE_READY=true")
    print("GOVERNANCE_SIGNED_AUDITOR_BUNDLE_READY=true")
    print("GOVERNANCE_SIGNED_BUNDLE_TIMESTAMP_READY=true")
    print("GOVERNANCE_TSA_LIVE_VERIFICATION_READY=true")
    print("GOVERNANCE_SIGNED_BUNDLE_LTV_READY=true")
    print("GOVERNANCE_REVOCATION_PREFLIGHT_READY=true")
    print("GOVERNANCE_REVOCATION_RESPONSE_READY=true")
    print("GOVERNANCE_REVOCATION_LIVE_FETCH_READY=true")
    print("GOVERNANCE_SEALED_AUDIT_ARCHIVE_READY=true")
    print("GOVERNANCE_EVIDENCE_RECORD_CHAIN_READY=true")
    print("GOVERNANCE_WORM_IMMUTABLE_STORAGE_READY=true")
    print("GOVERNANCE_REGULATOR_EXPORT_PROFILE_READY=true")
    print("GOVERNANCE_EVIDENCE_RENEWAL_RUNTIME_READY=true")
    print("GOVERNANCE_PQ_RENEWAL_PLAN_READY=true")
    print("GOVERNANCE_PQ_RUNTIME_VERIFICATION_READY=true")
    print("GOVERNANCE_HIDDEN_TRUST_ASSUMPTION_SCANNER_READY=true")
    print("GOVERNANCE_RUNTIME_PARITY_READY=true")
    print("GOVERNANCE_REPO_PRODUCTION_READINESS_READY=true")
    print("CANONICAL_GOVERNANCE_STATE_READY=true")
    print("DEPENDABOT_GOVERNED_AUTOMERGE_READY=true")
    print("BOUNDED_VALIDATION_READY=true")
    print("GOVERNED_BRANCH_HYGIENE_READY=true")
    print("FAIL_CLOSED_BEHAVIOR_PRESERVED=true")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
