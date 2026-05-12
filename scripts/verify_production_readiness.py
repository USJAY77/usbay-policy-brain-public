#!/usr/bin/env python3
from __future__ import annotations

import argparse
import fnmatch
import os
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
)
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


def collect_failures(root: Path, tracked_files: list[str] | None = None) -> list[str]:
    root = root.resolve()
    tracked = tracked_files if tracked_files is not None else run_git_ls_files(root)
    failures: list[str] = []
    failures.extend(check_helper_size(root))
    failures.extend(check_tracked_file_sizes(root, tracked))
    failures.extend(check_tracked_generated_artifacts(tracked))
    failures.extend(check_required_docs(root))
    failures.extend(check_secret_markers_in_generated_artifacts(root, tracked))
    failures.extend(check_production_manifest_required())
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
    print("FAIL_CLOSED_BEHAVIOR_PRESERVED=true")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
