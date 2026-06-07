#!/usr/bin/env python3
"""PB-021 governed local release automation.

This helper prepares a PB control release while preserving fail-closed branch,
validation, PR, check, and auto-merge controls. Dry-run mode performs no git
mutation, push, PR creation, check watching, or auto-merge.
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Sequence


REQUIRED_PR_SECTIONS = ("RISK", "MECHANISM", "GAP", "AUDIT", "IMPACT", "Decision", "Status")
PROTECTED_BRANCHES = {"main", "master"}
CONFLICT_MARKER_PATTERN = re.compile("|".join((re.escape("<" * 7), re.escape("=" * 7), re.escape(">" * 7))))
TITLE_PATTERN = re.compile(r"^PB-\d{3} (VERIFIED|BLOCKED|REVIEW_REQUIRED): .+")
DECISION_STATUS = {
    "VERIFIED": "READY FOR REVIEW",
    "BLOCKED": "FAIL_CLOSED",
    "REVIEW_REQUIRED": "AWAITING_APPROVAL",
}


class ReleaseBlocked(RuntimeError):
    """Raised when release governance blocks execution."""


@dataclass(frozen=True)
class ReleaseConfig:
    pb_number: str
    pb_metadata_slug: str
    pb_title: str
    decision: str
    status: str
    title: str
    branch_name: str
    commit_message: str
    pr_body: str
    repo_root: Path
    dry_run: bool
    required_check: tuple[str, ...]
    allow_governance_override: bool
    manual_override_supplied: bool

    @property
    def pb_slug(self) -> str:
        return f"pb{int(self.pb_number):03d}"

    @property
    def pb_label(self) -> str:
        return f"PB-{int(self.pb_number):03d}"

    @property
    def expected_document_path(self) -> str:
        doc_slug = self.pb_metadata_slug.upper().replace("-", "_")
        return f"docs/governance/PB{int(self.pb_number):03d}_{doc_slug}.md"

    @property
    def expected_test_path(self) -> str:
        test_slug = self.pb_metadata_slug.replace("-", "_")
        return f"tests/test_{self.pb_slug}_{test_slug}.py"


def run_command(command: Sequence[str], repo_root: Path, check: bool = True) -> subprocess.CompletedProcess[str]:
    completed = subprocess.run(
        list(command),
        cwd=repo_root,
        text=True,
        capture_output=True,
    )
    if check and completed.returncode != 0:
        output = (completed.stdout + completed.stderr).strip()
        raise ReleaseBlocked(f"COMMAND_FAILED:{' '.join(command)}:{output}")
    return completed


def git_output(args: Sequence[str], repo_root: Path) -> str:
    return run_command(["git", *args], repo_root).stdout.strip()


def current_branch(repo_root: Path) -> str:
    return git_output(["branch", "--show-current"], repo_root)


def changed_files(repo_root: Path) -> list[str]:
    output = git_output(["status", "--porcelain"], repo_root)
    files: list[str] = []
    for line in output.splitlines():
        if not line:
            continue
        files.append(line[3:] if len(line) > 3 else line)
    return files


def pb_file_patterns(config: ReleaseConfig) -> tuple[str, ...]:
    number = int(config.pb_number)
    patterns = [
        config.expected_document_path,
        f"scripts/{config.pb_slug}_",
        config.expected_test_path,
        f"governance/evidence/{config.pb_slug}_",
    ]
    if number == 21:
        patterns.append("scripts/usbay_pb_release.py")
    return tuple(patterns)


def discover_pb_files(config: ReleaseConfig) -> list[Path]:
    patterns = pb_file_patterns(config)
    files: list[Path] = []
    for candidate in config.repo_root.rglob("*"):
        if not candidate.is_file() or ".git" in candidate.parts:
            continue
        relative = candidate.relative_to(config.repo_root).as_posix()
        if any(relative.startswith(pattern) for pattern in patterns):
            files.append(candidate)
    return sorted(files)


def classify_required_files(config: ReleaseConfig, files: Sequence[Path]) -> dict[str, list[str]]:
    relative_files = [path.relative_to(config.repo_root).as_posix() for path in files]
    return {
        "docs": [path for path in relative_files if path == config.expected_document_path],
        "scripts": [
            path
            for path in relative_files
            if path.startswith(f"scripts/{config.pb_slug}_") or (int(config.pb_number) == 21 and path == "scripts/usbay_pb_release.py")
        ],
        "tests": [path for path in relative_files if path == config.expected_test_path],
        "evidence": [path for path in relative_files if path.startswith(f"governance/evidence/{config.pb_slug}_")],
    }


def validate_required_pb_files(config: ReleaseConfig) -> list[Path]:
    files = discover_pb_files(config)
    grouped = classify_required_files(config, files)
    missing = [kind for kind in ("docs", "scripts", "tests") if not grouped[kind]]
    if missing:
        raise ReleaseBlocked(f"PB_REQUIRED_FILES_MISSING:{','.join(missing)}")
    if not files and not changed_files(config.repo_root):
        raise ReleaseBlocked("WORKTREE_CLEAN_AND_NO_PB_FILES")
    return files


def validate_branch(config: ReleaseConfig) -> str:
    branch = current_branch(config.repo_root)
    if branch in PROTECTED_BRANCHES:
        raise ReleaseBlocked(f"PROTECTED_BRANCH_RELEASE_BLOCKED:{branch}")
    if config.branch_name in PROTECTED_BRANCHES:
        raise ReleaseBlocked(f"MAIN_TO_MAIN_PR_BLOCKED:{config.branch_name}")
    if config.dry_run:
        return config.branch_name
    if branch != config.branch_name and not config.dry_run:
        branch_exists = run_command(["git", "rev-parse", "--verify", config.branch_name], config.repo_root, check=False)
        if branch_exists.returncode == 0:
            run_command(["git", "switch", config.branch_name], config.repo_root)
        else:
            run_command(["git", "switch", "-c", config.branch_name], config.repo_root)
        branch = current_branch(config.repo_root)
    if branch != config.branch_name:
        raise ReleaseBlocked(f"BRANCH_MISMATCH:current={branch}:expected={config.branch_name}")
    return branch


def validate_release_metadata(config: ReleaseConfig) -> None:
    if config.manual_override_supplied and not config.allow_governance_override:
        raise ReleaseBlocked("MANUAL_RELEASE_METADATA_OVERRIDE_BLOCKED")
    if config.decision not in DECISION_STATUS:
        raise ReleaseBlocked(f"DECISION_INVALID:{config.decision}")
    if config.status not in set(DECISION_STATUS.values()):
        raise ReleaseBlocked(f"STATUS_INVALID:{config.status}")
    if DECISION_STATUS[config.decision] != config.status:
        raise ReleaseBlocked(f"DECISION_STATUS_MISMATCH:{config.decision}:{config.status}")
    if not config.pb_title.strip():
        raise ReleaseBlocked("PB_TITLE_MISSING")
    if config.pb_title != config.pb_title.strip():
        raise ReleaseBlocked("PB_TITLE_MALFORMED")
    if not config.pb_title[0].isupper():
        raise ReleaseBlocked("PB_TITLE_LOWERCASE_OR_INCOMPLETE")
    if not config.branch_name.strip():
        raise ReleaseBlocked("BRANCH_NAME_MISSING")
    if not config.title.strip():
        raise ReleaseBlocked("PR_TITLE_MISSING")
    if not TITLE_PATTERN.fullmatch(config.title.strip()):
        raise ReleaseBlocked("PR_TITLE_MALFORMED")
    expected_title = f"{config.pb_label} {config.decision}: {config.pb_title}"
    if config.title != expected_title:
        raise ReleaseBlocked(f"PR_TITLE_PB_MISMATCH:expected={expected_title}")
    if not config.commit_message.strip():
        raise ReleaseBlocked("COMMIT_MESSAGE_MISSING")
    if config.commit_message != config.title:
        raise ReleaseBlocked("COMMIT_MESSAGE_DOES_NOT_MATCH_PB_TITLE")
    if not config.pr_body.strip():
        raise ReleaseBlocked("PR_BODY_MISSING")


def validate_pr_body(pr_body: str) -> None:
    missing = [section for section in REQUIRED_PR_SECTIONS if section not in pr_body]
    if missing:
        raise ReleaseBlocked(f"PR_BODY_REQUIRED_SECTIONS_MISSING:{','.join(missing)}")
    forbidden = ("regulatory certification", "legal certification")
    lowered = pr_body.lower()
    for term in forbidden:
        if term in lowered:
            raise ReleaseBlocked(f"PR_BODY_FORBIDDEN_CLAIM:{term}")


def generate_pr_body(pb_number: str, pb_slug: str, generated_title: str, decision: str, status: str) -> str:
    return "\n\n".join(
        [
            "## RISK\nLocal release automation can block incomplete governance releases and must not weaken branch protection or human review.",
            f"## MECHANISM\n{generated_title} validates PB-{int(pb_number):03d} artifacts for `{pb_slug}` before commit, push, PR creation, check watching, or auto-merge.",
            "## GAP\nDry-run mode does not execute GitHub PR creation, remote checks, push, or auto-merge. Real mode still depends on external GitHub checks and human approvals.",
            "## AUDIT\nRelease output records generated title, branch, commit message, document path, test path, PB files, and forbidden bypass controls.",
            "## IMPACT\nThe helper reduces manual release work while preserving fail-closed validation, required checks, and human approval.",
            f"## Decision\n{decision}",
            f"## Status\n{status}",
        ]
    )


def py_files_for_compile(pb_files: Sequence[Path]) -> list[str]:
    return [str(path) for path in pb_files if path.suffix == ".py"]


def focused_tests_for(config: ReleaseConfig, pb_files: Sequence[Path]) -> list[str]:
    tests = [
        path.relative_to(config.repo_root).as_posix()
        for path in pb_files
        if path.relative_to(config.repo_root).as_posix().startswith("tests/") and path.suffix == ".py"
    ]
    if not tests:
        raise ReleaseBlocked("FOCUSED_TEST_MISSING")
    return tests


def scan_conflict_markers(paths: Sequence[Path]) -> None:
    offenders: list[str] = []
    for path in paths:
        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
        if CONFLICT_MARKER_PATTERN.search(text):
            offenders.append(str(path))
    if offenders:
        raise ReleaseBlocked("CONFLICT_MARKERS_DETECTED:" + ",".join(offenders))


def run_validation(config: ReleaseConfig, pb_files: Sequence[Path]) -> None:
    compile_targets = py_files_for_compile(pb_files)
    if compile_targets:
        run_command([sys.executable, "-m", "py_compile", *compile_targets], config.repo_root)
    run_command(["pytest", "-q", *focused_tests_for(config, pb_files)], config.repo_root)
    run_command(["git", "diff", "--check"], config.repo_root)
    scan_conflict_markers(pb_files)


def stage_and_commit(config: ReleaseConfig, pb_files: Sequence[Path]) -> None:
    relative_files = [path.relative_to(config.repo_root).as_posix() for path in pb_files]
    run_command(["git", "add", *relative_files], config.repo_root)
    body = [
        "actor: codex",
        f"action: release {config.pb_label} governance control artifacts",
        "reason: preserve fail-closed PB release automation with audit evidence and human review",
        "risk: release automation may block if evidence, checks, branch state, or required approvals are incomplete",
        "policy_ref: AGENTS.md fail-closed, branch governance, human oversight, audit-first engineering",
        "signed: false",
    ]
    run_command(["git", "commit", "-m", config.commit_message, *sum((["-m", line] for line in body), [])], config.repo_root)


def push_branch(config: ReleaseConfig) -> None:
    run_command(["git", "push", "-u", "origin", config.branch_name], config.repo_root)


def create_pr(config: ReleaseConfig) -> str:
    completed = run_command(
        [
            "gh",
            "pr",
            "create",
            "--base",
            "main",
            "--head",
            config.branch_name,
            "--title",
            config.title,
            "--body",
            config.pr_body,
        ],
        config.repo_root,
    )
    pr_url = completed.stdout.strip()
    if not pr_url:
        raise ReleaseBlocked("PR_URL_MISSING")
    return pr_url


def watch_checks(config: ReleaseConfig) -> None:
    completed = run_command(["gh", "pr", "checks", config.branch_name, "--watch"], config.repo_root)
    output = completed.stdout + completed.stderr
    for check_name in config.required_check:
        if check_name not in output:
            raise ReleaseBlocked(f"REQUIRED_CHECK_MISSING:{check_name}")


def enable_auto_merge(config: ReleaseConfig) -> None:
    run_command(["gh", "pr", "merge", config.branch_name, "--auto", "--squash"], config.repo_root)


def build_plan(config: ReleaseConfig, pb_files: Sequence[Path], branch: str) -> dict[str, object]:
    return {
        "decision": "VERIFIED",
        "release_decision": config.decision,
        "release_status": config.status,
        "dry_run": config.dry_run,
        "pb_number": config.pb_label,
        "title": config.title,
        "branch": branch,
        "commit_message": config.commit_message,
        "document_path": config.expected_document_path,
        "test_path": config.expected_test_path,
        "pr_body": config.pr_body,
        "pb_files": [path.relative_to(config.repo_root).as_posix() for path in pb_files],
        "governance_controls": {
            "admin_merge": "FORBIDDEN",
            "admin_override": "FORBIDDEN",
            "auto_approve_reviews": "FORBIDDEN",
            "branch_protection_bypass": "FORBIDDEN",
            "human_approval": "REQUIRED",
        },
    }


def release(config: ReleaseConfig) -> dict[str, object]:
    validate_release_metadata(config)
    validate_pr_body(config.pr_body)
    pb_files = validate_required_pb_files(config)
    branch = validate_branch(config)
    plan = build_plan(config, pb_files, branch)
    if config.dry_run:
        return plan
    if not config.required_check:
        raise ReleaseBlocked("REQUIRED_CHECK_LIST_MISSING")
    run_validation(config, pb_files)
    stage_and_commit(config, pb_files)
    push_branch(config)
    pr_url = create_pr(config)
    watch_checks(config)
    enable_auto_merge(config)
    return {**plan, "pr_url": pr_url, "auto_merge": "REQUESTED_AFTER_CHECKS"}


def parse_args() -> ReleaseConfig:
    parser = argparse.ArgumentParser(description="PB-021 governed PB release automation.")
    parser.add_argument("--pb-number", required=True)
    parser.add_argument("--pb-slug", required=True)
    parser.add_argument("--pb-title", required=True)
    parser.add_argument("--decision", required=True, choices=tuple(DECISION_STATUS))
    parser.add_argument("--status", required=True, choices=tuple(DECISION_STATUS.values()))
    parser.add_argument("--title", default=None)
    parser.add_argument("--branch-name", default=None)
    parser.add_argument("--commit-message", default=None)
    parser.add_argument("--pr-body", default=None)
    parser.add_argument("--repo-root", type=Path, default=Path.cwd())
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--required-check", action="append", default=[])
    parser.add_argument("--allow-title-override", action="store_true")
    parser.add_argument("--allow-governance-override", action="store_true")
    args = parser.parse_args()
    pb_label = f"PB-{int(args.pb_number):03d}"
    generated_title = f"{pb_label} {args.decision}: {args.pb_title}"
    generated_branch = f"usbay/{args.pb_slug}"
    generated_pr_body = generate_pr_body(args.pb_number, args.pb_slug, generated_title, args.decision, args.status)
    manual_override_supplied = any(
        value is not None
        for value in (args.title, args.branch_name, args.commit_message, args.pr_body)
    )
    return ReleaseConfig(
        pb_number=args.pb_number,
        pb_metadata_slug=args.pb_slug,
        pb_title=args.pb_title,
        decision=args.decision,
        status=args.status,
        title=args.title if args.title is not None else generated_title,
        branch_name=args.branch_name if args.branch_name is not None else generated_branch,
        commit_message=args.commit_message if args.commit_message is not None else generated_title,
        pr_body=args.pr_body if args.pr_body is not None else generated_pr_body,
        repo_root=args.repo_root.resolve(),
        dry_run=args.dry_run,
        required_check=tuple(args.required_check),
        allow_governance_override=args.allow_governance_override or args.allow_title_override,
        manual_override_supplied=manual_override_supplied,
    )


def main() -> int:
    config = parse_args()
    try:
        result = release(config)
    except ReleaseBlocked as exc:
        print("Decision: BLOCKED")
        print(str(exc))
        return 1
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
