from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "usbay_pb_release.py"


PR_BODY = """## RISK
Local release automation can block when governance evidence is incomplete.

## MECHANISM
The helper validates PB files, branch state, tests, checks, and human review controls.

## GAP
External GitHub checks are not executed during dry-run mode.

## AUDIT
All release steps emit deterministic local output.

## IMPACT
No branch protection bypass, admin merge, or auto-approval is permitted.

## Decision
VERIFIED

## Status
READY FOR REVIEW
"""


def _run(command: list[str], cwd: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(command, cwd=cwd, text=True, capture_output=True)


def _init_repo(path: Path, branch: str = "usbay/pb021-release") -> None:
    _run(["git", "init"], path)
    _run(["git", "config", "user.email", "codex@example.invalid"], path)
    _run(["git", "config", "user.name", "Codex"], path)
    _run(["git", "checkout", "-b", branch], path)


def _write_pb021_files(path: Path) -> None:
    (path / "docs" / "governance").mkdir(parents=True)
    (path / "scripts").mkdir()
    (path / "tests").mkdir()
    (path / "docs" / "governance" / "PB021_GOVERNANCE_RELEASE_AUTOMATION.md").write_text(
        "# PB-021\n", encoding="utf-8"
    )
    (path / "scripts" / "usbay_pb_release.py").write_text("print('release')\n", encoding="utf-8")
    (path / "tests" / "test_pb021_governance_release_automation.py").write_text(
        "def test_pb021():\n    assert True\n", encoding="utf-8"
    )


VALID_TITLE = "PB-021 VERIFIED: Governance Release Automation"
VALID_BRANCH = "usbay/governance-release-automation"


def _release_command(
    repo: Path,
    branch: str | None = None,
    pr_body: str | None = None,
    title: str | None = None,
    commit_message: str | None = None,
    pb_title: str = "Governance Release Automation",
    decision: str = "VERIFIED",
    status: str = "READY FOR REVIEW",
    allow_title_override: bool = False,
) -> list[str]:
    command = [
        sys.executable,
        str(SCRIPT),
        "--pb-number",
        "21",
        "--pb-slug",
        "governance-release-automation",
        "--pb-title",
        pb_title,
        "--decision",
        decision,
        "--status",
        status,
        "--repo-root",
        str(repo),
        "--dry-run",
    ]
    if title is not None:
        command.extend(["--title", title])
    if branch is not None:
        command.extend(["--branch-name", branch])
    if commit_message is not None:
        command.extend(["--commit-message", commit_message])
    if pr_body is not None:
        command.extend(["--pr-body", pr_body])
    if allow_title_override:
        command.append("--allow-governance-override")
    return command


def test_dry_run_generates_release_plan_without_git_mutation(tmp_path: Path) -> None:
    _init_repo(tmp_path, branch=VALID_BRANCH)
    _write_pb021_files(tmp_path)

    completed = _run(_release_command(tmp_path), ROOT)

    assert completed.returncode == 0, completed.stdout + completed.stderr
    result = json.loads(completed.stdout)
    assert result["dry_run"] is True
    assert result["pb_number"] == "PB-021"
    assert result["title"] == VALID_TITLE
    assert result["commit_message"] == VALID_TITLE
    assert result["branch"] == VALID_BRANCH
    assert result["release_decision"] == "VERIFIED"
    assert result["release_status"] == "READY FOR REVIEW"
    assert result["document_path"] == "docs/governance/PB021_GOVERNANCE_RELEASE_AUTOMATION.md"
    assert result["test_path"] == "tests/test_pb021_governance_release_automation.py"
    assert "## Decision\nVERIFIED" in result["pr_body"]
    assert "## Status\nREADY FOR REVIEW" in result["pr_body"]
    assert "scripts/usbay_pb_release.py" in result["pb_files"]
    status = _run(["git", "status", "--porcelain"], tmp_path)
    assert "?? docs/" in status.stdout


def test_missing_pb_files_are_blocked(tmp_path: Path) -> None:
    _init_repo(tmp_path, branch=VALID_BRANCH)

    completed = _run(_release_command(tmp_path), ROOT)

    assert completed.returncode == 1
    assert "PB_REQUIRED_FILES_MISSING" in completed.stdout


def test_main_branch_release_is_blocked(tmp_path: Path) -> None:
    _init_repo(tmp_path, branch="main")
    _write_pb021_files(tmp_path)

    completed = _run(_release_command(tmp_path), ROOT)

    assert completed.returncode == 1
    assert "PROTECTED_BRANCH_RELEASE_BLOCKED:main" in completed.stdout


def test_branch_name_auto_generated_correctly_in_dry_run(tmp_path: Path) -> None:
    _init_repo(tmp_path, branch="usbay/other")
    _write_pb021_files(tmp_path)

    completed = _run(_release_command(tmp_path), ROOT)

    assert completed.returncode == 0, completed.stdout + completed.stderr
    result = json.loads(completed.stdout)
    assert result["branch"] == VALID_BRANCH


def test_pr_body_must_include_governance_sections(tmp_path: Path) -> None:
    _init_repo(tmp_path, branch=VALID_BRANCH)
    _write_pb021_files(tmp_path)

    completed = _run(
        _release_command(tmp_path, pr_body="## RISK\nOnly risk provided.", allow_title_override=True),
        ROOT,
    )

    assert completed.returncode == 1
    assert "PR_BODY_REQUIRED_SECTIONS_MISSING" in completed.stdout
    assert "MECHANISM" in completed.stdout
    assert "GAP" in completed.stdout
    assert "AUDIT" in completed.stdout
    assert "IMPACT" in completed.stdout
    assert "Decision" in completed.stdout
    assert "Status" in completed.stdout


def test_missing_title_is_blocked(tmp_path: Path) -> None:
    _init_repo(tmp_path, branch=VALID_BRANCH)
    _write_pb021_files(tmp_path)

    completed = _run(_release_command(tmp_path, title="", commit_message="", allow_title_override=True), ROOT)

    assert completed.returncode == 1
    assert "PR_TITLE_MISSING" in completed.stdout


def test_malformed_title_is_blocked(tmp_path: Path) -> None:
    _init_repo(tmp_path, branch=VALID_BRANCH)
    _write_pb021_files(tmp_path)

    completed = _run(
        _release_command(tmp_path, title="Governance Release Automation", allow_title_override=True),
        ROOT,
    )

    assert completed.returncode == 1
    assert "PR_TITLE_MALFORMED" in completed.stdout


def test_lowercase_incomplete_title_is_blocked(tmp_path: Path) -> None:
    _init_repo(tmp_path, branch=VALID_BRANCH)
    _write_pb021_files(tmp_path)

    completed = _run(
        _release_command(tmp_path, title="pb-021 verified: Governance Release Automation", allow_title_override=True),
        ROOT,
    )

    assert completed.returncode == 1
    assert "PR_TITLE_MALFORMED" in completed.stdout


def test_commit_message_must_match_pb_title(tmp_path: Path) -> None:
    _init_repo(tmp_path, branch=VALID_BRANCH)
    _write_pb021_files(tmp_path)

    completed = _run(
        _release_command(tmp_path, commit_message="PB-021 VERIFIED: Different", allow_title_override=True),
        ROOT,
    )

    assert completed.returncode == 1
    assert "COMMIT_MESSAGE_DOES_NOT_MATCH_PB_TITLE" in completed.stdout


def test_empty_pr_body_is_blocked(tmp_path: Path) -> None:
    _init_repo(tmp_path, branch=VALID_BRANCH)
    _write_pb021_files(tmp_path)

    completed = _run(_release_command(tmp_path, pr_body="", allow_title_override=True), ROOT)

    assert completed.returncode == 1
    assert "PR_BODY_MISSING" in completed.stdout


def test_valid_pb_title_is_accepted(tmp_path: Path) -> None:
    _init_repo(tmp_path, branch=VALID_BRANCH)
    _write_pb021_files(tmp_path)

    completed = _run(_release_command(tmp_path), ROOT)

    assert completed.returncode == 0, completed.stdout + completed.stderr
    result = json.loads(completed.stdout)
    assert result["decision"] == "VERIFIED"
    assert result["title"] == VALID_TITLE
    assert result["commit_message"] == VALID_TITLE
    assert result["release_decision"] == "VERIFIED"
    assert result["release_status"] == "READY FOR REVIEW"


def test_manual_bad_title_blocked_without_override(tmp_path: Path) -> None:
    _init_repo(tmp_path, branch=VALID_BRANCH)
    _write_pb021_files(tmp_path)

    completed = _run(_release_command(tmp_path, title="PB-021 VERIFIED: Wrong"), ROOT)

    assert completed.returncode == 1
    assert "MANUAL_RELEASE_METADATA_OVERRIDE_BLOCKED" in completed.stdout


def test_lowercase_pb_title_blocks_generated_title(tmp_path: Path) -> None:
    _init_repo(tmp_path, branch=VALID_BRANCH)
    _write_pb021_files(tmp_path)

    completed = _run(_release_command(tmp_path, pb_title="governance Release Automation"), ROOT)

    assert completed.returncode == 1
    assert "PB_TITLE_LOWERCASE_OR_INCOMPLETE" in completed.stdout


def test_blocked_decision_generates_fail_closed_status(tmp_path: Path) -> None:
    _init_repo(tmp_path, branch=VALID_BRANCH)
    _write_pb021_files(tmp_path)

    completed = _run(
        _release_command(
            tmp_path,
            decision="BLOCKED",
            status="FAIL_CLOSED",
        ),
        ROOT,
    )

    assert completed.returncode == 0, completed.stdout + completed.stderr
    result = json.loads(completed.stdout)
    assert result["title"] == "PB-021 BLOCKED: Governance Release Automation"
    assert result["commit_message"] == "PB-021 BLOCKED: Governance Release Automation"
    assert "## Decision\nBLOCKED" in result["pr_body"]
    assert "## Status\nFAIL_CLOSED" in result["pr_body"]


def test_review_required_decision_generates_awaiting_approval_status(tmp_path: Path) -> None:
    _init_repo(tmp_path, branch=VALID_BRANCH)
    _write_pb021_files(tmp_path)

    completed = _run(
        _release_command(
            tmp_path,
            decision="REVIEW_REQUIRED",
            status="AWAITING_APPROVAL",
        ),
        ROOT,
    )

    assert completed.returncode == 0, completed.stdout + completed.stderr
    result = json.loads(completed.stdout)
    assert result["title"] == "PB-021 REVIEW_REQUIRED: Governance Release Automation"
    assert result["commit_message"] == "PB-021 REVIEW_REQUIRED: Governance Release Automation"
    assert result["release_decision"] == "REVIEW_REQUIRED"
    assert result["release_status"] == "AWAITING_APPROVAL"
    assert "## Decision\nREVIEW_REQUIRED" in result["pr_body"]
    assert "## Status\nAWAITING_APPROVAL" in result["pr_body"]


def test_decision_status_mismatch_blocks(tmp_path: Path) -> None:
    _init_repo(tmp_path, branch=VALID_BRANCH)
    _write_pb021_files(tmp_path)

    completed = _run(_release_command(tmp_path, decision="VERIFIED", status="FAIL_CLOSED"), ROOT)

    assert completed.returncode == 1
    assert "DECISION_STATUS_MISMATCH:VERIFIED:FAIL_CLOSED" in completed.stdout


def test_verified_with_awaiting_approval_blocks(tmp_path: Path) -> None:
    _init_repo(tmp_path, branch=VALID_BRANCH)
    _write_pb021_files(tmp_path)

    completed = _run(_release_command(tmp_path, decision="VERIFIED", status="AWAITING_APPROVAL"), ROOT)

    assert completed.returncode == 1
    assert "DECISION_STATUS_MISMATCH:VERIFIED:AWAITING_APPROVAL" in completed.stdout


def test_blocked_with_ready_for_review_blocks(tmp_path: Path) -> None:
    _init_repo(tmp_path, branch=VALID_BRANCH)
    _write_pb021_files(tmp_path)

    completed = _run(_release_command(tmp_path, decision="BLOCKED", status="READY FOR REVIEW"), ROOT)

    assert completed.returncode == 1
    assert "DECISION_STATUS_MISMATCH:BLOCKED:READY FOR REVIEW" in completed.stdout


def test_missing_decision_is_blocked(tmp_path: Path) -> None:
    _init_repo(tmp_path, branch=VALID_BRANCH)
    _write_pb021_files(tmp_path)
    command = _release_command(tmp_path)
    index = command.index("--decision")
    del command[index : index + 2]

    completed = _run(command, ROOT)

    assert completed.returncode == 2
    assert "the following arguments are required" in completed.stderr
    assert "--decision" in completed.stderr


def test_missing_status_is_blocked(tmp_path: Path) -> None:
    _init_repo(tmp_path, branch=VALID_BRANCH)
    _write_pb021_files(tmp_path)
    command = _release_command(tmp_path)
    index = command.index("--status")
    del command[index : index + 2]

    completed = _run(command, ROOT)

    assert completed.returncode == 2
    assert "the following arguments are required" in completed.stderr
    assert "--status" in completed.stderr


def test_invalid_decision_is_blocked_by_parser(tmp_path: Path) -> None:
    _init_repo(tmp_path, branch=VALID_BRANCH)
    _write_pb021_files(tmp_path)

    completed = _run(_release_command(tmp_path, decision="APPROVED", status="READY FOR REVIEW"), ROOT)

    assert completed.returncode == 2
    assert "invalid choice" in completed.stderr


def test_invalid_status_is_blocked_by_parser(tmp_path: Path) -> None:
    _init_repo(tmp_path, branch=VALID_BRANCH)
    _write_pb021_files(tmp_path)

    completed = _run(_release_command(tmp_path, decision="VERIFIED", status="APPROVED"), ROOT)

    assert completed.returncode == 2
    assert "invalid choice" in completed.stderr
