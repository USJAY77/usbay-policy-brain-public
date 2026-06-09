#!/usr/bin/env python3
"""PB-026 governance PR body integration checks.

This script verifies that generated governance PR bodies are complete and that
PR creation commands use the generated body instead of falling back to GitHub's
repository pull request template.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Sequence


REQUIRED_SECTIONS = (
    "PURPOSE",
    "RISK",
    "POLICY LINK",
    "REQUIRED APPROVALS",
    "GOVERNANCE CHECKS",
    "AUDIT",
    "IMPACT",
    "Decision",
    "Status",
)
FORBIDDEN_PLACEHOLDERS = (
    "Describe what is changing and why.",
    "System impact:",
    "User impact:",
    "Risk level:",
    "Policy ID:",
    "Policy version / hash:",
)
DECISION_STATUS = {
    "VERIFIED": "READY FOR REVIEW",
    "REVIEW_REQUIRED": "AWAITING_APPROVAL",
    "BLOCKED": "FAIL_CLOSED",
}


class PRBodyIntegrationBlocked(RuntimeError):
    """Raised when governance PR body integration fails closed."""


@dataclass(frozen=True)
class GovernancePRMetadata:
    pb_number: int
    pb_title: str
    decision: str
    status: str
    purpose: str
    risk: str
    policy_link: str
    required_approvals: tuple[str, ...]
    governance_checks: tuple[str, ...]
    audit: str
    impact: str

    @property
    def title(self) -> str:
        return f"PB-{self.pb_number:03d} {self.decision}: {self.pb_title}"


@dataclass(frozen=True)
class OpenPRRepairInput:
    pr_number: int
    pb_number: int
    pb_title: str
    original_body: str
    update_attempted: bool
    update_succeeded: bool
    update_error: str | None = None


def _require(condition: bool, reason: str) -> None:
    if not condition:
        raise PRBodyIntegrationBlocked(reason)


def _canonical_json(payload: Any) -> str:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"))


def _sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _section(name: str, body: str) -> str:
    _require(bool(body.strip()), f"SECTION_EMPTY:{name}")
    return f"## {name}\n{body.strip()}"


def pb026_metadata() -> GovernancePRMetadata:
    return GovernancePRMetadata(
        pb_number=26,
        pb_title="Governance PR Body Integration",
        decision="VERIFIED",
        status="READY FOR REVIEW",
        purpose="Ensure generated governance PR bodies replace the legacy GitHub PR template for PB governance pull requests.",
        risk="If PR creation falls back to the repository template, unresolved placeholders can enter review and create false audit completeness.",
        policy_link="AGENTS.md fail-closed branch governance, human oversight, branch protection, and audit-first engineering requirements.",
        required_approvals=("USBAY-AUDIT", "USBAY-GLOBAL23"),
        governance_checks=(
            "python3 -m py_compile scripts/governance_pr_body_integration.py",
            "pytest -q tests/test_pb026_pr_body_integration.py",
            "git diff --check",
            "conflict marker scan",
        ),
        audit="PB-026 generates an integration report proving the generated body is populated, placeholders are absent, and PR creation must supply the generated body.",
        impact="Governance PR creation fails closed when the generated body is missing, incomplete, or not supplied to the PR creation command.",
    )


def governance_metadata_for_pb(pb_number: int, pb_title: str, purpose: str, risk: str, audit: str, impact: str) -> GovernancePRMetadata:
    return GovernancePRMetadata(
        pb_number=pb_number,
        pb_title=pb_title,
        decision="VERIFIED",
        status="READY FOR REVIEW",
        purpose=purpose,
        risk=risk,
        policy_link="AGENTS.md fail-closed branch governance, human oversight, branch protection, and audit-first engineering requirements.",
        required_approvals=("USBAY-AUDIT", "USBAY-GLOBAL23"),
        governance_checks=(
            "generated governance PR body attached",
            "required sections populated",
            "forbidden placeholders absent",
            "branch protection preserved",
            "no admin merge",
            "no auto-approval",
        ),
        audit=audit,
        impact=impact,
    )


def placeholder_count(body: str) -> int:
    return sum(body.count(placeholder) for placeholder in FORBIDDEN_PLACEHOLDERS)


def validate_metadata(metadata: GovernancePRMetadata) -> None:
    _require(1 <= metadata.pb_number <= 999, "PB_NUMBER_INVALID")
    _require(bool(metadata.pb_title.strip()), "PB_TITLE_MISSING")
    _require(metadata.decision in DECISION_STATUS, f"DECISION_INVALID:{metadata.decision}")
    _require(metadata.status == DECISION_STATUS.get(metadata.decision), f"DECISION_STATUS_MISMATCH:{metadata.decision}:{metadata.status}")
    for field_name in ("purpose", "risk", "policy_link", "audit", "impact"):
        _require(bool(str(getattr(metadata, field_name)).strip()), f"FIELD_EMPTY:{field_name}")
    _require(bool(metadata.required_approvals), "REQUIRED_APPROVALS_EMPTY")
    _require(bool(metadata.governance_checks), "GOVERNANCE_CHECKS_EMPTY")


def generate_pr_body(metadata: GovernancePRMetadata) -> str:
    validate_metadata(metadata)
    return (
        "\n\n".join(
            (
                _section("PURPOSE", metadata.purpose),
                _section("RISK", metadata.risk),
                _section("POLICY LINK", metadata.policy_link),
                _section("REQUIRED APPROVALS", "\n".join(f"- {approval}" for approval in metadata.required_approvals)),
                _section("GOVERNANCE CHECKS", "\n".join(f"- {check}" for check in metadata.governance_checks)),
                _section("AUDIT", metadata.audit),
                _section("IMPACT", metadata.impact),
                _section("Decision", metadata.decision),
                _section("Status", metadata.status),
            )
        )
        + "\n"
    )


def validate_pr_body(body: str) -> dict[str, Any]:
    _require(bool(body.strip()), "PR_BODY_MISSING")
    placeholders = [placeholder for placeholder in FORBIDDEN_PLACEHOLDERS if placeholder in body]
    _require(not placeholders, "UNRESOLVED_TEMPLATE_PLACEHOLDER:" + ",".join(placeholders))
    headings = {match.group(1).strip() for match in re.finditer(r"^## (.+)$", body, flags=re.MULTILINE)}
    missing = [section for section in REQUIRED_SECTIONS if section not in headings]
    _require(not missing, "REQUIRED_SECTION_MISSING:" + ",".join(missing))
    empty: list[str] = []
    for section in REQUIRED_SECTIONS:
        marker = f"## {section}\n"
        start = body.find(marker)
        next_start = body.find("\n\n## ", start + len(marker))
        content = body[start + len(marker) : next_start if next_start != -1 else len(body)].strip()
        if not content:
            empty.append(section)
    _require(not empty, "SECTION_EMPTY:" + ",".join(empty))
    return {
        "body_hash": _sha256_text(body),
        "required_sections": {section: "POPULATED" for section in REQUIRED_SECTIONS},
        "forbidden_placeholders": {placeholder: "ABSENT" for placeholder in FORBIDDEN_PLACEHOLDERS},
    }


def validate_repository_template(template_text: str) -> dict[str, Any]:
    validation = validate_pr_body(template_text)
    _require("Fallback Guard" in template_text, "LEGACY_TEMPLATE_STILL_ACTIVE")
    return {
        **validation,
        "template_mode": "FAIL_CLOSED_FALLBACK_GUARD",
        "legacy_template": "REMOVED",
    }


def validate_pr_create_command(command: Sequence[str], expected_body_file: str, expected_body: str) -> dict[str, Any]:
    _require("gh" in command and "pr" in command and "create" in command, "PR_CREATE_COMMAND_INVALID")
    if "--body-file" in command:
        index = command.index("--body-file")
        _require(index + 1 < len(command), "PR_BODY_FILE_ARGUMENT_MISSING")
        _require(command[index + 1] == expected_body_file, "GENERATED_BODY_FILE_NOT_USED")
        return {"mode": "BODY_FILE", "generated_body_used": True, "body_hash": _sha256_text(expected_body)}
    if "--body" in command:
        index = command.index("--body")
        _require(index + 1 < len(command), "PR_BODY_ARGUMENT_MISSING")
        _require(command[index + 1] == expected_body, "GENERATED_BODY_TEXT_NOT_USED")
        return {"mode": "BODY_TEXT", "generated_body_used": True, "body_hash": _sha256_text(expected_body)}
    raise PRBodyIntegrationBlocked("GENERATED_PR_BODY_NOT_USED")


def build_report(
    metadata: GovernancePRMetadata,
    generated_body: str,
    template_text: str,
    command: Sequence[str],
    expected_body_file: str,
) -> dict[str, Any]:
    body_validation = validate_pr_body(generated_body)
    template_validation = validate_repository_template(template_text)
    command_validation = validate_pr_create_command(command, expected_body_file, generated_body)
    return {
        "control": "PB-026",
        "decision": "VERIFIED",
        "status": "READY FOR REVIEW",
        "title": metadata.title,
        "investigation": {
            "pr_192_body_source": "Repository evidence shows GitHub fallback template contained forbidden placeholders; PR body source cannot be fetched from the network-restricted environment.",
            "pull_request_template_overrides_generated_body": "YES_IF_GH_PR_CREATE_OMITS_BODY_OR_BODY_FILE",
            "generated_body_used": command_validation["generated_body_used"],
            "gh_pr_create_requires_generated_body": True,
        },
        "generated_body_validation": body_validation,
        "repository_template_validation": template_validation,
        "pr_create_command_validation": command_validation,
        "governance_controls": {
            "admin_bypass": "FORBIDDEN",
            "admin_merge": "FORBIDDEN",
            "auto_approval": "FORBIDDEN",
            "branch_protection_bypass": "FORBIDDEN",
            "fail_closed_if_generated_body_not_used": True,
        },
        "metadata": asdict(metadata),
        "report_hash": _sha256_text(_canonical_json({"metadata": asdict(metadata), "body": generated_body, "command": list(command)})),
    }


def build_open_pr_repair_report(records: Sequence[OpenPRRepairInput], *, open_pr_enumeration_status: str) -> dict[str, Any]:
    scanned: list[dict[str, Any]] = []
    for record in records:
        metadata = governance_metadata_for_pb(
            record.pb_number,
            record.pb_title,
            purpose=f"Repair PR #{record.pr_number} by replacing legacy template content with a generated governance PR body.",
            risk="Legacy template placeholders can create false audit completeness when they remain in open governance PR descriptions.",
            audit=f"PR #{record.pr_number} body was scanned for forbidden placeholders and regenerated from PB metadata without storing the raw original body.",
            impact="Open governance PR review receives a populated body with required approvals, audit context, decision, and status.",
        )
        generated_body = generate_pr_body(metadata)
        validation = validate_pr_body(generated_body)
        before = placeholder_count(record.original_body)
        after = 0 if record.update_succeeded else before
        decision = "VERIFIED" if record.update_succeeded and after == 0 else "FAIL_CLOSED"
        status = "READY FOR REVIEW" if decision == "VERIFIED" else "AUTHORIZATION_BLOCKED"
        scanned.append(
            {
                "pr_number": record.pr_number,
                "pb_number": record.pb_number,
                "pb_title": record.pb_title,
                "original_body_hash": _sha256_text(record.original_body),
                "generated_body_hash": validation["body_hash"],
                "placeholder_count_before": before,
                "placeholder_count_after": after,
                "pr_body_updated": record.update_succeeded,
                "update_attempted": record.update_attempted,
                "update_error": record.update_error,
                "decision": decision,
                "status": status,
            }
        )
    all_verified = all(item["decision"] == "VERIFIED" for item in scanned)
    report = {
        "control": "PB-026",
        "decision": "VERIFIED" if all_verified and open_pr_enumeration_status == "VERIFIED" else "FAIL_CLOSED",
        "status": "READY_FOR_REVIEW" if all_verified and open_pr_enumeration_status == "VERIFIED" else "AUTHORIZATION_BLOCKED",
        "open_pr_enumeration_status": open_pr_enumeration_status,
        "scanned_pr_numbers": [item["pr_number"] for item in scanned],
        "scanned_prs": scanned,
        "governance_controls": {
            "raw_pr_body_stored": False,
            "fail_closed_if_update_forbidden": True,
            "fail_closed_if_generated_body_missing": True,
            "fail_closed_if_open_pr_scan_incomplete": True,
        },
    }
    report["report_hash"] = _sha256_text(_canonical_json(report))
    return report


def write_outputs(body_path: Path, report_path: Path, template_path: Path) -> dict[str, Any]:
    metadata = pb026_metadata()
    generated_body = generate_pr_body(metadata)
    command = [
        "gh",
        "pr",
        "create",
        "--base",
        "main",
        "--head",
        "usbay/governance-pr-body-integration",
        "--title",
        metadata.title,
        "--body-file",
        body_path.as_posix(),
    ]
    template_text = template_path.read_text(encoding="utf-8")
    report = build_report(metadata, generated_body, template_text, command, body_path.as_posix())
    body_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.parent.mkdir(parents=True, exist_ok=True)
    body_path.write_text(generated_body, encoding="utf-8")
    report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return report


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="PB-026 governance PR body integration")
    parser.add_argument("--body-output", type=Path)
    parser.add_argument("--report-output", type=Path)
    parser.add_argument("--template-path", type=Path, default=Path(".github/pull_request_template.md"))
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        if args.body_output and args.report_output:
            report = write_outputs(args.body_output, args.report_output, args.template_path)
        else:
            metadata = pb026_metadata()
            body = generate_pr_body(metadata)
            report = {"decision": "VERIFIED", "body_validation": validate_pr_body(body)}
    except (PRBodyIntegrationBlocked, FileNotFoundError) as exc:
        print("Decision: FAIL_CLOSED")
        print(str(exc))
        return 1
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
