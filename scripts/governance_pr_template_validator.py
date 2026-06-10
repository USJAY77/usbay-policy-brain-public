#!/usr/bin/env python3
"""PB-025 governance PR template completion validator.

Generates and validates PB pull request bodies so unresolved template
placeholders cannot reach PR creation.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any


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
TITLE_PATTERN = re.compile(r"^PB-\d{3} (VERIFIED|REVIEW_REQUIRED|BLOCKED): .+")


class TemplateValidationBlocked(RuntimeError):
    """Raised when a generated PR body is not governance-complete."""


@dataclass(frozen=True)
class PRTemplateMetadata:
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
    def pb_label(self) -> str:
        return f"PB-{self.pb_number:03d}"

    @property
    def title(self) -> str:
        return f"{self.pb_label} {self.decision}: {self.pb_title}"


def _canonical_json(payload: Any) -> str:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"))


def _sha256_payload(payload: Any) -> str:
    return hashlib.sha256(_canonical_json(payload).encode("utf-8")).hexdigest()


def _require(condition: bool, reason: str) -> None:
    if not condition:
        raise TemplateValidationBlocked(reason)


def _section(name: str, body: str) -> str:
    body = body.strip()
    _require(bool(body), f"SECTION_EMPTY:{name}")
    return f"## {name}\n{body}"


def validate_metadata(metadata: PRTemplateMetadata) -> None:
    _require(1 <= metadata.pb_number <= 999, "PB_NUMBER_INVALID")
    _require(bool(metadata.pb_title.strip()), "PB_TITLE_MISSING")
    _require(metadata.pb_title == metadata.pb_title.strip(), "PB_TITLE_MALFORMED")
    _require(metadata.decision in DECISION_STATUS, f"DECISION_INVALID:{metadata.decision}")
    _require(metadata.status in set(DECISION_STATUS.values()), f"STATUS_INVALID:{metadata.status}")
    _require(metadata.status == DECISION_STATUS[metadata.decision], f"DECISION_STATUS_MISMATCH:{metadata.decision}:{metadata.status}")
    _require(bool(TITLE_PATTERN.fullmatch(metadata.title)), "PR_TITLE_MALFORMED")
    _require(bool(metadata.required_approvals), "REQUIRED_APPROVALS_EMPTY")
    _require(bool(metadata.governance_checks), "GOVERNANCE_CHECKS_EMPTY")
    for field_name in ("purpose", "risk", "policy_link", "audit", "impact"):
        _require(bool(str(getattr(metadata, field_name)).strip()), f"FIELD_EMPTY:{field_name}")


def generate_pr_body(metadata: PRTemplateMetadata) -> str:
    validate_metadata(metadata)
    body = "\n\n".join(
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
    return body + "\n"


def validate_pr_body(pr_body: str) -> dict[str, Any]:
    _require(bool(pr_body.strip()), "PR_BODY_MISSING")
    forbidden_found = [placeholder for placeholder in FORBIDDEN_PLACEHOLDERS if placeholder in pr_body]
    _require(not forbidden_found, "UNRESOLVED_TEMPLATE_PLACEHOLDER:" + ",".join(forbidden_found))
    heading_pattern = re.compile(r"^## (?P<section>.+)$", re.MULTILINE)
    present_sections = {match.group("section").strip() for match in heading_pattern.finditer(pr_body)}
    missing_sections = [section for section in REQUIRED_SECTIONS if section not in present_sections]
    _require(not missing_sections, "REQUIRED_SECTION_MISSING:" + ",".join(missing_sections))
    empty_sections: list[str] = []
    for section in REQUIRED_SECTIONS:
        marker = f"## {section}\n"
        start = pr_body.find(marker)
        if start == -1:
            continue
        next_start = pr_body.find("\n\n## ", start + len(marker))
        content = pr_body[start + len(marker) : next_start if next_start != -1 else len(pr_body)].strip()
        if not content:
            empty_sections.append(section)
    _require(not empty_sections, "SECTION_EMPTY:" + ",".join(empty_sections))
    return {
        "required_sections": {section: "POPULATED" for section in REQUIRED_SECTIONS},
        "forbidden_placeholders": {placeholder: "ABSENT" for placeholder in FORBIDDEN_PLACEHOLDERS},
        "body_hash": _sha256_payload({"body": pr_body}),
    }


def build_validation_report(metadata: PRTemplateMetadata, pr_body: str) -> dict[str, Any]:
    validation = validate_pr_body(pr_body)
    return {
        "control": "PB-025",
        "decision": "VERIFIED",
        "status": "READY FOR REVIEW",
        "title": metadata.title,
        "metadata": asdict(metadata),
        "validation": validation,
        "governance_controls": {
            "admin_bypass": "FORBIDDEN",
            "admin_merge": "FORBIDDEN",
            "auto_approval": "FORBIDDEN",
            "branch_protection_bypass": "FORBIDDEN",
            "pr_creation_blocked_on_invalid_body": True,
        },
    }


def pb025_metadata() -> PRTemplateMetadata:
    return PRTemplateMetadata(
        pb_number=25,
        pb_title="Governance PR Template Completion",
        decision="VERIFIED",
        status="READY FOR REVIEW",
        purpose="Eliminate unresolved governance template placeholders from generated PB pull request bodies before PR creation.",
        risk="Unresolved template placeholders can create audit ambiguity, hide missing governance information, or allow incomplete release metadata into review.",
        policy_link="AGENTS.md branch governance, fail-closed validation, human oversight, and audit-first engineering requirements.",
        required_approvals=("USBAY-AUDIT", "USBAY-GLOBAL23"),
        governance_checks=(
            "python3 -m py_compile scripts/governance_pr_template_validator.py",
            "pytest -q tests/test_pb025_pr_template_completion.py",
            "git diff --check",
            "conflict marker scan",
        ),
        audit="PB-025 generates a validation report and generated PR body proving all required sections are populated and all forbidden placeholders are absent.",
        impact="Generated PR bodies become deterministic, complete, and fail-closed when required governance fields are missing.",
    )


def write_outputs(body_path: Path | None, report_path: Path | None, metadata: PRTemplateMetadata) -> dict[str, Any]:
    pr_body = generate_pr_body(metadata)
    report = build_validation_report(metadata, pr_body)
    if body_path:
        body_path.parent.mkdir(parents=True, exist_ok=True)
        body_path.write_text(pr_body, encoding="utf-8")
    if report_path:
        report_path.parent.mkdir(parents=True, exist_ok=True)
        report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return report


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="PB-025 governance PR template completion validator")
    parser.add_argument("--pb025", action="store_true")
    parser.add_argument("--validate-body", type=Path)
    parser.add_argument("--body-output", type=Path)
    parser.add_argument("--report-output", type=Path)
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        if args.validate_body:
            report = {"decision": "VERIFIED", "validation": validate_pr_body(args.validate_body.read_text(encoding="utf-8"))}
        else:
            metadata = pb025_metadata()
            report = write_outputs(args.body_output, args.report_output, metadata)
    except (TemplateValidationBlocked, FileNotFoundError) as exc:
        print("Decision: FAIL_CLOSED")
        print(str(exc))
        return 1
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
