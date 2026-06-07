#!/usr/bin/env python3
"""PB-023 governance metadata authority.

This module is the local source of truth for PB release metadata. It derives
branch names, commit titles, PR titles, PR bodies, decision, and status from a
single PB metadata record and blocks manual drift unless an explicit governance
override is provided.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import asdict, dataclass, replace
from pathlib import Path
from typing import Any


REQUIRED_PR_SECTIONS = ("RISK", "MECHANISM", "GAP", "AUDIT", "IMPACT", "Decision", "Status")
DECISION_STATUS = {
    "VERIFIED": "READY FOR REVIEW",
    "REVIEW_REQUIRED": "AWAITING_APPROVAL",
    "BLOCKED": "FAIL_CLOSED",
}
TITLE_PATTERN = re.compile(r"^PB-(\d{3}) (VERIFIED|REVIEW_REQUIRED|BLOCKED): ([A-Z][A-Za-z0-9 &:/(),.'-]*(?: [A-Za-z0-9&:/(),.'-]+)*)$")
SLUG_PATTERN = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")


class MetadataAuthorityBlocked(RuntimeError):
    """Raised when governance metadata fails closed."""


@dataclass(frozen=True)
class PBMetadata:
    pb_number: int
    pb_slug: str
    pb_title: str
    decision: str
    status: str

    @property
    def pb_label(self) -> str:
        return f"PB-{self.pb_number:03d}"


@dataclass(frozen=True)
class GeneratedMetadata:
    pb_number: int
    pb_slug: str
    pb_title: str
    decision: str
    status: str
    branch_name: str
    commit_title: str
    pr_title: str
    pr_body: str


def _require(condition: bool, reason: str) -> None:
    if not condition:
        raise MetadataAuthorityBlocked(reason)


def _section(text: str, body: str) -> str:
    return f"## {text}\n{body.strip()}"


def validate_source_metadata(metadata: PBMetadata) -> None:
    _require(isinstance(metadata.pb_number, int), "PB_NUMBER_INVALID")
    _require(1 <= metadata.pb_number <= 999, "PB_NUMBER_OUT_OF_RANGE")
    _require(bool(metadata.pb_slug.strip()), "PB_SLUG_MISSING")
    _require(bool(SLUG_PATTERN.fullmatch(metadata.pb_slug)), "PB_SLUG_MALFORMED")
    _require(bool(metadata.pb_title.strip()), "PB_TITLE_MISSING")
    _require(metadata.pb_title == metadata.pb_title.strip(), "PB_TITLE_MALFORMED")
    _require(metadata.pb_title[0].isupper(), "PB_TITLE_LOWERCASE_OR_INCOMPLETE")
    _require(metadata.decision in DECISION_STATUS, f"DECISION_INVALID:{metadata.decision}")
    _require(metadata.status in set(DECISION_STATUS.values()), f"STATUS_INVALID:{metadata.status}")
    expected_status = DECISION_STATUS[metadata.decision]
    _require(metadata.status == expected_status, f"DECISION_STATUS_MISMATCH:{metadata.decision}:{metadata.status}")


def generate_pr_body(metadata: PBMetadata, title: str) -> str:
    sections = [
        _section(
            "RISK",
            "Manual PB metadata entry can create audit drift across branch names, commit titles, PR titles, PR bodies, decision, and status.",
        ),
        _section(
            "MECHANISM",
            f"{title} derives all governed release metadata from one PB metadata source and validates the generated outputs before release use.",
        ),
        _section(
            "GAP",
            "This control does not bypass branch protection, approve reviews, merge pull requests, or create external certification claims.",
        ),
        _section(
            "AUDIT",
            "Generated metadata records the PB number, slug, title, branch, commit title, PR title, PR body sections, decision, and status.",
        ),
        _section(
            "IMPACT",
            "Governance release metadata becomes deterministic and fail-closed when metadata is missing, malformed, mismatched, or manually overridden.",
        ),
        _section("Decision", metadata.decision),
        _section("Status", metadata.status),
    ]
    return "\n\n".join(sections) + "\n"


def generate_metadata(metadata: PBMetadata) -> GeneratedMetadata:
    validate_source_metadata(metadata)
    title = f"{metadata.pb_label} {metadata.decision}: {metadata.pb_title}"
    branch_name = f"usbay/{metadata.pb_slug}"
    pr_body = generate_pr_body(metadata, title)
    generated = GeneratedMetadata(
        pb_number=metadata.pb_number,
        pb_slug=metadata.pb_slug,
        pb_title=metadata.pb_title,
        decision=metadata.decision,
        status=metadata.status,
        branch_name=branch_name,
        commit_title=title,
        pr_title=title,
        pr_body=pr_body,
    )
    validate_generated_metadata(metadata, generated)
    return generated


def validate_pr_body(pr_body: str) -> None:
    _require(bool(pr_body.strip()), "PR_BODY_MISSING")
    missing = [section for section in REQUIRED_PR_SECTIONS if f"## {section}" not in pr_body]
    _require(not missing, "PR_BODY_REQUIRED_SECTIONS_MISSING:" + ",".join(missing))


def validate_generated_metadata(
    metadata: PBMetadata,
    generated: GeneratedMetadata,
    *,
    allow_governance_override: bool = False,
) -> None:
    validate_source_metadata(metadata)
    if not allow_governance_override:
        expected = {
            "branch_name": f"usbay/{metadata.pb_slug}",
            "commit_title": f"{metadata.pb_label} {metadata.decision}: {metadata.pb_title}",
            "pr_title": f"{metadata.pb_label} {metadata.decision}: {metadata.pb_title}",
            "decision": metadata.decision,
            "status": metadata.status,
        }
        actual = {
            "branch_name": generated.branch_name,
            "commit_title": generated.commit_title,
            "pr_title": generated.pr_title,
            "decision": generated.decision,
            "status": generated.status,
        }
        for key, value in expected.items():
            _require(actual[key] == value, f"MANUAL_METADATA_OVERRIDE_BLOCKED:{key}")
    _require(bool(generated.pr_title.strip()), "PR_TITLE_MISSING")
    match = TITLE_PATTERN.fullmatch(generated.pr_title)
    _require(match is not None, "PR_TITLE_MALFORMED")
    _require(int(match.group(1)) == metadata.pb_number, "PB_NUMBER_MISMATCH")
    _require(match.group(2) == metadata.decision, "PR_TITLE_DECISION_MISMATCH")
    _require(match.group(3) == metadata.pb_title, "PR_TITLE_TEXT_MISMATCH")
    _require(bool(generated.commit_title.strip()), "COMMIT_TITLE_MISSING")
    _require(generated.commit_title == generated.pr_title, "COMMIT_TITLE_MISMATCH")
    _require(generated.pb_number == metadata.pb_number, "PB_NUMBER_MISMATCH")
    _require(generated.decision == metadata.decision, "DECISION_MISMATCH")
    _require(generated.status == metadata.status, "STATUS_MISMATCH")
    validate_pr_body(generated.pr_body)
    _require(f"## Decision\n{metadata.decision}" in generated.pr_body, "PR_BODY_DECISION_MISMATCH")
    _require(f"## Status\n{metadata.status}" in generated.pr_body, "PR_BODY_STATUS_MISMATCH")


def load_metadata(path: Path) -> PBMetadata:
    try:
        payload: dict[str, Any] = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise MetadataAuthorityBlocked("METADATA_SOURCE_MISSING") from exc
    except json.JSONDecodeError as exc:
        raise MetadataAuthorityBlocked("METADATA_SOURCE_INVALID_JSON") from exc
    missing = [field for field in ("pb_number", "pb_slug", "pb_title", "decision", "status") if field not in payload]
    _require(not missing, "METADATA_REQUIRED_FIELDS_MISSING:" + ",".join(missing))
    return PBMetadata(
        pb_number=int(payload["pb_number"]),
        pb_slug=str(payload["pb_slug"]),
        pb_title=str(payload["pb_title"]),
        decision=str(payload["decision"]),
        status=str(payload["status"]),
    )


def build_report(metadata: PBMetadata, generated: GeneratedMetadata) -> dict[str, Any]:
    return {
        "decision": "VERIFIED",
        "control": "PB-023",
        "metadata_source": asdict(metadata),
        "generated_metadata": asdict(generated),
        "validation": {
            "title_format": "VERIFIED",
            "commit_title_matches_pr_title": generated.commit_title == generated.pr_title,
            "required_pr_sections": list(REQUIRED_PR_SECTIONS),
            "manual_override": "BLOCKED_BY_DEFAULT",
            "branch_protection_bypass": "FORBIDDEN",
            "auto_approval": "FORBIDDEN",
            "admin_merge": "FORBIDDEN",
        },
    }


def _remove_pr_body_section(pr_body: str, section: str) -> str:
    marker = f"## {section}\n"
    start = pr_body.find(marker)
    if start == -1:
        return pr_body
    next_start = pr_body.find("\n\n## ", start + len(marker))
    if next_start == -1:
        return pr_body[:start].rstrip() + "\n"
    return pr_body[:start] + pr_body[next_start + 2 :]


def _fail_closed_result(name: str, expected: str, reason: str | None) -> dict[str, str]:
    outcome = "FAIL_CLOSED" if reason else "NOT_BLOCKED"
    return {
        "test": name,
        "expected": expected,
        "outcome": outcome,
        "reason": reason or "CONTROL_DID_NOT_BLOCK",
    }


def run_enforcement_verification(metadata: PBMetadata) -> dict[str, Any]:
    generated = generate_metadata(metadata)
    negative_cases = [
        (
            "invalid_pr_title",
            replace(generated, pr_title="Governance Metadata Authority"),
            False,
        ),
        (
            "invalid_commit_title",
            replace(generated, commit_title="PB-023 VERIFIED: Different"),
            False,
        ),
        (
            "missing_pr_body",
            replace(generated, pr_body=""),
            False,
        ),
        (
            "missing_risk_section",
            replace(generated, pr_body=_remove_pr_body_section(generated.pr_body, "RISK")),
            False,
        ),
        (
            "missing_mechanism_section",
            replace(generated, pr_body=_remove_pr_body_section(generated.pr_body, "MECHANISM")),
            False,
        ),
        (
            "missing_gap_section",
            replace(generated, pr_body=_remove_pr_body_section(generated.pr_body, "GAP")),
            False,
        ),
        (
            "missing_audit_section",
            replace(generated, pr_body=_remove_pr_body_section(generated.pr_body, "AUDIT")),
            False,
        ),
        (
            "missing_impact_section",
            replace(generated, pr_body=_remove_pr_body_section(generated.pr_body, "IMPACT")),
            False,
        ),
        (
            "decision_mismatch",
            replace(generated, decision="BLOCKED"),
            True,
        ),
        (
            "status_mismatch",
            replace(generated, status="FAIL_CLOSED"),
            True,
        ),
    ]
    results: list[dict[str, str]] = []
    for name, candidate, allow_override in negative_cases:
        reason: str | None = None
        try:
            validate_generated_metadata(metadata, candidate, allow_governance_override=allow_override)
        except MetadataAuthorityBlocked as exc:
            reason = str(exc)
        results.append(_fail_closed_result(name, "FAIL_CLOSED", reason))
    all_blocked = all(result["outcome"] == "FAIL_CLOSED" for result in results)
    return {
        "control": "PB-023",
        "decision": "VERIFIED" if all_blocked else "BLOCKED",
        "status": "READY FOR REVIEW" if all_blocked else "FAIL_CLOSED",
        "enforcement_capable": all_blocked,
        "negative_tests": results,
        "summary": {
            "total": len(results),
            "fail_closed": sum(1 for result in results if result["outcome"] == "FAIL_CLOSED"),
            "not_blocked": sum(1 for result in results if result["outcome"] != "FAIL_CLOSED"),
        },
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="PB-023 governed metadata authority.")
    parser.add_argument("--metadata-json", type=Path)
    parser.add_argument("--pb-number", type=int)
    parser.add_argument("--pb-slug")
    parser.add_argument("--pb-title")
    parser.add_argument("--decision", choices=tuple(DECISION_STATUS))
    parser.add_argument("--status", choices=tuple(DECISION_STATUS.values()))
    parser.add_argument("--report-json", type=Path)
    parser.add_argument("--pr-body-output", type=Path)
    parser.add_argument("--commit-title-output", type=Path)
    parser.add_argument("--pr-title-output", type=Path)
    parser.add_argument("--enforcement-report-json", type=Path)
    return parser.parse_args()


def metadata_from_args(args: argparse.Namespace) -> PBMetadata:
    if args.metadata_json:
        return load_metadata(args.metadata_json)
    missing = [
        name
        for name, value in (
            ("pb_number", args.pb_number),
            ("pb_slug", args.pb_slug),
            ("pb_title", args.pb_title),
            ("decision", args.decision),
            ("status", args.status),
        )
        if value is None
    ]
    _require(not missing, "METADATA_REQUIRED_FIELDS_MISSING:" + ",".join(missing))
    return PBMetadata(
        pb_number=args.pb_number,
        pb_slug=args.pb_slug,
        pb_title=args.pb_title,
        decision=args.decision,
        status=args.status,
    )


def write_outputs(args: argparse.Namespace, report: dict[str, Any], generated: GeneratedMetadata) -> None:
    outputs = (
        (args.report_json, json.dumps(report, indent=2, sort_keys=True) + "\n"),
        (args.pr_body_output, generated.pr_body),
        (args.commit_title_output, generated.commit_title + "\n"),
        (args.pr_title_output, generated.pr_title + "\n"),
    )
    for path, content in outputs:
        if path is None:
            continue
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")


def write_enforcement_report(path: Path | None, report: dict[str, Any]) -> None:
    if path is None:
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def main() -> int:
    args = parse_args()
    try:
        metadata = metadata_from_args(args)
        generated = generate_metadata(metadata)
        report = build_report(metadata, generated)
        enforcement_report = run_enforcement_verification(metadata) if args.enforcement_report_json else None
        write_outputs(args, report, generated)
        if enforcement_report is not None:
            write_enforcement_report(args.enforcement_report_json, enforcement_report)
    except MetadataAuthorityBlocked as exc:
        print("Decision: BLOCKED")
        print(str(exc))
        return 1
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
