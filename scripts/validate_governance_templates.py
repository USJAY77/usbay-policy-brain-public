from __future__ import annotations

import argparse
import json
import re
from dataclasses import dataclass
from pathlib import Path


TITLE_RE = re.compile(r"^PB-\d{3}(?:-\d{3})? VERIFIED: [A-Z][A-Za-z0-9 .&/+:-]*$")
REQUIRED_PR_SECTIONS = ("PURPOSE", "RISK", "POLICY LINK", "GOVERNANCE CHECKS", "AUDIT", "IMPACT")
REQUIRED_AUDIT_SECTIONS = ("AUDIT",)
REQUIRED_EVIDENCE_SECTIONS = ("EVIDENCE PACKAGE", "SOURCE", "HASHES", "AUDIT", "IMPACT", "DECISION", "STATUS")


@dataclass(frozen=True)
class ValidationResult:
    valid: bool
    errors: tuple[str, ...]

    def to_dict(self) -> dict:
        return {"valid": self.valid, "errors": list(self.errors)}


def validate_title(title: str) -> ValidationResult:
    errors: list[str] = []
    if not title.strip():
        errors.append("TITLE_MISSING")
    elif not TITLE_RE.match(title.strip()):
        errors.append("TITLE_FORMAT_INVALID")
    return ValidationResult(not errors, tuple(errors))


def required_sections_missing(body: str, sections: tuple[str, ...]) -> list[str]:
    lines = {line.strip() for line in body.splitlines()}
    return [section for section in sections if section not in lines]


def validate_pr_body(body: str) -> ValidationResult:
    errors: list[str] = []
    if not body.strip():
        errors.append("PR_BODY_MISSING")
    for section in required_sections_missing(body, REQUIRED_PR_SECTIONS):
        errors.append(f"SECTION_MISSING:{section}")
    for section in required_sections_missing(body, REQUIRED_AUDIT_SECTIONS):
        errors.append(f"AUDIT_SECTION_MISSING:{section}")
    return ValidationResult(not errors, tuple(errors))


def validate_evidence_template(body: str) -> ValidationResult:
    errors = [f"SECTION_MISSING:{section}" for section in required_sections_missing(body, REQUIRED_EVIDENCE_SECTIONS)]
    return ValidationResult(not errors, tuple(errors))


def validate_template_inventory(template_dir: Path) -> dict:
    expected = {
        "generated_commit_title_template.txt": validate_title,
        "generated_pr_title_template.txt": validate_title,
        "generated_pr_body_template.md": validate_pr_body,
        "generated_review_template.md": lambda body: ValidationResult(
            not required_sections_missing(body, ("REVIEW SCOPE", "REVIEWER", "GOVERNANCE CHECKS", "AUDIT", "DECISION", "STATUS")),
            tuple(f"SECTION_MISSING:{section}" for section in required_sections_missing(body, ("REVIEW SCOPE", "REVIEWER", "GOVERNANCE CHECKS", "AUDIT", "DECISION", "STATUS"))),
        ),
        "generated_evidence_template.md": validate_evidence_template,
    }
    results: dict[str, dict] = {}
    for filename, validator in expected.items():
        path = template_dir / filename
        if not path.exists():
            results[filename] = {"valid": False, "errors": ["TEMPLATE_MISSING"]}
            continue
        content = path.read_text(encoding="utf-8")
        if filename.endswith("_title_template.txt"):
            sample = content.replace("{{PB_RANGE}}", "172").replace("{{SCOPE}}", "Governance Template Enforcement").strip()
            results[filename] = validator(sample).to_dict()
        else:
            results[filename] = validator(content).to_dict()
    return results


def render_pb_title(pb_range: str, scope: str) -> str:
    return f"PB-{pb_range} VERIFIED: {scope}"


def render_pr_body(
    *,
    purpose: str,
    risk: str,
    policy_link: str,
    governance_checks: str,
    audit: str,
    impact: str,
    decision: str,
    status: str,
) -> str:
    return "\n".join(
        [
            "PURPOSE",
            purpose,
            "",
            "RISK",
            risk,
            "",
            "POLICY LINK",
            policy_link,
            "",
            "GOVERNANCE CHECKS",
            governance_checks,
            "",
            "AUDIT",
            audit,
            "",
            "IMPACT",
            impact,
            "",
            "Decision",
            decision,
            "",
            "Status",
            status,
            "",
        ]
    )


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate USBAY governance templates.")
    parser.add_argument("--template-dir", default="templates")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    results = validate_template_inventory(Path(args.template_dir))
    valid = all(item["valid"] for item in results.values())
    payload = {"valid": valid, "templates": results}
    if args.json:
        print(json.dumps(payload, indent=2, sort_keys=True))
    else:
        print("VALID" if valid else "FAIL_CLOSED")
    return 0 if valid else 1


if __name__ == "__main__":
    raise SystemExit(main())
