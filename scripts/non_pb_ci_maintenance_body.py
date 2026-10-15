"""Draft-only non-PB CI maintenance bodies; no approval or publication effects.

Path and reference checks are structural. Humans must review the actual patch
for protected semantic changes. Supplied classification/evidence is not authority.
"""
from __future__ import annotations

import argparse
from dataclasses import dataclass
import json
from pathlib import Path
import re
import subprocess
from typing import Mapping, Sequence

from scripts.governance_pr_body_integration import (
    PRBodyIntegrationBlocked,
    validate_generated_pr_evidence,
    validate_pr_body,
)

ROUTE = "non_pb_ci_maintenance.v1"
REVIEWERS = ("USBAY-GLOBAL23", "USBAY-AUDIT")
SHA = re.compile(r"[0-9a-f]{40}")
REPOSITORY = re.compile(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+")
CI_PATH = re.compile(r"\.github/workflows/[A-Za-z0-9_-]+\.ya?ml")
LANE_PATH = re.compile(r"requirements-(?:ci|[a-z0-9]+(?:-[a-z0-9]+)*)\.txt")
FIELDS = frozenset({
    "route", "repository", "base_sha", "candidate_sha", "classification_reference",
    "purpose", "risk", "policy_reference", "validation_reference",
    "validation_head_sha", "validation_summary", "audit", "impact", "rollback_plan",
})


class MaintenanceBodyBlocked(ValueError):
    """Invalid, mixed or ambiguous input needs PB routing or clarification."""


@dataclass(frozen=True)
class MaintenanceMetadata:
    route: str
    repository: str
    base_sha: str
    candidate_sha: str
    classification_reference: str
    purpose: str
    risk: str
    policy_reference: str
    validation_reference: str
    validation_head_sha: str
    validation_summary: str
    audit: str
    impact: str
    rollback_plan: str


def _require(condition: bool, code: str) -> None:
    if not condition:
        raise MaintenanceBodyBlocked(code)


def metadata_from_mapping(value: Mapping[str, object]) -> MaintenanceMetadata:
    _require(type(value) is dict and set(value) == FIELDS, "METADATA_FIELDS_INVALID")
    result = MaintenanceMetadata(**value)
    validate_metadata(result)
    return result


def validate_metadata(metadata: MaintenanceMetadata) -> None:
    _require(type(metadata) is MaintenanceMetadata, "METADATA_TYPE_INVALID")
    for name in FIELDS:
        text = getattr(metadata, name)
        _require(type(text) is str and 0 < len(text) <= 16000 and text == text.strip(),
                 "METADATA_TEXT_INVALID:" + name)
        _require(not any(ord(c) < 32 and c != "\n" or 0xD800 <= ord(c) <= 0xDFFF for c in text),
                 "METADATA_TEXT_INVALID:" + name)
        _require(not any(line.lstrip().startswith("#") for line in text.splitlines()),
                 "METADATA_HEADING_INJECTION:" + name)
    _require(metadata.route == ROUTE, "ROUTE_INVALID")
    _require(REPOSITORY.fullmatch(metadata.repository) is not None, "REPOSITORY_INVALID")
    for name in ("base_sha", "candidate_sha", "validation_head_sha"):
        _require(SHA.fullmatch(getattr(metadata, name)) is not None, "SHA_INVALID:" + name)
    _require(metadata.base_sha != metadata.candidate_sha, "EMPTY_CHANGESET")
    _require(metadata.validation_head_sha == metadata.candidate_sha, "VALIDATION_HEAD_MISMATCH")
    prefix = "https://github.com/" + metadata.repository + "/actions/runs/"
    _require(metadata.validation_reference.startswith(prefix)
             and metadata.validation_reference[len(prefix):].isascii()
             and metadata.validation_reference[len(prefix):].isdigit(), "VALIDATION_REFERENCE_INVALID")


def validate_changeset(changes: Sequence[tuple[str, str]]) -> tuple[tuple[str, str], ...]:
    _require(type(changes) in (list, tuple) and 0 < len(changes) <= 100, "CHANGESET_INVALID")
    seen: set[str] = set()
    for entry in changes:
        _require(type(entry) in (list, tuple) and len(entry) == 2, "CHANGE_ENTRY_INVALID")
        status, path = entry
        _require(type(status) is str and status in {"A", "M"}, "CHANGE_STATUS_AMBIGUOUS")
        _require(type(path) is str and len(path) <= 240 and path not in seen,
                 "CHANGE_PATH_INVALID")
        _require(CI_PATH.fullmatch(path) is not None or LANE_PATH.fullmatch(path) is not None,
                 "PB_OR_HUMAN_CLARIFICATION_REQUIRED")
        seen.add(path)
    return tuple(sorted(tuple(entry) for entry in changes))


def read_git_changeset(root: Path, metadata: MaintenanceMetadata) -> tuple[tuple[str, str], ...]:
    """Read complete committed diff; no shell, index edits or network operations."""
    validate_metadata(metadata)
    command = ["git", "-C", str(root), "diff", "--no-ext-diff", "--no-textconv",
               "--no-renames", "--name-status", metadata.base_sha, metadata.candidate_sha, "--"]
    completed = subprocess.run(command, capture_output=True, text=True, timeout=10, check=False)
    _require(completed.returncode == 0 and len(completed.stdout) <= 64000, "GIT_CHANGESET_UNAVAILABLE")
    changes = [tuple(line.split("\t")) for line in completed.stdout.splitlines()]
    return validate_changeset(changes)


def generate_body(metadata: MaintenanceMetadata, changes: Sequence[tuple[str, str]]) -> str:
    validate_metadata(metadata)
    changeset = validate_changeset(changes)
    source = (f"Repository: {metadata.repository}\nBase: {metadata.base_sha}\n"
              f"Candidate: {metadata.candidate_sha}\n"
              f"Owner classification reference (supplied, not authenticated by this generator): "
              f"{metadata.classification_reference}")
    evidence = f"{metadata.validation_reference}\n{metadata.validation_summary}"
    checks = ("- Complete declared changeset and candidate/evidence references checked structurally.\n"
              "- Human reviewers must inspect the full patch, dependency impact and evidence; "
              "path eligibility alone cannot prove unchanged semantics.\n"
              "- All applicable dependency-policy evidence, branch protection and required CI checks remain mandatory.\n"
              "- Two required human reviews remain outstanding; no auto-approval or bypass.")
    sections = {
        "PURPOSE": metadata.purpose,
        "RISK": metadata.risk,
        "POLICY LINK": metadata.policy_reference,
        "REQUIRED APPROVALS": "\n".join("- " + reviewer for reviewer in REVIEWERS),
        "GOVERNANCE CHECKS": checks,
        "AUDIT": metadata.audit + "\n" + source,
        "IMPACT": metadata.impact,
        "MECHANISM": "Route " + ROUTE + "; no PB identifier assigned. "
                     "This generator produces review text only, not approval or authority.",
        "GAP": "REVIEW_REQUIRED: actual human scope/evidence review and applicable mandatory checks "
               "are still required. Mixed, ambiguous or protected-semantic changes must use PB routing "
               "or explicit human clarification. Supplied references are not authenticated evidence.",
        "VALIDATION": evidence,
        "VALIDATION RESULTS": metadata.validation_summary,
        "CHANGED FILES": "\n".join(f"- {status}: {path}" for status, path in changeset),
        "SOURCE": source,
        "COMMIT OR SOURCE REFERENCE": metadata.candidate_sha,
        "ROLLBACK": "No rollback, merge, deployment or activation is performed by body generation.",
        "ROLLBACK PLAN": metadata.rollback_plan,
        "Decision": "REVIEW_REQUIRED",
        "Status": "AWAITING_APPROVAL",
    }
    body = "\n\n".join(f"## {name}\n{text}" for name, text in sections.items()) + "\n"
    validate_pr_body(body)
    validate_generated_pr_evidence(body, source_reference=metadata.candidate_sha)
    return body


def validate_body(body: str, metadata: MaintenanceMetadata, changes: Sequence[tuple[str, str]]) -> None:
    """Exact regeneration prevents removal/substitution of sections or fixed safeguards."""
    _require(type(body) is str and body == generate_body(metadata, changes), "BODY_BINDING_MISMATCH")


def _closed_json(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        _require(key not in result, "DUPLICATE_METADATA_KEY")
        result[key] = value
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--metadata-json", type=Path, required=True)
    parser.add_argument("--repo-root", type=Path, required=True)
    args = parser.parse_args()
    try:
        with args.metadata_json.open("rb") as stream:
            raw = stream.read(128001)
        _require(len(raw) <= 128000, "METADATA_TOO_LARGE")
        metadata = metadata_from_mapping(json.loads(raw.decode("utf-8"), object_pairs_hook=_closed_json))
        changes = read_git_changeset(args.repo_root, metadata)
        print(generate_body(metadata, changes), end="")
    except (MaintenanceBodyBlocked, PRBodyIntegrationBlocked, OSError, ValueError, subprocess.SubprocessError) as exc:
        parser.exit(1, "NON_PB_ROUTE_BLOCKED: " + type(exc).__name__ + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
