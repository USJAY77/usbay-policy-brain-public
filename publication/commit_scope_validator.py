"""Fail-closed commit scope validation for publication runtime staging."""

from __future__ import annotations

from pathlib import PurePosixPath

from publication.models import CommitScopeResult, hash_payload


POLICY_VERSION = "USBAY-PUBGOV-024"

APPROVED_PUBGOV_013_021_FILES = (
    "publication/__init__.py",
    "publication/audit_persistence.py",
    "publication/classification.py",
    "publication/connector_gate.py",
    "publication/decision_engine.py",
    "publication/errors.py",
    "publication/evidence_chain.py",
    "publication/final_report.py",
    "publication/human_approval.py",
    "publication/models.py",
    "publication/registry_store.py",
    "publication/registry_validator.py",
    "publication/runtime_aggregator.py",
    "publication/sensitive_data_scanner.py",
    "publication/state_machine.py",
    "tests/test_publication_audit_persistence.py",
    "tests/test_publication_connector_gate.py",
    "tests/test_publication_evidence_chain.py",
    "tests/test_publication_final_report.py",
    "tests/test_publication_human_approval.py",
    "tests/test_publication_runtime_aggregator.py",
    "tests/test_publication_runtime_foundation.py",
    "tests/test_publication_sensitive_data_scanner.py",
    "docs/publication/USBAY_PUBGOV_013_TO_021_COMMIT_READINESS.md",
    "policy/publication/publication_approval_policy.json",
    "policy/publication/publication_classification_policy.json",
    "policy/publication/publication_registry_record.example.json",
    "policy/publication/publication_registry_schema.json",
)

FORBIDDEN_PREFIXES = (
    "docs/audits/",
    "docs/game/",
    "governance/",
    "pricing/",
    "pricing_poster/",
    "simulator/",
    "gateway/",
    "replit/",
)

FORBIDDEN_EXACT = {
    ".replit",
    "replit.nix",
}


def validate_commit_scope(candidate_files: list[str] | tuple[str, ...] | None) -> CommitScopeResult:
    if not candidate_files:
        return _result(
            approved=False,
            staged_files=(),
            rejected_files=(),
            reason="EMPTY_CANDIDATE_LIST",
        )

    normalized = tuple(_normalize_path(path) for path in candidate_files)
    unique_files = tuple(dict.fromkeys(normalized))
    approved_set = set(APPROVED_PUBGOV_013_021_FILES)
    rejected = tuple(path for path in unique_files if path not in approved_set or _is_forbidden(path))
    staged = tuple(path for path in APPROVED_PUBGOV_013_021_FILES if path in set(unique_files) and path not in rejected)

    if rejected:
        return _result(
            approved=False,
            staged_files=staged,
            rejected_files=tuple(sorted(rejected)),
            reason="FORBIDDEN_OR_UNAPPROVED_FILES",
        )

    return _result(
        approved=True,
        staged_files=staged,
        rejected_files=(),
        reason="APPROVED_SCOPE",
    )


def _normalize_path(path: str) -> str:
    rendered = str(path).replace("\\", "/").strip()
    if rendered.startswith("./"):
        rendered = rendered[2:]
    return PurePosixPath(rendered).as_posix()


def _is_forbidden(path: str) -> bool:
    if path in FORBIDDEN_EXACT:
        return True
    upper_path = path.upper()
    if "PBSEC" in upper_path or "PB015" in upper_path:
        return True
    if path.startswith("tests/") and not path.startswith("tests/test_publication_"):
        return True
    if path.startswith("docs/publication/") and path != "docs/publication/USBAY_PUBGOV_013_TO_021_COMMIT_READINESS.md":
        return True
    if path.startswith("policy/publication/") and path not in APPROVED_PUBGOV_013_021_FILES:
        return True
    return any(path.startswith(prefix) for prefix in FORBIDDEN_PREFIXES)


def _result(
    *,
    approved: bool,
    staged_files: tuple[str, ...],
    rejected_files: tuple[str, ...],
    reason: str,
) -> CommitScopeResult:
    evidence_payload = {
        "approved": approved,
        "staged_files": staged_files,
        "rejected_files": rejected_files,
        "policy_version": POLICY_VERSION,
        "reason": reason,
        "raw_file_content_stored": False,
    }
    return CommitScopeResult(
        approved=approved,
        rejected_files=rejected_files,
        staged_files=staged_files,
        evidence_hash=hash_payload(evidence_payload),
        policy_version=POLICY_VERSION,
        reason=reason,
    )
