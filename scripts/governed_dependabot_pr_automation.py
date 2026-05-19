#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import subprocess
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from governance.canonical_governance_state import build_canonical_governance_state, sha256_text
from governance.ci_status_normalization import normalize_ci_status


AUDIT_COMMENT = """Governed auto-merge approved.

USBAY validation completed:
- Dependabot PR eligibility verified
- dependency/workflow scope confirmed
- stale lineage recovery completed if required
- canonical evidence regeneration verified
- audit-artifact-guard passed
- production-readiness passed
- policy verification passed
- required GitHub checks passed

No governance controls were bypassed.
No continue-on-error was introduced.
Fail-closed behavior preserved.

Result:
This PR is safe to merge under USBAY governed dependency automation."""

REVIEW_LABEL = "governance-review-required"
REVIEW_APPROVED_LABEL = "governance-review-approved"

SAFE_DEPENDENCY_SCOPE = "SAFE_DEPENDENCY_SCOPE"
SAFE_WORKFLOW_VERSION_SCOPE = "SAFE_WORKFLOW_VERSION_SCOPE"
GOVERNANCE_SENSITIVE_SCOPE = "GOVERNANCE_SENSITIVE_SCOPE"
RUNTIME_SENSITIVE_SCOPE = "RUNTIME_SENSITIVE_SCOPE"
CRYPTOGRAPHIC_SENSITIVE_SCOPE = "CRYPTOGRAPHIC_SENSITIVE_SCOPE"
UNKNOWN_SCOPE = "UNKNOWN_SCOPE"

SAFE_DEPENDENCY_SCOPE_ALLOWED = "SAFE_DEPENDENCY_SCOPE_ALLOWED"
SAFE_WORKFLOW_VERSION_SCOPE_ALLOWED = "SAFE_WORKFLOW_VERSION_SCOPE_ALLOWED"
GOVERNANCE_SENSITIVE_SCOPE_BLOCKED = "GOVERNANCE_SENSITIVE_SCOPE_BLOCKED"
RUNTIME_SENSITIVE_SCOPE_BLOCKED = "RUNTIME_SENSITIVE_SCOPE_BLOCKED"
CRYPTOGRAPHIC_SENSITIVE_SCOPE_BLOCKED = "CRYPTOGRAPHIC_SENSITIVE_SCOPE_BLOCKED"
UNKNOWN_SCOPE_BLOCKED = "UNKNOWN_SCOPE_BLOCKED"
NON_DEPENDABOT_AUTHOR_BLOCKED = "NON_DEPENDABOT_AUTHOR_BLOCKED"
NON_DEPENDABOT_BRANCH_BLOCKED = "NON_DEPENDABOT_BRANCH_BLOCKED"
PERMISSION_WIDENING_BLOCKED = "PERMISSION_WIDENING_BLOCKED"
WORKFLOW_LOGIC_CHANGE_BLOCKED = "WORKFLOW_LOGIC_CHANGE_BLOCKED"
PR_NOT_FOUND = "PR_NOT_FOUND"
PR_BRANCH_MISMATCH = "PR_BRANCH_MISMATCH"
PR_SHA_MISMATCH = "PR_SHA_MISMATCH"
HEAD_SHA_MISMATCH = "HEAD_SHA_MISMATCH"
PR_NOT_OPEN = "PR_NOT_OPEN"
PR_AUTHOR_INVALID = "PR_AUTHOR_INVALID"
PR_LINEAGE_INVALID = "PR_LINEAGE_INVALID"
MERGE_COMMIT_MISMATCH = "MERGE_COMMIT_MISMATCH"
BASE_BRANCH_MISMATCH = "BASE_BRANCH_MISMATCH"
BRANCH_DELETED_BEFORE_RECONCILIATION = "BRANCH_DELETED_BEFORE_RECONCILIATION"
WORKFLOW_EVENT_STALE = "WORKFLOW_EVENT_STALE"
WORKFLOW_EVENT_AMBIGUOUS = "WORKFLOW_EVENT_AMBIGUOUS"
MERGE_PROVENANCE_UNVERIFIED = "MERGE_PROVENANCE_UNVERIFIED"
MERGE_LINEAGE_RECONCILED = "MERGE_LINEAGE_RECONCILED"
WORKFLOW_CONTEXT_UNTRUSTED = "WORKFLOW_CONTEXT_UNTRUSTED"
REQUIRED_CHECK_NOT_PUBLISHED = "REQUIRED_CHECK_NOT_PUBLISHED"
GOVERNANCE_LABEL_NOT_STATUS_CHECK = "GOVERNANCE_LABEL_NOT_STATUS_CHECK"
GOVERNANCE_REVIEW_REQUIRED = "GOVERNANCE_REVIEW_REQUIRED"
GOVERNANCE_REVIEW_MISSING = "GOVERNANCE_REVIEW_MISSING"

REQUIRED_CHECKS = (
    "audit-artifact-guard",
    "production-readiness",
    "governance-check",
    "policy-verification",
    "codeql-quality",
)
GOVERNANCE_LABELS = frozenset((REVIEW_LABEL, REVIEW_APPROVED_LABEL))

BLOCKED_PREFIXES = (
    "audit/",
    "gateway/",
    "governance/",
    "policy/",
    "policy_bundle/",
    "runtime/",
    "security/",
)

BLOCKED_EXACT_PATHS = {
    "audit/key_registry.json",
    "governance_release.json",
}

GOVERNANCE_SENSITIVE_PREFIXES = (
    "governance/",
    "policy/",
    "policy_bundle/",
    "audit/",
    "evidence/",
)
GOVERNANCE_SENSITIVE_WORKFLOW_PARTS = ("governance", "production", "audit")
RUNTIME_SENSITIVE_PREFIXES = (
    "runtime/",
    "gateway/",
    "enforcement/",
    "frontend/",
    "web/",
    "ui/",
)
RUNTIME_SENSITIVE_PARTS = (
    "runtime",
    "gateway",
    "enforcement",
    "bootstrap",
    "hydration",
    "fail_closed",
    "fail-closed",
)
CRYPTOGRAPHIC_SENSITIVE_PARTS = (
    "sign",
    "signing",
    "signature",
    "signatures",
    "key",
    "keys",
    "hash",
    "hashes",
    "attestation",
    "attestations",
    "nonce",
    "replay",
    "token",
    "audit-chain",
    "audit_chain",
    "rfc3161",
    "certificate",
)

SAFE_STATUSES = {"SUCCESS", "success", "completed_success"}
SAFE_CONCLUSIONS = {"SUCCESS", "success"}


@dataclass(frozen=True)
class DependabotPR:
    number: int
    author: str
    state: str
    base_branch: str
    head_branch: str
    changed_files: tuple[str, ...]
    checks: tuple[dict[str, Any], ...]
    labels: tuple[str, ...] = ()
    head_sha: str = ""
    url: str = ""
    file_patches: tuple[dict[str, str], ...] = ()
    merge_sha: str = ""
    repository_full_name: str = ""
    mergeable: bool | None = None
    superseded_by: str = ""


@dataclass(frozen=True)
class AutomationDecision:
    approved: bool
    blockers: tuple[str, ...]
    audit: dict[str, Any]


@dataclass(frozen=True)
class ScopeClassification:
    scope: str
    risk_tier: str
    automerge_allowed_scope: bool
    reason_codes: tuple[str, ...]
    blockers: tuple[str, ...]


@dataclass(frozen=True)
class PRResolution:
    valid: bool
    pr: DependabotPR | None
    reason_codes: tuple[str, ...]
    audit: dict[str, Any]


def _canonical_json(payload: Any) -> str:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"))


def _now_utc() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _is_allowed_workflow_path(path: str) -> bool:
    parts = path.split("/")
    if len(parts) != 3 or parts[0] != ".github" or parts[1] != "workflows":
        return False
    filename = parts[2]
    return bool(filename) and (filename.endswith(".yml") or filename.endswith(".yaml"))


def _is_allowed_dependency_path(path: str) -> bool:
    root_names = {
        "pyproject.toml",
        "setup.py",
        "setup.cfg",
        "package.json",
        "package-lock.json",
        "pnpm-lock.yaml",
        "yarn.lock",
        "Gemfile",
        "Gemfile.lock",
        "go.mod",
        "go.sum",
        "Cargo.toml",
        "Cargo.lock",
        "composer.json",
        "composer.lock",
        "Pipfile",
        "Pipfile.lock",
        "poetry.lock",
        ".github/dependabot.yml",
        ".github/dependabot.yaml",
    }
    if path in root_names:
        return True
    name = Path(path).name
    if "/" not in path and name.startswith("requirements") and name.endswith(".txt"):
        return True
    if path.startswith("requirements/") and len(path.split("/")) == 2 and name.endswith(".txt"):
        return True
    return "/" not in path and name.startswith("constraints") and name.endswith(".txt")


def _is_action_uses_version_line(line: str) -> bool:
    stripped = line.strip()
    if "#" in stripped:
        stripped = stripped.split("#", 1)[0].strip()
    if not stripped.startswith("uses:"):
        return False
    action = stripped.split(":", 1)[1].strip().strip("'\"")
    if "@" not in action:
        return False
    owner_repo, ref = action.rsplit("@", 1)
    owner_parts = owner_repo.split("/")
    if len(owner_parts) != 2:
        return False
    if not all(part and all(char.isalnum() or char in "-_." for char in part) for part in owner_parts):
        return False
    return bool(ref) and all(char.isalnum() or char in "-_./" for char in ref)


def _is_safe_dependency_or_workflow_path(path: str) -> bool:
    normalized = path.strip()
    if not normalized or normalized.startswith("/") or ".." in normalized.split("/"):
        return False
    if normalized in BLOCKED_EXACT_PATHS:
        return False
    if any(normalized.startswith(prefix) for prefix in BLOCKED_PREFIXES):
        return False
    return _is_allowed_dependency_path(normalized) or _is_allowed_workflow_path(normalized)


def classify_dependabot_scope(changed_files: list[str] | tuple[str, ...]) -> tuple[bool, tuple[str, ...]]:
    classification = classify_scope(changed_files)
    return classification.automerge_allowed_scope, classification.blockers


def _patch_map(file_patches: tuple[dict[str, str], ...]) -> dict[str, str]:
    return {str(item.get("path", "")): str(item.get("patch", "")) for item in file_patches}


def _workflow_patch_is_action_version_bump_only(path: str, patch: str) -> tuple[bool, tuple[str, ...]]:
    if not patch:
        return False, (WORKFLOW_LOGIC_CHANGE_BLOCKED,)
    reasons: list[str] = []
    changed_lines = [
        line[1:]
        for line in patch.splitlines()
        if (line.startswith("+") or line.startswith("-")) and not line.startswith(("+++", "---"))
    ]
    if not changed_lines:
        return False, (WORKFLOW_LOGIC_CHANGE_BLOCKED,)
    for line in changed_lines:
        stripped = line.strip()
        if not stripped:
            reasons.append(WORKFLOW_LOGIC_CHANGE_BLOCKED)
            continue
        if stripped.startswith(("permissions:", "secrets:", "env:", "run:", "with:", "if:", "uses: actions/github-script")):
            reasons.append(PERMISSION_WIDENING_BLOCKED if stripped.startswith("permissions:") else WORKFLOW_LOGIC_CHANGE_BLOCKED)
            continue
        if "secrets." in stripped or "github.token" in stripped or "GH_TOKEN" in stripped:
            reasons.append(PERMISSION_WIDENING_BLOCKED)
            continue
        if not _is_action_uses_version_line(line):
            reasons.append(WORKFLOW_LOGIC_CHANGE_BLOCKED)
    return not reasons, tuple(sorted(set(reasons)))


def classify_scope(
    changed_files: list[str] | tuple[str, ...],
    file_patches: tuple[dict[str, str], ...] = (),
) -> ScopeClassification:
    if not changed_files:
        return ScopeClassification(
            UNKNOWN_SCOPE,
            "BLOCKED",
            False,
            (UNKNOWN_SCOPE_BLOCKED,),
            ("changed_files_missing",),
        )

    normalized_files = tuple(path.strip() for path in changed_files if path.strip())
    patch_by_path = _patch_map(file_patches)
    reason_codes: list[str] = []
    blockers: list[str] = []

    for path in normalized_files:
        lower = path.lower()
        path_reason_count = len(reason_codes)
        if path.startswith("/") or ".." in path.split("/"):
            reason_codes.append(UNKNOWN_SCOPE_BLOCKED)
            blockers.append(f"unknown_changed_file:{path}")
        if path in BLOCKED_EXACT_PATHS or lower.startswith(GOVERNANCE_SENSITIVE_PREFIXES):
            reason_codes.append(GOVERNANCE_SENSITIVE_SCOPE_BLOCKED)
            blockers.append(f"governance_sensitive_file:{path}")
        if lower.startswith("scripts/") and ("governance" in lower or "production_readiness" in lower or "production-readiness" in lower):
            reason_codes.append(GOVERNANCE_SENSITIVE_SCOPE_BLOCKED)
            blockers.append(f"governance_sensitive_file:{path}")
        if lower.startswith(".github/workflows/") and any(part in lower for part in GOVERNANCE_SENSITIVE_WORKFLOW_PARTS):
            reason_codes.append(GOVERNANCE_SENSITIVE_SCOPE_BLOCKED)
            blockers.append(f"governance_sensitive_workflow:{path}")
        if lower.startswith("tests/") and "governance" in lower:
            reason_codes.append(GOVERNANCE_SENSITIVE_SCOPE_BLOCKED)
            blockers.append(f"governance_sensitive_test:{path}")
        if lower.startswith(RUNTIME_SENSITIVE_PREFIXES) or any(part in lower for part in RUNTIME_SENSITIVE_PARTS):
            reason_codes.append(RUNTIME_SENSITIVE_SCOPE_BLOCKED)
            blockers.append(f"runtime_sensitive_file:{path}")
        if any(part in lower for part in CRYPTOGRAPHIC_SENSITIVE_PARTS):
            reason_codes.append(CRYPTOGRAPHIC_SENSITIVE_SCOPE_BLOCKED)
            blockers.append(f"cryptographic_sensitive_file:{path}")
        if (
            len(reason_codes) == path_reason_count
            and not _is_allowed_dependency_path(path)
            and not _is_allowed_workflow_path(path)
        ):
            reason_codes.append(UNKNOWN_SCOPE_BLOCKED)
            blockers.append(f"unknown_changed_file:{path}")

    if reason_codes:
        if GOVERNANCE_SENSITIVE_SCOPE_BLOCKED in reason_codes:
            scope = GOVERNANCE_SENSITIVE_SCOPE
        elif RUNTIME_SENSITIVE_SCOPE_BLOCKED in reason_codes:
            scope = RUNTIME_SENSITIVE_SCOPE
        elif CRYPTOGRAPHIC_SENSITIVE_SCOPE_BLOCKED in reason_codes:
            scope = CRYPTOGRAPHIC_SENSITIVE_SCOPE
        else:
            scope = UNKNOWN_SCOPE
        return ScopeClassification(scope, "BLOCKED", False, tuple(sorted(set(reason_codes))), tuple(blockers))

    dependency_files = tuple(path for path in normalized_files if _is_allowed_dependency_path(path))
    workflow_files = tuple(path for path in normalized_files if _is_allowed_workflow_path(path))
    if dependency_files and len(dependency_files) == len(normalized_files):
        return ScopeClassification(
            SAFE_DEPENDENCY_SCOPE,
            "LOW",
            True,
            (SAFE_DEPENDENCY_SCOPE_ALLOWED,),
            (),
        )
    if workflow_files and len(workflow_files) == len(normalized_files):
        workflow_reasons: list[str] = []
        for path in workflow_files:
            ok, reasons = _workflow_patch_is_action_version_bump_only(path, patch_by_path.get(path, ""))
            if not ok:
                workflow_reasons.extend(reasons)
                blockers.append(f"workflow_logic_change:{path}")
        if workflow_reasons:
            return ScopeClassification(
                UNKNOWN_SCOPE,
                "BLOCKED",
                False,
                tuple(sorted(set(workflow_reasons))),
                tuple(blockers),
            )
        return ScopeClassification(
            SAFE_WORKFLOW_VERSION_SCOPE,
            "LOW",
            True,
            (SAFE_WORKFLOW_VERSION_SCOPE_ALLOWED,),
            (),
        )

    return ScopeClassification(
        UNKNOWN_SCOPE,
        "BLOCKED",
        False,
        (UNKNOWN_SCOPE_BLOCKED,),
        tuple(f"unknown_changed_file:{path}" for path in normalized_files),
    )


def _check_name(check: dict[str, Any]) -> str:
    return str(check.get("name") or check.get("context") or check.get("workflowName") or "")


def _check_passed(check: dict[str, Any]) -> bool:
    state = str(check.get("state") or check.get("status") or "")
    conclusion = str(check.get("conclusion") or check.get("bucket") or "")
    if state in SAFE_STATUSES or conclusion in SAFE_CONCLUSIONS:
        return True
    if state.lower() == "completed" and conclusion.lower() in SAFE_CONCLUSIONS:
        return True
    return False


def validate_required_checks(checks: tuple[dict[str, Any], ...], required_checks: tuple[str, ...] = REQUIRED_CHECKS) -> tuple[bool, tuple[str, ...]]:
    blockers: list[str] = []
    by_name: dict[str, dict[str, Any]] = {}
    for check in checks:
        name = _check_name(check)
        if name:
            by_name[name] = check
    for required in required_checks:
        if required in GOVERNANCE_LABELS:
            blockers.append(f"{GOVERNANCE_LABEL_NOT_STATUS_CHECK}:{required}")
            continue
        check = by_name.get(required)
        if check is None:
            blockers.append(f"{REQUIRED_CHECK_NOT_PUBLISHED}:{required}")
        elif not _check_passed(check):
            blockers.append(f"required_check_not_success:{required}")
    return not blockers, tuple(blockers)


def validate_governance_review(labels: tuple[str, ...]) -> tuple[bool, tuple[str, ...], tuple[str, ...], dict[str, Any]]:
    normalized = tuple(sorted({label.strip() for label in labels if label.strip()}))
    label_set = set(normalized)
    review_required = REVIEW_LABEL in label_set
    review_approved = REVIEW_APPROVED_LABEL in label_set
    blockers: list[str] = []
    reason_codes: list[str] = []

    if review_required and not review_approved:
        blockers.append("governance_review_missing")
        reason_codes.extend((GOVERNANCE_REVIEW_REQUIRED, GOVERNANCE_REVIEW_MISSING))

    audit = {
        "schema": "usbay.dependabot_governance_review_gate.v1",
        "labels": normalized,
        "review_required": review_required,
        "review_approved": review_approved,
        "status": "PASS" if not blockers else "BLOCK",
        "reason_codes": tuple(sorted(set(reason_codes))),
    }
    return not blockers, tuple(blockers), tuple(sorted(set(reason_codes))), audit


def _audit_hash(audit: dict[str, Any]) -> str:
    return __import__("hashlib").sha256(_canonical_json(audit).encode("utf-8")).hexdigest()


def _valid_sha(value: str | None) -> bool:
    return isinstance(value, str) and len(value) == 40 and all(ch in "0123456789abcdefABCDEF" for ch in value)


def _hash_only(value: str | int | None) -> str:
    return sha256_text(str(value or ""))


def _canonical_merge_provenance(
    *,
    pr: DependabotPR | None,
    requested_pr_number: int | None,
    workflow_context_source: str,
    workflow_run_id: str | None,
    event_type: str,
    reason_codes: tuple[str, ...],
    reconciliation_status: str,
) -> dict[str, Any]:
    provenance = {
        "schema_version": "usbay.merge_provenance_stub.v1",
        "pr_number": pr.number if pr is not None else requested_pr_number,
        "base_branch": pr.base_branch if pr is not None else "",
        "head_branch": pr.head_branch if pr is not None else "",
        "head_sha": pr.head_sha if pr is not None else "",
        "merge_sha": pr.merge_sha if pr is not None else "",
        "actor": pr.author if pr is not None else "",
        "event_source": workflow_context_source,
        "workflow_run_id": str(workflow_run_id or ""),
        "repository_full_name_hash": _hash_only(pr.repository_full_name if pr is not None else ""),
        "event_type": event_type,
        "reconciliation_status": reconciliation_status,
        "reason_codes": reason_codes,
        "signature_status": "SIGNATURE_UNVERIFIED",
    }
    provenance["audit_hash"] = _audit_hash(provenance)
    return provenance


def resolve_pr_identity(
    pr: DependabotPR | None,
    *,
    requested_pr_number: int | None,
    expected_head_branch: str | None = None,
    expected_head_sha: str | None = None,
    expected_base_branch: str = "main",
    expected_merge_sha: str | None = None,
    expected_repository_full_name: str | None = None,
    workflow_context_source: str = "workflow_dispatch",
    workflow_run_id: str | None = None,
    event_type: str | None = None,
    candidate_pr_count: int | None = None,
    branch_deleted: bool = False,
    merge_provenance_reconciled: bool = False,
) -> PRResolution:
    reason_codes: list[str] = []
    normalized_event_type = event_type or workflow_context_source
    if candidate_pr_count is not None and candidate_pr_count != 1:
        reason_codes.append(WORKFLOW_EVENT_AMBIGUOUS)
    if pr is None:
        if WORKFLOW_EVENT_AMBIGUOUS not in reason_codes:
            reason_codes.append(PR_NOT_FOUND)
        reason_tuple = tuple(sorted(set(reason_codes)))
        canonical_state = build_canonical_governance_state(
            pr_number=requested_pr_number,
            repository_full_name="",
            base_branch="",
            head_branch="",
            head_sha="",
            merge_sha="",
            actor="",
            event_type=normalized_event_type,
            workflow_run_id=workflow_run_id,
            workflow_name="dependabot-governed-automerge",
            branch_deleted=False,
            checks_status="BLOCK",
            runtime_evidence_hash="",
            policy_version_hash=_hash_only("dependabot-governed-automerge-policy.v1"),
            candidate_pr_count=candidate_pr_count,
            reconciliation_reason_codes=reason_tuple,
        )
        provenance = _canonical_merge_provenance(
            pr=None,
            requested_pr_number=requested_pr_number,
            workflow_context_source=workflow_context_source,
            workflow_run_id=workflow_run_id,
            event_type=normalized_event_type,
            reason_codes=tuple(canonical_state["reason_codes"]),
            reconciliation_status=str(canonical_state["reconciliation_status"]),
        )
        audit: dict[str, Any] = {
            "schema": "usbay.dependabot_pr_resolution.v1",
            "requested_pr_number": requested_pr_number,
            "workflow_context_source": workflow_context_source,
            "valid": False,
            "reason_codes": reason_tuple,
            "canonical_governance_state": canonical_state,
            "merge_provenance": provenance,
            "resolved_at_utc": _now_utc(),
        }
        audit["audit_hash"] = _audit_hash(audit)
        return PRResolution(False, None, reason_tuple, audit)

    if workflow_context_source == "workflow_dispatch" and requested_pr_number is None:
        reason_codes.append(WORKFLOW_CONTEXT_UNTRUSTED)
    if requested_pr_number is not None and pr.number != requested_pr_number:
        reason_codes.append(PR_NOT_FOUND)
    deleted_after_merge_reconciled = (
        branch_deleted
        and pr.state.upper() == "MERGED"
        and merge_provenance_reconciled
        and _valid_sha(pr.merge_sha)
        and (expected_merge_sha is None or pr.merge_sha == expected_merge_sha)
    )
    if pr.state.upper() != "OPEN" and not deleted_after_merge_reconciled:
        reason_codes.append(PR_NOT_OPEN)
    if pr.author != "dependabot[bot]":
        reason_codes.append(PR_AUTHOR_INVALID)
    if not pr.head_branch.startswith("dependabot/") and not deleted_after_merge_reconciled:
        reason_codes.append(PR_BRANCH_MISMATCH)
    if expected_head_branch and pr.head_branch != expected_head_branch:
        reason_codes.append(PR_BRANCH_MISMATCH)
    if pr.base_branch != expected_base_branch:
        reason_codes.extend((BASE_BRANCH_MISMATCH, PR_LINEAGE_INVALID))
    if expected_repository_full_name and pr.repository_full_name and pr.repository_full_name != expected_repository_full_name:
        reason_codes.append(PR_LINEAGE_INVALID)
    if expected_head_sha:
        if not _valid_sha(expected_head_sha) or pr.head_sha != expected_head_sha:
            reason_codes.extend((HEAD_SHA_MISMATCH, PR_SHA_MISMATCH))
    elif workflow_context_source == "workflow_dispatch":
        if not _valid_sha(pr.head_sha):
            reason_codes.append(PR_LINEAGE_INVALID)
    else:
        reason_codes.extend((WORKFLOW_CONTEXT_UNTRUSTED, WORKFLOW_EVENT_STALE))
    if expected_merge_sha and pr.merge_sha != expected_merge_sha:
        reason_codes.append(MERGE_COMMIT_MISMATCH)
    if branch_deleted and not deleted_after_merge_reconciled:
        reason_codes.append(BRANCH_DELETED_BEFORE_RECONCILIATION)
    if pr.merge_sha and not merge_provenance_reconciled and pr.state.upper() == "MERGED":
        reason_codes.append(MERGE_PROVENANCE_UNVERIFIED)
    if deleted_after_merge_reconciled:
        reason_codes.append(MERGE_LINEAGE_RECONCILED)
    if not _valid_sha(pr.head_sha) and not deleted_after_merge_reconciled:
        reason_codes.append(PR_LINEAGE_INVALID)

    reconciliation_status = "RECONCILED" if not set(reason_codes) - {MERGE_LINEAGE_RECONCILED} else "BLOCKED"
    reason_tuple = tuple(sorted(set(reason_codes)))
    canonical_state = build_canonical_governance_state(
        pr_number=pr.number,
        repository_full_name=pr.repository_full_name,
        base_branch=pr.base_branch,
        head_branch=pr.head_branch,
        head_sha=pr.head_sha,
        merge_sha=pr.merge_sha,
        actor=pr.author,
        event_type=normalized_event_type,
        workflow_run_id=workflow_run_id,
        workflow_name="dependabot-governed-automerge",
        branch_deleted=branch_deleted,
        checks_status="PASS" if not reason_tuple else "BLOCK",
        runtime_evidence_hash=_hash_only("dependabot-pr-resolution-runtime-evidence"),
        policy_version_hash=_hash_only("dependabot-governed-automerge-policy.v1"),
        expected_base_branch=expected_base_branch,
        expected_head_sha=expected_head_sha,
        expected_merge_sha=expected_merge_sha,
        candidate_pr_count=candidate_pr_count,
        reconciliation_reason_codes=reason_tuple,
    )
    provenance = _canonical_merge_provenance(
        pr=pr,
        requested_pr_number=requested_pr_number,
        workflow_context_source=workflow_context_source,
        workflow_run_id=workflow_run_id,
        event_type=normalized_event_type,
        reason_codes=tuple(canonical_state["reason_codes"]),
        reconciliation_status=str(canonical_state["reconciliation_status"]),
    )
    valid = canonical_state["canonical_state"] in {"GOVERNANCE_VALIDATED", "GOVERNANCE_REVIEW_REQUIRED"} and reconciliation_status == "RECONCILED"
    audit = {
        "schema": "usbay.dependabot_pr_resolution.v1",
        "requested_pr_number": requested_pr_number,
        "resolved_pr_number": pr.number,
        "author": pr.author,
        "base_branch": pr.base_branch,
        "head_branch": pr.head_branch,
        "head_sha": pr.head_sha,
        "merge_sha": pr.merge_sha,
        "expected_head_branch": expected_head_branch,
        "expected_head_sha": expected_head_sha,
        "expected_base_branch": expected_base_branch,
        "expected_merge_sha": expected_merge_sha,
        "workflow_context_source": workflow_context_source,
        "workflow_run_id_hash": _hash_only(workflow_run_id),
        "event_type": normalized_event_type,
        "branch_deleted": branch_deleted,
        "reconciliation_status": reconciliation_status,
        "valid": valid,
        "reason_codes": reason_tuple,
        "canonical_governance_state": canonical_state,
        "merge_provenance": provenance,
        "resolved_at_utc": _now_utc(),
    }
    audit["audit_hash"] = _audit_hash(audit)
    return PRResolution(valid, pr if valid else None, reason_tuple, audit)


def lineage_recovery_audit(lineage_diagnostics: dict[str, Any] | None) -> dict[str, Any]:
    diagnostics = lineage_diagnostics or {}
    stale_refs = diagnostics.get("stale_refs_expired", [])
    if not isinstance(stale_refs, list):
        stale_refs = []
    invalidation_status = diagnostics.get("invalidation_status", "NOT_REQUIRED")
    return {
        "schema": "usbay.dependabot_auto_merge_lineage_recovery.v1",
        "lineage_status": diagnostics.get("lineage_status", "CURRENT"),
        "stale_refs_expired": tuple(str(ref) for ref in stale_refs),
        "stale_lineage_invalidation": invalidation_status,
        "canonical_evidence_regeneration": "VERIFIED" if invalidation_status in {"NOT_REQUIRED", "EXPIRED_INVALID"} else "UNVERIFIED",
        "audit_trace_preserved": True,
    }


def evaluate_pr(
    pr: DependabotPR,
    *,
    required_checks: tuple[str, ...] = REQUIRED_CHECKS,
    lineage_diagnostics: dict[str, Any] | None = None,
) -> AutomationDecision:
    blockers: list[str] = []
    reason_codes: list[str] = []
    if pr.author != "dependabot[bot]":
        blockers.append("author_not_dependabot")
        reason_codes.append(NON_DEPENDABOT_AUTHOR_BLOCKED)
    if pr.state.upper() != "OPEN":
        blockers.append("pr_not_open")
    if pr.base_branch != "main":
        blockers.append("base_not_main")
    if not pr.head_branch.startswith("dependabot/"):
        blockers.append("head_branch_not_dependabot")
        reason_codes.append(NON_DEPENDABOT_BRANCH_BLOCKED)

    scope = classify_scope(pr.changed_files, pr.file_patches)
    reason_codes.extend(scope.reason_codes)
    if not scope.automerge_allowed_scope:
        blockers.extend(scope.blockers)

    checks_ok, check_blockers = validate_required_checks(pr.checks, required_checks)
    if not checks_ok:
        blockers.extend(check_blockers)
        for check_blocker in check_blockers:
            if check_blocker.startswith(f"{REQUIRED_CHECK_NOT_PUBLISHED}:"):
                reason_codes.append(REQUIRED_CHECK_NOT_PUBLISHED)
            if check_blocker.startswith(f"{GOVERNANCE_LABEL_NOT_STATUS_CHECK}:"):
                reason_codes.append(GOVERNANCE_LABEL_NOT_STATUS_CHECK)

    ci_status = normalize_ci_status(
        checks=pr.checks,
        required_checks=required_checks,
        pr_head_sha=pr.head_sha,
        mergeable=pr.mergeable,
        superseded_by=pr.superseded_by,
    )
    if not ci_status.merge_authority:
        blockers.append(f"ci_merge_authority_denied:{ci_status.canonical_state}")
        reason_codes.extend(ci_status.reason_codes)

    review_ok, review_blockers, review_reason_codes, review_audit = validate_governance_review(pr.labels)
    if not review_ok:
        blockers.extend(review_blockers)
        reason_codes.extend(review_reason_codes)

    lineage = lineage_recovery_audit(lineage_diagnostics)
    if lineage["canonical_evidence_regeneration"] != "VERIFIED":
        blockers.append("canonical_evidence_regeneration_unverified")

    audit = {
        "schema": "usbay.dependabot_governed_auto_merge_decision.v1",
        "pr_number": pr.number,
        "author": pr.author,
        "base_branch": pr.base_branch,
        "head_branch": pr.head_branch,
        "changed_files": tuple(pr.changed_files),
        "governance_labels": tuple(sorted(pr.labels)),
        "classified_scope": scope.scope,
        "risk_tier": scope.risk_tier,
        "allow_block_decision": "ALLOW" if not blockers else "BLOCK",
        "reason_codes": tuple(sorted(set(reason_codes))),
        "required_checks": required_checks,
        "required_check_semantics": "github_check_runs_only",
        "required_check_status": tuple(
            {
                "name": name,
                "semantic_type": "github_check_run",
                "status": "PASS" if any(_check_name(check) == name and _check_passed(check) for check in pr.checks) else "BLOCK",
            }
            for name in required_checks
        ),
        "governance_review": review_audit,
        "production_readiness_status": "PASS"
        if any(_check_name(check) == "production-readiness" and _check_passed(check) for check in pr.checks)
        else "BLOCK",
        "audit_artifact_guard_status": "PASS"
        if any(_check_name(check) == "audit-artifact-guard" and _check_passed(check) for check in pr.checks)
        else "BLOCK",
        "lineage_recovery": lineage,
        "canonical_ci_status": ci_status.audit,
        "approved": not blockers,
        "blockers": tuple(blockers),
        "evaluated_at_utc": _now_utc(),
    }
    audit["audit_hash"] = _audit_hash(audit)
    return AutomationDecision(approved=not blockers, blockers=tuple(blockers), audit=audit)


def _run_gh(args: list[str], *, input_text: str | None = None) -> str:
    completed = subprocess.run(
        ["gh", *args],
        input=input_text,
        text=True,
        capture_output=True,
        check=False,
    )
    if completed.returncode != 0:
        stderr = completed.stderr.strip().replace("\n", " ")
        raise SystemExit(f"GITHUB_COMMAND_FAILED:{' '.join(args)}:{stderr}")
    return completed.stdout


def _load_json_output(args: list[str]) -> Any:
    output = _run_gh(args)
    try:
        return json.loads(output)
    except json.JSONDecodeError as exc:
        raise SystemExit(f"GITHUB_JSON_INVALID:{exc}") from exc


def load_pr_from_github(number: int) -> DependabotPR:
    payload = _load_json_output(
        [
            "pr",
            "view",
            str(number),
            "--json",
            "number,author,state,baseRefName,headRefName,headRefOid,mergeCommit,mergeable,files,labels,statusCheckRollup,url",
        ]
    )
    author = payload.get("author") or {}
    files = payload.get("files") or []
    labels = payload.get("labels") or []
    checks = payload.get("statusCheckRollup") or []
    merge_commit = payload.get("mergeCommit") or {}
    diff = _run_gh(["pr", "diff", str(number)])
    patches = _parse_unified_diff(diff)
    return DependabotPR(
        number=int(payload["number"]),
        author=str(author.get("login", "")),
        state=str(payload.get("state", "")),
        base_branch=str(payload.get("baseRefName", "")),
        head_branch=str(payload.get("headRefName", "")),
        head_sha=str(payload.get("headRefOid", "")),
        changed_files=tuple(str(item.get("path", "")) for item in files),
        checks=tuple(checks),
        labels=tuple(str(item.get("name", "")) for item in labels),
        url=str(payload.get("url", "")),
        file_patches=patches,
        merge_sha=str(merge_commit.get("oid", "")),
        mergeable=bool(payload.get("mergeable")) if isinstance(payload.get("mergeable"), bool) else None,
    )


def _parse_unified_diff(diff_text: str) -> tuple[dict[str, str], ...]:
    patches: list[dict[str, str]] = []
    current_path: str | None = None
    current_lines: list[str] = []
    for line in diff_text.splitlines():
        if line.startswith("diff --git "):
            if current_path is not None:
                patches.append({"path": current_path, "patch": "\n".join(current_lines)})
            current_path = None
            current_lines = []
            parts = line.split()
            if len(parts) >= 4 and parts[3].startswith("b/"):
                current_path = parts[3][2:]
            continue
        if current_path is not None:
            current_lines.append(line)
    if current_path is not None:
        patches.append({"path": current_path, "patch": "\n".join(current_lines)})
    return tuple(patches)


def comment_and_label_blocked(pr_number: int | None, blockers: tuple[str, ...], audit: dict[str, Any], *, dry_run: bool) -> None:
    body = (
        "Governed auto-merge refused.\n\n"
        "USBAY fail-closed blockers:\n"
        + "\n".join(f"- {blocker}" for blocker in blockers)
        + f"\n\nAudit hash: {audit['audit_hash']}\n"
        "Label applied: governance-review-required\n"
    )
    if dry_run:
        print(body)
        return
    if pr_number is None:
        return
    _run_gh(["pr", "comment", str(pr_number), "--body", body])
    _run_gh(["pr", "edit", str(pr_number), "--add-label", REVIEW_LABEL])


def approve_comment_merge_and_delete(pr_number: int, *, dry_run: bool) -> None:
    if dry_run:
        print(AUDIT_COMMENT)
        print(f"DRY_RUN_MERGE_PR={pr_number}")
        return
    _run_gh(["pr", "comment", str(pr_number), "--body", AUDIT_COMMENT])
    _run_gh(["pr", "merge", str(pr_number), "--squash", "--delete-branch"])


def load_lineage_diagnostics(path: Path | None) -> dict[str, Any] | None:
    if path is None:
        return None
    if not path.is_file():
        raise SystemExit(f"LINEAGE_DIAGNOSTICS_MISSING:{path}")
    return json.loads(path.read_text(encoding="utf-8"))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Governed Dependabot PR recovery, validation, merge, and cleanup")
    parser.add_argument("--pr", type=int, required=True)
    parser.add_argument("--lineage-diagnostics", type=Path)
    parser.add_argument("--decision-output", type=Path)
    parser.add_argument("--resolution-output", type=Path)
    parser.add_argument("--expected-head-branch")
    parser.add_argument("--expected-head-sha")
    parser.add_argument("--expected-base-branch", default="main")
    parser.add_argument("--expected-merge-sha")
    parser.add_argument("--workflow-run-id")
    parser.add_argument("--workflow-context-source", default="workflow_dispatch")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--merge", action="store_true")
    args = parser.parse_args(argv)

    try:
        pr = load_pr_from_github(args.pr)
    except SystemExit as exc:
        if "GITHUB_COMMAND_FAILED:pr view" not in str(exc):
            raise
        pr = None
    resolution = resolve_pr_identity(
        pr,
        requested_pr_number=args.pr,
        expected_head_branch=args.expected_head_branch,
        expected_head_sha=args.expected_head_sha,
        expected_base_branch=args.expected_base_branch,
        expected_merge_sha=args.expected_merge_sha,
        workflow_context_source=args.workflow_context_source,
        workflow_run_id=args.workflow_run_id,
    )
    if args.resolution_output:
        args.resolution_output.parent.mkdir(parents=True, exist_ok=True)
        args.resolution_output.write_text(json.dumps(resolution.audit, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"DEPENDABOT_PR_RESOLUTION_VALID={str(resolution.valid).lower()}")
    print(f"DEPENDABOT_PR_RESOLUTION_AUDIT_HASH={resolution.audit['audit_hash']}")
    if not resolution.valid:
        comment_and_label_blocked(args.pr, resolution.reason_codes, resolution.audit, dry_run=args.dry_run)
        return 1
    pr = resolution.pr
    if pr is None:
        raise SystemExit(PR_NOT_FOUND)
    decision = evaluate_pr(pr, lineage_diagnostics=load_lineage_diagnostics(args.lineage_diagnostics))
    if args.decision_output:
        args.decision_output.parent.mkdir(parents=True, exist_ok=True)
        args.decision_output.write_text(json.dumps(decision.audit, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    print(f"DEPENDABOT_GOVERNED_AUTOMERGE_APPROVED={str(decision.approved).lower()}")
    print(f"DEPENDABOT_GOVERNED_AUTOMERGE_AUDIT_HASH={decision.audit['audit_hash']}")
    if not decision.approved:
        comment_and_label_blocked(pr.number, decision.blockers, decision.audit, dry_run=args.dry_run)
        return 1
    if args.merge:
        approve_comment_merge_and_delete(pr.number, dry_run=args.dry_run)
    else:
        print("DEPENDABOT_GOVERNED_AUTOMERGE_MERGE_SKIPPED=true")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
