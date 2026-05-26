#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from governance.canonical_governance_state import build_canonical_governance_state
from governance.toolchain_compatibility import (
    BRANCH_DELETED_AFTER_MERGE_VERIFIED,
    BRANCH_DELETION_UNVERIFIED,
    BRANCH_REF_NOT_FOUND,
    BRANCH_STATE_CONTRADICTORY,
    GH_PR_VIEW_FIELD_LIST,
    POST_MERGE_BRANCH_NORMALIZED,
    PROTECTED_BRANCH_CLEANUP_ALLOWED,
    PROTECTED_BRANCH_CLEANUP_DENIED,
    PROTECTED_BRANCH_LOOKUP_FAILED,
    ToolchainCompatibilityError,
    normalize_gh_pr_merge_state,
    normalize_post_merge_branch_state,
    normalize_protected_branch_cleanup,
    validate_gh_pr_view_fields,
)


REASON_BRANCH_ALREADY_MERGED = "BRANCH_ALREADY_MERGED"
REASON_RESTORED_AFTER_MERGE = "RESTORED_AFTER_MERGE"
REASON_BRANCH_NOT_MERGED_BLOCKED = "BRANCH_NOT_MERGED_BLOCKED"
REASON_OPEN_PR_BRANCH_BLOCKED = "OPEN_PR_BRANCH_BLOCKED"
REASON_PROTECTED_BRANCH_BLOCKED = "PROTECTED_BRANCH_BLOCKED"
REASON_LINEAGE_UNCLEAR_BLOCKED = "LINEAGE_UNCLEAR_BLOCKED"
REASON_VALID_NON_PROTECTED_BRANCH = "VALID_NON_PROTECTED_BRANCH"
REASON_PROTECTED_BRANCH_REQUIRED = "PROTECTED_BRANCH_REQUIRED"
REASON_BRANCH_PROTECTION_LOOKUP_FAILED = "BRANCH_PROTECTION_LOOKUP_FAILED"
REASON_MAIN_BRANCH_POLICY_REQUIRED = "MAIN_BRANCH_POLICY_REQUIRED"
REASON_GOVERNANCE_FEATURE_BRANCH_ALLOWED = "GOVERNANCE_FEATURE_BRANCH_ALLOWED"
REASON_RULESET_ENFORCEMENT_VERIFIED = "RULESET_ENFORCEMENT_VERIFIED"
REASON_RULESET_ENFORCEMENT_ACTIVE = "RULESET_ENFORCEMENT_ACTIVE"
REASON_RULESET_ENFORCEMENT_MISSING = "RULESET_ENFORCEMENT_MISSING"
REASON_RULESET_LOOKUP_FAILED = "RULESET_LOOKUP_FAILED"
REASON_MAIN_RULESET_VALIDATED = "MAIN_RULESET_VALIDATED"
REASON_REVIEW_AUTHORIZATION_REQUIRED = "REVIEW_AUTHORIZATION_REQUIRED"
REASON_DUAL_REVIEWER_AUTHORIZATION_VERIFIED = "DUAL_REVIEWER_AUTHORIZATION_VERIFIED"
REASON_DUAL_REVIEWER_AUTHORIZATION_MISSING = "DUAL_REVIEWER_AUTHORIZATION_MISSING"
REASON_MERGE_AUTHORIZATION_FINALIZED = "MERGE_AUTHORIZATION_FINALIZED"
REASON_MERGE_AUTHORIZATION_NOT_FINALIZED = "MERGE_AUTHORIZATION_NOT_FINALIZED"
REASON_GITHUB_WORKFLOW_STATE_UNVERIFIABLE = "GITHUB_WORKFLOW_STATE_UNVERIFIABLE"

REVIEW_LABEL = "governance-review-required"
AUDIT_SCHEMA = "usbay.post_merge_branch_hygiene.v1"
ALLOWED_BRANCH_PREFIXES = ("governance/", "dependabot/")
PROTECTED_BRANCHES = {"main", "master", "develop", "release"}


@dataclass(frozen=True)
class BranchHygieneInput:
    branch_name: str
    pr_number: int | None
    pr_merged: bool
    merge_commit_sha: str | None
    branch_head_sha: str | None
    main_contains_branch_head: bool | None
    merge_commit_on_main: bool | None
    open_pr_references_branch: bool
    protected_branch: bool
    protection_reason_code: str = REASON_VALID_NON_PROTECTED_BRANCH
    previously_deleted: bool = False
    toolchain_audit_evidence: dict[str, Any] | None = None
    branch_ref_not_found: bool = False
    branch_deletion_reconciliation: dict[str, Any] | None = None
    branch_protection_reconciliation: dict[str, Any] | None = None
    ruleset_governance: dict[str, Any] | None = None
    reviewer_authorization: dict[str, Any] | None = None
    merge_authorization_finalized: bool = False


@dataclass(frozen=True)
class BranchHygieneDecision:
    delete_branch: bool
    reason_code: str
    blockers: tuple[str, ...]
    audit: dict[str, Any]


def _now_utc() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _canonical_json(payload: Any) -> str:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"))


def _sha256_text(payload: str) -> str:
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _is_sha(value: str | None) -> bool:
    return isinstance(value, str) and len(value) == 40 and all(ch in "0123456789abcdefABCDEF" for ch in value)


def _allowed_branch_name(branch_name: str) -> bool:
    if not branch_name or branch_name.startswith("/") or ".." in branch_name.split("/"):
        return False
    return branch_name.startswith(ALLOWED_BRANCH_PREFIXES)


def evaluate_branch_hygiene(state: BranchHygieneInput) -> BranchHygieneDecision:
    blockers: list[str] = []
    reason_code = REASON_BRANCH_ALREADY_MERGED
    state_evidence_hash = _sha256_text(
        _canonical_json(
            {
                "branch_name": state.branch_name,
                "pr_number": state.pr_number,
                "pr_merged": state.pr_merged,
                "merge_commit_sha": state.merge_commit_sha,
                "branch_head_sha": state.branch_head_sha,
                "main_contains_branch_head": state.main_contains_branch_head,
                "merge_commit_on_main": state.merge_commit_on_main,
                "open_pr_references_branch": state.open_pr_references_branch,
                "protected_branch": state.protected_branch,
                "previously_deleted": state.previously_deleted,
                "toolchain_audit_hash": (state.toolchain_audit_evidence or {}).get("audit_hash"),
                "branch_ref_not_found": state.branch_ref_not_found,
                "branch_deletion_audit_hash": (state.branch_deletion_reconciliation or {}).get("audit_hash"),
                "branch_protection_audit_hash": (state.branch_protection_reconciliation or {}).get("audit_hash"),
                "ruleset_governance_audit_hash": (state.ruleset_governance or {}).get("audit_hash"),
                "reviewer_authorization_audit_hash": (state.reviewer_authorization or {}).get("audit_hash"),
                "merge_authorization_finalized": state.merge_authorization_finalized,
            }
        )
    )
    policy_hash = _sha256_text(AUDIT_SCHEMA)

    protection_reason_codes: list[str] = [state.protection_reason_code]
    ruleset_governance = state.ruleset_governance or {}
    reviewer_authorization = state.reviewer_authorization or {}
    governance_reason_codes: list[str] = []
    if not state.merge_authorization_finalized:
        blockers.append("merge_authorization_not_finalized")
        reason_code = REASON_LINEAGE_UNCLEAR_BLOCKED
        governance_reason_codes.append(REASON_MERGE_AUTHORIZATION_NOT_FINALIZED)
    else:
        governance_reason_codes.append(REASON_MERGE_AUTHORIZATION_FINALIZED)
    if ruleset_governance.get("reason_code") not in {
        REASON_RULESET_ENFORCEMENT_ACTIVE,
        REASON_RULESET_ENFORCEMENT_VERIFIED,
        REASON_MAIN_RULESET_VALIDATED,
    }:
        blockers.append("main_ruleset_governance_unverified")
        reason_code = REASON_LINEAGE_UNCLEAR_BLOCKED
        governance_reason_codes.append(str(ruleset_governance.get("reason_code") or REASON_RULESET_ENFORCEMENT_MISSING))
    else:
        governance_reason_codes.append(str(ruleset_governance.get("reason_code")))
    if reviewer_authorization.get("reason_code") != REASON_DUAL_REVIEWER_AUTHORIZATION_VERIFIED:
        blockers.append("dual_reviewer_authorization_missing")
        reason_code = REASON_LINEAGE_UNCLEAR_BLOCKED
        governance_reason_codes.append(
            str(reviewer_authorization.get("reason_code") or REASON_DUAL_REVIEWER_AUTHORIZATION_MISSING)
        )
    else:
        governance_reason_codes.append(REASON_DUAL_REVIEWER_AUTHORIZATION_VERIFIED)
    protection_reconciliation = state.branch_protection_reconciliation or {}
    protection_cleanup_reason = str(protection_reconciliation.get("reason_code", ""))
    if (
        state.protection_reason_code == REASON_BRANCH_PROTECTION_LOOKUP_FAILED
        and ruleset_governance.get("reason_code") not in {REASON_RULESET_ENFORCEMENT_ACTIVE, REASON_MAIN_RULESET_VALIDATED}
    ):
        blockers.append("branch_protection_lookup_failed")
        reason_code = REASON_LINEAGE_UNCLEAR_BLOCKED
    if state.branch_name in PROTECTED_BRANCHES:
        blockers.append("main_branch_policy_required")
        reason_code = REASON_PROTECTED_BRANCH_BLOCKED
        protection_reason_codes.append(REASON_MAIN_BRANCH_POLICY_REQUIRED)
    elif state.protected_branch and protection_cleanup_reason != PROTECTED_BRANCH_CLEANUP_ALLOWED:
        blockers.append("protected_branch")
        reason_code = REASON_PROTECTED_BRANCH_BLOCKED
        protection_reason_codes.append(REASON_PROTECTED_BRANCH_REQUIRED)
    if protection_cleanup_reason == PROTECTED_BRANCH_LOOKUP_FAILED:
        blockers.append("protected_branch_lookup_failed")
        reason_code = REASON_LINEAGE_UNCLEAR_BLOCKED
    elif protection_cleanup_reason == PROTECTED_BRANCH_CLEANUP_DENIED:
        blockers.append("protected_branch_cleanup_denied")
        reason_code = REASON_PROTECTED_BRANCH_BLOCKED
    if not _allowed_branch_name(state.branch_name):
        blockers.append("branch_pattern_not_allowed")
        reason_code = REASON_PROTECTED_BRANCH_BLOCKED if state.branch_name in PROTECTED_BRANCHES else REASON_LINEAGE_UNCLEAR_BLOCKED
    elif state.branch_name.startswith("governance/") and not state.protected_branch:
        protection_reason_codes.append(REASON_GOVERNANCE_FEATURE_BRANCH_ALLOWED)
    if state.open_pr_references_branch:
        blockers.append("open_pr_references_branch")
        reason_code = REASON_OPEN_PR_BRANCH_BLOCKED
    if state.branch_ref_not_found:
        deletion_reason = str((state.branch_deletion_reconciliation or {}).get("reason_code", ""))
        if deletion_reason == BRANCH_DELETED_AFTER_MERGE_VERIFIED:
            reason_code = BRANCH_DELETED_AFTER_MERGE_VERIFIED
        else:
            blockers.append("branch_deletion_unverified")
            reason_code = REASON_LINEAGE_UNCLEAR_BLOCKED
    if not state.pr_merged:
        blockers.append("pr_not_merged")
        reason_code = REASON_BRANCH_NOT_MERGED_BLOCKED
    if state.pr_number is None:
        blockers.append("pr_number_missing")
        reason_code = REASON_LINEAGE_UNCLEAR_BLOCKED
    if not _is_sha(state.merge_commit_sha):
        blockers.append("merge_commit_sha_missing_or_invalid")
        reason_code = REASON_LINEAGE_UNCLEAR_BLOCKED
    if not state.branch_ref_not_found and not _is_sha(state.branch_head_sha):
        blockers.append("branch_head_sha_missing_or_invalid")
        reason_code = REASON_LINEAGE_UNCLEAR_BLOCKED

    containment_proven = state.main_contains_branch_head is True or state.merge_commit_on_main is True
    if not state.branch_ref_not_found and (state.main_contains_branch_head is None or state.merge_commit_on_main is None):
        blockers.append("main_containment_proof_ambiguous")
        reason_code = REASON_LINEAGE_UNCLEAR_BLOCKED
    elif not containment_proven:
        blockers.append("branch_head_not_reachable_from_main")
        reason_code = REASON_LINEAGE_UNCLEAR_BLOCKED

    if not blockers and state.previously_deleted:
        reason_code = REASON_RESTORED_AFTER_MERGE

    audit = {
        "schema": AUDIT_SCHEMA,
        "branch_name": state.branch_name,
        "pr_number": state.pr_number,
        "merge_commit_sha": state.merge_commit_sha,
        "branch_head_sha": state.branch_head_sha,
        "main_containment_proof": {
            "branch_head_reachable_from_main": state.main_contains_branch_head,
            "merge_commit_reachable_from_main": state.merge_commit_on_main,
        },
        "branch_protection": {
            "protected": state.protected_branch,
            "reason_codes": tuple(sorted(set(protection_reason_codes))),
        },
        "toolchain_compatibility": state.toolchain_audit_evidence or {},
        "branch_deletion_reconciliation": state.branch_deletion_reconciliation or {},
        "branch_protection_reconciliation": state.branch_protection_reconciliation or {},
        "governance_enforcement": {
            "ruleset_governance": ruleset_governance,
            "reviewer_authorization": reviewer_authorization,
            "merge_authorization_finalized": state.merge_authorization_finalized,
            "reason_codes": tuple(sorted(set(governance_reason_codes))),
        },
        "deletion_decision": "DELETE" if not blockers else "BLOCK",
        "reason_code": reason_code,
        "blockers": tuple(blockers),
        "previously_deleted": state.previously_deleted,
        "canonical_governance_state": build_canonical_governance_state(
            pr_number=state.pr_number,
            repository_full_name="usbay/branch-hygiene",
            base_branch="main",
            head_branch=state.branch_name,
            head_sha=state.branch_head_sha or "",
            merge_sha=state.merge_commit_sha or "",
            actor="github-actions[bot]",
            event_type="delete" if state.previously_deleted else "workflow_dispatch",
            workflow_run_id="branch-hygiene",
            workflow_name="governed-branch-hygiene",
            branch_deleted=state.previously_deleted,
            checks_status={"conclusion": "success"} if not blockers else {"conclusion": "failure"},
            runtime_evidence_hash=state_evidence_hash,
            policy_version_hash=policy_hash,
            prior_event_sequence_state="MERGE_COMMITTED" if state.previously_deleted else None,
        ),
        "audit_record_created_before_delete": True,
        "evaluated_at_utc": _now_utc(),
    }
    audit["audit_hash"] = _sha256_text(_canonical_json(audit))
    return BranchHygieneDecision(delete_branch=not blockers, reason_code=reason_code, blockers=tuple(blockers), audit=audit)


def write_audit_record(path: Path, audit: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(audit, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _run_gh(args: list[str]) -> str:
    completed = subprocess.run(["gh", *args], text=True, capture_output=True, check=False)
    if completed.returncode != 0:
        stderr = completed.stderr.strip().replace("\n", " ")
        raise SystemExit(f"GITHUB_COMMAND_FAILED:{' '.join(args)}:{stderr}")
    return completed.stdout


def _run_gh_result(args: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(["gh", *args], text=True, capture_output=True, check=False)


def classify_workflow_run_retrieval(
    *,
    endpoint: str,
    parameters: dict[str, Any],
    returncode: int,
    stdout: str,
    stderr: str,
    attempts: int = 1,
) -> dict[str, Any]:
    evidence = {
        "schema": "usbay.github.workflow_run_retrieval.v1",
        "endpoint_hash": _sha256_text(endpoint),
        "parameter_hash": _sha256_text(_canonical_json(parameters)),
        "attempts": attempts,
        "retry_behavior": "NO_RETRY_FOR_404_TERMINAL_STATE",
        "state": "VERIFIED",
        "reason_code": "WORKFLOW_RUN_METADATA_RETRIEVED",
        "governance_integrity_impact": False,
    }
    if returncode == 0:
        evidence["audit_hash"] = _sha256_text(_canonical_json(evidence))
        return evidence

    rendered = f"{stdout}\n{stderr}"
    if "HTTP 404" in rendered or "Not Found" in rendered:
        evidence.update(
            {
                "state": "UNVERIFIABLE",
                "reason_code": REASON_GITHUB_WORKFLOW_STATE_UNVERIFIABLE,
                "failure_class": "STALE_OR_DELETED_WORKFLOW_RUN",
                "fail_closed": True,
                "retry_behavior": "NO_RETRY_FOR_404_TERMINAL_STATE",
            }
        )
    else:
        evidence.update(
            {
                "state": "UNVERIFIABLE",
                "reason_code": REASON_GITHUB_WORKFLOW_STATE_UNVERIFIABLE,
                "failure_class": "GITHUB_API_RETRIEVAL_FAILED",
                "fail_closed": True,
                "retry_behavior": "CALLER_MAY_RETRY_TRANSIENT_NON_404_FAILURE",
            }
        )
    evidence["audit_hash"] = _sha256_text(_canonical_json(evidence))
    return evidence


def _gh_json(args: list[str]) -> Any:
    output = _run_gh(args)
    try:
        return json.loads(output)
    except json.JSONDecodeError as exc:
        raise SystemExit(f"GITHUB_JSON_INVALID:{exc}") from exc


def _branch_head_sha(repo: str, branch_name: str) -> str | None:
    payload = _gh_json(["api", f"repos/{repo}/git/ref/heads/{branch_name}"])
    obj = payload.get("object") if isinstance(payload, dict) else {}
    sha = obj.get("sha") if isinstance(obj, dict) else None
    return str(sha) if sha else None


def _branch_head_state(repo: str, branch_name: str) -> tuple[str | None, bool]:
    completed = _run_gh_result(["api", f"repos/{repo}/git/ref/heads/{branch_name}"])
    if completed.returncode == 0:
        try:
            payload = json.loads(completed.stdout)
        except json.JSONDecodeError as exc:
            raise SystemExit(f"GITHUB_JSON_INVALID:{exc}") from exc
        obj = payload.get("object") if isinstance(payload, dict) else {}
        sha = obj.get("sha") if isinstance(obj, dict) else None
        return (str(sha) if sha else None), False
    stderr = completed.stderr.strip()
    stdout = completed.stdout.strip()
    if "HTTP 404" in stderr or "Not Found" in stderr or "HTTP 404" in stdout or "Not Found" in stdout:
        return None, True
    raise SystemExit(f"GITHUB_COMMAND_FAILED:api repos/{repo}/git/ref/heads/{branch_name}:{stderr or stdout}")


def _ruleset_authority_active(ruleset_governance: dict[str, Any] | None) -> bool:
    return (ruleset_governance or {}).get("reason_code") in {
        REASON_RULESET_ENFORCEMENT_ACTIVE,
        REASON_MAIN_RULESET_VALIDATED,
        REASON_RULESET_ENFORCEMENT_VERIFIED,
    }


def _branch_protection_state(
    repo: str,
    branch_name: str,
    ruleset_governance: dict[str, Any] | None = None,
) -> tuple[bool, str]:
    if _ruleset_authority_active(ruleset_governance):
        if branch_name in PROTECTED_BRANCHES:
            return True, REASON_RULESET_ENFORCEMENT_ACTIVE
        if branch_name.startswith("governance/") or branch_name.startswith("dependabot/"):
            return False, (
                REASON_GOVERNANCE_FEATURE_BRANCH_ALLOWED
                if branch_name.startswith("governance/")
                else REASON_VALID_NON_PROTECTED_BRANCH
            )
    if branch_name in PROTECTED_BRANCHES:
        completed = _run_gh_result(["api", f"repos/{repo}/branches/{branch_name}/protection"])
        if completed.returncode == 0:
            return True, REASON_MAIN_BRANCH_POLICY_REQUIRED
        return True, REASON_BRANCH_PROTECTION_LOOKUP_FAILED
    completed = _run_gh_result(["api", f"repos/{repo}/branches/{branch_name}/protection"])
    if completed.returncode == 0:
        return True, REASON_PROTECTED_BRANCH_REQUIRED
    stderr = completed.stderr.strip()
    stdout = completed.stdout.strip()
    if "HTTP 404" in stderr or "Not Found" in stderr or "HTTP 404" in stdout or "Not Found" in stdout:
        if branch_name.startswith("governance/") or branch_name.startswith("dependabot/"):
            return False, (
                REASON_GOVERNANCE_FEATURE_BRANCH_ALLOWED
                if branch_name.startswith("governance/")
                else REASON_VALID_NON_PROTECTED_BRANCH
            )
    return True, REASON_BRANCH_PROTECTION_LOOKUP_FAILED


def _main_ruleset_state(repo: str) -> dict[str, Any]:
    completed = _run_gh_result(["api", f"repos/{repo}/rulesets"])
    if completed.returncode != 0:
        return _ruleset_evidence([], REASON_RULESET_LOOKUP_FAILED)
    try:
        payload = json.loads(completed.stdout)
    except json.JSONDecodeError:
        return _ruleset_evidence([], REASON_RULESET_LOOKUP_FAILED)
    if not isinstance(payload, list):
        return _ruleset_evidence([], REASON_RULESET_LOOKUP_FAILED)
    active_rulesets = []
    for ruleset in payload:
        if not isinstance(ruleset, dict):
            continue
        enforcement = str(ruleset.get("enforcement", "")).lower()
        target = str(ruleset.get("target", "")).lower()
        conditions = ruleset.get("conditions") if isinstance(ruleset.get("conditions"), dict) else {}
        ref_name = conditions.get("ref_name") if isinstance(conditions.get("ref_name"), dict) else {}
        include = ref_name.get("include") if isinstance(ref_name.get("include"), list) else []
        applies_to_main = (
            target in {"branch", ""}
            and enforcement == "active"
            and (
                not include
                or "refs/heads/main" in include
                or "~DEFAULT_BRANCH" in include
                or "main" in include
            )
        )
        if applies_to_main:
            active_rulesets.append(ruleset)
    reason = REASON_RULESET_ENFORCEMENT_ACTIVE if active_rulesets else REASON_RULESET_ENFORCEMENT_MISSING
    return _ruleset_evidence(active_rulesets, reason)


def _ruleset_evidence(rulesets: list[dict[str, Any]], reason_code: str) -> dict[str, Any]:
    bounded_rulesets = [
        {
            "ruleset_id_hash": _sha256_text(str(ruleset.get("id", ""))),
            "ruleset_name_hash": _sha256_text(str(ruleset.get("name", ""))),
            "enforcement": str(ruleset.get("enforcement", "")),
            "target": str(ruleset.get("target", "")),
        }
        for ruleset in rulesets
    ]
    evidence = {
        "schema": "usbay.branch_hygiene.ruleset_governance.v1",
        "target_branch_hash": _sha256_text("main"),
        "active_ruleset_count": len(rulesets),
        "ruleset_hash": _sha256_text(_canonical_json(bounded_rulesets)),
        "reason_code": reason_code,
        "legacy_branch_protection_fallback_only": True,
    }
    evidence["audit_hash"] = _sha256_text(_canonical_json(evidence))
    return evidence


def _reviewer_authorization_state(repo: str, pr_number: int) -> dict[str, Any]:
    completed = _run_gh_result(["api", f"repos/{repo}/pulls/{pr_number}/reviews"])
    if completed.returncode != 0:
        return _reviewer_evidence([], REASON_DUAL_REVIEWER_AUTHORIZATION_MISSING)
    try:
        payload = json.loads(completed.stdout)
    except json.JSONDecodeError:
        return _reviewer_evidence([], REASON_DUAL_REVIEWER_AUTHORIZATION_MISSING)
    if not isinstance(payload, list):
        return _reviewer_evidence([], REASON_DUAL_REVIEWER_AUTHORIZATION_MISSING)
    latest_by_reviewer: dict[str, dict[str, Any]] = {}
    for review in payload:
        if not isinstance(review, dict):
            continue
        user = review.get("user") if isinstance(review.get("user"), dict) else {}
        login = str(user.get("login") or "")
        submitted_at = str(review.get("submitted_at") or "")
        if not login:
            continue
        current = latest_by_reviewer.get(login)
        if current is None or submitted_at >= str(current.get("submitted_at") or ""):
            latest_by_reviewer[login] = review
    approved = [
        login
        for login, review in latest_by_reviewer.items()
        if str(review.get("state") or "").upper() == "APPROVED"
    ]
    reason = (
        REASON_DUAL_REVIEWER_AUTHORIZATION_VERIFIED
        if len(set(approved)) >= 2
        else REASON_DUAL_REVIEWER_AUTHORIZATION_MISSING
    )
    return _reviewer_evidence(approved, reason)


def _reviewer_evidence(approved_logins: list[str], reason_code: str) -> dict[str, Any]:
    reviewer_hashes = sorted(_sha256_text(login) for login in set(approved_logins))
    evidence = {
        "schema": "usbay.branch_hygiene.reviewer_authorization.v1",
        "required_approver_count": 2,
        "approved_reviewer_count": len(reviewer_hashes),
        "approved_reviewer_hashes": reviewer_hashes,
        "requirement_reason_code": REASON_REVIEW_AUTHORIZATION_REQUIRED,
        "reason_code": reason_code,
    }
    evidence["audit_hash"] = _sha256_text(_canonical_json(evidence))
    return evidence


def _protection_lookup_result(*, protected: bool, protection_reason: str, branch_ref_not_found: bool) -> str:
    if branch_ref_not_found:
        return "DELETED"
    if protection_reason == REASON_BRANCH_PROTECTION_LOOKUP_FAILED:
        return "LOOKUP_FAILED"
    return "PROTECTED" if protected else "NOT_PROTECTED"


def _open_pr_references_branch(branch_name: str) -> bool:
    payload = _gh_json(["pr", "list", "--state", "open", "--head", branch_name, "--json", "number"])
    return bool(payload)


def _pr_state(pr_number: int) -> dict[str, Any]:
    try:
        validate_gh_pr_view_fields(GH_PR_VIEW_FIELD_LIST)
    except ToolchainCompatibilityError as exc:
        raise SystemExit(exc.reason_code) from exc
    return _gh_json(["pr", "view", str(pr_number), "--json", GH_PR_VIEW_FIELD_LIST])


def normalize_pr_merge_state(pr: dict[str, Any]) -> dict[str, Any]:
    try:
        return normalize_gh_pr_merge_state(pr)
    except ToolchainCompatibilityError as exc:
        raise SystemExit(exc.reason_code) from exc


def _previously_deleted_from_event(path: Path | None, branch_name: str) -> bool:
    if path is None or not path.is_file():
        return False
    try:
        event = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return False
    return event.get("ref") == branch_name and event.get("created") is True


def _contains_ref(ref: str) -> bool:
    completed = subprocess.run(["git", "merge-base", "--is-ancestor", ref, "origin/main"], check=False)
    return completed.returncode == 0


def load_state_from_github(repo: str, pr_number: int, event_path: Path | None) -> BranchHygieneInput:
    pr = _pr_state(pr_number)
    merge_state = normalize_pr_merge_state(pr)
    branch_name = str(pr.get("headRefName") or "")
    merge_commit_sha = str(merge_state["merge_commit_sha"])
    branch_head, branch_ref_not_found = _branch_head_state(repo, branch_name)
    ruleset_governance = _main_ruleset_state(repo)
    protected, protection_reason = _branch_protection_state(repo, branch_name, ruleset_governance)
    open_pr = _open_pr_references_branch(branch_name)
    merge_commit_on_main = _contains_ref(merge_commit_sha) if merge_commit_sha else None
    try:
        deletion_state = normalize_post_merge_branch_state(
            branch_name=branch_name,
            branch_ref_found=not branch_ref_not_found,
            branch_head_sha=branch_head,
            merge_state=merge_state,
            merge_commit_on_main=merge_commit_on_main,
        )
    except ToolchainCompatibilityError as exc:
        raise SystemExit(exc.reason_code) from exc
    branch_deletion_audit = deletion_state.get("audit_evidence") if isinstance(deletion_state.get("audit_evidence"), dict) else {}
    reviewer_authorization = _reviewer_authorization_state(repo, pr_number)
    merge_authorization_finalized = (
        bool(merge_state["pr_merged"])
        and _is_sha(merge_commit_sha)
        and merge_commit_on_main is True
        and bool(merge_state.get("merged_at"))
        and bool(merge_state.get("merged_by_login"))
    )
    cleanup_policy_allows = (
        _allowed_branch_name(branch_name)
        and branch_name not in PROTECTED_BRANCHES
        and not protected
        and not open_pr
    )
    try:
        protection_cleanup = normalize_protected_branch_cleanup(
            branch_name=branch_name,
            protection_lookup_result=_protection_lookup_result(
                protected=protected,
                protection_reason=protection_reason,
                branch_ref_not_found=branch_ref_not_found,
            ),
            merge_state=merge_state,
            branch_reconciliation_state=deletion_state,
            cleanup_policy_allows_deletion=cleanup_policy_allows,
        )
    except ToolchainCompatibilityError as exc:
        raise SystemExit(exc.reason_code) from exc
    branch_protection_audit = protection_cleanup.get("audit_evidence") if isinstance(protection_cleanup.get("audit_evidence"), dict) else {}
    return BranchHygieneInput(
        branch_name=branch_name,
        pr_number=pr_number,
        pr_merged=bool(merge_state["pr_merged"]),
        merge_commit_sha=merge_commit_sha,
        branch_head_sha=branch_head,
        main_contains_branch_head=_contains_ref(branch_head) if branch_head else None,
        merge_commit_on_main=merge_commit_on_main,
        open_pr_references_branch=open_pr,
        protected_branch=protected,
        protection_reason_code=protection_reason,
        previously_deleted=_previously_deleted_from_event(event_path, branch_name),
        toolchain_audit_evidence=merge_state.get("audit_evidence") if isinstance(merge_state.get("audit_evidence"), dict) else {},
        branch_ref_not_found=branch_ref_not_found,
        branch_deletion_reconciliation=branch_deletion_audit,
        branch_protection_reconciliation=branch_protection_audit,
        ruleset_governance=ruleset_governance,
        reviewer_authorization=reviewer_authorization,
        merge_authorization_finalized=merge_authorization_finalized,
    )


def delete_remote_branch(repo: str, branch_name: str) -> None:
    if branch_name in PROTECTED_BRANCHES or not _allowed_branch_name(branch_name):
        raise SystemExit("BRANCH_DELETE_REFUSED_UNSAFE_NAME")
    _run_gh(["api", "-X", "DELETE", f"repos/{repo}/git/refs/heads/{branch_name}"])


def comment_refusal(pr_number: int | None, blockers: tuple[str, ...], reason_code: str) -> None:
    if pr_number is None:
        return
    body = (
        "Governed post-merge branch hygiene refused.\n\n"
        f"Reason code: {reason_code}\n"
        "Blockers:\n"
        + "\n".join(f"- {blocker}" for blocker in blockers)
        + "\n\nHuman governance review is required before branch cleanup.\n"
    )
    _run_gh(["pr", "comment", str(pr_number), "--body", body])
    _run_gh(["pr", "edit", str(pr_number), "--add-label", REVIEW_LABEL])


def run_self_test() -> int:
    good_state = BranchHygieneInput(
        branch_name="governance/self-test",
        pr_number=1,
        pr_merged=True,
        merge_commit_sha="a" * 40,
        branch_head_sha="b" * 40,
        main_contains_branch_head=True,
        merge_commit_on_main=True,
        open_pr_references_branch=False,
        protected_branch=False,
        protection_reason_code=REASON_GOVERNANCE_FEATURE_BRANCH_ALLOWED,
        ruleset_governance={
            "reason_code": REASON_MAIN_RULESET_VALIDATED,
            "audit_hash": "c" * 64,
        },
        reviewer_authorization={
            "reason_code": REASON_DUAL_REVIEWER_AUTHORIZATION_VERIFIED,
            "approved_reviewer_count": 2,
            "audit_hash": "d" * 64,
        },
        merge_authorization_finalized=True,
    )
    allowed = evaluate_branch_hygiene(good_state)
    missing_reviewers = evaluate_branch_hygiene(
        BranchHygieneInput(
            **{
                **good_state.__dict__,
                "reviewer_authorization": {
                    "reason_code": REASON_DUAL_REVIEWER_AUTHORIZATION_MISSING,
                    "approved_reviewer_count": 1,
                    "audit_hash": "e" * 64,
                },
            }
        )
    )
    missing_ruleset = evaluate_branch_hygiene(
        BranchHygieneInput(
            **{
                **good_state.__dict__,
                "ruleset_governance": {
                    "reason_code": REASON_RULESET_ENFORCEMENT_MISSING,
                    "audit_hash": "f" * 64,
                },
            }
        )
    )
    not_finalized = evaluate_branch_hygiene(
        BranchHygieneInput(**{**good_state.__dict__, "merge_authorization_finalized": False})
    )
    if (
        not allowed.delete_branch
        or missing_reviewers.delete_branch
        or missing_ruleset.delete_branch
        or not_finalized.delete_branch
    ):
        print("BRANCH_HYGIENE_SELF_TEST=false", flush=True)
        return 1
    print("BRANCH_HYGIENE_SELF_TEST=true", flush=True)
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Governed post-merge branch hygiene")
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--repo")
    parser.add_argument("--pr", type=int)
    parser.add_argument("--event-path", type=Path)
    parser.add_argument("--audit-output", type=Path)
    parser.add_argument("--delete", action="store_true")
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args(argv)
    if args.self_test:
        return run_self_test()
    if not args.repo or args.pr is None or args.audit_output is None:
        raise SystemExit("BRANCH_HYGIENE_ARGUMENT_MISSING")

    state = load_state_from_github(args.repo, args.pr, args.event_path)
    decision = evaluate_branch_hygiene(state)
    write_audit_record(args.audit_output, decision.audit)
    print(f"BRANCH_HYGIENE_DECISION={decision.audit['deletion_decision']}", flush=True)
    print(f"BRANCH_HYGIENE_REASON_CODE={decision.reason_code}", flush=True)
    print(f"BRANCH_HYGIENE_AUDIT_HASH={decision.audit['audit_hash']}", flush=True)
    print(
        "BRANCH_HYGIENE_GOVERNANCE_EVIDENCE_JSON="
        + json.dumps(decision.audit["governance_enforcement"], sort_keys=True, separators=(",", ":")),
        flush=True,
    )
    if not decision.delete_branch:
        if not args.dry_run:
            comment_refusal(state.pr_number, decision.blockers, decision.reason_code)
        return 1
    if args.delete and not args.dry_run and not state.branch_ref_not_found:
        delete_remote_branch(args.repo, state.branch_name)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
