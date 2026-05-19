from __future__ import annotations

import hashlib
import json
from typing import Any, Iterable

TOOLCHAIN_COMPATIBILITY_SCHEMA = "usbay.toolchain_compatibility.v1"

TOOLCHAIN_SCHEMA_UNSUPPORTED_FIELD = "TOOLCHAIN_SCHEMA_UNSUPPORTED_FIELD"
TOOLCHAIN_SCHEMA_DRIFT_DETECTED = "TOOLCHAIN_SCHEMA_DRIFT_DETECTED"
TOOLCHAIN_SCHEMA_VALIDATED = "TOOLCHAIN_SCHEMA_VALIDATED"
PR_MERGE_STATE_UNDETERMINED = "PR_MERGE_STATE_UNDETERMINED"
PR_MERGE_STATE_NORMALIZED = "PR_MERGE_STATE_NORMALIZED"
BRANCH_DELETED_AFTER_MERGE_VERIFIED = "BRANCH_DELETED_AFTER_MERGE_VERIFIED"
BRANCH_DELETION_UNVERIFIED = "BRANCH_DELETION_UNVERIFIED"
BRANCH_STATE_CONTRADICTORY = "BRANCH_STATE_CONTRADICTORY"
BRANCH_REF_NOT_FOUND = "BRANCH_REF_NOT_FOUND"
POST_MERGE_BRANCH_NORMALIZED = "POST_MERGE_BRANCH_NORMALIZED"

TOOLCHAIN_COMPATIBILITY_REASON_CODES = (
    TOOLCHAIN_SCHEMA_UNSUPPORTED_FIELD,
    TOOLCHAIN_SCHEMA_DRIFT_DETECTED,
    TOOLCHAIN_SCHEMA_VALIDATED,
    PR_MERGE_STATE_UNDETERMINED,
    PR_MERGE_STATE_NORMALIZED,
    BRANCH_DELETED_AFTER_MERGE_VERIFIED,
    BRANCH_DELETION_UNVERIFIED,
    BRANCH_STATE_CONTRADICTORY,
    BRANCH_REF_NOT_FOUND,
    POST_MERGE_BRANCH_NORMALIZED,
)

SUPPORTED_GH_PR_VIEW_FIELDS = (
    "headRefName",
    "mergeCommit",
    "mergeStateStatus",
    "mergedAt",
    "mergedBy",
    "number",
    "state",
)
GH_PR_VIEW_FIELD_LIST = ",".join(SUPPORTED_GH_PR_VIEW_FIELDS)


class ToolchainCompatibilityError(RuntimeError):
    def __init__(self, reason_code: str, audit_evidence: dict[str, Any] | None = None) -> None:
        super().__init__(reason_code)
        self.reason_code = reason_code
        self.audit_evidence = audit_evidence or {}


def canonical_json(payload: Any) -> str:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def validate_gh_pr_view_fields(requested_fields: str | Iterable[str]) -> dict[str, Any]:
    requested = _field_tuple(requested_fields)
    unsupported = tuple(field for field in requested if field not in SUPPORTED_GH_PR_VIEW_FIELDS)
    evidence = toolchain_audit_evidence(
        requested_fields=requested,
        normalized_merge_state=None,
        reason_code=TOOLCHAIN_SCHEMA_VALIDATED if not unsupported else TOOLCHAIN_SCHEMA_UNSUPPORTED_FIELD,
        unsupported_fields=unsupported,
    )
    if unsupported:
        raise ToolchainCompatibilityError(TOOLCHAIN_SCHEMA_UNSUPPORTED_FIELD, evidence)
    return evidence


def normalize_gh_pr_merge_state(pr: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(pr, dict):
        raise ToolchainCompatibilityError(
            PR_MERGE_STATE_UNDETERMINED,
            toolchain_audit_evidence(
                requested_fields=SUPPORTED_GH_PR_VIEW_FIELDS,
                normalized_merge_state={"pr_merged": False},
                reason_code=PR_MERGE_STATE_UNDETERMINED,
            ),
        )
    state = str(pr.get("state") or "").upper()
    merged_at = str(pr.get("mergedAt") or "")
    merge_commit = pr.get("mergeCommit") or {}
    merge_commit_sha = str(merge_commit.get("oid") or "") if isinstance(merge_commit, dict) else ""
    merged_by = pr.get("mergedBy")
    merge_state_status = str(pr.get("mergeStateStatus") or "")
    if state == "MERGED":
        if not merged_at or not _is_sha(merge_commit_sha):
            raise ToolchainCompatibilityError(
                PR_MERGE_STATE_UNDETERMINED,
                toolchain_audit_evidence(
                    requested_fields=SUPPORTED_GH_PR_VIEW_FIELDS,
                    normalized_merge_state={"state": state, "pr_merged": False},
                    reason_code=PR_MERGE_STATE_UNDETERMINED,
                ),
            )
        normalized = {
            "pr_merged": True,
            "merge_commit_sha": merge_commit_sha,
            "state": state,
            "merged_at": merged_at,
            "merge_state_status": merge_state_status,
            "merged_by_login": str(merged_by.get("login") or "") if isinstance(merged_by, dict) else "",
            "reason_code": PR_MERGE_STATE_NORMALIZED,
        }
        normalized["audit_evidence"] = toolchain_audit_evidence(
            requested_fields=SUPPORTED_GH_PR_VIEW_FIELDS,
            normalized_merge_state=normalized,
            reason_code=PR_MERGE_STATE_NORMALIZED,
        )
        return normalized
    if merged_at or _is_sha(merge_commit_sha):
        raise ToolchainCompatibilityError(
            PR_MERGE_STATE_UNDETERMINED,
            toolchain_audit_evidence(
                requested_fields=SUPPORTED_GH_PR_VIEW_FIELDS,
                normalized_merge_state={"state": state, "pr_merged": False},
                reason_code=PR_MERGE_STATE_UNDETERMINED,
            ),
        )
    normalized = {
        "pr_merged": False,
        "merge_commit_sha": "",
        "state": state,
        "merged_at": "",
        "merge_state_status": merge_state_status,
        "merged_by_login": str(merged_by.get("login") or "") if isinstance(merged_by, dict) else "",
        "reason_code": PR_MERGE_STATE_NORMALIZED,
    }
    normalized["audit_evidence"] = toolchain_audit_evidence(
        requested_fields=SUPPORTED_GH_PR_VIEW_FIELDS,
        normalized_merge_state=normalized,
        reason_code=PR_MERGE_STATE_NORMALIZED,
    )
    return normalized


def normalize_post_merge_branch_state(
    *,
    branch_name: str,
    branch_ref_found: bool,
    branch_head_sha: str | None,
    merge_state: dict[str, Any],
    merge_commit_on_main: bool | None,
) -> dict[str, Any]:
    pr_merged = bool(merge_state.get("pr_merged"))
    merge_commit_sha = str(merge_state.get("merge_commit_sha") or "")
    merged_at = str(merge_state.get("merged_at") or "")
    merge_proof_valid = pr_merged and bool(merged_at) and _is_sha(merge_commit_sha) and merge_commit_on_main is True
    if branch_ref_found and _is_sha(branch_head_sha):
        normalized = {
            "deletion_reconciliation_state": "MERGED_RETAINED_BRANCH" if pr_merged else "UNMERGED_RETAINED_BRANCH",
            "branch_ref_not_found": False,
            "branch_head_required": True,
            "reason_code": POST_MERGE_BRANCH_NORMALIZED,
            "merge_commit_sha": merge_commit_sha,
        }
    elif not branch_ref_found:
        if merge_proof_valid:
            normalized = {
                "deletion_reconciliation_state": "MERGED_DELETED_BRANCH",
                "branch_ref_not_found": True,
                "branch_head_required": False,
                "reason_code": BRANCH_DELETED_AFTER_MERGE_VERIFIED,
                "merge_commit_sha": merge_commit_sha,
            }
        elif pr_merged:
            raise ToolchainCompatibilityError(
                BRANCH_DELETION_UNVERIFIED,
                branch_deletion_audit_evidence(
                    branch_name=branch_name,
                    merge_state=merge_state,
                    branch_ref_found=branch_ref_found,
                    merge_commit_on_main=merge_commit_on_main,
                    reason_code=BRANCH_DELETION_UNVERIFIED,
                ),
            )
        else:
            raise ToolchainCompatibilityError(
                BRANCH_STATE_CONTRADICTORY,
                branch_deletion_audit_evidence(
                    branch_name=branch_name,
                    merge_state=merge_state,
                    branch_ref_found=branch_ref_found,
                    merge_commit_on_main=merge_commit_on_main,
                    reason_code=BRANCH_STATE_CONTRADICTORY,
                ),
            )
    else:
        raise ToolchainCompatibilityError(
            BRANCH_STATE_CONTRADICTORY,
            branch_deletion_audit_evidence(
                branch_name=branch_name,
                merge_state=merge_state,
                branch_ref_found=branch_ref_found,
                merge_commit_on_main=merge_commit_on_main,
                reason_code=BRANCH_STATE_CONTRADICTORY,
            ),
        )
    normalized["audit_evidence"] = branch_deletion_audit_evidence(
        branch_name=branch_name,
        merge_state=merge_state,
        branch_ref_found=branch_ref_found,
        merge_commit_on_main=merge_commit_on_main,
        reason_code=str(normalized["reason_code"]),
    )
    return normalized


def branch_deletion_audit_evidence(
    *,
    branch_name: str,
    merge_state: dict[str, Any],
    branch_ref_found: bool,
    merge_commit_on_main: bool | None,
    reason_code: str,
) -> dict[str, Any]:
    merge_commit_sha = str(merge_state.get("merge_commit_sha") or "")
    merge_proof = {
        "branch_name_hash": sha256_text(branch_name),
        "pr_merged": bool(merge_state.get("pr_merged")),
        "merged_at_present": bool(merge_state.get("merged_at")),
        "merge_commit_oid_hash": sha256_text(merge_commit_sha) if merge_commit_sha else "",
        "merge_commit_on_main": merge_commit_on_main,
    }
    evidence = {
        "schema": TOOLCHAIN_COMPATIBILITY_SCHEMA,
        "tool_name": "gh",
        "command_family": "branch ref reconciliation",
        "merge_proof_hash": sha256_text(canonical_json(merge_proof)),
        "deleted_branch_name_hash": sha256_text(branch_name),
        "merge_commit_oid_hash": sha256_text(merge_commit_sha) if merge_commit_sha else "",
        "branch_ref_found": branch_ref_found,
        "deletion_reconciliation_state": _deletion_state(branch_ref_found, merge_state),
        "reason_code": reason_code,
    }
    evidence["audit_hash"] = sha256_text(canonical_json(evidence))
    return evidence


def toolchain_audit_evidence(
    *,
    requested_fields: str | Iterable[str],
    normalized_merge_state: dict[str, Any] | None,
    reason_code: str,
    unsupported_fields: tuple[str, ...] = (),
) -> dict[str, Any]:
    requested = _field_tuple(requested_fields)
    normalized = {
        "pr_merged": bool((normalized_merge_state or {}).get("pr_merged")),
        "merge_commit_sha_present": bool((normalized_merge_state or {}).get("merge_commit_sha")),
        "state": str((normalized_merge_state or {}).get("state", "")),
        "reason_code": str((normalized_merge_state or {}).get("reason_code", reason_code)),
    }
    evidence = {
        "schema": TOOLCHAIN_COMPATIBILITY_SCHEMA,
        "tool_name": "gh",
        "command_family": "pr view",
        "supported_field_list_hash": sha256_text(canonical_json(SUPPORTED_GH_PR_VIEW_FIELDS)),
        "requested_field_list_hash": sha256_text(canonical_json(requested)),
        "normalized_merge_state": normalized,
        "unsupported_field_count": len(unsupported_fields),
        "reason_code": reason_code,
    }
    evidence["audit_hash"] = sha256_text(canonical_json(evidence))
    return evidence


def _field_tuple(fields: str | Iterable[str]) -> tuple[str, ...]:
    if isinstance(fields, str):
        raw = fields.split(",")
    else:
        raw = list(fields)
    return tuple(field.strip() for field in raw if str(field).strip())


def _is_sha(value: str | None) -> bool:
    return isinstance(value, str) and len(value) == 40 and all(ch in "0123456789abcdefABCDEF" for ch in value)


def _deletion_state(branch_ref_found: bool, merge_state: dict[str, Any]) -> str:
    if branch_ref_found and bool(merge_state.get("pr_merged")):
        return "MERGED_RETAINED_BRANCH"
    if branch_ref_found:
        return "UNMERGED_RETAINED_BRANCH"
    if bool(merge_state.get("pr_merged")):
        return "MERGED_DELETED_BRANCH"
    return "UNMERGED_DELETED_BRANCH"
