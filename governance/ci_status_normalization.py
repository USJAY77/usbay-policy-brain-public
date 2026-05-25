"""Canonical CI status normalization for USBAY dependency merge authority.

Governance scope: normalize GitHub check/workflow evidence for dependency PR
merge decisions. This module is local-only, deterministic, hash-evidence based,
and fail-closed. It never executes workflows, trusts mergeable metadata alone,
or logs raw payloads, secrets, tokens, or environment values.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

CI_STATUS_NORMALIZATION_SCHEMA = "usbay.ci_status_normalization.v1"
CI_STATUS_VERIFIED = "CI_STATUS_VERIFIED"
CI_STATUS_PARTIAL = "CI_STATUS_PARTIAL"
CI_STATUS_STALE = "CI_STATUS_STALE"
CI_STATUS_PROPAGATING = "CI_STATUS_PROPAGATING"
CI_STATUS_MISSING = "CI_STATUS_MISSING"
CI_STATUS_CONTRADICTORY = "CI_STATUS_CONTRADICTORY"
CI_STATUS_FAIL_CLOSED = "CI_STATUS_FAIL_CLOSED"

CI_REASON_STATUS_VERIFIED = "CI_STATUS_VERIFIED"
CI_REASON_STATUS_PARTIAL = "CI_STATUS_PARTIAL"
CI_REASON_STATUS_STALE = "CI_STATUS_STALE"
CI_REASON_STATUS_PROPAGATING = "CI_STATUS_PROPAGATING"
CI_REASON_STATUS_MISSING = "CI_STATUS_MISSING"
CI_REASON_STATUS_CONTRADICTORY = "CI_STATUS_CONTRADICTORY"
CI_REASON_STATUS_FAIL_CLOSED = "CI_STATUS_FAIL_CLOSED"
CI_REQUIRED_CHECKS_PASSED = "CI_REQUIRED_CHECKS_PASSED"
CI_REQUIRED_CHECK_MISSING = "CI_REQUIRED_CHECK_MISSING"
CI_REQUIRED_CHECK_STALE = "CI_REQUIRED_CHECK_STALE"
CI_REQUIRED_CHECK_PENDING = "CI_REQUIRED_CHECK_PENDING"
CI_REQUIRED_CHECK_FAILED = "CI_REQUIRED_CHECK_FAILED"
CI_PARTIAL_WORKFLOW_VISIBILITY = "CI_PARTIAL_WORKFLOW_VISIBILITY"
CI_DELAYED_PROPAGATION_DETECTED = "CI_DELAYED_PROPAGATION_DETECTED"
CI_STALE_CONTEXT_INVALIDATED = "CI_STALE_CONTEXT_INVALIDATED"
CI_SUPERSEDED_PR_REJECTED = "CI_SUPERSEDED_PR_REJECTED"
CI_MERGEABILITY_CONTRADICTORY = "CI_MERGEABILITY_CONTRADICTORY"
CI_MERGE_AUTHORITY_GRANTED = "CI_MERGE_AUTHORITY_GRANTED"
CI_MERGE_AUTHORITY_DENIED = "CI_MERGE_AUTHORITY_DENIED"
CI_PROPAGATION_PENDING = "CI_PROPAGATION_PENDING"
CI_PROPAGATION_TIMEOUT = "CI_PROPAGATION_TIMEOUT"
CI_WORKFLOW_FANOUT_INCOMPLETE = "CI_WORKFLOW_FANOUT_INCOMPLETE"
CI_RECONCILIATION_SUCCEEDED = "CI_RECONCILIATION_SUCCEEDED"
CI_RECONCILIATION_DENIED = "CI_RECONCILIATION_DENIED"

_SUCCESS_VALUES = {"SUCCESS", "COMPLETED_SUCCESS", "PASS", "PASSED"}
_COMPLETED_VALUES = {"COMPLETED", "SUCCESS", "COMPLETED_SUCCESS"}
_PENDING_VALUES = {"PENDING", "QUEUED", "IN_PROGRESS", "WAITING", "REQUESTED"}
_FAILURE_VALUES = {"FAILURE", "FAILED", "ERROR", "CANCELLED", "CANCELED", "TIMED_OUT", "ACTION_REQUIRED", "SKIPPED"}


@dataclass(frozen=True)
class CIStatusNormalizationResult:
    canonical_state: str
    merge_authority: bool
    reason_codes: tuple[str, ...]
    blockers: tuple[str, ...]
    audit: dict[str, Any]


@dataclass(frozen=True)
class CIPropagationReconciliationResult:
    canonical_state: str
    merge_authority: bool
    reason_codes: tuple[str, ...]
    blockers: tuple[str, ...]
    audit: dict[str, Any]


def canonical_json(payload: Any) -> str:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"))


def sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def normalize_ci_status(
    *,
    checks: tuple[dict[str, Any], ...] | list[dict[str, Any]],
    required_checks: tuple[str, ...] | list[str],
    pr_head_sha: str = "",
    mergeable: bool | None = None,
    superseded_by: str | None = None,
    timestamp_utc: str | None = None,
) -> CIStatusNormalizationResult:
    timestamp = timestamp_utc or utc_now()
    required = tuple(str(check).strip() for check in required_checks if str(check).strip())
    normalized_checks = tuple(_normalize_check(check) for check in checks)
    by_name: dict[str, list[dict[str, str]]] = {}
    for check in normalized_checks:
        if check["name"]:
            by_name.setdefault(check["name"], []).append(check)

    reason_codes: list[str] = []
    blockers: list[str] = []
    required_status: list[dict[str, str]] = []

    if superseded_by:
        reason_codes.extend((CI_SUPERSEDED_PR_REJECTED, CI_REASON_STATUS_STALE))
        blockers.append("ci_superseded_pr_rejected")

    for name in required:
        entries = by_name.get(name, [])
        status = _required_check_status(name, entries, pr_head_sha)
        required_status.append(status)
        reason_codes.extend(status["reason_codes"].split(",") if status["reason_codes"] else [])
        if status["blocker"]:
            blockers.append(status["blocker"])

    if not required:
        reason_codes.extend((CI_REASON_STATUS_MISSING, CI_REQUIRED_CHECK_MISSING))
        blockers.append("ci_required_checks_missing")

    canonical_state = _canonical_state(required_status, bool(superseded_by))
    if canonical_state == CI_STATUS_VERIFIED:
        reason_codes.extend((CI_REASON_STATUS_VERIFIED, CI_REQUIRED_CHECKS_PASSED))
    elif canonical_state == CI_STATUS_PROPAGATING:
        reason_codes.extend((CI_REASON_STATUS_PROPAGATING, CI_DELAYED_PROPAGATION_DETECTED))
    elif canonical_state == CI_STATUS_PARTIAL:
        reason_codes.extend((CI_REASON_STATUS_PARTIAL, CI_PARTIAL_WORKFLOW_VISIBILITY))
    elif canonical_state == CI_STATUS_STALE:
        reason_codes.extend((CI_REASON_STATUS_STALE, CI_STALE_CONTEXT_INVALIDATED))
    elif canonical_state == CI_STATUS_MISSING:
        reason_codes.append(CI_REASON_STATUS_MISSING)
    elif canonical_state == CI_STATUS_CONTRADICTORY:
        reason_codes.append(CI_REASON_STATUS_CONTRADICTORY)
    else:
        reason_codes.append(CI_REASON_STATUS_FAIL_CLOSED)

    if mergeable is False and canonical_state == CI_STATUS_VERIFIED:
        canonical_state = CI_STATUS_CONTRADICTORY
        reason_codes.extend((CI_MERGEABILITY_CONTRADICTORY, CI_REASON_STATUS_CONTRADICTORY))
        blockers.append("ci_mergeability_contradictory")

    merge_authority = canonical_state == CI_STATUS_VERIFIED and not blockers
    reason_codes.append(CI_MERGE_AUTHORITY_GRANTED if merge_authority else CI_MERGE_AUTHORITY_DENIED)

    workflow_names = tuple(sorted({check["name"] for check in normalized_checks if check["name"]}))
    audit = {
        "schema": CI_STATUS_NORMALIZATION_SCHEMA,
        "canonical_state": canonical_state,
        "normalized_workflow_list": workflow_names,
        "normalized_workflow_list_hash": sha256_text(canonical_json(workflow_names)),
        "required_checks": required,
        "required_checks_hash": sha256_text(canonical_json(required)),
        "required_check_status": tuple(required_status),
        "stale_detection": "STALE_CONTEXTS_INVALIDATED" if _has_status(required_status, "STALE") else "NO_STALE_CONTEXTS",
        "propagation_delays": "DETECTED" if _has_status(required_status, "PROPAGATING") else "NONE",
        "superseded_pr_detection": "SUPERSEDED" if superseded_by else "NOT_SUPERSEDED",
        "mergeability_signal": "TRUE" if mergeable is True else "FALSE" if mergeable is False else "UNKNOWN",
        "final_merge_authority_verdict": "ALLOW" if merge_authority else "BLOCK",
        "reason_codes": tuple(sorted(set(reason_codes))),
        "blockers": tuple(sorted(set(blockers))),
        "timestamp_utc": timestamp,
    }
    audit["audit_hash"] = sha256_text(canonical_json(audit))
    return CIStatusNormalizationResult(
        canonical_state=canonical_state,
        merge_authority=merge_authority,
        reason_codes=tuple(sorted(set(reason_codes))),
        blockers=tuple(sorted(set(blockers))),
        audit=audit,
    )


def reconcile_ci_propagation(
    *,
    snapshots: tuple[tuple[dict[str, Any], ...], ...] | list[tuple[dict[str, Any], ...] | list[dict[str, Any]]],
    required_checks: tuple[str, ...] | list[str],
    pr_head_sha: str = "",
    mergeable: bool | None = None,
    superseded_by: str | None = None,
    max_reconciliation_attempts: int = 3,
    timestamp_utc: str | None = None,
) -> CIPropagationReconciliationResult:
    timestamp = timestamp_utc or utc_now()
    if max_reconciliation_attempts < 1:
        max_reconciliation_attempts = 1
    bounded_snapshots = tuple(tuple(snapshot) for snapshot in snapshots[:max_reconciliation_attempts])
    attempts: list[dict[str, Any]] = []
    reason_codes: list[str] = []
    blockers: list[str] = []

    if not bounded_snapshots:
        normalized = normalize_ci_status(
            checks=(),
            required_checks=required_checks,
            pr_head_sha=pr_head_sha,
            mergeable=mergeable,
            superseded_by=superseded_by,
            timestamp_utc=timestamp,
        )
        attempts.append(_attempt_summary(1, normalized))
        reason_codes.extend((CI_PROPAGATION_TIMEOUT, CI_RECONCILIATION_DENIED))
        blockers.append("ci_propagation_timeout")
    else:
        for index, snapshot in enumerate(bounded_snapshots, start=1):
            normalized = normalize_ci_status(
                checks=snapshot,
                required_checks=required_checks,
                pr_head_sha=pr_head_sha,
                mergeable=mergeable,
                superseded_by=superseded_by,
                timestamp_utc=timestamp,
            )
            attempts.append(_attempt_summary(index, normalized))
            reason_codes.extend(normalized.reason_codes)
            terminal_denied = normalized.canonical_state in {
                CI_STATUS_STALE,
                CI_STATUS_CONTRADICTORY,
                CI_STATUS_FAIL_CLOSED,
            }
            if normalized.merge_authority:
                reason_codes.append(CI_RECONCILIATION_SUCCEEDED)
                return _propagation_result(
                    canonical_state=CI_STATUS_VERIFIED,
                    merge_authority=True,
                    reason_codes=reason_codes,
                    blockers=(),
                    attempts=attempts,
                    timestamp_utc=timestamp,
                    max_reconciliation_attempts=max_reconciliation_attempts,
                )
            if terminal_denied:
                reason_codes.append(CI_RECONCILIATION_DENIED)
                blockers.extend(normalized.blockers)
                break
            if normalized.canonical_state in {CI_STATUS_MISSING, CI_STATUS_PARTIAL, CI_STATUS_PROPAGATING}:
                reason_codes.append(CI_PROPAGATION_PENDING)
                if normalized.canonical_state == CI_STATUS_PARTIAL:
                    reason_codes.append(CI_WORKFLOW_FANOUT_INCOMPLETE)
                blockers.extend(normalized.blockers)

    final_state = _propagation_final_state(attempts)
    if final_state in {CI_STATUS_MISSING, CI_STATUS_PARTIAL, CI_STATUS_PROPAGATING}:
        reason_codes.extend((CI_PROPAGATION_TIMEOUT, CI_RECONCILIATION_DENIED))
        blockers.append("ci_propagation_timeout")
    elif CI_RECONCILIATION_DENIED not in reason_codes:
        reason_codes.append(CI_RECONCILIATION_DENIED)

    return _propagation_result(
        canonical_state=final_state,
        merge_authority=False,
        reason_codes=reason_codes,
        blockers=blockers,
        attempts=attempts,
        timestamp_utc=timestamp,
        max_reconciliation_attempts=max_reconciliation_attempts,
    )


def _normalize_check(check: dict[str, Any]) -> dict[str, str]:
    name = str(check.get("name") or check.get("context") or check.get("workflowName") or "").strip()
    status = str(check.get("status") or check.get("state") or "").strip().upper()
    conclusion = str(check.get("conclusion") or check.get("bucket") or "").strip().upper()
    sha = str(check.get("headSha") or check.get("head_sha") or check.get("sha") or check.get("commitSha") or "").strip()
    if not status and conclusion in _SUCCESS_VALUES:
        status = "COMPLETED"
    return {"name": name, "status": status, "conclusion": conclusion, "sha": sha}


def _attempt_summary(index: int, normalized: CIStatusNormalizationResult) -> dict[str, Any]:
    return {
        "attempt": index,
        "canonical_state": normalized.canonical_state,
        "merge_authority": normalized.merge_authority,
        "audit_hash": normalized.audit["audit_hash"],
        "workflow_list_hash": normalized.audit["normalized_workflow_list_hash"],
        "required_check_status_hash": sha256_text(canonical_json(normalized.audit["required_check_status"])),
    }


def _propagation_result(
    *,
    canonical_state: str,
    merge_authority: bool,
    reason_codes: list[str],
    blockers: tuple[str, ...] | list[str],
    attempts: list[dict[str, Any]],
    timestamp_utc: str,
    max_reconciliation_attempts: int,
) -> CIPropagationReconciliationResult:
    clean_reason_codes = tuple(sorted(set(reason_codes)))
    clean_blockers = tuple(sorted(set(blockers)))
    audit = {
        "schema": "usbay.ci_propagation_reconciliation.v1",
        "canonical_state": canonical_state,
        "merge_authority": merge_authority,
        "attempt_count": len(attempts),
        "max_reconciliation_attempts": max_reconciliation_attempts,
        "attempts": tuple(attempts),
        "attempts_hash": sha256_text(canonical_json(attempts)),
        "reason_codes": clean_reason_codes,
        "blockers": clean_blockers,
        "timestamp_utc": timestamp_utc,
        "final_merge_authority_verdict": "ALLOW" if merge_authority else "BLOCK",
    }
    audit["audit_hash"] = sha256_text(canonical_json(audit))
    return CIPropagationReconciliationResult(canonical_state, merge_authority, clean_reason_codes, clean_blockers, audit)


def _propagation_final_state(attempts: list[dict[str, Any]]) -> str:
    if not attempts:
        return CI_STATUS_MISSING
    return str(attempts[-1]["canonical_state"])


def _required_check_status(name: str, entries: list[dict[str, str]], pr_head_sha: str) -> dict[str, str]:
    if not entries:
        return {
            "name": name,
            "status": "MISSING",
            "reason_codes": CI_REQUIRED_CHECK_MISSING,
            "blocker": f"ci_required_check_missing:{name}",
        }
    unique_outcomes = sorted({_outcome(entry) for entry in entries})
    if len(unique_outcomes) > 1:
        return {
            "name": name,
            "status": "CONTRADICTORY",
            "reason_codes": CI_REASON_STATUS_CONTRADICTORY,
            "blocker": f"ci_required_check_contradictory:{name}",
        }
    if pr_head_sha and any(entry["sha"] and entry["sha"] != pr_head_sha for entry in entries):
        return {
            "name": name,
            "status": "STALE",
            "reason_codes": CI_REQUIRED_CHECK_STALE,
            "blocker": f"ci_required_check_stale:{name}",
        }
    outcome = unique_outcomes[0]
    if outcome == "PASS":
        return {"name": name, "status": "PASS", "reason_codes": "", "blocker": ""}
    if outcome == "PROPAGATING":
        return {
            "name": name,
            "status": "PROPAGATING",
            "reason_codes": CI_REQUIRED_CHECK_PENDING,
            "blocker": f"ci_required_check_propagating:{name}",
        }
    return {
        "name": name,
        "status": "FAIL",
        "reason_codes": CI_REQUIRED_CHECK_FAILED,
        "blocker": f"ci_required_check_failed:{name}",
    }


def _outcome(entry: dict[str, str]) -> str:
    status = entry["status"]
    conclusion = entry["conclusion"]
    if status in _COMPLETED_VALUES and conclusion in _SUCCESS_VALUES:
        return "PASS"
    if status in _SUCCESS_VALUES and not conclusion:
        return "PASS"
    if conclusion in _SUCCESS_VALUES and not status:
        return "PASS"
    if status in _PENDING_VALUES or conclusion in _PENDING_VALUES:
        return "PROPAGATING"
    if status in _FAILURE_VALUES or conclusion in _FAILURE_VALUES:
        return "FAIL"
    return "FAIL"


def _canonical_state(required_status: list[dict[str, str]], superseded: bool) -> str:
    if superseded:
        return CI_STATUS_STALE
    statuses = {item["status"] for item in required_status}
    if not statuses or statuses == {"MISSING"}:
        return CI_STATUS_MISSING
    if "CONTRADICTORY" in statuses:
        return CI_STATUS_CONTRADICTORY
    if "STALE" in statuses:
        return CI_STATUS_STALE
    if "FAIL" in statuses:
        return CI_STATUS_FAIL_CLOSED
    if "PROPAGATING" in statuses:
        return CI_STATUS_PROPAGATING
    if "MISSING" in statuses:
        return CI_STATUS_PARTIAL
    if statuses == {"PASS"}:
        return CI_STATUS_VERIFIED
    return CI_STATUS_FAIL_CLOSED


def _has_status(required_status: list[dict[str, str]], status: str) -> bool:
    return any(item["status"] == status for item in required_status)
