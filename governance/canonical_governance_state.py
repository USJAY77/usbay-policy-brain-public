"""Canonical governance authority state for USBAY orchestration.

This module reconciles normalized GitHub orchestration evidence into one
hash-only governance state. It does not trust raw event payloads, execute
workflows, approve merges, bypass branch protection, or log secrets.
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

CANONICAL_GOVERNANCE_STATE_SCHEMA = "usbay.canonical_governance_state.v1"
CANONICAL_GOVERNANCE_STATE_ERROR_SCHEMA = "usbay.canonical_governance_state_error_registry.v1"
CANONICAL_GOVERNANCE_STATE_ERROR_REGISTRY_PATH = Path("governance/canonical_governance_state_errors.json")

GOVERNANCE_VALIDATED = "GOVERNANCE_VALIDATED"
GOVERNANCE_REVIEW_REQUIRED = "GOVERNANCE_REVIEW_REQUIRED"
GOVERNANCE_BLOCKED = "GOVERNANCE_BLOCKED"
GOVERNANCE_UNKNOWN = "GOVERNANCE_UNKNOWN"

CANONICAL_GOVERNANCE_STATE_REASON_CODES = (
    "CANONICAL_GOVERNANCE_STATE_CREATED",
    "CANONICAL_GOVERNANCE_STATE_UNKNOWN",
    "CANONICAL_GOVERNANCE_STATE_BLOCKED",
    "EVENT_SEQUENCE_RECONCILED",
    "EVENT_SEQUENCE_CONFLICT",
    "AUTHORITY_SOURCE_UNTRUSTED",
    "AUTHORITY_SOURCE_AMBIGUOUS",
    "RECONCILIATION_HASH_CREATED",
    "GOVERNANCE_REGISTRY_SYNC_REQUIRED",
    "RUNTIME_EVIDENCE_MISSING",
    "POLICY_HASH_MISSING",
    "POLICY_HASH_MISMATCH",
)

_POSITIVE_CODES = {
    "CANONICAL_GOVERNANCE_STATE_CREATED",
    "EVENT_SEQUENCE_RECONCILED",
    "RECONCILIATION_HASH_CREATED",
}
_EXTERNAL_POSITIVE_CODES = {"MERGE_LINEAGE_RECONCILED"}
_BLOCKING_CODES = {
    "CANONICAL_GOVERNANCE_STATE_UNKNOWN",
    "CANONICAL_GOVERNANCE_STATE_BLOCKED",
    "EVENT_SEQUENCE_CONFLICT",
    "AUTHORITY_SOURCE_UNTRUSTED",
    "AUTHORITY_SOURCE_AMBIGUOUS",
    "GOVERNANCE_REGISTRY_SYNC_REQUIRED",
    "POLICY_HASH_MISSING",
    "POLICY_HASH_MISMATCH",
}
_REVIEW_CODES = {"RUNTIME_EVIDENCE_MISSING"}
_ORDER = {
    "PR_OPEN": 1,
    "CHECKS_COMPLETE": 2,
    "MERGE_ALLOWED": 3,
    "MERGE_COMMITTED": 4,
    "BRANCH_DELETED": 5,
}
_SAFE_ACTORS = {"dependabot[bot]", "github-actions[bot]"}
_SAFE_EVENT_TYPES = {"pull_request", "workflow_run", "push", "workflow_dispatch", "delete", "branch_delete"}
_SAFE_WORKFLOW_SOURCES = {"pull_request", "workflow_run", "push", "workflow_dispatch", "delete", "branch_delete"}


class CanonicalGovernanceStateError(RuntimeError):
    pass


def canonical_json(payload: Any) -> str:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"))


def sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def valid_hash(value: str | None) -> bool:
    return isinstance(value, str) and len(value) == 64 and all(ch in "0123456789abcdefABCDEF" for ch in value)


def valid_sha(value: str | None) -> bool:
    return isinstance(value, str) and len(value) == 40 and all(ch in "0123456789abcdefABCDEF" for ch in value)


def load_canonical_governance_state_error_registry(root: Path) -> dict[str, dict[str, str]]:
    path = root / CANONICAL_GOVERNANCE_STATE_ERROR_REGISTRY_PATH
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        raise CanonicalGovernanceStateError("canonical_governance_state_error_registry_missing") from exc
    if not isinstance(payload, dict) or payload.get("schema") != CANONICAL_GOVERNANCE_STATE_ERROR_SCHEMA:
        raise CanonicalGovernanceStateError("canonical_governance_state_error_registry_invalid")
    entries = payload.get("errors")
    if not isinstance(entries, list):
        raise CanonicalGovernanceStateError("canonical_governance_state_error_registry_invalid")
    registry: dict[str, dict[str, str]] = {}
    for entry in entries:
        if not isinstance(entry, dict) or not entry.get("code"):
            raise CanonicalGovernanceStateError("canonical_governance_state_error_registry_invalid")
        registry[str(entry["code"])] = {
            "description": str(entry.get("description", "")),
            "fail_closed_reason": str(entry.get("fail_closed_reason", "")),
        }
    missing = sorted(set(CANONICAL_GOVERNANCE_STATE_REASON_CODES) - set(registry))
    if missing:
        raise CanonicalGovernanceStateError("canonical_governance_state_error_registry_incomplete:" + ",".join(missing))
    return registry


def derive_event_sequence_state(
    *,
    event_type: str,
    checks_status: str | dict[str, Any] | None,
    merge_sha: str,
    branch_deleted: bool,
) -> str:
    normalized_event = event_type.strip()
    checks = _checks_passed(checks_status)
    if branch_deleted:
        return "BRANCH_DELETED"
    if normalized_event == "push" and merge_sha:
        return "MERGE_COMMITTED"
    if checks and normalized_event in {"pull_request", "workflow_run", "workflow_dispatch"}:
        return "CHECKS_COMPLETE"
    if normalized_event == "pull_request":
        return "PR_OPEN"
    return "UNKNOWN"


def build_canonical_governance_state(
    *,
    pr_number: int | None,
    repository_full_name: str,
    base_branch: str,
    head_branch: str,
    head_sha: str,
    merge_sha: str = "",
    actor: str,
    event_type: str,
    workflow_run_id: str | int | None = None,
    workflow_name: str = "",
    branch_deleted: bool = False,
    checks_status: str | dict[str, Any] | None = None,
    runtime_evidence_hash: str = "",
    policy_version_hash: str = "",
    timestamp_utc: str | None = None,
    expected_base_branch: str = "main",
    expected_head_sha: str | None = None,
    expected_merge_sha: str | None = None,
    candidate_pr_count: int | None = None,
    prior_event_sequence_state: str | None = None,
    reconciliation_reason_codes: tuple[str, ...] = (),
) -> dict[str, Any]:
    timestamp = timestamp_utc or utc_now()
    reason_codes: list[str] = list(reconciliation_reason_codes)
    normalized_event_type = event_type.strip()
    event_sequence_state = derive_event_sequence_state(
        event_type=normalized_event_type,
        checks_status=checks_status,
        merge_sha=merge_sha,
        branch_deleted=branch_deleted,
    )

    if pr_number is None and normalized_event_type in {"pull_request", "workflow_run", "workflow_dispatch"}:
        reason_codes.append("EVENT_SEQUENCE_CONFLICT")
    if candidate_pr_count is not None and candidate_pr_count != 1:
        reason_codes.append("AUTHORITY_SOURCE_AMBIGUOUS")
    if not repository_full_name or "/" not in repository_full_name:
        reason_codes.append("AUTHORITY_SOURCE_UNTRUSTED")
    if actor not in _SAFE_ACTORS:
        reason_codes.append("AUTHORITY_SOURCE_UNTRUSTED")
    if normalized_event_type not in _SAFE_EVENT_TYPES:
        reason_codes.append("AUTHORITY_SOURCE_UNTRUSTED")
    if workflow_name and normalized_event_type not in _SAFE_WORKFLOW_SOURCES:
        reason_codes.append("AUTHORITY_SOURCE_UNTRUSTED")
    if base_branch != expected_base_branch:
        reason_codes.append("EVENT_SEQUENCE_CONFLICT")
    if expected_head_sha and head_sha != expected_head_sha:
        reason_codes.append("EVENT_SEQUENCE_CONFLICT")
    if expected_merge_sha and merge_sha != expected_merge_sha:
        reason_codes.append("EVENT_SEQUENCE_CONFLICT")
    if branch_deleted and not valid_sha(merge_sha):
        reason_codes.append("EVENT_SEQUENCE_CONFLICT")
    if normalized_event_type == "workflow_run" and not workflow_run_id:
        reason_codes.append("EVENT_SEQUENCE_CONFLICT")
    if event_sequence_state == "UNKNOWN":
        reason_codes.append("CANONICAL_GOVERNANCE_STATE_UNKNOWN")
    if prior_event_sequence_state and _event_order(event_sequence_state) < _event_order(prior_event_sequence_state):
        reason_codes.append("EVENT_SEQUENCE_CONFLICT")
    if not runtime_evidence_hash:
        reason_codes.append("RUNTIME_EVIDENCE_MISSING")
    if not policy_version_hash:
        reason_codes.append("POLICY_HASH_MISSING")
    elif not valid_hash(policy_version_hash):
        reason_codes.append("POLICY_HASH_MISMATCH")

    effective_codes = set(reason_codes) - _POSITIVE_CODES - _EXTERNAL_POSITIVE_CODES
    has_blocker = bool(effective_codes & _BLOCKING_CODES) or bool(effective_codes - _REVIEW_CODES)
    if has_blocker:
        canonical_state = GOVERNANCE_BLOCKED
        reason_codes.append("CANONICAL_GOVERNANCE_STATE_BLOCKED")
        reconciliation_status = "BLOCKED"
        authority_source = "UNTRUSTED" if "AUTHORITY_SOURCE_UNTRUSTED" in reason_codes else "RECONCILED_WITH_BLOCKERS"
    elif set(reason_codes) & _REVIEW_CODES:
        canonical_state = GOVERNANCE_REVIEW_REQUIRED
        reconciliation_status = "REVIEW_REQUIRED"
        authority_source = "GITHUB_RECONCILED_HASH_ONLY"
    else:
        canonical_state = GOVERNANCE_VALIDATED
        reconciliation_status = "RECONCILED"
        authority_source = "GITHUB_RECONCILED_HASH_ONLY"
        reason_codes.append("EVENT_SEQUENCE_RECONCILED")

    reason_codes.append("CANONICAL_GOVERNANCE_STATE_CREATED")
    reason_codes.append("RECONCILIATION_HASH_CREATED")
    reason_tuple = tuple(sorted(set(reason_codes)))
    fingerprint_payload = {
        "pr_number": pr_number,
        "repository_full_name_hash": sha256_text(repository_full_name),
        "base_branch": base_branch,
        "head_branch": head_branch,
        "head_sha": head_sha,
        "merge_sha": merge_sha,
        "actor": actor,
        "event_type": normalized_event_type,
        "workflow_run_id_hash": sha256_text(str(workflow_run_id or "")),
        "workflow_name_hash": sha256_text(workflow_name),
        "branch_deleted": branch_deleted,
        "checks_status": _normalized_checks_status(checks_status),
        "runtime_evidence_hash": runtime_evidence_hash,
        "policy_version_hash": policy_version_hash,
        "timestamp_utc": timestamp,
    }
    event_fingerprint = sha256_text(canonical_json(fingerprint_payload))
    reconciliation_hash = sha256_text(canonical_json({"event_fingerprint": event_fingerprint, "reason_codes": reason_tuple}))
    state = {
        "schema_version": CANONICAL_GOVERNANCE_STATE_SCHEMA,
        "canonical_state": canonical_state,
        "authority_source": authority_source,
        "event_sequence_state": event_sequence_state,
        "reconciliation_status": reconciliation_status,
        "reason_codes": reason_tuple,
        "policy_version_hash": policy_version_hash,
        "event_fingerprint": event_fingerprint,
        "reconciliation_hash": reconciliation_hash,
        "signature_status": "SIGNATURE_UNVERIFIED",
    }
    state["audit_hash"] = sha256_text(canonical_json(state))
    return state


def _event_order(event_sequence_state: str) -> int:
    return _ORDER.get(event_sequence_state, 0)


def _checks_passed(checks_status: str | dict[str, Any] | None) -> bool:
    if isinstance(checks_status, str):
        return checks_status.upper() in {"PASS", "SUCCESS", "CHECKS_COMPLETE"}
    if isinstance(checks_status, dict):
        values = [str(value).upper() for value in checks_status.values()]
        return bool(values) and all(value in {"PASS", "SUCCESS"} for value in values)
    return False


def _normalized_checks_status(checks_status: str | dict[str, Any] | None) -> str:
    if isinstance(checks_status, str):
        return checks_status.upper()
    if isinstance(checks_status, dict):
        return sha256_text(canonical_json({str(key): str(value).upper() for key, value in sorted(checks_status.items())}))
    return "UNKNOWN"
