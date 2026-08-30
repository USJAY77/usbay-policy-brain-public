from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from typing import Any


SCHEMA_VERSION = "usbay.correction_proposal.v1"
AUDIT_SCHEMA_VERSION = "usbay.correction_proposal_audit.v1"
DECISION_DENY = "DENY"
DECISION_PROPOSE = "PROPOSE"
DECISION_MANUAL_EXECUTION_ELIGIBLE = "MANUAL_EXECUTION_ELIGIBLE"
APPROVAL_PENDING = "PENDING"
APPROVAL_APPROVED = "APPROVED"
APPROVAL_REJECTED = "REJECTED"
APPROVAL_EXPIRED = "EXPIRED"
EXECUTION_BLOCKED = "BLOCKED"
EXECUTION_NOT_EXECUTED = "NOT_EXECUTED"
REASON_OK = "ok"
REASON_APPROVAL_REQUIRED = "human_approval_required"
REASON_APPROVAL_REJECTED = "proposal_rejected"
REASON_APPROVAL_EXPIRED = "proposal_expired"
REASON_UNKNOWN_STATE = "unknown_proposal_state"
REASON_UNSUPPORTED_ISSUE = "unsupported_proposal_issue"


ISSUE_CONTRACTS = {
    "CI_FAILURE": {
        "risk_level": "MEDIUM",
        "proposed_action": "prepare_ci_failure_remediation_patch",
    },
    "DEPENDENCY_REMEDIATION": {
        "risk_level": "MEDIUM",
        "proposed_action": "prepare_dependency_remediation_patch",
    },
    "RUNTIME_DRIFT": {
        "risk_level": "HIGH",
        "proposed_action": "prepare_runtime_drift_investigation_patch",
    },
    "REVOCATION": {
        "risk_level": "HIGH",
        "proposed_action": "prepare_revocation_registry_update_patch",
    },
    "NONCE_STORE": {
        "risk_level": "HIGH",
        "proposed_action": "prepare_nonce_store_remediation_patch",
    },
}


class CorrectionProposalError(RuntimeError):
    pass


def _utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _canonical(data: dict[str, Any]) -> str:
    return json.dumps(data, sort_keys=True, separators=(",", ":"))


def _sha256(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _parse_timestamp(value: str) -> datetime:
    return datetime.fromisoformat(str(value).replace("Z", "+00:00")).astimezone(timezone.utc)


def _proposal_payload(proposal: dict[str, Any]) -> dict[str, Any]:
    payload = dict(proposal)
    payload.pop("proposal_hash", None)
    payload.pop("audit_evidence", None)
    return payload


def proposal_hash(proposal: dict[str, Any]) -> str:
    return _sha256(_canonical(_proposal_payload(proposal)))


def audit_evidence(proposal: dict[str, Any], *, reason_code: str) -> dict[str, Any]:
    evidence = {
        "schema_version": AUDIT_SCHEMA_VERSION,
        "proposal_id": str(proposal.get("proposal_id", "")),
        "proposal_hash": str(proposal.get("proposal_hash", "")),
        "risk_level": str(proposal.get("risk_level", "")),
        "proposed_action": str(proposal.get("proposed_action", "")),
        "approval_status": str(proposal.get("approval_status", "")),
        "execution_status": str(proposal.get("execution_status", "")),
        "timestamp": str(proposal.get("timestamp", "")),
        "reason_code": reason_code,
    }
    evidence["audit_hash"] = _sha256(_canonical(evidence))
    return evidence


def detect_governance_issue(issue_type: str, *, observed_failure: str, source: str = "local_validation") -> dict[str, Any]:
    normalized_issue = str(issue_type).strip().upper()
    if normalized_issue not in ISSUE_CONTRACTS:
        return {
            "decision": DECISION_DENY,
            "reason_code": REASON_UNSUPPORTED_ISSUE,
            "issue_type": normalized_issue,
            "source": str(source),
        }
    return {
        "decision": "DETECTED",
        "reason_code": REASON_OK,
        "issue_type": normalized_issue,
        "observed_failure_hash": _sha256(str(observed_failure)),
        "source": str(source),
    }


def generate_correction_proposal(
    issue: dict[str, Any],
    *,
    proposed_action: str | None = None,
    timestamp: str | None = None,
    expires_at: str | None = None,
) -> dict[str, Any]:
    if not isinstance(issue, dict) or issue.get("decision") != "DETECTED":
        raise CorrectionProposalError(REASON_UNSUPPORTED_ISSUE)
    issue_type = str(issue.get("issue_type", "")).upper()
    contract = ISSUE_CONTRACTS.get(issue_type)
    if contract is None:
        raise CorrectionProposalError(REASON_UNSUPPORTED_ISSUE)
    created_at = timestamp or _utc_now()
    action = str(proposed_action or contract["proposed_action"])
    base = {
        "schema_version": SCHEMA_VERSION,
        "proposal_id": "",
        "issue_type": issue_type,
        "risk_level": contract["risk_level"],
        "proposed_action": action,
        "approval_status": APPROVAL_PENDING,
        "execution_status": EXECUTION_BLOCKED,
        "timestamp": created_at,
        "expires_at": str(expires_at or ""),
        "human_approval_required": True,
        "auto_execution_allowed": False,
        "source": str(issue.get("source", "")),
        "observed_failure_hash": str(issue.get("observed_failure_hash", "")),
    }
    base["proposal_id"] = _sha256(_canonical(base))
    base["proposal_hash"] = proposal_hash(base)
    base["audit_evidence"] = audit_evidence(base, reason_code=REASON_APPROVAL_REQUIRED)
    return base


def _is_expired(proposal: dict[str, Any], now: str | None = None) -> bool:
    expires_at = str(proposal.get("expires_at", "") or "")
    if not expires_at:
        return False
    try:
        now_dt = _parse_timestamp(now or _utc_now())
        expires_dt = _parse_timestamp(expires_at)
    except Exception:
        return True
    return now_dt > expires_dt


def evaluate_proposal_approval(proposal: dict[str, Any], *, now: str | None = None) -> dict[str, Any]:
    if not isinstance(proposal, dict):
        return {
            "decision": DECISION_DENY,
            "reason_code": REASON_UNKNOWN_STATE,
            "execution_status": EXECUTION_BLOCKED,
            "audit_evidence": audit_evidence({}, reason_code=REASON_UNKNOWN_STATE),
        }
    if proposal.get("proposal_hash") != proposal_hash(proposal):
        reason = REASON_UNKNOWN_STATE
    elif _is_expired(proposal, now=now):
        reason = REASON_APPROVAL_EXPIRED
    elif proposal.get("approval_status") == APPROVAL_APPROVED:
        result = dict(proposal)
        result["execution_status"] = EXECUTION_NOT_EXECUTED
        return {
            "decision": DECISION_MANUAL_EXECUTION_ELIGIBLE,
            "reason_code": REASON_OK,
            "execution_status": EXECUTION_NOT_EXECUTED,
            "auto_execution_allowed": False,
            "audit_evidence": audit_evidence(result, reason_code=REASON_OK),
        }
    elif proposal.get("approval_status") == APPROVAL_REJECTED:
        reason = REASON_APPROVAL_REJECTED
    elif proposal.get("approval_status") == APPROVAL_PENDING:
        reason = REASON_APPROVAL_REQUIRED
    else:
        reason = REASON_UNKNOWN_STATE
    result = dict(proposal)
    result["execution_status"] = EXECUTION_BLOCKED
    return {
        "decision": DECISION_DENY,
        "reason_code": reason,
        "execution_status": EXECUTION_BLOCKED,
        "auto_execution_allowed": False,
        "audit_evidence": audit_evidence(result, reason_code=reason),
    }


def with_approval_status(proposal: dict[str, Any], approval_status: str) -> dict[str, Any]:
    updated = dict(proposal)
    updated["approval_status"] = str(approval_status)
    updated["execution_status"] = EXECUTION_BLOCKED
    updated["proposal_hash"] = proposal_hash(updated)
    updated["audit_evidence"] = audit_evidence(updated, reason_code=REASON_APPROVAL_REQUIRED)
    return updated
