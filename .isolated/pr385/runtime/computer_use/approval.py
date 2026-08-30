from __future__ import annotations

import hashlib
import json
import uuid
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from runtime.computer_use.action_schema import ComputerUseAction, audit_hash_for_action
from runtime.computer_use.audit_recorder import ComputerUseAuditRecorder


APPROVAL_REQUEST_SCHEMA: dict[str, Any] = {
    "schema": "usbay.computer_use.approval_request.v1",
    "required_fields": [
        "request_id",
        "action_id",
        "action_hash",
        "requested_reason",
        "requested_at",
        "status",
        "approval_audit_hash",
    ],
    "allowed_statuses": ["PENDING"],
    "fail_closed_on_missing_field": True,
    "raw_tokens_allowed": False,
}


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _iso(value: datetime) -> str:
    return value.isoformat().replace("+00:00", "Z")


def _hash(payload: dict[str, Any]) -> str:
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def approval_request_schema() -> dict[str, Any]:
    return json.loads(json.dumps(APPROVAL_REQUEST_SCHEMA))


@dataclass(frozen=True)
class ApprovalRequest:
    request_id: str
    action_id: str
    action_hash: str
    requested_reason: str
    requested_at: str
    status: str
    approval_audit_hash: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class ApprovalDecision:
    request_id: str
    action_id: str
    action_hash: str
    decision: str
    reviewer_id: str
    approval_reason: str
    decided_at: str
    expires_at: str | None
    approval_token: str | None
    approval_token_hash: str | None
    approval_audit_hash: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class ApprovalValidation:
    valid: bool
    decision: str
    reason: str
    approval_reference: str | None = None
    approval_audit_hash: str | None = None


class ComputerUseApprovalQueue:
    def __init__(self, *, audit_recorder: ComputerUseAuditRecorder, evidence_path: Path | str | None = None) -> None:
        self.audit_recorder = audit_recorder
        self.evidence_path = Path(evidence_path) if evidence_path is not None else None
        self._requests: dict[str, ApprovalRequest] = {}
        self._decisions: dict[str, ApprovalDecision] = {}
        self._tokens: dict[str, str] = {}
        self._consumed_tokens: set[str] = set()

    def request_approval(self, action: ComputerUseAction, *, reason: str) -> ApprovalRequest:
        action_hash = audit_hash_for_action(action.to_dict())
        request_payload = {
            "action_id": action.action_id,
            "action_hash": action_hash,
            "requested_reason": reason,
            "requested_at": _iso(_now()),
            "status": "PENDING",
        }
        request_id = f"approval-{uuid.uuid4().hex}"
        audit_event = self.audit_recorder.record(
            {
                "event_type": "approval_requested",
                "request_id": request_id,
                **request_payload,
            }
        )
        request = ApprovalRequest(
            request_id=request_id,
            approval_audit_hash=audit_event["audit_hash"],
            **request_payload,
        )
        self._requests[request_id] = request
        return request

    def approve(
        self,
        request_id: str,
        *,
        reviewer_id: str,
        approval_reason: str,
        ttl_seconds: int = 300,
    ) -> ApprovalDecision:
        request = self._require_request(request_id)
        if not reviewer_id:
            raise RuntimeError("APPROVAL_REVIEWER_REQUIRED")
        if not approval_reason:
            raise RuntimeError("APPROVAL_REASON_REQUIRED")
        expires_at = _now() + timedelta(seconds=ttl_seconds)
        token_payload = {
            "request_id": request.request_id,
            "action_id": request.action_id,
            "action_hash": request.action_hash,
            "reviewer_id": reviewer_id,
            "decision": "APPROVED",
            "expires_at": _iso(expires_at),
            "nonce": uuid.uuid4().hex,
        }
        token = "approval." + _hash(token_payload)
        token_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()
        decision = self._record_decision(
            request,
            decision="APPROVED",
            reviewer_id=reviewer_id,
            approval_reason=approval_reason,
            expires_at=_iso(expires_at),
            approval_token=token,
            approval_token_hash=token_hash,
        )
        self._tokens[token_hash] = decision.request_id
        return decision

    def deny(self, request_id: str, *, reviewer_id: str, approval_reason: str) -> ApprovalDecision:
        request = self._require_request(request_id)
        if not reviewer_id:
            raise RuntimeError("APPROVAL_REVIEWER_REQUIRED")
        if not approval_reason:
            raise RuntimeError("APPROVAL_REASON_REQUIRED")
        return self._record_decision(
            request,
            decision="DENIED",
            reviewer_id=reviewer_id,
            approval_reason=approval_reason,
            expires_at=None,
            approval_token=None,
            approval_token_hash=None,
        )

    def validate_token(self, token: str | None, action: ComputerUseAction) -> ApprovalValidation:
        if not token:
            return ApprovalValidation(False, "FAIL_CLOSED", "APPROVAL_TOKEN_MISSING")
        token_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()
        if token_hash in self._consumed_tokens:
            return ApprovalValidation(False, "BLOCK", "APPROVAL_TOKEN_REPLAYED")
        request_id = self._tokens.get(token_hash)
        if not request_id:
            return ApprovalValidation(False, "FAIL_CLOSED", "APPROVAL_TOKEN_UNKNOWN")
        decision = self._decisions.get(request_id)
        if decision is None or decision.decision != "APPROVED":
            return ApprovalValidation(False, "BLOCK", "APPROVAL_NOT_GRANTED")
        if decision.action_id != action.action_id:
            return ApprovalValidation(False, "FAIL_CLOSED", "APPROVAL_ACTION_ID_MISMATCH")
        if decision.action_hash != audit_hash_for_action(action.to_dict()):
            return ApprovalValidation(False, "FAIL_CLOSED", "APPROVAL_ACTION_HASH_MISMATCH")
        if decision.expires_at is None:
            return ApprovalValidation(False, "FAIL_CLOSED", "APPROVAL_EXPIRATION_MISSING")
        expires_at = datetime.fromisoformat(decision.expires_at.replace("Z", "+00:00"))
        if _now() >= expires_at:
            return ApprovalValidation(False, "BLOCK", "APPROVAL_TOKEN_EXPIRED")
        self._consumed_tokens.add(token_hash)
        self.audit_recorder.record(
            {
                "event_type": "approval_token_consumed",
                "request_id": request_id,
                "action_id": action.action_id,
                "action_hash": decision.action_hash,
                "approval_token_hash": token_hash,
                "approval_audit_hash": decision.approval_audit_hash,
            }
        )
        return ApprovalValidation(True, "ALLOW", "APPROVAL_TOKEN_VALID", request_id, decision.approval_audit_hash)

    def denied_action(self, action: ComputerUseAction) -> ApprovalValidation | None:
        action_hash = audit_hash_for_action(action.to_dict())
        for decision in self._decisions.values():
            if decision.action_id == action.action_id and decision.action_hash == action_hash and decision.decision == "DENIED":
                return ApprovalValidation(
                    False,
                    "BLOCK",
                    "APPROVAL_DENIED",
                    decision.request_id,
                    decision.approval_audit_hash,
                )
        return None

    def export_evidence(self, path: Path | str | None = None) -> dict[str, Any]:
        evidence = {
            "requests": [request.to_dict() for request in self._requests.values()],
            "decisions": [self._redacted_decision(decision) for decision in self._decisions.values()],
            "consumed_token_count": len(self._consumed_tokens),
            "raw_tokens_exported": False,
        }
        evidence["evidence_hash"] = _hash(evidence)
        output_path = Path(path) if path is not None else self.evidence_path
        if output_path is not None:
            output_path.parent.mkdir(parents=True, exist_ok=True)
            output_path.write_text(json.dumps(evidence, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        return evidence

    def _record_decision(
        self,
        request: ApprovalRequest,
        *,
        decision: str,
        reviewer_id: str,
        approval_reason: str,
        expires_at: str | None,
        approval_token: str | None,
        approval_token_hash: str | None,
    ) -> ApprovalDecision:
        audit_event = self.audit_recorder.record(
            {
                "event_type": "approval_decision",
                "request_id": request.request_id,
                "action_id": request.action_id,
                "action_hash": request.action_hash,
                "decision": decision,
                "reviewer_id": reviewer_id,
                "approval_reason": approval_reason,
                "expires_at": expires_at,
                "approval_token_hash": approval_token_hash,
            }
        )
        approval = ApprovalDecision(
            request_id=request.request_id,
            action_id=request.action_id,
            action_hash=request.action_hash,
            decision=decision,
            reviewer_id=reviewer_id,
            approval_reason=approval_reason,
            decided_at=audit_event["timestamp"],
            expires_at=expires_at,
            approval_token=approval_token,
            approval_token_hash=approval_token_hash,
            approval_audit_hash=audit_event["audit_hash"],
        )
        self._decisions[request.request_id] = approval
        return approval

    def _require_request(self, request_id: str) -> ApprovalRequest:
        request = self._requests.get(request_id)
        if request is None:
            raise RuntimeError("APPROVAL_REQUEST_UNKNOWN")
        return request

    def _redacted_decision(self, decision: ApprovalDecision) -> dict[str, Any]:
        payload = decision.to_dict()
        payload["approval_token"] = None
        return payload
