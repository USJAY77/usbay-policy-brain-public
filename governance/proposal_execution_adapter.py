from __future__ import annotations

from pathlib import Path
from typing import Any, Callable

from governance.correction_proposals import APPROVAL_APPROVED, _canonical, _sha256
from governance.proposal_registry import (
    REASON_PROPOSAL_EXPIRED,
    STATE_APPROVED,
    STATE_BLOCKED,
    STATE_EXECUTED,
    ProposalRegistry,
    ProposalRegistryError,
)
from governance.runtime_revocation_registry import (
    DECISION_NEXT_CHECK,
    RuntimeRevocationRegistryError,
    evaluate_runtime_revocation,
    load_runtime_revocation_registry,
)
from security.persistent_nonce_store import (
    NONCE_RESULT_RESERVED,
    PersistentNonceStoreError,
)
from security.policy_registry import PolicyRegistryError


STATE_CREATED = "CREATED"
STATE_PENDING_APPROVAL = "PENDING_APPROVAL"
STATE_EXECUTION_ELIGIBLE = "EXECUTION_ELIGIBLE"
STATE_EXPIRED = "EXPIRED"

DECISION_DENY = "DENY"
DECISION_EXECUTION_ELIGIBLE = "EXECUTION_ELIGIBLE"

REASON_OK = "ok"
REASON_APPROVAL_REQUIRED = "approval_required"
REASON_PROPOSAL_NOT_FOUND = "proposal_not_found"
REASON_PROPOSAL_HASH_MISMATCH = "proposal_hash_mismatch"
REASON_PROPOSAL_EXPIRED = "proposal_expired"
REASON_PROPOSAL_REVOKED = "proposal_revoked"
REASON_REVOCATION_DENY = "runtime_revocation_denied"
REASON_NONCE_DENY = "nonce_validation_failed"
REASON_POLICY_SIGNATURE_INVALID = "policy_signature_invalid"
REASON_REGISTRY_UNAVAILABLE = "proposal_registry_unavailable"
REASON_UNKNOWN_STATE = "unknown_execution_state"


PolicyLoader = Callable[[], dict[str, Any]]


def _hash_value(value: str) -> str:
    return _sha256(str(value))


def _decision_hash(payload: dict[str, Any]) -> str:
    return _sha256(_canonical(payload))


def _default_policy_loader() -> dict[str, Any]:
    from gateway.app import load_policy_registry, runtime_provenance_context

    return load_policy_registry(provenance_context=runtime_provenance_context())


def execution_audit_evidence(
    *,
    proposal_id: str,
    proposal_hash: str,
    approval_id: str,
    execution_id: str,
    actor: str,
    timestamp: str,
    reason_code: str,
    decision: str,
    execution_state: str,
) -> dict[str, Any]:
    decision_payload = {
        "proposal_id": str(proposal_id),
        "proposal_hash": str(proposal_hash),
        "approval_id": str(approval_id),
        "execution_id": str(execution_id),
        "actor_hash": _hash_value(actor) if actor else "",
        "timestamp": str(timestamp),
        "reason_code": str(reason_code),
        "decision": str(decision),
        "execution_state": str(execution_state),
    }
    evidence = {
        "schema_version": "usbay.proposal_execution_adapter_audit.v1",
        "proposal_id": str(proposal_id),
        "proposal_hash": str(proposal_hash),
        "approval_id": str(approval_id),
        "execution_id": str(execution_id),
        "decision_hash": _decision_hash(decision_payload),
        "actor_hash": decision_payload["actor_hash"],
        "timestamp": str(timestamp),
        "reason_code": str(reason_code),
    }
    evidence["audit_hash"] = _decision_hash(evidence)
    return evidence


def _result(
    *,
    proposal_id: str = "",
    proposal_hash: str = "",
    approval_id: str = "",
    execution_id: str = "",
    actor: str = "",
    timestamp: str,
    decision: str,
    execution_state: str,
    reason_code: str,
) -> dict[str, Any]:
    return {
        "decision": decision,
        "execution_state": execution_state,
        "reason_code": reason_code,
        "audit_evidence": execution_audit_evidence(
            proposal_id=proposal_id,
            proposal_hash=proposal_hash,
            approval_id=approval_id,
            execution_id=execution_id,
            actor=actor,
            timestamp=timestamp,
            reason_code=reason_code,
            decision=decision,
            execution_state=execution_state,
        ),
    }


class ProposalExecutionAdapter:
    def __init__(
        self,
        *,
        proposal_registry: ProposalRegistry,
        nonce_store: Any,
        revocation_registry_path: Path | str,
        policy_loader: PolicyLoader | None = None,
    ):
        self.proposal_registry = proposal_registry
        self.nonce_store = nonce_store
        self.revocation_registry_path = Path(revocation_registry_path)
        self.policy_loader = policy_loader or _default_policy_loader

    def evaluate(self, request: dict[str, Any], *, timestamp: str) -> dict[str, Any]:
        proposal_id = str(request.get("proposal_id", "") if isinstance(request, dict) else "")
        submitted_hash = str(request.get("proposal_hash", "") if isinstance(request, dict) else "")
        approval_id = str(request.get("approval_id", "") if isinstance(request, dict) else "")
        execution_id = str(request.get("execution_id", "") if isinstance(request, dict) else "")
        actor = str(request.get("actor", "") if isinstance(request, dict) else "")

        if not isinstance(request, dict) or not proposal_id or not submitted_hash or not approval_id or not execution_id:
            return _result(
                proposal_id=proposal_id,
                proposal_hash=submitted_hash,
                approval_id=approval_id,
                execution_id=execution_id,
                actor=actor,
                timestamp=timestamp,
                decision=DECISION_DENY,
                execution_state=STATE_BLOCKED,
                reason_code=REASON_APPROVAL_REQUIRED,
            )

        try:
            record = self.proposal_registry.assert_execution_allowed(proposal_id, now=timestamp)
        except ProposalRegistryError as exc:
            reason = str(exc) or REASON_REGISTRY_UNAVAILABLE
            if reason == REASON_PROPOSAL_EXPIRED:
                state = STATE_EXPIRED
                reason = REASON_PROPOSAL_EXPIRED
            elif "unavailable" in reason or "corrupted" in reason:
                state = STATE_BLOCKED
                reason = REASON_REGISTRY_UNAVAILABLE
            elif "not_found" in reason:
                state = STATE_BLOCKED
                reason = REASON_PROPOSAL_NOT_FOUND
            else:
                state = STATE_BLOCKED
                reason = REASON_UNKNOWN_STATE
            return _result(
                proposal_id=proposal_id,
                proposal_hash=submitted_hash,
                approval_id=approval_id,
                execution_id=execution_id,
                actor=actor,
                timestamp=timestamp,
                decision=DECISION_DENY,
                execution_state=state,
                reason_code=reason,
            )

        if record.get("lifecycle_state") == STATE_BLOCKED:
            return _result(
                proposal_id=proposal_id,
                proposal_hash=submitted_hash,
                approval_id=approval_id,
                execution_id=execution_id,
                actor=actor,
                timestamp=timestamp,
                decision=DECISION_DENY,
                execution_state=STATE_BLOCKED,
                reason_code=REASON_PROPOSAL_REVOKED,
            )
        if (
            record.get("proposal_hash") != submitted_hash
            or record.get("approval_status") != APPROVAL_APPROVED
            or record.get("lifecycle_state") != STATE_APPROVED
        ):
            return _result(
                proposal_id=proposal_id,
                proposal_hash=submitted_hash,
                approval_id=approval_id,
                execution_id=execution_id,
                actor=actor,
                timestamp=timestamp,
                decision=DECISION_DENY,
                execution_state=STATE_BLOCKED,
                reason_code=REASON_PROPOSAL_HASH_MISMATCH
                if record.get("proposal_hash") != submitted_hash
                else REASON_APPROVAL_REQUIRED,
            )

        try:
            registry = load_runtime_revocation_registry(self.revocation_registry_path)
            revocation = evaluate_runtime_revocation(
                registry,
                runtime_id=str(request.get("runtime_id", "")),
                device_id=str(request.get("device_id", "")),
                attestation_id=str(request.get("attestation_id", "")),
                operator_id=str(request.get("operator_id", "")),
                timestamp=timestamp,
            )
        except RuntimeRevocationRegistryError:
            revocation = {"decision": DECISION_DENY, "reason_code": REASON_REVOCATION_DENY}
        if revocation.get("decision") != DECISION_NEXT_CHECK:
            return _result(
                proposal_id=proposal_id,
                proposal_hash=submitted_hash,
                approval_id=approval_id,
                execution_id=execution_id,
                actor=actor,
                timestamp=timestamp,
                decision=DECISION_DENY,
                execution_state=STATE_BLOCKED,
                reason_code=str(revocation.get("reason_code") or REASON_REVOCATION_DENY),
            )

        try:
            policy = self.policy_loader()
        except (PolicyRegistryError, Exception):
            policy = {}
        if not isinstance(policy, dict) or policy.get("policy_signature_valid") is not True:
            return _result(
                proposal_id=proposal_id,
                proposal_hash=submitted_hash,
                approval_id=approval_id,
                execution_id=execution_id,
                actor=actor,
                timestamp=timestamp,
                decision=DECISION_DENY,
                execution_state=STATE_BLOCKED,
                reason_code=REASON_POLICY_SIGNATURE_INVALID,
            )

        nonce = str(request.get("nonce", ""))
        nonce_hash = _hash_value(nonce) if nonce else ""
        decision_id = _decision_hash(
            {
                "proposal_id": proposal_id,
                "proposal_hash": submitted_hash,
                "approval_id": approval_id,
                "execution_id": execution_id,
                "timestamp": timestamp,
            }
        )
        try:
            nonce_result = self.nonce_store.reserve(nonce_hash, decision_id=decision_id, timestamp=timestamp)
        except (PersistentNonceStoreError, Exception):
            nonce_result = {"state": REASON_NONCE_DENY}
        if nonce_result.get("state") != NONCE_RESULT_RESERVED:
            return _result(
                proposal_id=proposal_id,
                proposal_hash=submitted_hash,
                approval_id=approval_id,
                execution_id=execution_id,
                actor=actor,
                timestamp=timestamp,
                decision=DECISION_DENY,
                execution_state=STATE_BLOCKED,
                reason_code=REASON_NONCE_DENY,
            )

        return _result(
            proposal_id=proposal_id,
            proposal_hash=submitted_hash,
            approval_id=approval_id,
            execution_id=execution_id,
            actor=actor,
            timestamp=timestamp,
            decision=DECISION_EXECUTION_ELIGIBLE,
            execution_state=STATE_EXECUTION_ELIGIBLE,
            reason_code=REASON_OK,
        )
