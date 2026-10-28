"""Offline product preparation only; never a runtime execution authorization.

Registry, grants and audit callback are trusted operator dependencies, not request
fields. Replay memory is process-local: this API must not be wired into a live
connector or advertised as durable/restart-safe authorization.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime, timezone
import re
from threading import RLock
from typing import Callable

from control_plane.agent_registry import AgentRegistry
from governance.connector_framework import sha256_payload
from governance.human_approval_gate_contract import HUMAN_APPROVAL_GATE_VERSION, evaluate_human_approval


@dataclass(frozen=True)
class DryRunRequest:
    action_id: str
    actor: str
    agent: str
    tenant: str
    capability: str
    policy_version: str
    target_hash: str
    payload_hash: str
    dry_run: bool = True

    @property
    def binding(self) -> str:
        return sha256_payload(asdict(self))


@dataclass(frozen=True)
class DryRunGrant:
    """Trusted local review fixture; not a signed human identity attestation."""

    request_binding: str
    reviewer: str
    issued_at: datetime
    expires_at: datetime
    revoked: bool = False


class ProductDryRun:
    def __init__(
        self,
        *,
        registry: AgentRegistry,
        tenant_bindings: dict[str, tuple[str, ...]],
        policy_version: str,
        grants: dict[str, DryRunGrant],
        audit: Callable[[dict], dict],
        clock: Callable[[], datetime] = lambda: datetime.now(timezone.utc),
        approval_source: Callable[[DryRunRequest], DryRunGrant | None] | None = None,
        consume_attempt: Callable[[str, str], bool] | None = None,
    ) -> None:
        self.registry = registry
        self.tenant_bindings = dict(tenant_bindings)
        self.policy_version = policy_version
        self.grants = dict(grants)
        self.audit = audit
        self.clock = clock
        self.approval_source = approval_source
        self.consume_attempt = consume_attempt
        self._seen: set[str] = set()
        self._lock = RLock()

    def prepare(self, request: DryRunRequest) -> dict:
        # Serialize reservation + audit so identical concurrent requests cannot
        # both yield PREPARED_DRY_RUN. Audit failure burns the attempt ID.
        with self._lock:
            blockers: list[str] = []
            values = asdict(request)
            if any(not isinstance(v, str) or not v.strip() for k, v in values.items() if k != "dry_run"):
                blockers.append("MALFORMED_REQUEST")
            for key in ("target_hash", "payload_hash"):
                if not isinstance(values[key], str) or not re.fullmatch(r"[0-9a-f]{64}", values[key]):
                    blockers.append("INVALID_CONTENT_HASH")
            if request.dry_run is not True:
                blockers.append("LIVE_EXECUTION_DISABLED")
            if not self.policy_version or request.policy_version != self.policy_version:
                blockers.append("POLICY_MISMATCH")
            if request.tenant not in self.tenant_bindings.get(request.actor, ()):
                blockers.append("ACTOR_TENANT_MISMATCH")
            if request.tenant not in self.tenant_bindings.get(request.agent, ()):
                blockers.append("AGENT_TENANT_MISMATCH")
            try:
                state = self.registry.decision_for(
                    request.agent, requested_action=request.capability,
                    capabilities=(request.capability,),
                )
                if state.get("decision") != "ALLOW":
                    blockers.append("AGENT_NOT_READY_OR_CAPABILITY_DENIED")
            except Exception:
                blockers.append("AGENT_LOOKUP_FAILED")
            binding = request.binding
            try:
                now = self.clock()
                grant = (self.approval_source(request) if self.approval_source
                         else self.grants.get(binding))
                if (grant is None or grant.revoked is not False
                        or grant.request_binding != binding
                        or not grant.reviewer or grant.reviewer == request.agent
                        or grant.issued_at.tzinfo is None or grant.expires_at.tzinfo is None
                        or now.tzinfo is None or not grant.issued_at <= now < grant.expires_at):
                    blockers.append("SCOPED_REVIEW_MISSING_OR_INVALID")
                else:
                    review = evaluate_human_approval({
                        "validation_passed": True,
                        "blast_radius": "OFFLINE_DRY_RUN_ONLY",
                        "changed_files": [binding],
                        "policy_version": HUMAN_APPROVAL_GATE_VERSION,
                        "human_reviewer": grant.reviewer,
                        "approval_timestamp": grant.issued_at.isoformat(),
                    }, actor=request.actor)
                    if review.decision != "APPROVED_FOR_PUBLICATION":
                        blockers.append("HUMAN_REVIEW_BLOCKED")
            except Exception:
                blockers.append("SCOPED_REVIEW_MISSING_OR_INVALID")
            attempt = sha256_payload(request.action_id)
            if attempt in self._seen:
                blockers.append("ACTION_ID_REUSED")
            self._seen.add(attempt)
            if self.consume_attempt is not None:
                try:
                    if self.consume_attempt(attempt, binding) is not True:
                        blockers.append("PERSISTENT_REPLAY_BLOCKED")
                except Exception:
                    blockers.append("PERSISTENT_REPLAY_UNAVAILABLE")
            # Only hashes and fixed codes reach the audit callback. No user
            # labels, mail bodies, recipients, trade data or grant contents.
            event = {
                "schema": "usbay.product_dry_run.v1",
                "request_hash": binding,
                "action_hash": attempt,
                "tenant_hash": sha256_payload(request.tenant),
                "decision": "BLOCKED" if blockers else "PREPARED_DRY_RUN",
                "blockers": sorted(set(blockers)),
                "external_mutation_performed": False,
                "execution_authorized": False,
            }
            audit_hash = None
            try:
                receipt = self.audit(dict(event))
                audit_hash = receipt.get("audit_hash")
                if receipt.get("decision") != "PASS" or not isinstance(audit_hash, str) or not re.fullmatch(r"[0-9a-f]{64}", audit_hash):
                    raise ValueError("INVALID_AUDIT_RECEIPT")
            except Exception:
                blockers.append("AUDIT_FAILED")
                audit_hash = None
            return {
                **event,
                "decision": "BLOCKED" if blockers else "PREPARED_DRY_RUN",
                "blockers": sorted(set(blockers)),
                "audit_hash": audit_hash,
            }
