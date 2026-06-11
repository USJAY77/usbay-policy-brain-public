from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256

from runtime.execution_adapters.adapter_approval_binding import AdapterApprovalBinding


DESKTOP_ACTIONS = {"read_screen", "click", "type", "scroll", "wait", "stop"}
HIGH_RISK_DESKTOP_ACTIONS = {"click", "type"}


def desktop_audit_hash(*parts: object) -> str:
    return sha256("|".join(str(part) for part in parts).encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class DesktopTargetSchema:
    target_id: str
    target_type: str
    coordinates: tuple[int, int] | None = None


@dataclass(frozen=True)
class DesktopActionSchema:
    action_id: str
    action_type: str
    risk_level: str
    required_capability: str
    text: str | None = None


@dataclass(frozen=True)
class DesktopExecutionRequest:
    action: DesktopActionSchema
    target: DesktopTargetSchema
    policy_version: str | None
    audit_id: str | None
    approval_binding: AdapterApprovalBinding | None = None
    dry_run: bool = True


@dataclass(frozen=True)
class DesktopAdapterDecision:
    adapter: str
    decision: str
    reason: str
    action_id: str | None
    policy_version: str | None
    audit_hash: str
    live_execution_performed: bool = False


class DesktopAdapterContract:
    adapter_name = "desktop"

    def validate(self, request: DesktopExecutionRequest | None) -> DesktopAdapterDecision:
        if request is None:
            return self._decision(None, "FAIL_CLOSED", "request_missing", None)
        if not request.policy_version:
            return self._decision(request, "FAIL_CLOSED", "policy_version_missing", request.action.action_id)
        if not request.audit_id:
            return self._decision(request, "FAIL_CLOSED", "audit_id_missing", request.action.action_id)
        if request.dry_run is not True:
            return self._decision(request, "FAIL_CLOSED", "live_desktop_execution_forbidden", request.action.action_id)
        if request.action.action_type not in DESKTOP_ACTIONS:
            return self._decision(request, "BLOCK", "unsupported_desktop_action", request.action.action_id)
        if not request.action.required_capability:
            return self._decision(request, "FAIL_CLOSED", "required_capability_missing", request.action.action_id)
        if request.action.action_type in HIGH_RISK_DESKTOP_ACTIONS or request.action.risk_level in {"HIGH", "CRITICAL"}:
            if request.approval_binding is None:
                return self._decision(request, "HUMAN_REVIEW", "desktop_action_requires_approval", request.action.action_id)
            if request.approval_binding.decision != "ALLOW":
                return self._decision(request, "FAIL_CLOSED", "approval_binding_invalid", request.action.action_id)
        return self._decision(request, "ALLOW", "desktop_adapter_request_validated", request.action.action_id)

    def _decision(
        self,
        request: DesktopExecutionRequest | None,
        decision: str,
        reason: str,
        action_id: str | None,
    ) -> DesktopAdapterDecision:
        policy_version = request.policy_version if request else None
        audit_hash = desktop_audit_hash(self.adapter_name, action_id, decision, reason, policy_version)
        return DesktopAdapterDecision(self.adapter_name, decision, reason, action_id, policy_version, audit_hash)

