from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256

from runtime.execution_adapters.adapter_approval_binding import AdapterApprovalBinding


BROWSER_ACTIONS = {"open_url", "read_page", "click", "type", "scroll", "wait", "stop"}
HIGH_RISK_BROWSER_TARGETS = {"merge", "delete", "deploy", "approve", "login", "credential", "token"}


def browser_audit_hash(*parts: object) -> str:
    return sha256("|".join(str(part) for part in parts).encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class BrowserNavigationSchema:
    url: str | None
    target_origin: str | None
    navigation_intent: str


@dataclass(frozen=True)
class BrowserActionSchema:
    action_id: str
    action_type: str
    target: str
    risk_level: str
    approval_binding: AdapterApprovalBinding | None = None


@dataclass(frozen=True)
class BrowserAdapterRequest:
    action: BrowserActionSchema
    navigation: BrowserNavigationSchema
    policy_version: str | None
    audit_id: str | None
    dry_run: bool = True


@dataclass(frozen=True)
class BrowserAdapterDecision:
    adapter: str
    decision: str
    reason: str
    action_id: str | None
    audit_hash: str
    live_execution_performed: bool = False


class BrowserAdapterContract:
    adapter_name = "browser"

    def validate(self, request: BrowserAdapterRequest | None) -> BrowserAdapterDecision:
        if request is None:
            return self._decision(None, "FAIL_CLOSED", "request_missing", None)
        if request.dry_run is not True:
            return self._decision(request, "FAIL_CLOSED", "live_browser_execution_forbidden", request.action.action_id)
        if not request.policy_version:
            return self._decision(request, "FAIL_CLOSED", "policy_version_missing", request.action.action_id)
        if not request.audit_id:
            return self._decision(request, "FAIL_CLOSED", "audit_id_missing", request.action.action_id)
        if request.action.action_type not in BROWSER_ACTIONS:
            return self._decision(request, "BLOCK", "unsupported_browser_action", request.action.action_id)
        target = request.action.target.lower()
        privileged = any(term in target for term in HIGH_RISK_BROWSER_TARGETS)
        if request.action.risk_level in {"HIGH", "CRITICAL"} or privileged:
            if request.action.approval_binding is None:
                return self._decision(request, "HUMAN_REVIEW", "browser_action_requires_approval", request.action.action_id)
            if request.action.approval_binding.decision != "ALLOW":
                return self._decision(request, "FAIL_CLOSED", "approval_binding_invalid", request.action.action_id)
        return self._decision(request, "ALLOW", "browser_adapter_request_validated", request.action.action_id)

    def _decision(
        self,
        request: BrowserAdapterRequest | None,
        decision: str,
        reason: str,
        action_id: str | None,
    ) -> BrowserAdapterDecision:
        policy_version = request.policy_version if request else None
        audit_hash = browser_audit_hash(self.adapter_name, action_id, decision, reason, policy_version)
        return BrowserAdapterDecision(self.adapter_name, decision, reason, action_id, audit_hash)

